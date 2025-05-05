//go:build linux
// +build linux

/*
rxtls — fast tool in Go for working with Certificate Transparency logs
Copyright (C) 2025  Pepijn van der Stap <rxtls@vanderstap.info>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package core

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/x-stp/rxtls/internal/certlib"

	"github.com/zeebo/xxh3"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

// WorkItem represents a unit of work (fetching/processing a block of CT entries).
// It is pooled via sync.Pool to reduce allocations in the hot path.
// Memory layout: Struct fields are standard types. Padding is not explicitly added here
// but could be considered if profiling reveals false sharing on LogInfo or Callback access.
type WorkItem struct {
	LogURL   string                     // Used for sharding work across workers.
	LogInfo  *certlib.CTLogInfo         // Pointer to CT log metadata needed for processing (e.g., DownloadEntries). Reused.
	Start    int64                      // Start index for the entry block.
	End      int64                      // End index for the entry block.
	Attempt  int                        // Tracks retry attempts for failed processing.
	Callback func(item *WorkItem) error // Function to execute for this work item. Zero-alloc if it's a method value or global func.
	Ctx      context.Context            // Added context for the specific task
}

// Scheduler manages a pool of worker goroutines, assigns them to CPU cores (on Linux),
// and dispatches WorkItems to them based on a hash of the LogURL.
// Goal: Maximize parallel processing, minimize cross-core communication overhead.
// Memory layout: Contains slices and maps. Ensure worker slice doesn't cause false sharing if accessed concurrently (unlikely here).
type Scheduler struct {
	numWorkers   int
	workers      []*worker          // Slice of worker goroutine managers.
	ctx          context.Context    // Master context for shutdown signalling.
	cancel       context.CancelFunc // Function to trigger shutdown.
	shutdown     atomic.Bool        // Flag to prevent submitting work during/after shutdown.
	workItemPool sync.Pool          // Pool for reusing WorkItem structs, reducing GC pressure.
	activeWork   sync.WaitGroup     // Tracks actively processing work items.
	// TODO: Add padding if profiling shows contention on shutdown flag or pool access.
}

// worker encapsulates a single worker goroutine and its state.
// Goal: Each worker processes tasks independently on its assigned core.
// Memory layout: Contains channel and pointers. Padding is unlikely to be needed unless queue access becomes a major bottleneck.
type worker struct {
	id          int             // Identifier for logging/debugging.
	cpuAffinity int             // Target CPU core ID for affinity setting.
	queue       chan *WorkItem  // Buffered channel acting as the work queue for this worker.
	scheduler   *Scheduler      // Pointer back to the scheduler for accessing shared resources (e.g., pool).
	ctx         context.Context // Worker-specific context linked to the scheduler's context.
	limiter     *rate.Limiter   // Rate limiter for this worker's queue
}

// NewScheduler creates, configures, and starts the scheduler and its worker pool.
// It attempts to set CPU affinity for each worker on Linux systems.
// Operation: Blocking (at startup), allocates worker/channel resources.
func NewScheduler(parentCtx context.Context) (*Scheduler, error) {
	// Calculate worker count based on CPU cores and multiplier.
	numWorkers := runtime.NumCPU() * WorkerMultiplier
	if numWorkers <= 0 {
		numWorkers = 1 // Safety: Ensure at least one worker exists.
	}

	// Create a cancellable context for the scheduler and its workers.
	sctx, cancel := context.WithCancel(parentCtx)

	// Initialize the scheduler struct.
	s := &Scheduler{
		numWorkers: numWorkers,
		workers:    make([]*worker, numWorkers), // Preallocate worker slice.
		ctx:        sctx,
		cancel:     cancel,
		workItemPool: sync.Pool{ // Initialize the WorkItem pool.
			New: func() interface{} {
				// Allocate a new WorkItem only when the pool is empty.
				return &WorkItem{}
			},
		},
		// shutdown flag defaults to false (zero value).
	}

	// Rate limiter settings
	// Allow bursts up to queue size, high initial rate (e.g., 1000/s)
	initialRate := rate.Limit(1000)
	burstSize := MaxShardQueueSize

	// Create and start each worker goroutine.
	for i := 0; i < numWorkers; i++ {
		w := &worker{
			id:          i,
			cpuAffinity: i % runtime.NumCPU(),                    // Simple round-robin core assignment.
			queue:       make(chan *WorkItem, MaxShardQueueSize), // Create buffered channel queue.
			scheduler:   s,
			ctx:         sctx,
			// Initialize limiter for each worker
			limiter: rate.NewLimiter(initialRate, burstSize),
		}
		s.workers[i] = w
		go w.run() // Launch the worker's main loop non-blockingly.
	}

	log.Printf("Scheduler initialized with %d workers (CPU affinity enabled).\n", numWorkers)
	return s, nil
}

// run is the main processing loop for a single worker goroutine.
// It first attempts to set CPU affinity, then enters a loop reading from its queue.
// Hot Path: Yes. Must be zero-GC, non-blocking (except on queue read).
func (w *worker) run() {
	// Set CPU Affinity - this is best-effort.
	setAffinity(w.id, w.cpuAffinity)

	// Loop indefinitely, processing work items until context is cancelled.
	for {
		select {
		// Prioritize checking for shutdown signal.
		case <-w.ctx.Done():
			return // Exit goroutine on context cancellation.
		// Read the next work item from the dedicated channel queue.
		// This blocks if the queue is empty, yielding the CPU.
		case item := <-w.queue:
			if item == nil { // Safety check, queue should only receive non-nil items.
				continue
			}

			// Mark work as done when the callback finishes or panics
			func() {
				defer w.scheduler.activeWork.Done() // Signal completion via WaitGroup
				defer func() {
					if r := recover(); r != nil {
						// Log panics in callbacks
						log.Printf("Panic recovered in worker %d processing item for %s (%d-%d): %v", w.id, item.LogURL, item.Start, item.End, r)
						// TODO: Increment a panic/failure counter stat
					}
				}()

				// Execute the assigned task. This is the core work (e.g., download, parse, write).
				// Performance depends heavily on the callback implementation.
				err := item.Callback(item)
				if err != nil {
					// Basic error logging. Replace with structured/batched logging.
					// TODO: Implement retry mechanism using item.Attempt instead of just logging.
					log.Printf("Error processing item for %s (%d-%d): %v\n", item.LogURL, item.Start, item.End, err)
				}
			}()

			// Return the WorkItem struct to the pool for reuse.
			// Reset fields to avoid data leakage between uses.
			item.Callback = nil
			item.LogURL = ""
			item.LogInfo = nil
			item.Ctx = nil                     // Reset context
			w.scheduler.workItemPool.Put(item) // Reduces allocation churn.
		}
	}
}

// setAffinity attempts to bind the current goroutine's OS thread to a specific CPU core.
// This is a Linux-specific optimization to improve cache locality.
// Operation: Blocking (briefly for syscalls), potentially fails silently.
func setAffinity(workerID, cpuID int) {
	// runtime.LockOSThread ensures the goroutine doesn't migrate OS threads
	// between this call and the SchedSetaffinity syscall.
	runtime.LockOSThread()
	// No defer runtime.UnlockOSThread() because the worker goroutine runs for the
	// lifetime of the scheduler; unlocking isn't necessary unless the thread needs
	// to be reused for other goroutines later (which isn't the case here).

	var cpuSet unix.CPUSet
	cpuSet.Zero()     // Initialize the CPU set.
	cpuSet.Set(cpuID) // Add the target CPU core to the set.

	// Get the OS thread ID for the current goroutine.
	tid := unix.Gettid()

	// Attempt to set the CPU affinity for this thread.
	err := unix.SchedSetaffinity(tid, &cpuSet)
	if err != nil {
		// Log failure as a warning; the program can continue without affinity.
		log.Printf("Warning: Failed to set CPU affinity for worker %d on core %d (tid: %d): %v\n", workerID, cpuID, tid, err)
	}
}

// SubmitWork routes a work item to a specific worker queue based on hashing the logURL.
// It uses a non-blocking send to the worker's channel to provide backpressure.
// Hot Path: Yes, called frequently to dispatch work.
// Operation: Non-blocking (unless pool Get blocks), low allocation (pool Get/Put).
func (s *Scheduler) SubmitWork(ctx context.Context, logInfo *certlib.CTLogInfo, start, end int64, callback func(item *WorkItem) error) error {
	if s.shutdown.Load() {
		return fmt.Errorf("scheduler is shutting down")
	}
	logURL := logInfo.URL
	shardIndex := int(xxh3.HashString(logURL) % uint64(s.numWorkers))
	targetWorker := s.workers[shardIndex]

	// NOTE: Rate limiting is now handled by the CALLER using limiter.Wait()
	// before calling SubmitWork. SubmitWork now focuses purely on the atomic
	// queue submission attempt and reporting backpressure.

	item := s.workItemPool.Get().(*WorkItem)
	item.LogURL = logURL
	item.LogInfo = logInfo
	item.Start = start
	item.End = end
	item.Attempt = 0
	item.Callback = callback
	item.Ctx = ctx
	s.activeWork.Add(1)

	select {
	case targetWorker.queue <- item:
		// Optional: Increase rate limit slowly on success?
		// currentLimit := targetWorker.limiter.Limit()
		// targetWorker.limiter.SetLimit(min(currentLimit * 1.01, rate.Limit(10000))) // Example increase
		return nil // Success
	default:
		// Queue is full - signal backpressure immediately
		s.activeWork.Done()
		s.workItemPool.Put(item)
		// Optional: Aggressively reduce rate limit on detected backpressure
		// currentLimit := targetWorker.limiter.Limit()
		// newLimit := max(currentLimit / 2, rate.Limit(1)) // Halve rate, minimum 1/s
		// targetWorker.limiter.SetLimit(newLimit)
		// log.Printf("Worker %d queue full, reducing limit to %v", targetWorker.id, newLimit)
		return fmt.Errorf("worker %d for log %s: %w", targetWorker.id, logURL, ErrQueueFull)
	}
}

// Wait waits until all submitted work items have been processed.
func (s *Scheduler) Wait() {
	log.Println("Scheduler waiting for active work to complete...")
	s.activeWork.Wait()
	log.Println("Scheduler active work completed.")
}

// Shutdown initiates a graceful shutdown of the scheduler and its workers.
// Operation: Non-blocking signal, does not wait for workers to finish.
func (s *Scheduler) Shutdown() {
	// Use atomic CompareAndSwap to ensure shutdown logic runs only once.
	if s.shutdown.CompareAndSwap(false, true) {
		log.Println("Scheduler shutting down...")
		// Cancel the context, signalling all workers listening on w.ctx.Done().
		s.cancel()
		// Note: This function returns immediately. Waiting for actual worker completion
		// would require additional synchronization (e.g., a sync.WaitGroup coordinated
		// within the worker run loops or the calling code).
		// TODO: Add mechanism to wait for worker completion if required by caller.
		log.Println("Scheduler shutdown signal sent.")
	}
}
