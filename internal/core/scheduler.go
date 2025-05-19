//go:build linux
// +build linux

/*
Package core provides the central logic for rxtls, including the scheduler, download manager,
and domain extractor. It defines common data structures and constants used across these components.
*/

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
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/x-stp/rxtls/internal/certlib"
	"github.com/x-stp/rxtls/internal/metrics"
	"github.com/zeebo/xxh3"

	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

// Scheduler-specific constants.
const (
	// DefaultWorkerRateLimit is the default rate limit (requests per second) applied to each worker's limiter.
	// This is an initial value and can be dynamically adjusted.
	DefaultWorkerRateLimit = rate.Limit(25)

	// DefaultWorkerBurst is the default burst size for each worker's rate limiter.
	// It allows a worker to exceed its rate limit for a short period, up to this many additional requests.
	DefaultWorkerBurst = 35
)

// Scheduler manages a pool of worker goroutines to process WorkItems concurrently.
// It distributes work based on a sharding key (typically the log URL) to ensure that
// items for the same log are usually processed by the same worker, which can be beneficial
// for cache locality or per-log resource management (like rate limiting).
//
// The Scheduler supports graceful shutdown via context cancellation.
//
// Key features:
// - Worker pool for concurrent task execution.
// - Sharded work distribution using xxh3 hashing of log URLs.
// - Per-worker rate limiting using golang.org/x/time/rate.
// - CPU affinity setting for workers on Linux systems to potentially improve performance.
// - Pooling of WorkItem structs to reduce allocations.
// - Graceful shutdown and waiting for active work to complete.
// - Dynamic adjustment of worker rate limits based on queue pressure and task success/failure.
// - Periodic logging of rate limiter and queue statuses.
type Scheduler struct {
	// numWorkers is the total number of worker goroutines managed by the scheduler.
	// Typically initialized based on CPU core count and WorkerMultiplier.
	numWorkers int
	// workers is a slice holding pointers to all active Worker instances.
	workers []*Worker
	// ctx is the master context for the scheduler. When this context is cancelled,
	// all workers are signalled to shut down.
	ctx context.Context
	// cancel is the function to call to cancel the scheduler's master context (ctx).
	cancel context.CancelFunc
	// shutdown indicates atomically whether the scheduler is in the process of shutting down.
	// If true, new work submissions will be rejected.
	shutdown atomic.Bool
	// workItemPool is a sync.Pool for reusing WorkItem structs, reducing garbage collection overhead.
	workItemPool sync.Pool
	// activeWork is a sync.WaitGroup used to track the number of currently active (submitted but not yet completed)
	// work items. The scheduler's Wait() method blocks until this counter reaches zero.
	activeWork sync.WaitGroup
	// metricsRegistry is a reference to the Prometheus metrics registry, used for custom metric collection.
	// This field is currently not fully utilized for direct registration but could be for advanced metrics.
	metricsRegistry *metrics.Metrics // Retained for potential future direct metric interactions.
}

// Worker represents a single goroutine dedicated to processing WorkItems from its queue.
// Each worker has its own queue, rate limiter, and potentially CPU affinity.
//
// Concurrency: A Worker runs in its own goroutine. Its internal state (metrics, rate limiter)
// is managed for concurrent access, primarily through atomic operations or by the rate.Limiter itself.
type Worker struct {
	// Immutable fields, set at worker creation and not changed thereafter.

	// id is a unique identifier for this worker (e.g., its index in the scheduler's worker slice).
	id int
	// ctx is the context for this specific worker. It is derived from the scheduler's master context.
	// Cancellation of this context signals the worker to shut down its run loop.
	ctx context.Context
	// cancel is the function to cancel this worker's context. (Currently unused as worker context is derived from scheduler).
	_ func() // Retained field from previous structure, explicitly ignore `cancel context.CancelFunc`
	// scheduler is a pointer back to the parent Scheduler that manages this worker.
	scheduler *Scheduler
	// queue is the channel from which this worker receives WorkItems to process.
	// It is a buffered channel with a capacity defined by MaxShardQueueSize.
	queue chan *WorkItem
	// limiter is this worker's individual rate limiter, controlling how frequently it can
	// start processing new items, particularly relevant before operations like network requests.
	limiter *rate.Limiter
	// cpuAffinity is the CPU core ID to which this worker's goroutine will attempt to be pinned
	// on Linux systems. A value of -1 indicates no affinity is set or supported.
	cpuAffinity int

	// Metrics for this worker, updated atomically.

	// processed is the total number of WorkItems successfully processed by this worker.
	processed atomic.Int64
	// errors is the total number of WorkItems that resulted in an error during processing by this worker.
	errors atomic.Int64
	// panics is the total number of panics recovered during callback execution by this worker.
	panics atomic.Int64
	// busy indicates atomically whether the worker is currently processing a WorkItem.
	busy atomic.Bool
	// lastActive stores the Unix nanosecond timestamp of when the worker last started processing an item.
	// Useful for monitoring worker activity and idleness.
	lastActive atomic.Int64

	// Rate Limiter Tracking for dynamic adjustments and logging.

	// currentLimit stores the current rate limit (requests/sec) of this worker's limiter.
	// Stored as atomic.Value containing a float64 for safe concurrent access.
	currentLimit atomic.Value
	// lastLimitUpdate records the time of the last dynamic adjustment to this worker's rate limit.
	lastLimitUpdate time.Time
}

// NewScheduler creates, initializes, and starts a new Scheduler instance.
// It determines the number of workers based on CPU cores and WorkerMultiplier,
// creates and starts each worker goroutine, and sets up a periodic logger for rate limiter statuses.
//
// Parameters:
//
//	parentCtx: The parent context for the scheduler. If this context is cancelled,
//	           the scheduler and all its workers will begin to shut down.
//
// Returns:
//
//	A pointer to the newly created Scheduler, or an error if initialization fails
//	(though current implementation always returns nil error on success).
//
// Operation: This function is blocking during the initialization of workers. It starts multiple goroutines.
func NewScheduler(parentCtx context.Context) (*Scheduler, error) {
	numWorkers := runtime.NumCPU() * WorkerMultiplier
	if numWorkers <= 0 {
		numWorkers = 1 // Ensure at least one worker.
	}
	if numWorkers > MaxWorkers { // Cap the number of workers.
		numWorkers = MaxWorkers
	}

	sctx, cancel := context.WithCancel(parentCtx)

	s := &Scheduler{
		numWorkers: numWorkers,
		workers:    make([]*Worker, numWorkers),
		ctx:        sctx,
		cancel:     cancel,
		workItemPool: sync.Pool{
			New: func() interface{} {
				// Initialize WorkItems with CreatedAt to track potential queue latency.
				return &WorkItem{CreatedAt: time.Now()}
			},
		},
		metricsRegistry: metrics.GetMetrics(), // Get global metrics instance.
	}

	// Initialize each worker.
	// Initial rate limit is set high, assuming it will be adjusted dynamically.
	// Burst size allows for some initial burstiness or uneven work distribution.
	initialRate := rate.Limit(1000) // High initial rate, expecting dynamic adjustment.
	burstSize := MaxShardQueueSize  // Allow burst up to queue size.

	for i := 0; i < numWorkers; i++ {
		w := &Worker{
			id:          i,
			cpuAffinity: i % runtime.NumCPU(), // Distribute affinity across available cores.
			queue:       make(chan *WorkItem, MaxShardQueueSize),
			scheduler:   s,
			ctx:         sctx, // Worker context is the same as scheduler's cancellable context.
			limiter:     rate.NewLimiter(initialRate, burstSize),
		}
		w.currentLimit.Store(float64(initialRate)) // Store initial rate for logging/monitoring.
		w.lastLimitUpdate = time.Now()
		s.workers[i] = w
		go w.run() // Start the worker's main processing loop in a new goroutine.
	}

	// Start a goroutine to periodically log the status of all worker rate limiters and queues.
	go s.logRateLimiterStatus()

	log.Printf("Scheduler initialized with %d workers (CPU affinity: %t).",
		numWorkers, runtime.GOOS == "linux")
	return s, nil
}

// SubmitWork attempts to submit a WorkItem to an appropriate worker's queue.
// Work is sharded based on the hash of the logInfo.URL to attempt to send work for the
// same log to the same worker. This can improve cache efficiency or allow for per-log
// resource management (like rate limiting) if workers specialize.
//
// If the target worker's queue is full, this method implements a dynamic rate adjustment strategy:
// - On successful submission: It may slightly increase the worker's rate limit.
// - On queue full (backpressure): It decreases the worker's rate limit and returns ErrQueueFull.
//
// This method is thread-safe.
//
// Parameters:
//
//	ctx: Context for the submission itself; can be used for immediate cancellation of submission attempt.
//	logInfo: Metadata about the CT log this work pertains to.
//	start: The starting index of the entry range for this work.
//	end: The ending index (inclusive) for this work.
//	callback: The WorkCallback function to be executed for this work item.
//
// Returns:
//
//	nil if the work was successfully submitted.
//	ErrQueueFull if the target worker's queue was full after considering rate limits.
//	An error if the scheduler is shutting down or if another error occurs.
func (s *Scheduler) SubmitWork(ctx context.Context, logInfo *certlib.CTLogInfo, start, end int64, callback WorkCallback) error {
	if s.shutdown.Load() {
		return fmt.Errorf("scheduler is shutting down, cannot submit work for %s", logInfo.URL)
	}

	logURL := logInfo.URL // Cache for local use, as logInfo might be a pointer to changing data if not careful.
	// Determine the target worker using consistent hashing of the log URL.
	// This aims to direct work for the same log to the same worker.
	shardIndex := int(xxh3.HashString(logURL) % uint64(s.numWorkers))
	targetWorker := s.workers[shardIndex]

	// Log current rate limit before attempting to use it (for debugging/monitoring).
	currentRate := targetWorker.limiter.Limit()
	// Debug-level logging, consider making this conditional via a flag.
	// log.Printf("Worker %d rate limit before submission: %.2f r/s for log %s (%d-%d)",
	// 	targetWorker.id, float64(currentRate), logURL, start, end)

	// Get a WorkItem from the pool to reduce allocations.
	item := s.workItemPool.Get().(*WorkItem)
	// Populate the WorkItem fields.
	item.LogURL = logURL
	item.LogInfo = logInfo
	item.Start = start
	item.End = end
	item.Attempt = 0 // Reset attempt count for new/reused item.
	item.Callback = callback
	item.Ctx = ctx              // Associate the submission context with the item.
	item.CreatedAt = time.Now() // Update creation time for reused items.
	item.Error = nil            // Clear any previous error.
	s.activeWork.Add(1)         // Increment active work counter.

	// Attempt to send the item to the target worker's queue.
	// This is non-blocking due to the select with a default case.
	select {
	case targetWorker.queue <- item:
		// Successfully submitted to queue.
		// Dynamic Rate Adjustment: On successful enqueue, slightly increase the rate limit.
		// This is a simple heuristic; more sophisticated AIMD (Additive Increase, Multiplicative Decrease)
		// could be used but is more complex to tune with external rate limiters.
		newRateValue := float64(currentRate) * 1.02 // Modest 2% increase.
		if newRateValue > 2000 {                    // Cap increase.
			newRateValue = 2000
		}
		if newRateLimit := rate.Limit(newRateValue); newRateLimit != currentRate {
			targetWorker.limiter.SetLimit(newRateLimit)
			targetWorker.currentLimit.Store(newRateValue)
			targetWorker.lastLimitUpdate = time.Now()
			// log.Printf("Worker %d rate limit INCREASED (submission success): %.2f -> %.2f r/s for %s",
			// 	targetWorker.id, float64(currentRate), newRateValue, logURL)
		}
		return nil
	default:
		// Queue is full (backpressure).
		s.activeWork.Done()      // Decrement active work as this item won't be processed now.
		s.workItemPool.Put(item) // Return item to pool.

		// Dynamic Rate Adjustment: On queue full, significantly decrease the rate limit.
		newRateValue := float64(currentRate) * 0.75 // Substantial 25% decrease.
		if newRateValue < 5 {
			newRateValue = 5 // Floor to prevent stalling.
		}
		if newRateLimit := rate.Limit(newRateValue); newRateLimit != currentRate {
			targetWorker.limiter.SetLimit(newRateLimit)
			targetWorker.currentLimit.Store(newRateValue)
			targetWorker.lastLimitUpdate = time.Now()
			log.Printf("Worker %d rate limit DECREASED (queue full): %.2f -> %.2f r/s for %s",
				targetWorker.id, float64(currentRate), newRateValue, logURL)
		}
		return fmt.Errorf("worker %d for log %s queue is full: %w", targetWorker.id, logURL, ErrQueueFull)
	}
}

// Wait blocks until all WorkItems submitted to the scheduler have been completed
// (i.e., their callback has finished executing, successfully or with an error).
// This is achieved by waiting on the `activeWork` WaitGroup.
// This method is typically called before shutting down the application to ensure
// all pending work is processed.
func (s *Scheduler) Wait() {
	s.activeWork.Wait()
}

// Shutdown initiates a graceful shutdown of the scheduler and its workers.
// It cancels the scheduler's master context, which signals all workers to stop
// processing new items from their queues and finish their current item.
// Then, it waits for all active work to complete using `s.Wait()`.
// This function is idempotent.
func (s *Scheduler) Shutdown() {
	if s.shutdown.Load() { // Prevent multiple shutdowns.
		return
	}
	s.shutdown.Store(true)
	log.Println("Scheduler shutting down...")
	s.cancel() // Signal all workers and operations using this context to stop.
	s.Wait()   // Wait for all active work items to be processed.
	log.Println("Scheduler shutdown complete.")
}

// run is the main processing loop for a Worker goroutine.
// It continuously attempts to read WorkItems from its queue.
// When an item is received, it calls `processWorkItem`.
// The loop terminates when the worker's context (w.ctx) is cancelled.
// CPU affinity is set at the beginning of this loop if on Linux.
func (w *Worker) run() {
	// Set CPU affinity for this worker's goroutine if on Linux.
	// This can potentially improve performance by reducing cache misses and context switching.
	if runtime.GOOS == "linux" && w.cpuAffinity >= 0 {
		setCPUAffinity(w.id, w.cpuAffinity)
	}

	log.Printf("Worker %d started (CPU affinity: %d, OS: %s)", w.id, w.cpuAffinity, runtime.GOOS)

	for {
		select {
		case <-w.ctx.Done(): // Check for scheduler shutdown signal.
			log.Printf("Worker %d shutting down (context cancelled).", w.id)
			return
		case item, ok := <-w.queue: // Read from the worker's dedicated queue.
			if !ok {
				// Queue channel has been closed, which might indicate an issue or specific shutdown sequence.
				log.Printf("Worker %d queue channel closed, shutting down.", w.id)
				return
			}
			if item == nil { // Should not happen with proper pooling, but good to check.
				continue
			}
			w.processWorkItem(item) // Process the received work item.
		}
	}
}

// processWorkItem handles the execution of a single WorkItem.
// It marks the worker as busy, executes the item's callback function (with panic recovery),
// and then handles the result (success, failure with potential retry, or cancellation).
func (w *Worker) processWorkItem(item *WorkItem) {
	w.busy.Store(true)
	w.lastActive.Store(time.Now().UnixNano())
	// metrics.GetMetrics().WorkerBusy.WithLabelValues(fmt.Sprintf("%d", w.id)).Set(1)
	defer func() {
		w.busy.Store(false)
		// metrics.GetMetrics().WorkerBusy.WithLabelValues(fmt.Sprintf("%d", w.id)).Set(0)
	}()

	// Check if the item's specific context is cancelled before processing.
	if item.Ctx.Err() != nil {
		w.handleCancelledItem(item) // Item's context was cancelled.
		return
	}
	// Also check the worker's main context.
	if w.ctx.Err() != nil {
		w.handleCancelledItem(item) // Worker is shutting down.
		return
	}

	var err error
	// Execute the callback in a deferred function to recover from panics.
	func() {
		defer func() {
			if r := recover(); r != nil {
				w.panics.Add(1)
				// metrics.GetMetrics().WorkerPanics.WithLabelValues(fmt.Sprintf("%d", w.id)).Inc()
				// Capture stack trace for better debugging.
				buf := make([]byte, 10240)
				written := runtime.Stack(buf, false)
				err = fmt.Errorf("panic in callback for %s (%d-%d): %v\nStack:\n%s",
					item.LogURL, item.Start, item.End, r, string(buf[:written]))
				log.Printf("[PANIC] Worker %d: %v", w.id, err) // Log panic prominently.
			}
		}()
		err = item.Callback(item) // Execute the actual work.
	}()

	if err != nil {
		w.handleFailedItem(item, err)
	} else {
		w.handleSuccessfulItem(item)
	}
}

// handleSuccessfulItem is called when a WorkItem's callback executes without error.
// It increments success metrics, potentially adjusts the worker's rate limit upwards,
// signals completion to the scheduler, and returns the WorkItem to the pool.
func (w *Worker) handleSuccessfulItem(item *WorkItem) {
	w.processed.Add(1)
	// metrics.GetMetrics().WorkerProcessed.WithLabelValues(fmt.Sprintf("%d", w.id), item.LogURL).Inc()

	// Dynamic Rate Adjustment: On success, potentially increase rate limit.
	currentRateLimit := w.limiter.Limit()
	// Heuristic: Increase rate if consistently successful. This can be tuned.
	// For example, increase every N successes or if error rate is very low.
	// Current implementation: increase slightly after a certain number of consecutive successes.
	consecutiveSuccesses := w.processed.Load() - w.errors.Load() // Simple proxy for recent success.

	if consecutiveSuccesses > 5 && consecutiveSuccesses%5 == 0 { // Trigger every 5 net successes (after initial 5).
		newRateValue := float64(currentRateLimit) * 1.05 // Increase by 5%.
		if newRateValue > 2000 {                         // Apply a cap.
			newRateValue = 2000
		}
		if newRate := rate.Limit(newRateValue); newRate != currentRateLimit {
			w.limiter.SetLimit(newRate)
			w.currentLimit.Store(newRateValue)
			w.lastLimitUpdate = time.Now()
			// log.Printf("Worker %d rate limit INCREASED (success): %.2f -> %.2f r/s (streak: %d)",
			// 	w.id, float64(currentRateLimit), newRateValue, consecutiveSuccesses)
		}
	}

	w.scheduler.activeWork.Done() // Signal that this work item is complete.
	// Reset and return WorkItem to the pool.
	item.Callback = nil
	item.LogInfo = nil
	item.Ctx = nil
	item.Error = nil
	w.scheduler.workItemPool.Put(item)
}

// handleFailedItem is called when a WorkItem's callback returns an error.
// It increments error metrics, potentially adjusts the worker's rate limit downwards,
// and then checks if the item should be retried based on its attempt count and the error's nature.
// If retries are exhausted or the error is not retryable, the item is finalized; otherwise, it's rescheduled.
func (w *Worker) handleFailedItem(item *WorkItem, err error) {
	w.errors.Add(1)
	// metrics.GetMetrics().WorkerErrors.WithLabelValues(fmt.Sprintf("%d", w.id), item.LogURL, "callback_error").Inc()
	item.Error = err // Store the error in the WorkItem.

	// Dynamic Rate Adjustment: On failure, decrease rate limit more aggressively.
	currentRateLimit := w.limiter.Limit()
	newRateValue := float64(currentRateLimit) * 0.80 // Decrease by 20%.
	if newRateValue < 5 {
		newRateValue = 5 // Floor to prevent complete stall.
	}
	if newRate := rate.Limit(newRateValue); newRate != currentRateLimit {
		w.limiter.SetLimit(newRate)
		w.currentLimit.Store(newRateValue)
		w.lastLimitUpdate = time.Now()
		log.Printf("Worker %d rate limit DECREASED (item error): %.2f -> %.2f r/s for %s due to: %v",
			w.id, float64(currentRateLimit), newRateValue, item.LogURL, err)
	}

	// Check if the error is explicitly marked as non-retryable by our custom error type,
	// or if it's a context cancellation error (which shouldn't be retried).
	isNonRetryableError := errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
	if cerr, ok := err.(*customError); ok {
		if !cerr.IsRetryable() {
			isNonRetryableError = true
		}
	}

	if item.Attempt < MaxRetries && !isNonRetryableError { // Use MaxRetries from constants.go
		log.Printf("Worker %d retrying item for %s (%d-%d) after error (attempt %d): %v",
			w.id, item.LogURL, item.Start, item.End, item.Attempt+1, err)
		w.retryItem(item)
		return
	}

	// Retries exhausted or error is not retryable.
	log.Printf("Worker %d failed to process item for %s (%d-%d) after %d attempts, final error: %v",
		w.id, item.LogURL, item.Start, item.End, item.Attempt+1, err)
	w.scheduler.activeWork.Done() // Signal completion (failure).
	// Reset and return WorkItem to the pool.
	item.Callback = nil
	item.LogInfo = nil
	item.Ctx = nil
	// item.Error is already set.
	w.scheduler.workItemPool.Put(item)
}

// handleCancelledItem is called when a WorkItem cannot be processed because its context
// or the worker's context was cancelled.
// It marks the item with ErrWorkerShutdown (or similar context error) and returns it to the pool.
func (w *Worker) handleCancelledItem(item *WorkItem) {
	if item.Ctx.Err() != nil {
		item.Error = item.Ctx.Err() // Prefer item's specific context error.
	} else if w.ctx.Err() != nil {
		item.Error = w.ctx.Err() // Worker context cancelled.
	} else {
		item.Error = ErrWorkerShutdown // Fallback.
	}
	// log.Printf("Worker %d cancelling item for %s (%d-%d) due to context: %v",
	// 	w.id, item.LogURL, item.Start, item.End, item.Error)

	w.scheduler.activeWork.Done() // Signal completion (cancelled).
	// Reset and return WorkItem to the pool.
	item.Callback = nil
	item.LogInfo = nil
	item.Ctx = nil
	w.scheduler.workItemPool.Put(item)
}

// retryItem increments the attempt counter for a WorkItem and schedules it for a delayed retry.
// The delay is calculated using `calculateRetryDelay`.
func (w *Worker) retryItem(item *WorkItem) {
	item.Attempt++
	delay := calculateRetryDelay(item.Attempt)
	w.scheduleRetry(item, delay)
}

// scheduleRetry attempts to re-queue a WorkItem after the specified delay.
// It handles context cancellations (item's, worker's) during the delay or re-queueing attempt.
// If the worker's own queue is full, it tries to submit to other workers. If all are full,
// it schedules another retry with doubled delay (a simple form of load shedding for retries).
func (w *Worker) scheduleRetry(item *WorkItem, delay time.Duration) {
	// Wait for the retry delay, but also listen for context cancellations.
	select {
	case <-time.After(delay):
		// Delay elapsed, proceed with retry.
	case <-item.Ctx.Done():
		// Item's context was cancelled during the delay.
		w.handleCancelledItem(item)
		return
	case <-w.ctx.Done():
		// Worker/Scheduler context was cancelled during the delay.
		w.handleCancelledItem(item)
		return
	}

	// Re-check contexts after delay, as they might have been cancelled right when delay ended.
	if item.Ctx.Err() != nil {
		w.handleCancelledItem(item)
		return
	}
	if w.ctx.Err() != nil {
		w.handleCancelledItem(item)
		return
	}

	// Attempt to re-submit to this worker's queue first.
	select {
	case w.queue <- item:
		// Successfully re-queued to the same worker.
		return
	default:
		// This worker's queue is full. Try to submit to another worker's queue.
		// This provides a basic form of load balancing for retries.
		for i := 0; i < w.scheduler.numWorkers; i++ {
			// Cycle through other workers, starting from the next one.
			otherWorker := w.scheduler.workers[(w.id+i+1)%w.scheduler.numWorkers]
			select {
			case otherWorker.queue <- item:
				// log.Printf("Worker %d re-queued item for %s (%d-%d) to worker %d after delay %v",
				// 	w.id, item.LogURL, item.Start, item.End, otherWorker.id, delay)
				return // Successfully re-queued to another worker.
			default:
				// Other worker's queue is also full, try the next.
			}
		}

		// All other worker queues are also full. Schedule another retry with a longer delay.
		log.Printf("Worker %d: All worker queues full for retrying %s (%d-%d), will retry again after %v.",
			w.id, item.LogURL, item.Start, item.End, delay*2)
		go w.scheduleRetry(item, delay*2) // Recursive call, ensure this doesn't lead to infinite loops without progress.
	}
}

// calculateRetryDelay computes the delay for the next retry attempt using exponential backoff
// with jitter. Constants like RetryBaseDelay, RetryMaxDelay, RetryBackoffMultiplier, and
// RetryJitterFactor are used from `common.go`.
//
// Parameters:
//
//	attempt: The current retry attempt number (1-based for calculation).
//
// Returns:
//
//	The calculated time.Duration for the retry delay.
func calculateRetryDelay(attempt int) time.Duration {
	// Exponential backoff: baseDelay * (multiplier ^ (attempt - 1))
	delay := time.Duration(float64(RetryBaseDelay) * math.Pow(RetryBackoffMultiplier, float64(attempt-1)))
	if delay > RetryMaxDelay {
		delay = RetryMaxDelay // Cap the delay at RetryMaxDelay.
	}

	// Add jitter: random percentage of the current delay.
	jitterRange := float64(delay) * RetryJitterFactor
	// math/rand is used here for simplicity; for crypto-secure random, use crypto/rand.
	// Since this is for jitter, math/rand is acceptable.
	jitterAmount := time.Duration(rand.Float64() * jitterRange) // rand.Float64() is [0.0, 1.0)
	return delay + jitterAmount
}

// setCPUAffinity attempts to set the CPU affinity for the current goroutine (OS thread)
// to a specific CPU core ID. This is only effective on Linux.
// If an error occurs during SchedSetaffinity, it is logged.
//
// Parameters:
//
//	workerID: The ID of the worker, used for logging purposes.
//	cpuID: The ID of the CPU core to which affinity should be set.
func setCPUAffinity(workerID, cpuID int) {
	var cpuSet unix.CPUSet
	cpuSet.Zero()     // Clears the set.
	cpuSet.Set(cpuID) // Adds the specified CPU to the set.
	// SchedSetaffinity sets the CPU affinity mask of the thread specified by pid.
	// If pid is zero, then the affinity mask of the calling thread is set.
	if err := unix.SchedSetaffinity(0, &cpuSet); err != nil {
		log.Printf("Warning: Worker %d failed to set CPU affinity to %d: %v", workerID, cpuID, err)
	}
}

// logRateLimiterStatus periodically logs the current status of each worker's rate limiter and queue.
// This includes the current rate limit, queue length/capacity, and processed/error counts.
// It also logs a summary (min, max, average rate limit) across all workers.
// This function runs in its own goroutine and stops when the scheduler's context is cancelled.
func (s *Scheduler) logRateLimiterStatus() {
	ticker := time.NewTicker(30 * time.Second) // Log status every 30 seconds.
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done(): // Scheduler is shutting down.
			return
		case <-ticker.C:
			if len(s.workers) == 0 {
				continue
			}
			var totalLimit float64
			minLimit := s.workers[0].limiter.Limit() // Initialize with the first worker's limit.
			maxLimit := s.workers[0].limiter.Limit()

			for i, w := range s.workers {
				currentWorkerLimit := w.limiter.Limit()
				totalLimit += float64(currentWorkerLimit)

				if currentWorkerLimit < minLimit {
					minLimit = currentWorkerLimit
				}
				if currentWorkerLimit > maxLimit {
					maxLimit = currentWorkerLimit
				}

				queueLen := len(w.queue)
				queueCap := cap(w.queue)
				queueFillPercent := 0.0
				if queueCap > 0 {
					queueFillPercent = float64(queueLen) / float64(queueCap) * 100
				}

				log.Printf("[SchedulerStats] Worker %2d: RateLimit=%.2f r/s, Queue=%4d/%4d (%.1f%%), Processed=%7d, Errors=%4d, LastUpdate: %s ago",
					i, float64(currentWorkerLimit), queueLen, queueCap, queueFillPercent,
					w.processed.Load(), w.errors.Load(), time.Since(w.lastLimitUpdate).Round(time.Second))
			}

			avgLimit := totalLimit / float64(len(s.workers))
			log.Printf("[SchedulerStats] Summary: AvgRate=%.2f r/s, MinRate=%.2f r/s, MaxRate=%.2f r/s, Workers=%d",
				avgLimit, float64(minLimit), float64(maxLimit), len(s.workers))
		}
	}
}
