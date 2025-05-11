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
	"math"
	"math/rand"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/x-stp/rxtls/internal/certlib"
	"github.com/zeebo/xxh3"

	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sys/unix"
	"golang.org/x/time/rate"
)

const (
	// DefaultWorkerRateLimit is the default rate limit per worker
	DefaultWorkerRateLimit = rate.Limit(25)

	// DefaultWorkerBurst is the default burst limit per worker
	DefaultWorkerBurst = 35

	// MaxShardQueueSize is the maximum size of a shard's queue
	MaxShardQueueSize = 1000

	// WorkerMultiplier is the multiplier for the number of workers
	WorkerMultiplier = 2

	// RetryBaseDelay is the base delay for retries
	RetryBaseDelay = 125 * time.Millisecond

	// RetryMaxDelay is the maximum delay for retries
	RetryMaxDelay = 30 * time.Second

	// RetryBackoffMultiplier is the multiplier for exponential backoff
	RetryBackoffMultiplier = 1.5

	// RetryJitterFactor is the jitter factor for randomized backoff
	RetryJitterFactor = 0.2
)

// WorkItem represents a unit of work to be processed by the scheduler
type WorkItem struct {
	// Immutable fields
	LogURL    string
	LogInfo   *certlib.CTLogInfo
	Start     int64
	End       int64
	Callback  WorkCallback
	Ctx       context.Context
	CreatedAt time.Time

	// Mutable fields
	Attempt int
	Error   error
}

// WorkCallback is the function signature for work item callbacks
type WorkCallback func(item *WorkItem) error

// Scheduler manages a pool of workers and distributes work among them
type Scheduler struct {
	numWorkers   int
	workers      []*Worker
	ctx          context.Context
	cancel       context.CancelFunc
	shutdown     atomic.Bool
	workItemPool sync.Pool
	activeWork   sync.WaitGroup // Tracks active work
	metrics      *prometheus.GaugeVec
}

// Worker represents a worker goroutine in the scheduler
type Worker struct {
	// Immutable fields
	id          int
	ctx         context.Context
	cancel      context.CancelFunc
	scheduler   *Scheduler
	queue       chan *WorkItem
	limiter     *rate.Limiter
	cpuAffinity int

	// Metrics
	processed  atomic.Int64
	errors     atomic.Int64
	panics     atomic.Int64
	busy       atomic.Bool
	lastActive atomic.Int64
}

// NewScheduler creates a new scheduler with the specified number of workers
func NewScheduler(parentCtx context.Context) (*Scheduler, error) {
	numWorkers := runtime.NumCPU() * WorkerMultiplier
	if numWorkers <= 0 {
		numWorkers = 1
	}

	sctx, cancel := context.WithCancel(parentCtx)

	s := &Scheduler{
		numWorkers: numWorkers,
		workers:    make([]*Worker, numWorkers),
		ctx:        sctx,
		cancel:     cancel,
		workItemPool: sync.Pool{
			New: func() interface{} {
				return &WorkItem{
					CreatedAt: time.Now(),
				}
			},
		},
	}

	initialRate := rate.Limit(1000)
	burstSize := MaxShardQueueSize

	for i := 0; i < numWorkers; i++ {
		w := &Worker{
			id:          i,
			cpuAffinity: i % runtime.NumCPU(),
			queue:       make(chan *WorkItem, MaxShardQueueSize),
			scheduler:   s,
			ctx:         sctx,
			limiter:     rate.NewLimiter(initialRate, burstSize),
		}
		s.workers[i] = w
		go w.run() // Start the worker goroutine
	}

	fmt.Printf("Scheduler initialized with %d workers (CPU affinity enabled).\n", numWorkers)
	return s, nil
}

// SubmitWork submits work to the least loaded worker
func (s *Scheduler) SubmitWork(ctx context.Context, logInfo *certlib.CTLogInfo, start, end int64, callback WorkCallback) error {
	if s.shutdown.Load() {
		return fmt.Errorf("scheduler is shutting down")
	}

	logURL := logInfo.URL
	shardIndex := int(xxh3.HashString(logURL) % uint64(s.numWorkers))
	targetWorker := s.workers[shardIndex]

	item := s.workItemPool.Get().(*WorkItem)
	item.LogURL = logURL
	item.LogInfo = logInfo
	item.Start = start
	item.End = end
	item.Attempt = 0
	item.Callback = callback
	item.Ctx = ctx
	item.CreatedAt = time.Now()
	s.activeWork.Add(1)

	select {
	case targetWorker.queue <- item:
		// Optional: Increase rate limit on success
		return nil
	default:
		// Backpressure: Queue full.
		s.activeWork.Done()
		s.workItemPool.Put(item)
		// Optional: Decrease rate limit
		return fmt.Errorf("worker %d for log %s: %w", targetWorker.id, logURL, ErrQueueFull)
	}
}

// Wait waits for all active work to complete
func (s *Scheduler) Wait() {
	s.activeWork.Wait()
}

// Shutdown shuts down the scheduler
func (s *Scheduler) Shutdown() {
	s.shutdown.Store(true)
	s.cancel()
	s.Wait()
}

// run is the main loop for a worker
func (w *Worker) run() {
	// Set CPU affinity if supported
	if runtime.GOOS == "linux" {
		setCPUAffinity(w.id, w.cpuAffinity)
	}

	log.Printf("Worker %d started", w.id)

	for {
		select {
		case <-w.ctx.Done():
			// Scheduler is shutting down
			log.Printf("Worker %d shutting down", w.id)
			return

		case item := <-w.queue:
			// Process work item
			w.processWorkItem(item)
		}
	}
}

// processWorkItem processes a work item
func (w *Worker) processWorkItem(item *WorkItem) {
	// Mark worker as busy
	w.busy.Store(true)
	w.lastActive.Store(time.Now().UnixNano())

	// Ensure worker is marked as not busy when done
	defer func() {
		w.busy.Store(false)
	}()

	// Check if context is cancelled
	if item.Ctx.Err() != nil {
		w.handleCancelledItem(item)
		return
	}

	// Execute callback with panic recovery
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				w.panics.Add(1)
				err = fmt.Errorf("panic in callback: %v", r)
			}
		}()

		// Execute callback
		err = item.Callback(item)
	}()

	// Handle result
	if err != nil {
		w.handleFailedItem(item, err)
	} else {
		w.handleSuccessfulItem(item)
	}
}

// handleSuccessfulItem handles a successful work item
func (w *Worker) handleSuccessfulItem(item *WorkItem) {
	// Update metrics
	w.processed.Add(1)

	// Mark work as done
	w.scheduler.activeWork.Done()

	// Return item to pool
	item.Callback = nil
	item.LogInfo = nil
	item.Ctx = nil
	item.Error = nil
	w.scheduler.workItemPool.Put(item)
}

// handleFailedItem handles a failed work item
func (w *Worker) handleFailedItem(item *WorkItem, err error) {
	// Update metrics
	w.errors.Add(1)

	// Store error
	item.Error = err

	// Check if we should retry
	if item.Attempt < 3 {
		w.retryItem(item)
		return
	}

	// Exhausted retries
	// Mark work as done
	w.scheduler.activeWork.Done()

	// Return to pool
	item.Callback = nil
	item.LogInfo = nil
	item.Ctx = nil
	item.Error = nil
	w.scheduler.workItemPool.Put(item)
}

// handleCancelledItem handles a cancelled work item
func (w *Worker) handleCancelledItem(item *WorkItem) {
	// Store error
	item.Error = ErrWorkerShutdown

	// Mark work as done
	w.scheduler.activeWork.Done()

	// Return to pool
	item.Callback = nil
	item.LogInfo = nil
	item.Ctx = nil
	w.scheduler.workItemPool.Put(item)
}

// retryItem schedules a retry for an item
func (w *Worker) retryItem(item *WorkItem) {
	item.Attempt++
	delay := calculateRetryDelay(item.Attempt)
	w.scheduleRetry(item, delay)
}

// scheduleRetry schedules a retry after a delay
func (w *Worker) scheduleRetry(item *WorkItem, delay time.Duration) {
	// Wait for retry delay
	select {
	case <-time.After(delay):
		// Continue with retry
	case <-item.Ctx.Done():
		// Context cancelled, no retry
		w.handleCancelledItem(item)
		return
	case <-w.ctx.Done():
		// Scheduler shutting down, no retry
		w.handleCancelledItem(item)
		return
	}

	// Check if context is still valid
	if item.Ctx.Err() != nil {
		w.handleCancelledItem(item)
		return
	}

	// Submit to worker's queue
	select {
	case w.queue <- item:
		// Successfully queued
		return
	default:
		// Queue is full, try another worker
		for i := 0; i < w.scheduler.numWorkers; i++ {
			worker := w.scheduler.workers[(w.id+i+1)%w.scheduler.numWorkers]
			select {
			case worker.queue <- item:
				// Successfully queued
				return
			default:
				// Queue is full, try next worker
			}
		}

		// All queues are full, retry later
		go w.scheduleRetry(item, delay*2)
	}
}

// calculateRetryDelay calculates the retry delay with exponential backoff and jitter
func calculateRetryDelay(attempt int) time.Duration {
	// Base delay with exponential backoff
	delay := time.Duration(float64(RetryBaseDelay) * math.Pow(RetryBackoffMultiplier, float64(attempt-1)))
	if delay > RetryMaxDelay {
		delay = RetryMaxDelay
	}

	// Add jitter
	jitterRange := float64(delay) * RetryJitterFactor
	jitterAmount := time.Duration(rand.Float64() * jitterRange)
	return delay + jitterAmount
}

// setCPUAffinity sets the CPU affinity for a worker
func setCPUAffinity(workerID, cpuID int) {
	// Set CPU affinity for the current thread
	var cpuSet unix.CPUSet
	cpuSet.Zero()
	cpuSet.Set(cpuID)
	unix.SchedSetaffinity(0, &cpuSet)
}
