//go:build !linux
// +build !linux

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

// This file provides a stub implementation of the scheduler for non-Linux platforms
// where CPU affinity setting is not available or not implemented via x/sys/unix.

package core

import (
	"context"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/x-stp/rxtls/internal/certlib"

	"github.com/zeebo/xxh3" // Consistent hashing
	"golang.org/x/time/rate"
)

// Scheduler definition MUST be identical across builds.
// Manages workers and dispatch, but without affinity.
type Scheduler struct {
	numWorkers   int
	workers      []*Worker
	ctx          context.Context
	cancel       context.CancelFunc
	shutdown     atomic.Bool
	workItemPool sync.Pool
	activeWork   sync.WaitGroup // Tracks active work
}

// Worker definition MUST be identical, cpuAffinity field is present but unused.
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

// NewScheduler creates and starts the scheduler (stub version without affinity).
// Operation: Blocking (at startup), allocates worker/channel resources.
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
			cpuAffinity: -1, // Mark as unused
			queue:       make(chan *WorkItem, MaxShardQueueSize),
			scheduler:   s,
			ctx:         sctx,
			limiter:     rate.NewLimiter(initialRate, burstSize), // Init limiter
		}
		s.workers[i] = w
		go w.run() // Start the worker goroutine
	}

	fmt.Printf("Scheduler initialized with %d workers (CPU affinity disabled).\n", numWorkers)
	return s, nil
}

// run is the main loop for a worker goroutine (stub version without affinity setup).
// Hot Path: Yes. Must be zero-GC, non-blocking (except on queue read).
func (w *Worker) run() {
	// No LockOSThread or affinity setting needed/possible on non-Linux.
	for {
		select {
		case <-w.ctx.Done():
			return
		case item := <-w.queue:
			if item == nil {
				continue
			}

			// Mark work as done when the callback finishes or panics
			func() {
				defer w.scheduler.activeWork.Done() // Signal completion via WaitGroup
				defer func() {
					if r := recover(); r != nil {
						log.Printf("Panic recovered in worker %d processing item for %s (%d-%d): %v", w.id, item.LogURL, item.Start, item.End, r)
						// TODO: Increment failure counter
					}
				}()

				err := item.Callback(item)
				if err != nil {
					// Basic error logging.
					// TODO: Implement retry mechanism using item.Attempt.
					fmt.Printf("Error processing item for %s (%d-%d): %v\n", item.LogURL, item.Start, item.End, err)
				}
			}()

			// Return item to pool, resetting fields.
			item.Callback = nil
			item.LogURL = ""
			item.LogInfo = nil
			item.Ctx = nil
			item.Error = nil
			w.scheduler.workItemPool.Put(item)
		}
	}
}

// setAffinity is a no-op stub on non-Linux platforms.
func setAffinity(workerID, cpuID int) {
	// Affinity not supported/implemented on this OS.
}

// SubmitWork definition MUST be identical across builds.
// Hot Path: Yes. Non-blocking, low allocation.
func (s *Scheduler) SubmitWork(ctx context.Context, logInfo *certlib.CTLogInfo, start, end int64, callback WorkCallback) error {
	if s.shutdown.Load() {
		return fmt.Errorf("scheduler is shutting down")
	}

	logURL := logInfo.URL
	hash := xxh3.HashString(logURL)
	shardIndex := int(hash % uint64(s.numWorkers))
	targetWorker := s.workers[shardIndex]

	// NOTE: Rate limiting handled by caller

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

// Wait definition MUST be identical across builds.
func (s *Scheduler) Wait() {
	s.activeWork.Wait()
}

// Shutdown definition MUST be identical across builds.
func (s *Scheduler) Shutdown() {
	s.shutdown.Store(true)
	s.cancel()
	s.Wait()
}
