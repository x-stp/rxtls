package io

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

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// DefaultBufferSize is the default buffer size for disk I/O
	DefaultBufferSize = 256 * 1024 // 256KB

	// PageSize is the OS page size for aligned writes
	PageSize = 4096 // 4KB, typical OS page size

	// FlushInterval is how often to flush buffers automatically
	FlushInterval = 2 * time.Second

	// BackpressureThreshold is the percentage of buffer capacity that triggers backpressure
	BackpressureThreshold = 0.8 // 80%
)

var (
	// ErrBufferFull is returned when the buffer is full and backpressure is applied
	ErrBufferFull = errors.New("write buffer full, applying backpressure")

	// ErrBufferClosed is returned when attempting to write to a closed buffer
	ErrBufferClosed = errors.New("write buffer closed")

	// ErrFlushTimeout is returned when a flush operation times out
	ErrFlushTimeout = errors.New("flush operation timed out")
)

// BufferMetrics holds metrics for a buffer
type BufferMetrics struct {
	BytesWritten     atomic.Int64
	BytesFlushed     atomic.Int64
	FlushCount       atomic.Int64
	WriteCount       atomic.Int64
	BackpressureHits atomic.Int64
	ErrorCount       atomic.Int64
	LastFlushTime    atomic.Int64 // Unix timestamp in nanoseconds
	LastWriteTime    atomic.Int64 // Unix timestamp in nanoseconds
	LastErrorTime    atomic.Int64 // Unix timestamp in nanoseconds
}

// AsyncBuffer is a high-performance buffer for disk I/O with async flushing
type AsyncBuffer struct {
	// Immutable after creation
	file           *os.File
	gzWriter       *gzip.Writer
	bufWriter      *bufio.Writer
	flushInterval  time.Duration
	bufferSize     int
	alignWrites    bool
	compressed     bool
	flushThreshold float64
	fileDescriptor int
	identifier     string // For logging/metrics

	// Mutable state protected by mutex
	mu              sync.Mutex
	closed          bool
	lastFlushTime   time.Time
	flushInProgress bool
	writeQueue      [][]byte // Pending writes that couldn't fit in buffer

	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc

	// Wait group for flush operations
	flushWg sync.WaitGroup

	// Metrics (atomic)
	metrics BufferMetrics

	// Signaling channels
	flushComplete chan struct{} // Signals when a flush is complete
	backpressure  chan struct{} // Signals when backpressure is applied/released
}

// AsyncBufferOptions configures an AsyncBuffer
type AsyncBufferOptions struct {
	BufferSize     int
	FlushInterval  time.Duration
	AlignWrites    bool
	Compressed     bool
	FlushThreshold float64
	Identifier     string
}

// DefaultAsyncBufferOptions returns the default options for AsyncBuffer
func DefaultAsyncBufferOptions() *AsyncBufferOptions {
	return &AsyncBufferOptions{
		BufferSize:     DefaultBufferSize,
		FlushInterval:  FlushInterval,
		AlignWrites:    true,
		Compressed:     false,
		FlushThreshold: BackpressureThreshold,
		Identifier:     "",
	}
}

// NewAsyncBuffer creates a new AsyncBuffer
func NewAsyncBuffer(ctx context.Context, path string, options *AsyncBufferOptions) (*AsyncBuffer, error) {
	if options == nil {
		options = DefaultAsyncBufferOptions()
	}

	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Open file with direct I/O if supported and requested
	flag := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if options.AlignWrites && runtime.GOOS == "linux" {
		// O_DIRECT is only available on Linux
		// Use a constant value instead of syscall.O_DIRECT to avoid build errors on other platforms
		const O_DIRECT = 0x4000 // Linux specific
		flag |= O_DIRECT
	}

	file, err := os.OpenFile(path, flag, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}

	// Get file descriptor for direct operations
	fd := int(file.Fd())

	// Create buffer context
	bufCtx, bufCancel := context.WithCancel(ctx)

	// Create the buffer
	ab := &AsyncBuffer{
		file:           file,
		bufferSize:     options.BufferSize,
		alignWrites:    options.AlignWrites,
		compressed:     options.Compressed,
		flushInterval:  options.FlushInterval,
		flushThreshold: options.FlushThreshold,
		fileDescriptor: fd,
		identifier:     options.Identifier,
		lastFlushTime:  time.Now(),
		ctx:            bufCtx,
		cancel:         bufCancel,
		flushComplete:  make(chan struct{}, 1),
		backpressure:   make(chan struct{}, 1),
	}

	// Set up the writer chain
	if options.Compressed {
		gzw, err := gzip.NewWriterLevel(file, gzip.BestSpeed)
		if err != nil {
			file.Close()
			bufCancel()
			return nil, fmt.Errorf("failed to create gzip writer: %w", err)
		}
		ab.gzWriter = gzw
		ab.bufWriter = bufio.NewWriterSize(gzw, options.BufferSize)
	} else {
		ab.bufWriter = bufio.NewWriterSize(file, options.BufferSize)
	}

	// Start background flusher
	ab.startBackgroundFlusher()

	return ab, nil
}

// startBackgroundFlusher starts a goroutine that periodically flushes the buffer
func (ab *AsyncBuffer) startBackgroundFlusher() {
	ticker := time.NewTicker(ab.flushInterval)

	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := ab.Flush(); err != nil && !errors.Is(err, ErrFlushTimeout) {
					ab.metrics.ErrorCount.Add(1)
					ab.metrics.LastErrorTime.Store(time.Now().UnixNano())
					// TODO: Log error
				}
			case <-ab.ctx.Done():
				return
			}
		}
	}()
}

// Write writes data to the buffer
func (ab *AsyncBuffer) Write(data []byte) (int, error) {
	ab.mu.Lock()
	defer ab.mu.Unlock()

	if ab.closed {
		return 0, ErrBufferClosed
	}

	// Check if we need to apply backpressure
	if float64(ab.bufWriter.Buffered())/float64(ab.bufferSize) >= ab.flushThreshold {
		// Signal backpressure
		select {
		case ab.backpressure <- struct{}{}:
		default:
			// Channel already has a value
		}

		ab.metrics.BackpressureHits.Add(1)

		// If we have too many pending writes, return error
		if len(ab.writeQueue) > 100 {
			return 0, ErrBufferFull
		}

		// Queue the write for later
		dataCopy := make([]byte, len(data))
		copy(dataCopy, data)
		ab.writeQueue = append(ab.writeQueue, dataCopy)

		// Trigger a flush
		go ab.Flush()

		return len(data), nil
	}

	// Write to buffer
	n, err := ab.bufWriter.Write(data)
	if err != nil {
		ab.metrics.ErrorCount.Add(1)
		ab.metrics.LastErrorTime.Store(time.Now().UnixNano())
		return n, fmt.Errorf("failed to write to buffer: %w", err)
	}

	ab.metrics.BytesWritten.Add(int64(n))
	ab.metrics.WriteCount.Add(1)
	ab.metrics.LastWriteTime.Store(time.Now().UnixNano())

	// Process queued writes if buffer has space
	if len(ab.writeQueue) > 0 && float64(ab.bufWriter.Buffered())/float64(ab.bufferSize) < ab.flushThreshold {
		// Process some queued writes
		processed := 0
		for i, queuedData := range ab.writeQueue {
			if float64(ab.bufWriter.Buffered()+len(queuedData))/float64(ab.bufferSize) >= ab.flushThreshold {
				break
			}

			n, err := ab.bufWriter.Write(queuedData)
			if err != nil {
				ab.metrics.ErrorCount.Add(1)
				ab.metrics.LastErrorTime.Store(time.Now().UnixNano())
				break
			}

			ab.metrics.BytesWritten.Add(int64(n))
			ab.metrics.WriteCount.Add(1)
			processed = i + 1
		}

		// Remove processed items from queue
		if processed > 0 {
			ab.writeQueue = ab.writeQueue[processed:]
		}

		// If queue is empty, release backpressure
		if len(ab.writeQueue) == 0 {
			// Clear backpressure signal
			select {
			case <-ab.backpressure:
			default:
			}
		}
	}

	return n, nil
}

// Flush flushes the buffer to disk
func (ab *AsyncBuffer) Flush() error {
	ab.mu.Lock()

	if ab.closed {
		ab.mu.Unlock()
		return ErrBufferClosed
	}

	if ab.flushInProgress {
		// Another flush is already in progress
		ab.mu.Unlock()

		// Wait for it to complete with timeout
		select {
		case <-ab.flushComplete:
			return nil
		case <-time.After(5 * time.Second):
			return ErrFlushTimeout
		case <-ab.ctx.Done():
			return ab.ctx.Err()
		}
	}

	// Nothing to flush
	if ab.bufWriter.Buffered() == 0 {
		ab.mu.Unlock()
		return nil
	}

	// Mark flush in progress
	ab.flushInProgress = true
	ab.flushWg.Add(1)
	ab.mu.Unlock()

	// Perform the flush in a separate goroutine to avoid blocking
	go func() {
		defer ab.flushWg.Done()
		defer func() {
			ab.mu.Lock()
			ab.flushInProgress = false
			ab.lastFlushTime = time.Now()
			ab.mu.Unlock()

			// Signal flush complete
			select {
			case ab.flushComplete <- struct{}{}:
			default:
			}
		}()

		// Flush the buffer
		if err := ab.bufWriter.Flush(); err != nil {
			ab.metrics.ErrorCount.Add(1)
			ab.metrics.LastErrorTime.Store(time.Now().UnixNano())
			return
		}

		// If compressed, flush the gzip writer
		if ab.compressed && ab.gzWriter != nil {
			if err := ab.gzWriter.Flush(); err != nil {
				ab.metrics.ErrorCount.Add(1)
				ab.metrics.LastErrorTime.Store(time.Now().UnixNano())
				return
			}
		}

		// Sync to disk
		if err := ab.file.Sync(); err != nil {
			ab.metrics.ErrorCount.Add(1)
			ab.metrics.LastErrorTime.Store(time.Now().UnixNano())
			return
		}

		// Update metrics
		ab.metrics.FlushCount.Add(1)
		ab.metrics.BytesFlushed.Add(int64(ab.bufWriter.Buffered()))
		ab.metrics.LastFlushTime.Store(time.Now().UnixNano())
	}()

	return nil
}

// Close flushes and closes the buffer
func (ab *AsyncBuffer) Close() error {
	ab.mu.Lock()

	if ab.closed {
		ab.mu.Unlock()
		return nil
	}

	ab.closed = true
	ab.mu.Unlock()

	// Cancel context to stop background flusher
	ab.cancel()

	// Wait for any in-progress flushes to complete
	ab.flushWg.Wait()

	// Final flush
	if err := ab.bufWriter.Flush(); err != nil {
		return fmt.Errorf("failed to flush buffer on close: %w", err)
	}

	// Close gzip writer if used
	if ab.compressed && ab.gzWriter != nil {
		if err := ab.gzWriter.Close(); err != nil {
			return fmt.Errorf("failed to close gzip writer: %w", err)
		}
	}

	// Close file
	if err := ab.file.Close(); err != nil {
		return fmt.Errorf("failed to close file: %w", err)
	}

	return nil
}

// WaitForBackpressure waits for backpressure to be applied
func (ab *AsyncBuffer) WaitForBackpressure(ctx context.Context) error {
	select {
	case <-ab.backpressure:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetMetrics returns the current metrics for the buffer
func (ab *AsyncBuffer) GetMetrics() BufferMetrics {
	return ab.metrics
}

// BufferPool manages a pool of AsyncBuffers
type BufferPool struct {
	mu      sync.RWMutex
	buffers map[string]*AsyncBuffer
	ctx     context.Context
	cancel  context.CancelFunc
	options *AsyncBufferOptions
}

// NewBufferPool creates a new BufferPool
func NewBufferPool(ctx context.Context, options *AsyncBufferOptions) *BufferPool {
	poolCtx, poolCancel := context.WithCancel(ctx)

	return &BufferPool{
		buffers: make(map[string]*AsyncBuffer),
		ctx:     poolCtx,
		cancel:  poolCancel,
		options: options,
	}
}

// GetBuffer returns a buffer for the given path, creating it if necessary
func (bp *BufferPool) GetBuffer(path string) (*AsyncBuffer, error) {
	// First check if buffer exists with read lock
	bp.mu.RLock()
	buffer, exists := bp.buffers[path]
	bp.mu.RUnlock()

	if exists {
		return buffer, nil
	}

	// Create new buffer with write lock
	bp.mu.Lock()
	defer bp.mu.Unlock()

	// Check again in case another goroutine created it
	buffer, exists = bp.buffers[path]
	if exists {
		return buffer, nil
	}

	// Create new buffer
	options := *bp.options // Copy options
	options.Identifier = path

	buffer, err := NewAsyncBuffer(bp.ctx, path, &options)
	if err != nil {
		return nil, err
	}

	bp.buffers[path] = buffer
	return buffer, nil
}

// Close closes all buffers in the pool
func (bp *BufferPool) Close() error {
	bp.cancel() // Cancel context to stop all background operations

	bp.mu.Lock()
	defer bp.mu.Unlock()

	var lastErr error
	for path, buffer := range bp.buffers {
		if err := buffer.Close(); err != nil {
			lastErr = fmt.Errorf("failed to close buffer %s: %w", path, err)
		}
	}

	return lastErr
}

// Flush flushes all buffers in the pool
func (bp *BufferPool) Flush() error {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	var lastErr error
	for path, buffer := range bp.buffers {
		if err := buffer.Flush(); err != nil {
			lastErr = fmt.Errorf("failed to flush buffer %s: %w", path, err)
		}
	}

	return lastErr
}
