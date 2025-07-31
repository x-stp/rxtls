package core

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
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/x-stp/rxtls/internal/certlib"
	"github.com/x-stp/rxtls/internal/util"

	"github.com/zeebo/xxh3"
)

// Constants for download performance
const (
	// OutputFlushInterval is how often to flush buffers to disk
	OutputFlushInterval = 5 * time.Second

	// Setup concurrency maximums
	MaxSetupConcurrency = 16

	// Writer buffer sizes
	DefaultBufferSize = 8 * 1024 * 1024 // 8MB

	// Memory pool size for string building
	StringPoolSize = 1024 * 1024 // 1MB

	// Distribution strategy - submit in batches to allow better parallelism
	batchSize int64 = 100 // Submit blocks in batches
)

// Error types specific to download operations
var (
	ErrDownloadCancelled = errors.New("download operation cancelled")
	ErrLogSetupFailed    = errors.New("log setup failed")
	ErrDownloadFailed    = errors.New("download failed")
)

// DownloadManager manages the process of downloading raw cert entries from CT logs.
type DownloadManager struct {
	scheduler     *Scheduler
	config        *DownloadConfig
	stats         *DownloadStats
	ctx           context.Context
	cancel        context.CancelFunc
	outputMap     sync.Map  // Maps log URL -> *lockedWriter
	stringPool    sync.Pool // Reusable string builders
	setupComplete atomic.Bool
}

// DownloadConfig holds configuration for downloading.
type DownloadConfig struct {
	OutputDir         string
	BufferSize        int
	MaxConcurrentLogs int
	CompressOutput    bool // If true, output files will be .gz
}

// DownloadStats holds runtime statistics for downloads.
type DownloadStats struct {
	TotalLogs          atomic.Int64
	ProcessedLogs      atomic.Int64
	FailedLogs         atomic.Int64
	TotalEntries       atomic.Int64
	ProcessedEntries   atomic.Int64 // Entries successfully fetched and written
	FailedEntries      atomic.Int64 // Entries failed (download, parse leaf, write)
	OutputBytesWritten atomic.Int64
	StartTime          time.Time
	RetryCount         atomic.Int64 // Count of retried blocks
	SuccessFirstTry    atomic.Int64 // Count of blocks successful on first try
}

// Implement PeriodicStats + FinalStats interface for DownloadStats
func (s *DownloadStats) GetStartTime() time.Time      { return s.StartTime }
func (s *DownloadStats) GetTotalLogs() int64          { return s.TotalLogs.Load() }
func (s *DownloadStats) GetProcessedLogs() int64      { return s.ProcessedLogs.Load() }
func (s *DownloadStats) GetFailedLogs() int64         { return s.FailedLogs.Load() }
func (s *DownloadStats) GetTotalEntries() int64       { return s.TotalEntries.Load() }
func (s *DownloadStats) GetProcessedEntries() int64   { return s.ProcessedEntries.Load() }
func (s *DownloadStats) GetFailedEntries() int64      { return s.FailedEntries.Load() }
func (s *DownloadStats) GetOutputBytesWritten() int64 { return s.OutputBytesWritten.Load() }
func (s *DownloadStats) GetTotalDomainsFound() int64  { return 0 } // Not applicable
func (s *DownloadStats) GetRetryRate() float64 {
	if s.ProcessedEntries.Load() == 0 {
		return 0
	}
	return float64(s.RetryCount.Load()) / float64(s.ProcessedEntries.Load())
}

// NewDownloadManager creates a new download manager instance.
func NewDownloadManager(ctx context.Context, config *DownloadConfig) (*DownloadManager, error) {
	scheduler, err := NewScheduler(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scheduler: %w", err)
	}

	// Set a sensible default buffer size if not specified
	if config.BufferSize <= 0 {
		config.BufferSize = DefaultBufferSize
	}

	dmCtx, cancel := context.WithCancel(ctx)
	dm := &DownloadManager{
		scheduler: scheduler,
		config:    config,
		stats:     &DownloadStats{StartTime: time.Now()},
		ctx:       dmCtx,
		cancel:    cancel,
		stringPool: sync.Pool{
			New: func() interface{} {
				return strings.Builder{}
			},
		},
	}

	// Start background flush worker
	go dm.periodicFlush()

	return dm, nil
}

// periodicFlush runs in background to periodically flush output files
func (dm *DownloadManager) periodicFlush() {
	ticker := time.NewTicker(OutputFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-dm.ctx.Done():
			// Flush one last time before exiting
			dm.flushAllWriters()
			return
		case <-ticker.C:
			dm.flushAllWriters()
		}
	}
}

// flushAllWriters flushes all writers but doesn't close them
func (dm *DownloadManager) flushAllWriters() {
	var flushCount int
	dm.outputMap.Range(func(key, value interface{}) bool {
		if value == nil {
			return true
		}

		lw, ok := value.(*lockedWriter)
		if !ok || lw == nil {
			log.Printf("Warning: Invalid writer type in map during flush for key %v", key)
			return true
		}

		// Use a short-term lock just for flushing
		func() {
			lw.mu.Lock()
			defer lw.mu.Unlock()
			if lw.writer != nil {
				if err := lw.writer.Flush(); err != nil {
					log.Printf("Warning: Error flushing writer for %s: %v", key.(string), err)
				} else {
					flushCount++
				}
			}
		}()
		return true
	})

	if flushCount > 0 {
		log.Printf("Flushed %d output files to disk", flushCount)
	}
}

// DownloadCertificates orchestrates the download process for the given logs.
func (dm *DownloadManager) DownloadCertificates(logsToProcess interface{}) error {
	// Convert the interface to the expected type
	logs, ok := logsToProcess.([]certlib.CTLogInfo)
	if !ok {
		return fmt.Errorf("invalid logs type: expected []certlib.CTLogInfo")
	}

	dm.stats.TotalLogs.Store(int64(len(logs)))
	log.Printf("Starting certificate download for %d logs...", len(logs))

	// Create base output directory
	if err := os.MkdirAll(dm.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory '%s': %w", dm.config.OutputDir, err)
	}

	// Limit concurrent setup
	concurrencyLimit := runtime.NumCPU()
	if concurrencyLimit > MaxSetupConcurrency {
		concurrencyLimit = MaxSetupConcurrency
	}

	// Setup logs concurrently with limited concurrency
	var wg sync.WaitGroup
	setupSem := make(chan struct{}, concurrencyLimit)
	setupErrors := make(chan error, len(logs)) // Collect errors

	for i := range logs {
		select {
		case <-dm.ctx.Done():
			log.Println("Download cancelled during log setup.")
			return ErrDownloadCancelled
		case setupSem <- struct{}{}:
			wg.Add(1)
			go func(logInfo certlib.CTLogInfo) {
				defer wg.Done()
				defer func() { <-setupSem }()

				if err := dm.processSingleLogForDownload(&logInfo); err != nil {
					if !errors.Is(err, ErrDownloadCancelled) { // Don't log cancellations
						log.Printf("Error processing log %s for download: %v", logInfo.URL, err)
					}
					dm.stats.FailedLogs.Add(1)
					setupErrors <- fmt.Errorf("log %s: %w", logInfo.URL, err)
				} else {
					dm.stats.ProcessedLogs.Add(1)
				}
			}(logs[i])
		}
	}

	wg.Wait() // Wait for setup goroutines
	close(setupErrors)

	// Mark setup complete
	dm.setupComplete.Store(true)

	// Check for setup errors
	var setupErrorsList []error
	for err := range setupErrors {
		setupErrorsList = append(setupErrorsList, err)
	}

	// If all logs failed, return a combined error
	if len(setupErrorsList) == len(logs) {
		return fmt.Errorf("%w: all logs failed setup: %v", ErrLogSetupFailed, errors.Join(setupErrorsList...))
	}

	if dm.ctx.Err() != nil {
		log.Println("Download cancelled after log setup phase.")
		dm.Shutdown()
		return ErrDownloadCancelled
	}

	totalLogSize := dm.stats.TotalEntries.Load()
	log.Printf("All download work submitted (%d entries). Waiting for scheduler...", totalLogSize)

	// Wait for all submitted download tasks
	dm.scheduler.Wait()

	// Check for cancellation during processing
	if dm.ctx.Err() != nil {
		log.Println("Download cancelled during processing phase.")
		dm.Shutdown()
		return ErrDownloadCancelled
	}

	// Check if we had complete success or partial success
	processedEntries := dm.stats.ProcessedEntries.Load()
	failedEntries := dm.stats.FailedEntries.Load()

	log.Printf("Download processing complete. Finalizing... (Success: %d, Failed: %d entries)",
		processedEntries, failedEntries)

	// Shutdown (this will flush and close all writers)
	dm.Shutdown()

	// Return error if there were significant failures
	if failedEntries > 0 && failedEntries >= processedEntries/10 { // More than 10% failure rate
		return fmt.Errorf("%w: %d of %d entries failed to download",
			ErrDownloadFailed, failedEntries, processedEntries+failedEntries)
	}

	retryRate := dm.stats.GetRetryRate()
	log.Printf("Certificate download finished successfully. Retry rate: %.2f%%", retryRate*100)
	return nil
}

// processSingleLogForDownload handles STH fetch, output setup, and work submission for one log.
func (dm *DownloadManager) processSingleLogForDownload(ctlog *certlib.CTLogInfo) error {
	log.Printf("Setting up download for log: %s", ctlog.URL)

	// Fetch log info with a short timeout
	ctxWithTimeout, cancel := context.WithTimeout(dm.ctx, 30*time.Second)
	defer cancel()

	// Create a derived context for this specific log
	logCtx, logCancel := context.WithCancel(dm.ctx)
	defer func() {
		// If we exit with error, cancel any pending work for this log
		if logCtx.Err() == nil {
			logCancel()
		}
	}()

	// Get log info with timeout
	if err := certlib.GetLogInfo(ctlog); err != nil {
		return fmt.Errorf("failed to get log info for %s: %w", ctlog.URL, err)
	}

	// Check context before proceeding
	if ctxWithTimeout.Err() != nil {
		return ErrDownloadCancelled
	}

	treeSize := int64(ctlog.TreeSize)
	if treeSize == 0 {
		log.Printf("Skipping log %s: tree size is 0", ctlog.URL)
		return nil
	}

	blockSize := int64(ctlog.BlockSize)
	if blockSize <= 0 {
		blockSize = DefaultLogEntryBlockSize
	}

	// Setup Output Writer
	filename := fmt.Sprintf("%s_certs.csv", util.SanitizeFilename(ctlog.URL))
	if dm.config.CompressOutput {
		filename += ".gz"
	}
	filePath := filepath.Join(dm.config.OutputDir, filename)

	// Create output file with temp name, then rename when complete to avoid partial files
	tempFilePath := filePath + ".tmp"
	file, err := os.Create(tempFilePath)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", tempFilePath, err)
	}

	var writer *bufio.Writer
	var gzWriter *gzip.Writer

	if dm.config.CompressOutput {
		gzWriter, _ = gzip.NewWriterLevel(file, gzip.BestSpeed)
		writer = bufio.NewWriterSize(gzWriter, dm.config.BufferSize)
	} else {
		writer = bufio.NewWriterSize(file, dm.config.BufferSize)
	}

	// Write header: offset,leaf_input_b64,extra_data_b64
	headerLine := "offset,leaf_input_b64,extra_data_b64\n"
	_, err = writer.WriteString(headerLine)
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to write header to %s: %w", tempFilePath, err)
	}

	// Store the locked writer instance
	lw := &lockedWriter{
		writer:    writer,
		gzWriter:  gzWriter,
		file:      file,
		filePath:  tempFilePath,
		finalPath: filePath,
	}
	dm.outputMap.Store(ctlog.URL, lw)

	// Submit Work Blocks in chunks for more even distribution
	numBlocks := (treeSize + blockSize - 1) / blockSize
	log.Printf("Log %s: TreeSize=%d, BlockSize=%d, NumBlocks=%d (Download)",
		ctlog.URL, treeSize, blockSize, numBlocks)

	// Track total entries
	dm.stats.TotalEntries.Add(treeSize)

	// Distribution strategy - submit in batches to allow better parallelism
	var submittedBlocks, droppedBlocks int64

	for i := int64(0); i < numBlocks; i += batchSize {
		// Check for context cancellation between batches
		if dm.ctx.Err() != nil {
			return ErrDownloadCancelled
		}

		end := i + batchSize
		if end > numBlocks {
			end = numBlocks
		}

		// Submit blocks in this batch
		for j := i; j < end; j++ {
			if dm.ctx.Err() != nil {
				return ErrDownloadCancelled
			}

			start := j * blockSize
			endEntry := start + blockSize - 1
			if endEntry >= treeSize {
				endEntry = treeSize - 1
			}

			// Use log-specific context for the work item
			err := dm.submitDownloadBlock(logCtx, ctlog, start, endEntry)
			if err != nil {
				if errors.Is(err, ErrQueueFull) {
					// Adjust total entries for dropped blocks
					entriesInBlock := endEntry - start + 1
					dm.stats.TotalEntries.Add(-entriesInBlock)
					droppedBlocks++
				} else if errors.Is(err, ErrDownloadCancelled) {
					return err
				} else {
					log.Printf("Error submitting block %d-%d for %s: %v",
						start, endEntry, ctlog.URL, err)
				}
			} else {
				submittedBlocks++
			}
		}

		// Small sleep between batches to avoid overwhelming scheduler
		if end < numBlocks {
			time.Sleep(250 * time.Millisecond)
		}
	}

	// Report submission stats
	if droppedBlocks > 0 {
		log.Printf("Log %s: Submitted %d blocks, dropped %d blocks due to backpressure",
			ctlog.URL, submittedBlocks, droppedBlocks)
	} else {
		log.Printf("Successfully submitted all %d download blocks for %s",
			submittedBlocks, ctlog.URL)
	}

	return nil
}

// submitDownloadBlock attempts to submit a work block with retries
func (dm *DownloadManager) submitDownloadBlock(ctx context.Context, ctlog *certlib.CTLogInfo, start, end int64) error {
	// Determine target worker based on log URL (consistent sharding)
	shardIndex := int(xxh3.HashString(ctlog.URL) % uint64(dm.scheduler.numWorkers))
	targetWorker := dm.scheduler.workers[shardIndex]

	// Wait on rate limiter
	waitStart := time.Now()
	if err := targetWorker.limiter.Wait(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			return ErrDownloadCancelled
		}
		return fmt.Errorf("rate limiter wait failed: %w", err)
	}

	waitDuration := time.Since(waitStart)
	if waitDuration > 100*time.Millisecond {
		log.Printf("Worker %d rate limit caused %v wait for log %s (%d-%d), limit: %.2f req/s",
			targetWorker.id, waitDuration, ctlog.URL, start, end,
			float64(targetWorker.limiter.Limit()))
	}

	// Attempt submission with retry for transient full queue
	maxRetries := MaxSubmitRetries
	retryDelay := 1000 * time.Millisecond

	for attempt := 0; attempt < maxRetries; attempt++ {
		if ctx.Err() != nil {
			return ErrDownloadCancelled
		}

		err := dm.scheduler.SubmitWork(ctx, ctlog, start, end, dm.downloadCallback)
		if err == nil {
			return nil // Success
		}

		// Handle specific error types
		if errors.Is(err, ErrQueueFull) || strings.Contains(err.Error(), "queue full") {
			// Exponential backoff with jitter
			jitter := time.Duration(float64(retryDelay) * (0.5 + rand.Float64()))
			select {
			case <-time.After(jitter):
				retryDelay = retryDelay * 2
				if retryDelay > 500*time.Millisecond {
					retryDelay = 500 * time.Millisecond
				}
				continue // Retry submission
			case <-ctx.Done():
				return ErrDownloadCancelled
			}
		}

		// Non-retriable error
		log.Printf("Permanent error submitting download work for %s (%d-%d): %v",
			ctlog.URL, start, end, err)
		return err
	}

	// All retries exhausted
	log.Printf("Dropped download block %s (%d-%d) after %d retries (queue full).",
		ctlog.URL, start, end, maxRetries)
	return ErrQueueFull
}

// downloadCallback fetches entries and writes raw data to the output file.
// It's called by the worker for each block to be downloaded.
func (dm *DownloadManager) downloadCallback(item *WorkItem) error {
	logInfo := item.LogInfo
	if logInfo == nil {
		return fmt.Errorf("internal error: WorkItem missing LogInfo (download)")
	}

	// Extract context from the work item
	ctx := item.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Track retries
	isRetry := item.Attempt > 0
	if isRetry {
		dm.stats.RetryCount.Add(1)
	}

	// Download entries with retry logic already in certlib.DownloadEntries
	downloadStart := time.Now()
	entriesResponse, err := certlib.DownloadEntries(ctx, logInfo, int(item.Start), int(item.End))
	downloadDuration := time.Since(downloadStart)

	if err != nil {
		dm.stats.FailedEntries.Add(item.End - item.Start + 1)

		// Log different error levels based on context
		if errors.Is(err, context.Canceled) {
			// This is expected during shutdown, don't log as error
			return err
		}

		return fmt.Errorf("failed to download entries %d-%d for %s (attempt %d): %w",
			item.Start, item.End, item.LogURL, item.Attempt+1, err)
	}

	// Get the locked writer for this log
	writerUntyped, ok := dm.outputMap.Load(item.LogURL)
	if !ok {
		dm.stats.FailedEntries.Add(int64(len(entriesResponse.Entries)))
		return fmt.Errorf("output writer not found for log %s (download)", item.LogURL)
	}

	lw, ok := writerUntyped.(*lockedWriter)
	if !ok || lw == nil {
		return fmt.Errorf("invalid writer type found in map for log %s (download)", item.LogURL)
	}

	// Process entries in batches to minimize lock contention
	entriesCount := len(entriesResponse.Entries)

	// Get a string builder from the pool
	sbInterface := dm.stringPool.Get()
	sb := sbInterface.(strings.Builder)
	sb.Reset()
	sb.Grow(entriesCount * 512) // Pre-allocate approximate space

	// Build output in memory first
	for i, entry := range entriesResponse.Entries {
		certIndex := item.Start + int64(i)
		fmt.Fprintf(&sb, "%d,%s,%s\n", certIndex, entry.LeafInput, entry.ExtraData)
	}

	// Get the built string
	outputData := sb.String()

	// Reset and return the builder to the pool
	sb.Reset()
	dm.stringPool.Put(&sb)

	// Lock once for the entire write
	lw.mu.Lock()
	n, err := lw.writer.WriteString(outputData)
	lw.mu.Unlock()

	if err != nil {
		dm.stats.FailedEntries.Add(int64(entriesCount))
		return fmt.Errorf("error writing to output buffer for %s: %w", item.LogURL, err)
	}

	// Update stats
	dm.stats.ProcessedEntries.Add(int64(entriesCount))
	dm.stats.OutputBytesWritten.Add(int64(n))

	// Track first-attempt success
	if !isRetry {
		dm.stats.SuccessFirstTry.Add(1)
	}

	// Performance logging for slow blocks
	if downloadDuration > 2*time.Second {
		entriesPerSec := float64(entriesCount) / downloadDuration.Seconds()
		log.Printf("Slow download: %s (%d-%d): %.2f entries/sec, %d bytes written",
			item.LogURL, item.Start, item.End, entriesPerSec, n)
	}

	return nil
}

// Shutdown gracefully closes resources.
func (dm *DownloadManager) Shutdown() {
	if dm.ctx.Err() != nil {
		// Already shut down
		return
	}

	log.Println("Shutting down Download Manager...")
	dm.cancel() // Cancel context

	// Shutdown scheduler (this will wait for worker queues to empty)
	if dm.scheduler != nil {
		dm.scheduler.Shutdown()
	}

	log.Println("Flushing and closing download writers...")

	// Close and rename all writers
	var successCount, errorCount int

	dm.outputMap.Range(func(key, value interface{}) bool {
		if value == nil {
			return true
		}

		lw, ok := value.(*lockedWriter)
		if !ok || lw == nil {
			log.Printf("Warning: Invalid writer type in map during download shutdown for key %v", key)
			return true
		}

		// Lock, flush, close and rename
		func() {
			lw.mu.Lock()
			defer lw.mu.Unlock()

			closeErr := false

			// Flush buffers
			if lw.writer != nil {
				if err := lw.writer.Flush(); err != nil {
					log.Printf("Error flushing download writer for %s: %v", key.(string), err)
					closeErr = true
				}
			}

			// Close gzip writer if present
			if lw.gzWriter != nil {
				if err := lw.gzWriter.Close(); err != nil {
					log.Printf("Error closing gzip download writer for %s: %v", key.(string), err)
					closeErr = true
				}
			}

			// Close file
			if lw.file != nil {
				if err := lw.file.Close(); err != nil {
					log.Printf("Error closing file for download %s: %v", key.(string), err)
					closeErr = true
				}
			}

			// Rename temp file to final name if we're fully set up
			if dm.setupComplete.Load() && !closeErr && lw.filePath != "" && lw.finalPath != "" {
				if err := os.Rename(lw.filePath, lw.finalPath); err != nil {
					log.Printf("Error renaming temp file %s to %s: %v",
						lw.filePath, lw.finalPath, err)
					errorCount++
				} else {
					successCount++
				}
			} else if closeErr {
				errorCount++
			}
		}()
		return true
	})

	log.Printf("Download Manager shutdown complete. Finalized %d files with %d errors.",
		successCount, errorCount)
}

// GetStats returns the current statistics.
func (dm *DownloadManager) GetStats() *DownloadStats {
	return dm.stats
}
