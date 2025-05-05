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

// lockedWriter moved to shared_types.go

// DownloadManager manages the process of downloading raw cert entries from CT logs.
type DownloadManager struct {
	scheduler *Scheduler
	config    *DownloadConfig
	stats     *DownloadStats
	ctx       context.Context
	cancel    context.CancelFunc
	outputMap sync.Map // Maps log URL -> *bufio.Writer (or gzipped writer)
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

// NewDownloadManager creates a new download manager instance.
func NewDownloadManager(ctx context.Context, config *DownloadConfig) (*DownloadManager, error) {
	scheduler, err := NewScheduler(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scheduler: %w", err)
	}
	dmCtx, cancel := context.WithCancel(ctx)
	dm := &DownloadManager{
		scheduler: scheduler,
		config:    config,
		stats:     &DownloadStats{StartTime: time.Now()},
		ctx:       dmCtx,
		cancel:    cancel,
	}
	return dm, nil
}

// DownloadCertificates orchestrates the download process for the given logs.
func (dm *DownloadManager) DownloadCertificates(logsToProcess []certlib.CTLogInfo) error {
	dm.stats.TotalLogs.Store(int64(len(logsToProcess)))
	log.Printf("Starting certificate download for %d logs...", len(logsToProcess))

	// Create base output directory
	if err := os.MkdirAll(dm.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory '%s': %w", dm.config.OutputDir, err)
	}

	var wg sync.WaitGroup
	setupSem := make(chan struct{}, runtime.NumCPU()) // Limit concurrent setup

	for i := range logsToProcess {
		select {
		case <-dm.ctx.Done():
			log.Println("Download cancelled during log setup.")
			return dm.ctx.Err()
		case setupSem <- struct{}{}:
			wg.Add(1)
			go func(logInfo certlib.CTLogInfo) {
				defer wg.Done()
				defer func() { <-setupSem }()
				if err := dm.processSingleLogForDownload(&logInfo); err != nil {
					log.Printf("Error processing log %s for download: %v", logInfo.URL, err)
					dm.stats.FailedLogs.Add(1)
				} else {
					dm.stats.ProcessedLogs.Add(1)
				}
			}(logsToProcess[i])
		}
	}

	wg.Wait() // Wait for setup goroutines

	if dm.ctx.Err() != nil {
		log.Println("Download cancelled after log setup phase.")
		dm.Shutdown()
		return dm.ctx.Err()
	}

	log.Println("All download work submitted. Waiting for scheduler...")
	dm.scheduler.Wait() // Wait for all submitted download tasks
	log.Println("Scheduler finished download processing.")

	if dm.ctx.Err() != nil {
		log.Println("Download cancelled during processing phase.")
		dm.Shutdown()
		return dm.ctx.Err()
	}

	log.Println("Download processing complete. Finalizing...")
	dm.Shutdown()
	log.Println("Certificate download finished successfully.")
	return nil
}

// processSingleLogForDownload handles STH fetch, output setup, and work submission for one log.
func (dm *DownloadManager) processSingleLogForDownload(ctlog *certlib.CTLogInfo) error {
	log.Printf("Setting up download for log: %s", ctlog.URL)
	if err := certlib.GetLogInfo(ctlog); err != nil {
		return fmt.Errorf("failed to get log info for %s: %w", ctlog.URL, err)
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

	// Setup Output Writer using util package
	filename := fmt.Sprintf("%s_certs.csv", util.SanitizeFilename(ctlog.URL))
	if dm.config.CompressOutput {
		filename += ".gz"
	}
	filePath := filepath.Join(dm.config.OutputDir, filename)
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", filePath, err)
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
	_, err = writer.WriteString("offset,leaf_input_b64,extra_data_b64\n")
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to write header to %s: %w", filePath, err)
	}

	// Store the locked writer instance
	lw := &lockedWriter{
		writer:   writer,
		gzWriter: gzWriter,
		file:     file,
	}
	dm.outputMap.Store(ctlog.URL, lw)

	// Submit Work Blocks
	numBlocks := (treeSize + blockSize - 1) / blockSize
	log.Printf("Log %s: TreeSize=%d, BlockSize=%d, NumBlocks=%d (Download)", ctlog.URL, treeSize, blockSize, numBlocks)
	dm.stats.TotalEntries.Add(treeSize)

	for i := int64(0); i < numBlocks; i++ {
		if dm.ctx.Err() != nil {
			return dm.ctx.Err()
		}
		start := i * blockSize
		end := start + blockSize - 1
		if end >= treeSize {
			end = treeSize - 1
		}
		currentLogInfo := ctlog

		// Determine target worker and wait on its rate limiter
		shardIndex := int(xxh3.HashString(currentLogInfo.URL) % uint64(dm.scheduler.numWorkers))
		targetWorker := dm.scheduler.workers[shardIndex]
		if err := targetWorker.limiter.Wait(dm.ctx); err != nil {
			log.Printf("Context cancelled while waiting on rate limiter for %s (Download)", currentLogInfo.URL)
			return err
		}

		// Now attempt submission (with minimal retry for transient full queue)
		maxSubmitRetries := 2
		submitRetryDelay := 10 * time.Millisecond
		submitted := false
		for attempt := 0; attempt < maxSubmitRetries; attempt++ {
			if dm.ctx.Err() != nil {
				return dm.ctx.Err()
			}
			err := dm.scheduler.SubmitWork(dm.ctx, currentLogInfo, start, end, dm.downloadCallback)
			if err == nil {
				submitted = true
				break
			}
			if errors.Is(err, ErrQueueFull) || strings.Contains(err.Error(), "queue full") {
				select {
				case <-time.After(submitRetryDelay):
					continue // Retry submit
				case <-dm.ctx.Done():
					return dm.ctx.Err()
				}
			}
			log.Printf("Permanent error submitting download work for %s (%d-%d): %v", currentLogInfo.URL, start, end, err)
			dm.stats.TotalEntries.Add(-(end - start + 1))
			return err
		}
		if !submitted {
			log.Printf("Dropped download block %s (%d-%d) after %d retries (post-rate limit).", currentLogInfo.URL, start, end, maxSubmitRetries)
			dm.stats.TotalEntries.Add(-(end - start + 1))
		}
	}
	log.Printf("Successfully submitted all %d download blocks for %s", numBlocks, ctlog.URL)
	return nil
}

// downloadCallback fetches entries and writes raw data to the output file.
func (dm *DownloadManager) downloadCallback(item *WorkItem) error {
	logInfo := item.LogInfo
	if logInfo == nil {
		return fmt.Errorf("internal error: WorkItem missing LogInfo (download)")
	}

	// Extract context from the work item
	ctx := item.Ctx
	if ctx == nil {
		ctx = context.Background()
	} // Fallback

	// TODO: Implement retry using item.Attempt
	entriesResponse, err := certlib.DownloadEntries(ctx, logInfo, int(item.Start), int(item.End))
	if err != nil {
		dm.stats.FailedEntries.Add(item.End - item.Start + 1)
		return fmt.Errorf("failed to download entries %d-%d for %s: %w", item.Start, item.End, item.LogURL, err)
	}

	// Find the correct output writer
	writerUntyped, ok := dm.outputMap.Load(item.LogURL)
	if !ok {
		dm.stats.FailedEntries.Add(int64(len(entriesResponse.Entries)))
		return fmt.Errorf("output writer not found for log %s (download)", item.LogURL)
	}
	// MUST be pointer assertion
	lw, ok := writerUntyped.(*lockedWriter)
	if !ok || lw == nil {
		return fmt.Errorf("invalid writer type found in map for log %s (download)", item.LogURL)
	}

	// Process and Write Entries
	// Lock the writer before the batch write
	lw.mu.Lock()
	var linesWritten int64
	var bytesWritten int64
	var writeErr error // To capture error within the loop
	for i, entry := range entriesResponse.Entries {
		certIndex := item.Start + int64(i)
		line := fmt.Sprintf("%d,%s,%s\n", certIndex, entry.LeafInput, entry.ExtraData)
		n, err := lw.writer.WriteString(line) // Use lw.writer
		if err != nil {
			log.Printf("Error writing download entry %d for %s: %v", certIndex, item.LogURL, err)
			dm.stats.FailedEntries.Add(int64(len(entriesResponse.Entries)) - linesWritten)
			writeErr = fmt.Errorf("error writing to output buffer for %s (download): %w", item.LogURL, err)
			break // Stop writing this batch on error
		}
		bytesWritten += int64(n)
		linesWritten++
	}
	lw.mu.Unlock() // Unlock after the loop
	if writeErr != nil {
		return writeErr // Return error after unlocking
	}

	// Update stats
	dm.stats.ProcessedEntries.Add(linesWritten)
	dm.stats.OutputBytesWritten.Add(bytesWritten)

	return nil // Success for this block
}

// Shutdown gracefully closes resources.
func (dm *DownloadManager) Shutdown() {
	log.Println("Shutting down Download Manager...")
	dm.cancel()
	if dm.scheduler != nil {
		dm.scheduler.Shutdown()
	}
	log.Println("Flushing download writers...")
	dm.outputMap.Range(func(key, value interface{}) bool {
		if value == nil {
			return true
		} // Skip nil
		// MUST be pointer assertion
		lw, ok := value.(*lockedWriter)
		if !ok || lw == nil {
			log.Printf("Warning: Invalid writer type in map during download shutdown for key %v", key)
			return true
		}

		// Locking and closing logic remains the same, using the lw pointer
		func() {
			lw.mu.Lock()
			defer lw.mu.Unlock()
			if lw.writer != nil {
				if err := lw.writer.Flush(); err != nil {
					log.Printf("Error flushing download writer for %s: %v", key.(string), err)
				}
			}
			if lw.gzWriter != nil {
				if err := lw.gzWriter.Close(); err != nil {
					log.Printf("Error closing gzip download writer for %s: %v", key.(string), err)
				}
			}
			if lw.file != nil {
				if err := lw.file.Close(); err != nil {
					log.Printf("Error closing file for download %s: %v", key.(string), err)
				}
			}
		}()
		return true
	})
	log.Println("Download Manager shutdown complete.")
}

// GetStats returns the current statistics.
func (dm *DownloadManager) GetStats() *DownloadStats {
	return dm.stats
}
