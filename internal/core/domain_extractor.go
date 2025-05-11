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

// DomainExtractor orchestrates fetching CT log entries, parsing certificates,
// extracting domains, and writing them to per-log output files.
// Goal: High-throughput domain extraction pipeline.
// Concurrency: Uses the core Scheduler for parallel processing of log blocks.
// Manages output writers concurrently using sync.Map.
type DomainExtractor struct {
	scheduler *Scheduler // Manages worker goroutines and dispatch.
	config    *DomainExtractorConfig
	stats     *DomainExtractorStats // Holds atomic counters for metrics.
	ctx       context.Context       // Main context for cancellation.
	cancel    context.CancelFunc    // Function to trigger cancellation.
	// outputMap maps log URLs to their dedicated buffered (and potentially gzipped) writers.
	// sync.Map is used for concurrent-safe access from multiple worker callbacks.
	outputMap sync.Map // Maps log URL -> *lockedWriter
	// TODO: Consider adding padding if config/stats access becomes contended.
}

// DomainExtractorConfig holds operational parameters.
// Memory layout: Simple fields, padding unlikely needed unless part of a highly contended larger struct.
type DomainExtractorConfig struct {
	OutputDir  string
	BufferSize int // Buffer size for network and disk I/O.
	// MaxConcurrentLogs is currently implicitly handled by the number of workers
	// in the scheduler, but could be used for finer control (e.g., limiting STH fetches).
	MaxConcurrentLogs int
	Turbo             bool // Enables optimizations like DNS prewarming (TODO).
	CompressOutput    bool // Flag to enable gzip compression on output CSVs.
}

// DomainExtractorStats uses atomic counters for safe concurrent updates from workers.
// Goal: Provide observability without lock contention.
// Memory layout: Uses atomic.Int64. Ensure fields are 64-bit aligned.
// Padding could be added between counters if false sharing is detected under heavy load.
type DomainExtractorStats struct {
	TotalLogs          atomic.Int64
	ProcessedLogs      atomic.Int64
	FailedLogs         atomic.Int64
	TotalEntries       atomic.Int64
	ProcessedEntries   atomic.Int64
	FailedEntries      atomic.Int64
	TotalDomainsFound  atomic.Int64
	OutputBytesWritten atomic.Int64
	StartTime          time.Time
}

// NewDomainExtractor initializes the domain extractor, including the core scheduler.
// Operation: Blocking (at startup), allocates scheduler and its resources.
func NewDomainExtractor(ctx context.Context, config *DomainExtractorConfig) (*DomainExtractor, error) {
	// Initialize the core scheduler.
	scheduler, err := NewScheduler(ctx) // Pass parent context.
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scheduler: %w", err)
	}

	// Create a dedicated cancellable context for this run.
	extractorCtx, cancel := context.WithCancel(ctx)

	de := &DomainExtractor{
		scheduler: scheduler,
		config:    config,
		stats:     &DomainExtractorStats{StartTime: time.Now()},
		ctx:       extractorCtx,
		cancel:    cancel,
		// outputMap is ready for use (zero value of sync.Map).
	}

	return de, nil
}

// ExtractDomainsToCSV is the main entry point for the domain extraction command.
// It orchestrates fetching log info, setting up writers, and dispatching work.
// Operation: Long-running, potentially blocking on setup semaphore and context cancellation.
func (de *DomainExtractor) ExtractDomainsToCSV(logsToProcess []certlib.CTLogInfo) error {
	de.stats.TotalLogs.Store(int64(len(logsToProcess))) // Initialize total log count stat.
	log.Printf("Starting domain extraction for %d logs...", len(logsToProcess))

	// Create output directory - potentially blocking I/O, but only at startup.
	if err := os.MkdirAll(de.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory '%s': %w", de.config.OutputDir, err)
	}

	var wg sync.WaitGroup
	// setupSem limits concurrency during the initial phase for each log
	// (GetLogInfo, os.Create, writer setup) to avoid overwhelming the network/disk
	// with setup tasks before processing begins.
	setupSem := make(chan struct{}, runtime.NumCPU()) // Limit setup tasks, e.g., to #CPUs.

	// Loop to launch setup goroutine for each log.
	for i := range logsToProcess {
		select {
		case <-de.ctx.Done(): // Check for early cancellation.
			log.Println("Extraction cancelled during log setup launch.")
			// Need to wait for already launched goroutines if any.
			wg.Wait()
			return de.ctx.Err()
		case setupSem <- struct{}{}: // Acquire semaphore slot.
			wg.Add(1)
			// Launch setup and work submission in a separate goroutine per log.
			go func(logInfo certlib.CTLogInfo) {
				defer wg.Done()
				defer func() { <-setupSem }() // Release semaphore slot.

				// processSingleLogForDomains fetches STH, creates file/writer, submits all work blocks.
				if err := de.processSingleLogForDomains(&logInfo); err != nil {
					// Log error and mark log as failed.
					log.Printf("Error setting up log %s for domains: %v", logInfo.URL, err)
					de.stats.FailedLogs.Add(1)
				} else {
					// Successfully submitted all work items for this log.
					de.stats.ProcessedLogs.Add(1)
				}
			}(logsToProcess[i]) // Pass log info by value (copy) to the goroutine.
		}
	}

	wg.Wait() // Wait for all log setup goroutines (STH fetch, file create, work submission) to complete.

	// Check if context was cancelled during setup phase.
	if de.ctx.Err() != nil {
		log.Println("Extraction cancelled after log setup phase.")
		// Shutdown scheduler and flush writers even if cancelled during setup
		de.Shutdown()
		return de.ctx.Err()
	}

	// Wait for all submitted work items (entry fetching/processing) to complete.
	// The scheduler.Wait() blocks until its internal WaitGroup counter reaches zero.
	log.Println("All setup complete, waiting for scheduler workers to process submitted items...")
	de.scheduler.Wait()
	log.Println("Scheduler finished processing all submitted items.")

	// Check context again in case of cancellation signal received *during* processing.
	if de.ctx.Err() != nil {
		log.Println("Extraction cancelled during processing phase.")
		// Need to ensure shutdown is called to flush files etc.
		de.Shutdown()
		return de.ctx.Err()
	}

	// If we reach here, processing completed without external cancellation signal.
	log.Println("Processing complete. Finalizing...")
	de.Shutdown() // Final flush/close of writers and scheduler cleanup.
	log.Println("Domain extraction finished successfully.")
	return nil // Explicitly return nil for successful completion.
}

// processSingleLogForDomains sets up a single log for domain extraction:
// fetches STH, creates the output file/writer, calculates work blocks, and submits them.
// Operation: Can block on network (GetLogInfo) and disk (os.Create). Should be run concurrently.
func (de *DomainExtractor) processSingleLogForDomains(ctlog *certlib.CTLogInfo) error {
	log.Printf("Processing log: %s", ctlog.URL)

	// 1. Fetch Log Info (STH).
	// Network call - potentially blocking. Could add retries here.
	// TODO: Consider batching STH fetches or using a dedicated goroutine pool.
	if err := certlib.GetLogInfo(ctlog); err != nil {
		return fmt.Errorf("failed to get log info for %s: %w", ctlog.URL, err)
	}
	treeSize := int64(ctlog.TreeSize)
	if treeSize == 0 {
		log.Printf("Skipping log %s: tree size is 0", ctlog.URL)
		return nil // Not an error, just no work to do.
	}
	blockSize := int64(ctlog.BlockSize)
	if blockSize <= 0 {
		blockSize = DefaultLogEntryBlockSize // Use default if log info is incomplete.
	}

	// 2. Setup Output Writer.
	// File path generation uses util package now.
	filename := fmt.Sprintf("%s_domains.csv", util.SanitizeFilename(ctlog.URL))
	if de.config.CompressOutput {
		filename += ".gz"
	}
	filePath := filepath.Join(de.config.OutputDir, filename)

	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output file %s: %w", filePath, err)
	}
	// DO NOT defer file.Close() here.

	var writer *bufio.Writer
	var gzWriter *gzip.Writer
	var fileToClose *os.File = file // Assign to variable we will store

	if de.config.CompressOutput {
		gzWriter, _ = gzip.NewWriterLevel(file, gzip.BestSpeed)
		// DO NOT defer gzWriter.Close() here.
		writer = bufio.NewWriterSize(gzWriter, de.config.BufferSize)
	} else {
		writer = bufio.NewWriterSize(file, de.config.BufferSize)
	}
	// DO NOT defer writer.Flush() here.

	// Write CSV header
	header := "offset,cn,primary_domain,all_domains,country,state,locality,org,issuer_cn,domain_org_hash\n"
	_, err = writer.WriteString(header)
	if err != nil {
		fileToClose.Close() // Close file if header write fails
		return fmt.Errorf("failed to write header to %s: %w", filePath, err)
	}

	// Store the writer and necessary closers
	lw := &lockedWriter{
		writer:   writer,
		gzWriter: gzWriter, // Will be nil if not compressing
		file:     fileToClose,
	}
	de.outputMap.Store(ctlog.URL, lw)

	// 3. Calculate and Submit Work Blocks.
	numBlocks := (treeSize + blockSize - 1) / blockSize
	log.Printf("Log %s: TreeSize=%d, BlockSize=%d, NumBlocks=%d", ctlog.URL, treeSize, blockSize, numBlocks)

	// Initialize total entry count for this log.
	de.stats.TotalEntries.Add(treeSize)

	// Loop through all blocks for the log.
	// This loop submits work non-blockingly but can be paced by scheduler backpressure.
	for i := int64(0); i < numBlocks; i++ {
		if de.ctx.Err() != nil {
			return de.ctx.Err()
		}
		start := i * blockSize
		end := start + blockSize - 1
		if end >= treeSize {
			end = treeSize - 1
		}
		currentLogInfo := ctlog

		// Determine target worker and wait on its rate limiter
		shardIndex := int(xxh3.HashString(currentLogInfo.URL) % uint64(de.scheduler.numWorkers))
		targetWorker := de.scheduler.workers[shardIndex]
		if err := targetWorker.limiter.Wait(de.ctx); err != nil {
			// Context cancelled while waiting
			log.Printf("Context cancelled while waiting on rate limiter for %s", currentLogInfo.URL)
			return err
		}

		// Now attempt submission (with minimal retry for transient full queue)
		maxSubmitRetries := 15 // Only retry briefly after rate limit wait
		submitRetryDelay := 750 * time.Millisecond
		submitted := false
		for attempt := 0; attempt < maxSubmitRetries; attempt++ {
			if de.ctx.Err() != nil {
				return de.ctx.Err()
			}

			err := de.scheduler.SubmitWork(de.ctx, currentLogInfo, start, end, de.domainExtractorCallback)
			if err == nil {
				submitted = true
				break // Success
			}

			if errors.Is(err, ErrQueueFull) || strings.Contains(err.Error(), "queue full") {
				// Queue was full even after rate limit wait - brief sleep and retry once more
				select {
				case <-time.After(submitRetryDelay):
					continue // Retry submit
				case <-de.ctx.Done():
					return de.ctx.Err()
				}
			}

			// Permanent error
			log.Printf("Permanent error submitting work for %s (%d-%d): %v", currentLogInfo.URL, start, end, err)
			de.stats.TotalEntries.Add(-(end - start + 1))
			return err
		}

		if !submitted {
			log.Printf("Dropped block %s (%d-%d) after %d retries (post-rate limit).", currentLogInfo.URL, start, end, maxSubmitRetries)
			de.stats.TotalEntries.Add(-(end - start + 1))
		}
	}
	log.Printf("Successfully submitted all %d blocks for %s", numBlocks, ctlog.URL)
	return nil
}

// domainExtractorCallback is the function executed by each worker goroutine.
// It fetches CT log entries, parses certificates, extracts domains, and writes to the log-specific output file.
// Hot Path: Yes. Must be highly concurrent, low-allocation, and non-blocking where possible.
func (de *DomainExtractor) domainExtractorCallback(item *WorkItem) error {
	startTime := time.Now() // Start timer for this block

	// 1. Fetch Entries.
	logInfo := item.LogInfo
	if logInfo == nil {
		return fmt.Errorf("internal error: WorkItem missing LogInfo for %s (%d-%d)", item.LogURL, item.Start, item.End)
	}
	// Use the context associated with this specific work item for the download.
	ctx := item.Ctx
	if ctx == nil {
		// Fallback, though context should always be passed.
		ctx = context.Background()
	}

	downloadStart := time.Now()
	// Pass the context to DownloadEntries
	entriesResponse, err := certlib.DownloadEntries(ctx, logInfo, int(item.Start), int(item.End))
	downloadDuration := time.Since(downloadStart)
	if err != nil {
		numEntries := item.End - item.Start + 1
		de.stats.FailedEntries.Add(numEntries)
		// Log download failure, but don't spam if context cancelled
		if !errors.Is(err, context.Canceled) {
			log.Printf("Worker failed download for %s (%d-%d) in %v: %v", item.LogURL, item.Start, item.End, downloadDuration, err)
		}
		return fmt.Errorf("failed to download entries %d-%d for %s: %w", item.Start, item.End, item.LogURL, err)
	}

	// 2. Find the Output Writer.
	writerUntyped, ok := de.outputMap.Load(item.LogURL)
	if !ok {
		return fmt.Errorf("output writer not found for log %s", item.LogURL)
	}
	// MUST be pointer assertion
	lw, ok := writerUntyped.(*lockedWriter)
	if !ok || lw == nil {
		return fmt.Errorf("invalid writer type in map for log %s", item.LogURL)
	}

	// 3. Process Entries in the downloaded block.
	processStart := time.Now()
	var linesToWrite []string
	var domainsFoundInBlock int64
	var failedParses int64

	for i, entry := range entriesResponse.Entries {
		certIndex := item.Start + int64(i)

		// --- Debug Start: Parse Cert ---
		parseStart := time.Now()
		certData, err := certlib.ParseCertificateEntry(entry.LeafInput, entry.ExtraData, item.LogURL)
		parseDuration := time.Since(parseStart)
		// --- Debug End: Parse Cert ---

		if err != nil {
			// Check if it's the known precert parsing skip
			if strings.Contains(err.Error(), "skipped parsing Precert TBS") {
				// Don't log every single one, maybe sample? Log as debug level later.
				// log.Printf("[Worker Debug] Skipped precert TBS parsing for cert %d from %s", certIndex, item.LogURL)
			} else {
				// Log actual unexpected parsing errors more visibly
				log.Printf("[Worker Error] Failed to parse cert %d from %s (in %v): %v", certIndex, item.LogURL, parseDuration, err)
			}
			de.stats.FailedEntries.Add(1)
			failedParses++
			continue
		}

		// --- Debug Start: Generate CSV Line ---
		csvLineStart := time.Now()
		csvLine := certData.ToDomainsCSVLine(int(certIndex))
		_ = time.Since(csvLineStart) // csvLineDuration - currently unused, avoid alloc
		// --- Debug End: Generate CSV Line ---

		// --- Debug Start: Check CSV Line & Domains ---
		if len(certData.AllDomains) == 0 && certData.Subject.CN != "" {
			// If CSV line was generated but no domains were found (even CN), log it.
			// log.Printf("[Worker Debug] Cert %d from %s parsed OK (type %s) but yielded 0 domains? CN='%s'", certIndex, item.LogURL, certData.Type, certData.Subject.CN)
		}
		if csvLine == "" {
			log.Printf("[Worker Debug] Cert %d from %s generated EMPTY CSV line (in %v). Parsed Type: %s", certIndex, item.LogURL, parseDuration, certData.Type)
		}
		// --- Debug End: Check CSV Line & Domains ---

		linesToWrite = append(linesToWrite, csvLine)
		domainsFoundInBlock += int64(len(certData.AllDomains))
	}
	processDuration := time.Since(processStart)

	// 4. Write Batch to Output Buffer.
	writeStart := time.Now() // Correctly get start time for write
	lw.mu.Lock()
	bytesWritten := 0
	var writeErr error
	var linesSuccessfullyWritten int
	for i, line := range linesToWrite {
		n, err := lw.writer.WriteString(line)
		if err != nil {
			log.Printf("Error writing to output for %s (line %d): %v", item.LogURL, i, err)
			linesSuccessfullyWritten = i // Record how many lines were fully written
			de.stats.FailedEntries.Add(int64(len(linesToWrite) - linesSuccessfullyWritten))
			writeErr = fmt.Errorf("error writing to output buffer for %s: %w", item.LogURL, err)
			break
		}
		bytesWritten += n
	}
	if writeErr == nil { // Ensure all lines were accounted for if no error occurred
		linesSuccessfullyWritten = len(linesToWrite)
	}
	lw.mu.Unlock()
	writeDuration := time.Since(writeStart) // Calculate duration after unlock
	if writeErr != nil {
		return writeErr
	}

	// 5. Update Statistics (atomically).
	numProcessed := int64(linesSuccessfullyWritten)
	// Adjust for parsing failures if needed - depends if FailedEntries already counted them
	// For simplicity now, assume ProcessedEntries is just successfully written lines.
	de.stats.ProcessedEntries.Add(numProcessed)
	de.stats.TotalDomainsFound.Add(domainsFoundInBlock)
	de.stats.OutputBytesWritten.Add(int64(bytesWritten))

	// Uncomment detailed timing log for debugging
	log.Printf("Worker finished block %s (%d-%d): Entries=%d, FailedParse=%d, Domains=%d, TotalTime=%v (Down:%v, ProcLoop:%v, Write:%v)",
		item.LogURL, item.Start, item.End,
		len(entriesResponse.Entries),
		failedParses,
		domainsFoundInBlock,
		time.Since(startTime), // Total time for the callback
		downloadDuration,      // Time for DownloadEntries
		processDuration,       // Time for the processing loop (parsing + CSV gen)
		writeDuration)         // Time for the write loop + lock

	return nil // Success for this block.
}

// Shutdown gracefully cancels the context, shuts down the scheduler, and flushes/closes output files.
// Operation: Mostly non-blocking signals, but Range and Flush can block briefly.
func (de *DomainExtractor) Shutdown() {
	log.Println("Shutting down Domain Extractor...")
	de.cancel() // Signal all operations using the extractor's context.

	if de.scheduler != nil {
		// Signal the scheduler to stop accepting new work and cancel its workers.
		de.scheduler.Shutdown()
	}

	// Flush and Close all output writers/files
	log.Println("Flushing and closing output writers...")
	de.outputMap.Range(func(key, value interface{}) bool {
		if value == nil {
			return true
		}
		// MUST be pointer assertion with ok check
		lw, ok := value.(*lockedWriter)
		if !ok || lw == nil {
			log.Printf("Warning: Invalid type found in outputMap for key %v during shutdown", key)
			return true
		}

		func() {
			lw.mu.Lock()
			defer lw.mu.Unlock()
			// Close in correct order: bufio -> gzip -> file
			if lw.writer != nil {
				if err := lw.writer.Flush(); err != nil {
					log.Printf("Error flushing writer for %s on shutdown: %v", key.(string), err)
				}
			}
			if lw.gzWriter != nil {
				if err := lw.gzWriter.Close(); err != nil {
					log.Printf("Error closing gzip writer for %s on shutdown: %v", key.(string), err)
				}
			}
			if lw.file != nil {
				if err := lw.file.Close(); err != nil {
					log.Printf("Error closing file for %s on shutdown: %v", key.(string), err)
				}
			}
		}()

		return true // Continue iteration.
	})
	log.Println("Domain Extractor shutdown complete.")
}

// GetStats returns the pointer
func (de *DomainExtractor) GetStats() *DomainExtractorStats { return de.stats }
