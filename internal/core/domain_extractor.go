/*
Package core provides the central logic for rxtls, including the scheduler, download manager,
and domain extractor. It defines common data structures and constants used across these components.

Key responsibilities of the core package include:
- Managing concurrent operations through a worker pool (Scheduler).
- Orchestrating the download of certificate entries from Certificate Transparency logs (DownloadManager).
- Processing downloaded entries to extract domain names and other relevant metadata (DomainExtractor - if used).
- Defining shared data types like WorkItem and CTLogInfo (though CTLogInfo is primarily from certlib).
- Establishing common constants for retry logic, queue sizes, and default behaviors.
*/
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

// DomainExtractor orchestrates the fetching of CT log entries, parsing of certificates,
// extraction of domain names (Common Name and Subject Alternative Names), and writing
// these domains to per-log CSV output files.
//
// It leverages the core.Scheduler for concurrent processing of certificate data blocks
// retrieved from different CT logs. The DomainExtractor manages its own set of output
// writers, ensuring that data for each log is written to a dedicated, correctly formatted file.
//
// Concurrency:
// - Log setup (STH fetching, file creation) is done concurrently, limited by a semaphore.
// - Work item submission to the scheduler is non-blocking but paced by scheduler backpressure.
// - Callbacks (domainExtractorCallback) run concurrently on worker goroutines managed by the Scheduler.
// - Output file access is synchronized using a sync.Map of *lockedWriter instances.
//
// Graceful Shutdown:
// - Responds to context cancellation to halt operations.
// - Ensures all buffered data is flushed and files are closed properly during shutdown.
type DomainExtractor struct {
	// scheduler is the core component responsible for managing worker goroutines
	// and dispatching certificate processing tasks.
	scheduler *Scheduler
	// config holds operational parameters for the domain extraction process,
	// such as output directory, buffer sizes, and compression settings.
	config *DomainExtractorConfig
	// stats maintains runtime statistics for the domain extraction process,
	// including counts of processed logs, entries, domains, and failures.
	// All fields are updated atomically for safe concurrent access.
	stats *DomainExtractorStats
	// ctx is the primary context for the DomainExtractor. Cancellation of this context
	// signals all ongoing operations (setup, processing, I/O) to terminate gracefully.
	ctx context.Context
	// cancel is the function to call to trigger the cancellation of the DomainExtractor's context (ctx).
	cancel context.CancelFunc
	// outputMap stores a mapping from a CT log's URL (string) to its dedicated *lockedWriter instance.
	// This allows concurrent-safe writes to multiple output files, one for each log being processed.
	// sync.Map is used for efficient concurrent read/write access.
	outputMap sync.Map
	// stringPool is a pool of string.Builder instances to reduce allocations during CSV line creation.
	stringPool sync.Pool
	// setupComplete indicates atomically whether the initial setup phase (STH fetching for all logs) has finished.
	// This is used by the Shutdown method to decide whether to rename temporary output files.
	setupComplete atomic.Bool
}

// DomainExtractorConfig holds configuration parameters specific to the domain extraction process.
// These settings control aspects like output locations, I/O buffering, concurrency limits,
// and output compression.
//
// Memory Layout: Fields are simple types. Padding is generally not a concern unless this struct
// becomes part of a much larger, highly contended structure, which is not its current usage.
type DomainExtractorConfig struct {
	// OutputDir specifies the base directory where extracted domain CSV files will be stored.
	// Each processed CT log will have its own CSV file within this directory.
	OutputDir string
	// BufferSize defines the size of the I/O buffers (e.g., for bufio.Writer) used when
	// writing domain data to disk. Larger buffers can improve I/O performance by reducing
	// the number of syscalls, at the cost of increased memory usage.
	BufferSize int
	// MaxConcurrentLogs, if set, would notionally limit the number of CT logs processed in parallel
	// during the setup phase (e.g., fetching STH). However, in the current implementation,
	// concurrency is primarily managed by the scheduler's worker pool size and a setup semaphore.
	// This field could be used for finer-grained control in future enhancements.
	MaxConcurrentLogs int // Currently informational, main concurrency via scheduler & setupSem.
	// Turbo, if true, indicates that high-speed mode optimizations should be enabled.
	// This might involve more aggressive network settings (e.g., via client.ConfigureTurboMode)
	// or other performance-enhancing tweaks. DNS prewarming is a potential TODO here.
	Turbo bool
	// CompressOutput, if true, enables gzip compression for the output CSV files.
	// This reduces disk space usage at the cost of some CPU overhead for compression.
	// Output files will have a ".gz" extension if enabled.
	CompressOutput bool
}

// DomainExtractorStats holds runtime statistics for the domain extraction process.
// All counters are implemented using atomic operations (atomic.Int64) to ensure safe
// concurrent updates from multiple worker goroutines without requiring explicit locking
// for each increment, thus minimizing contention.
//
// Memory Layout: All fields are atomic.Int64 or time.Time. Standard Go struct alignment rules apply.
// Ensure 64-bit alignment for atomics if manual padding were ever considered (not currently needed).
type DomainExtractorStats struct {
	// TotalLogs is the total number of CT logs selected for domain extraction.
	TotalLogs atomic.Int64
	// ProcessedLogs is the number of CT logs for which setup (STH fetch, output file creation)
	// and work submission completed successfully.
	ProcessedLogs atomic.Int64
	// FailedLogs is the number of CT logs that failed during the setup phase.
	FailedLogs atomic.Int64
	// TotalEntries is the sum of tree sizes for all successfully processed logs,
	// representing the total number of certificate entries expected to be processed.
	// This value can be an estimate if some logs fail STH fetching after initial selection.
	TotalEntries atomic.Int64
	// ProcessedEntries is the total number of certificate entries successfully downloaded,
	// parsed, and for which domain data was written to an output file.
	ProcessedEntries atomic.Int64
	// FailedEntries is the count of certificate entries that failed at some stage
	// (e.g., download error, parsing error, write error to output file).
	FailedEntries atomic.Int64
	// TotalDomainsFound is the total number of unique domain names (CNs and SANs)
	// extracted from all processed certificates.
	TotalDomainsFound atomic.Int64
	// OutputBytesWritten is the total number of bytes written to all output CSV files.
	// This includes CSV headers and compressed size if compression is enabled.
	OutputBytesWritten atomic.Int64
	// StartTime records the time when the domain extraction process was initiated.
	// Used to calculate overall processing duration.
	StartTime time.Time
	// RetryCount is the count of retried blocks during domain extraction
	RetryCount atomic.Int64
	// SuccessFirstTry is the count of blocks successful on first try
	SuccessFirstTry atomic.Int64
}

// GetStartTime returns the StartTime of the extraction process.
func (s *DomainExtractorStats) GetStartTime() time.Time { return s.StartTime }

// GetTotalLogs returns the total number of logs being processed.
func (s *DomainExtractorStats) GetTotalLogs() int64 { return s.TotalLogs.Load() }

// GetProcessedLogs returns the number of logs successfully set up for processing.
func (s *DomainExtractorStats) GetProcessedLogs() int64 { return s.ProcessedLogs.Load() }

// GetFailedLogs returns the number of logs that failed during setup.
func (s *DomainExtractorStats) GetFailedLogs() int64 { return s.FailedLogs.Load() }

// GetTotalEntries returns the estimated total number of entries to be processed.
func (s *DomainExtractorStats) GetTotalEntries() int64 { return s.TotalEntries.Load() }

// GetProcessedEntries returns the number of entries successfully processed.
func (s *DomainExtractorStats) GetProcessedEntries() int64 { return s.ProcessedEntries.Load() }

// GetFailedEntries returns the number of entries that failed during processing.
func (s *DomainExtractorStats) GetFailedEntries() int64 { return s.FailedEntries.Load() }

// GetTotalDomainsFound returns the total number of unique domains found.
func (s *DomainExtractorStats) GetTotalDomainsFound() int64 { return s.TotalDomainsFound.Load() }

// GetOutputBytesWritten returns the total bytes written to output files.
func (s *DomainExtractorStats) GetOutputBytesWritten() int64 { return s.OutputBytesWritten.Load() }

// GetRetryRate returns the retry rate as a fraction of processed entries
func (s *DomainExtractorStats) GetRetryRate() float64 {
	if s.ProcessedEntries.Load() == 0 {
		return 0
	}
	return float64(s.RetryCount.Load()) / float64(s.ProcessedEntries.Load())
}

// NewDomainExtractor creates and initializes a new DomainExtractor instance.
// It requires a parent context (for overall cancellation) and a DomainExtractorConfig.
// This function initializes the core scheduler, sets up internal state, and prepares the
// extractor for processing.
//
// Operation: This is a blocking operation at startup as it initializes the scheduler,
// which in turn starts its worker goroutines. Any errors during scheduler initialization
// will be returned.
func NewDomainExtractor(ctx context.Context, config *DomainExtractorConfig) (*DomainExtractor, error) {
	// Initialize the core scheduler, passing the parent context to it.
	scheduler, err := NewScheduler(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize scheduler: %w", err)
	}

	// Create a new, cancellable context that is a child of the provided parent context.
	// This allows the DomainExtractor to manage its own lifecycle and gracefully shut down
	// its operations without affecting other parts of the application that might share the parent context.
	extractorCtx, cancel := context.WithCancel(ctx)

	de := &DomainExtractor{
		scheduler: scheduler,
		config:    config,
		stats:     &DomainExtractorStats{StartTime: time.Now()},
		ctx:       extractorCtx,
		cancel:    cancel,
		stringPool: sync.Pool{
			New: func() interface{} {
				return strings.Builder{}
			},
		},
		// outputMap (sync.Map) is ready for use as its zero value is a valid, empty map.
	}

	return de, nil
}

// ExtractDomainsToCSV is the primary method for initiating the domain extraction process.
// It takes a slice of certlib.CTLogInfo structs (passed as an interface{} for flexibility,
// then type-asserted) representing the CT logs to process.
//
// The method orchestrates several key steps:
//  1. Type assertion of the input `logsToProcess`.
//  2. Initialization of statistics (total log count).
//  3. Creation of the main output directory.
//  4. Concurrent setup for each log: This involves fetching the Signed Tree Head (STH)
//     to get the log's current size, creating the per-log output CSV file and its writer,
//     and then submitting all necessary work blocks (ranges of entries) to the scheduler.
//     A semaphore limits the concurrency of this setup phase to avoid overwhelming resources.
//  5. Waiting for all log setup goroutines to complete.
//  6. Waiting for the scheduler to process all submitted work items (actual entry fetching and parsing).
//  7. Graceful shutdown of the extractor, ensuring all data is flushed and resources are closed.
//
// Operation: This is a long-running, blocking method. It returns an error if the input type is incorrect,
// if the output directory cannot be created, if context cancellation occurs, or if a significant
// number of processing errors occur.
func (de *DomainExtractor) ExtractDomainsToCSV(logsToProcess interface{}) error {
	// Ensure logsToProcess is of the expected type []certlib.CTLogInfo.
	logs, ok := logsToProcess.([]certlib.CTLogInfo)
	if !ok {
		return fmt.Errorf("invalid logs type: expected []certlib.CTLogInfo, got %T", logsToProcess)
	}

	de.stats.TotalLogs.Store(int64(len(logs))) // Initialize total log count stat.
	log.Printf("Starting domain extraction for %d logs...", len(logs))

	// Create the base output directory. This is an early check; if it fails, no further work is done.
	// The permissions 0755 allow read/execute for everyone and write for the owner.
	if err := os.MkdirAll(de.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory '%s': %w", de.config.OutputDir, err)
	}

	var wg sync.WaitGroup
	// setupSem limits the number of concurrent log setup operations (STH fetch, file creation).
	// This prevents overwhelming the network or disk with too many simultaneous setup tasks
	// before the main processing begins. Using runtime.NumCPU() is a common heuristic.
	setupConcurrency := runtime.NumCPU()
	if setupConcurrency > MaxSetupConcurrency { // Cap concurrency if NumCPU is very high.
		setupConcurrency = MaxSetupConcurrency
	}
	setupSem := make(chan struct{}, setupConcurrency)

	// Loop to launch a setup goroutine for each log selected for processing.
	for i := range logs {
		// Check for early cancellation before launching a new goroutine.
		// This is important if the context is cancelled while this loop is still iterating.
		select {
		case <-de.ctx.Done():
			log.Println("Extraction cancelled during log setup launch.")
			wg.Wait() // Wait for any already launched goroutines to finish.
			return de.ctx.Err()
		case setupSem <- struct{}{}: // Acquire a slot from the semaphore to limit concurrent setups.
			wg.Add(1) // Increment WaitGroup counter for this new goroutine.
			// Launch the setup and work submission for this log in a new goroutine.
			// This allows multiple logs to be set up concurrently, up to the semaphore limit.
			go func(logInfo certlib.CTLogInfo) {
				defer wg.Done()               // Decrement WaitGroup counter when goroutine exits.
				defer func() { <-setupSem }() // Release semaphore slot when goroutine exits.

				// processSingleLogForDomains handles fetching STH, creating the output file/writer,
				// and submitting all work blocks for this specific log to the scheduler.
				if err := de.processSingleLogForDomains(&logInfo); err != nil {
					// If setup for a log fails, log the error and mark the log as failed.
					// Do not return immediately, allow other logs to continue their setup.
					log.Printf("Error setting up log %s for domains: %v", logInfo.URL, err)
					de.stats.FailedLogs.Add(1)
				} else {
					// If setup and work submission were successful for this log, increment processed logs count.
					de.stats.ProcessedLogs.Add(1)
				}
			}(logs[i]) // Pass logInfo by value (a copy) to the goroutine to avoid race conditions on the loop variable.
		}
	}

	// Wait for all log setup goroutines to complete. This ensures that STH fetches, file creations,
	// and work submissions for all selected logs have finished (or failed) before proceeding.
	wg.Wait()

	// Check if the context was cancelled during the setup phase (e.g., by a signal).
	if de.ctx.Err() != nil {
		log.Println("Extraction cancelled after log setup phase.")
		// Even if cancelled during setup, ensure resources are cleaned up.
		de.Shutdown()
		return de.ctx.Err()
	}

	log.Println("All setup complete, waiting for scheduler workers to process submitted items...")
	// Wait for the scheduler to process all work items that were submitted by the setup goroutines.
	// The scheduler's Wait() method blocks until its internal WaitGroup counter (tracking active work) reaches zero.
	de.scheduler.Wait()
	log.Println("Scheduler finished processing all submitted items.")

	// Check the context again in case a cancellation signal was received *during* the processing phase.
	if de.ctx.Err() != nil {
		log.Println("Extraction cancelled during processing phase.")
		// Ensure shutdown is called to flush files and clean up other resources.
		de.Shutdown()
		return de.ctx.Err()
	}

	// If execution reaches this point, all work has been processed (or attempted)
	// without external cancellation via the context.
	log.Println("Processing complete. Finalizing...")
	de.Shutdown() // Perform final flush/close of writers and scheduler cleanup.
	log.Println("Domain extraction finished successfully.")
	return nil // Explicitly return nil to indicate successful completion of the command.
}

// processSingleLogForDomains handles the setup for a single CT log. It performs the following steps:
// 1. Fetches the log's Signed Tree Head (STH) to determine its size.
// 2. Creates and opens the output CSV file for this log (using a temporary name initially).
// 3. Sets up the necessary buffered (and potentially gzipped) writer for the file.
// 4. Writes the CSV header to the output file.
// 5. Stores the writer in the DomainExtractor's outputMap.
// 6. Calculates the number of entry blocks based on log size and block size.
// 7. Submits each block as a WorkItem to the scheduler for processing.
//
// This function is designed to be run in a separate goroutine for each log to enable concurrent setup.
// It can block on network I/O (GetLogInfo) and disk I/O (os.Create, writer.WriteString).
// Any errors encountered during these critical setup steps will be returned, causing this log
// to be marked as failed.
func (de *DomainExtractor) processSingleLogForDomains(ctlog *certlib.CTLogInfo) error {
	log.Printf("Processing log: %s", ctlog.URL)

	// 1. Fetch Log Info (STH).
	// This network call can be time-consuming and is a potential point of failure.
	// certlib.GetLogInfo may have its own retry logic.
	// TODO: Consider adding a specific timeout for GetLogInfo if not handled by certlib or global client.
	if err := certlib.GetLogInfo(ctlog); err != nil {
		return fmt.Errorf("failed to get log info for %s: %w", ctlog.URL, err)
	}
	treeSize := int64(ctlog.TreeSize)
	if treeSize == 0 {
		log.Printf("Skipping log %s: tree size is 0, no entries to process.", ctlog.URL)
		return nil // Not an error, but no work to do for this log.
	}
	blockSize := int64(ctlog.BlockSize)
	if blockSize <= 0 {
		// If the log info doesn't provide a valid block size, use a sensible default.
		blockSize = DefaultLogEntryBlockSize
		log.Printf("Warning: Log %s has invalid block size (%d), using default: %d", ctlog.URL, ctlog.BlockSize, blockSize)
	}

	// 2. Setup Output Writer.
	// Generate a sanitized filename from the log URL to avoid issues with special characters.
	filename := fmt.Sprintf("%s_domains.csv", util.SanitizeFilename(ctlog.URL))
	if de.config.CompressOutput {
		filename += ".gz"
	}
	filePath := filepath.Join(de.config.OutputDir, filename)

	// Atomicity: Write to a temporary file first, then rename on successful completion of all writes for this log.
	// This prevents partial/corrupt files if the process is interrupted.
	tempFilePath := filePath + ".tmp"
	file, err := os.Create(tempFilePath)
	if err != nil {
		return fmt.Errorf("failed to create temporary output file %s: %w", tempFilePath, err)
	}
	// Note: File is not closed here with defer. It will be closed by the lockedWriter in Shutdown().

	var writer *bufio.Writer
	var gzWriter *gzip.Writer // Keep as specific type for Close() method.

	if de.config.CompressOutput {
		// Use gzip.BestSpeed for faster compression, as I/O is often the bottleneck.
		gzWriter, _ = gzip.NewWriterLevel(file, gzip.BestSpeed)
		writer = bufio.NewWriterSize(gzWriter, de.config.BufferSize)
	} else {
		writer = bufio.NewWriterSize(file, de.config.BufferSize)
	}

	// Write CSV header.
	// TODO: Consider making the header columns configurable or defined as constants.
	header := "offset,cn,primary_domain,all_domains,country,state,locality,org,issuer_cn,domain_org_hash\n"
	if _, err := writer.WriteString(header); err != nil {
		file.Close() // Attempt to close file if header write fails.
		return fmt.Errorf("failed to write CSV header to %s: %w", tempFilePath, err)
	}

	// Store the writer, gzip writer (if any), and file handle in a lockedWriter struct.
	// This ensures thread-safe access and proper resource management during shutdown.
	lw := &lockedWriter{
		writer:    writer,
		gzWriter:  gzWriter, // Will be nil if not compressing.
		file:      file,
		filePath:  tempFilePath,
		finalPath: filePath,
	}
	de.outputMap.Store(ctlog.URL, lw)

	// 3. Calculate and Submit Work Blocks.
	numBlocks := (treeSize + blockSize - 1) / blockSize // Ceiling division.
	log.Printf("Log %s: TreeSize=%d, BlockSize=%d, NumBlocks=%d", ctlog.URL, treeSize, blockSize, numBlocks)

	// Initialize total entry count for this log for statistics.
	de.stats.TotalEntries.Add(treeSize)

	var submittedBlocks, droppedBlocks int64
	// Loop through all blocks for the log and submit them as WorkItems.
	// This loop submits work non-blockingly (to the scheduler's queue) but can be paced
	// by the scheduler's rate limiter and queue capacity (backpressure).
	for i := int64(0); i < numBlocks; i += batchSize { // Submit in larger batches
		if de.ctx.Err() != nil {
			return de.ctx.Err() // Early exit if context is cancelled.
		}
		batchEnd := i + batchSize
		if batchEnd > numBlocks {
			batchEnd = numBlocks
		}

		for j := i; j < batchEnd; j++ {
			if de.ctx.Err() != nil {
				return de.ctx.Err()
			}
			start := j * blockSize
			end := start + blockSize - 1
			if end >= treeSize {
				end = treeSize - 1 // Adjust last block's end index.
			}

			if err := de.submitDomainExtractionBlock(de.ctx, ctlog, start, end); err != nil {
				if errors.Is(err, ErrQueueFull) {
					droppedBlocks++
					de.stats.TotalEntries.Add(-(end - start + 1)) // Adjust total as this block won't be processed.
				} else if de.ctx.Err() != nil {
					return de.ctx.Err() // Propagate cancellation.
				} else {
					// Log other submission errors but continue trying to submit subsequent blocks for this log.
					log.Printf("Error submitting domain extraction block %s (%d-%d): %v", ctlog.URL, start, end, err)
				}
			} else {
				submittedBlocks++
			}
		}
		// Brief pause between submitting large batches to allow scheduler to distribute work if queues are filling.
		if batchEnd < numBlocks {
			time.Sleep(250 * time.Millisecond)
		}
	}

	if droppedBlocks > 0 {
		log.Printf("Log %s: Submitted %d blocks, DRGOPPED %d blocks due to backpressure.", ctlog.URL, submittedBlocks, droppedBlocks)
	} else {
		log.Printf("Successfully submitted all %d blocks for %s", submittedBlocks, ctlog.URL)
	}
	return nil
}

// submitDomainExtractionBlock handles the logic for submitting a single block of work
// for domain extraction to the scheduler, including rate limiting and retries on submission failure.
func (de *DomainExtractor) submitDomainExtractionBlock(ctx context.Context, ctlog *certlib.CTLogInfo, start, end int64) error {
	// Determine target worker based on log URL for consistent sharding.
	hash := xxh3.HashString(ctlog.URL)
	shardIndex := int(hash % uint64(de.scheduler.numWorkers))
	targetWorker := de.scheduler.workers[shardIndex]

	// Wait on the worker's specific rate limiter.
	waitStart := time.Now()
	if err := targetWorker.limiter.Wait(ctx); err != nil {
		if errors.Is(err, context.Canceled) { // Renamed from dm.ctx.Err() for clarity
			return ErrDownloadCancelled // Use specific error
		}
		return fmt.Errorf("rate limiter wait failed for %s: %w", ctlog.URL, err)
	}
	waitDuration := time.Since(waitStart)
	if waitDuration > 100*time.Millisecond {
		log.Printf("Worker %d rate limit wait for %s (%d-%d): %v, current limit: %.2f req/s",
			targetWorker.id, ctlog.URL, start, end, waitDuration, float64(targetWorker.limiter.Limit()))
	}

	// Attempt to submit the work item with retries if the queue is full.
	// Uses constants from common.go or constants.go for retry policy.
	maxRetries := MaxSubmitRetries // From constants.go
	retryDelay := RetryBaseDelay   // From common.go

	for attempt := 0; attempt < maxRetries; attempt++ {
		if ctx.Err() != nil {
			return ErrDownloadCancelled
		}
		err := de.scheduler.SubmitWork(ctx, ctlog, start, end, de.domainExtractorCallback)
		if err == nil {
			return nil // Successfully submitted.
		}

		if errors.Is(err, ErrQueueFull) {
			log.Printf("Queue full for worker %d log %s, attempt %d/%d, retrying in %v...",
				targetWorker.id, ctlog.URL, attempt+1, maxRetries, retryDelay)
			select {
			case <-time.After(retryDelay):
				retryDelay = time.Duration(float64(retryDelay) * RetryBackoffMultiplier) // Exponential backoff
				if retryDelay > RetryMaxDelay {
					retryDelay = RetryMaxDelay
				}
				continue // Retry submission.
			case <-ctx.Done():
				return ErrDownloadCancelled
			}
		}
		// For other errors, do not retry submission to this worker immediately.
		return fmt.Errorf("permanent error submitting work for %s (%d-%d) to worker %d: %w",
			ctlog.URL, start, end, targetWorker.id, err)
	}

	// All retries exhausted for submission.
	return ErrQueueFull // Indicate that the block was dropped due to persistent queue full state.
}

// domainExtractorCallback is the function executed by each worker goroutine from the scheduler.
// It performs the core work for a given WorkItem:
//  1. Fetches the batch of certificate entries from the CT log server.
//  2. For each entry, parses the certificate data (X.509 or Precert).
//  3. Extracts all domain names (Common Name and Subject Alternative Names).
//  4. Formats the extracted data into a CSV line.
//  5. Appends the CSV line to a batch for writing.
//  6. After processing all entries in the WorkItem, writes the batch of CSV lines to the
//     log-specific output file, using the appropriate lockedWriter.
//
// Error Handling:
// - Errors during entry download are considered fatal for the block and are returned.
// - Certificate parsing errors are logged, and the specific entry is skipped; processing continues.
// - Errors during writing to the output file are considered fatal and returned.
//
// Performance:
// - This is a hot path and should be optimized for low allocation and high concurrency.
// - Uses a strings.Builder from a sync.Pool for efficient string concatenation of CSV lines.
// - File writes are batched and locked appropriately to balance I/O efficiency and concurrency.
//
// Context Awareness:
//   - The callback respects the context passed within the WorkItem (item.Ctx),
//     allowing for cancellation of individual download/processing tasks.
func (de *DomainExtractor) domainExtractorCallback(item *WorkItem) error {
	startTime := time.Now() // Start timer for overall block processing.

	// Track retries
	isRetry := item.Attempt > 0
	if isRetry {
		de.stats.RetryCount.Add(1)
	}

	// 1. Fetch Entries.
	logInfo := item.LogInfo
	if logInfo == nil {
		// This should ideally not happen if WorkItems are constructed correctly.
		return fmt.Errorf("internal error: WorkItem for %s (%d-%d) is missing LogInfo", item.LogURL, item.Start, item.End)
	}

	// Use the context associated with this specific work item for the download operation.
	// This allows for finer-grained cancellation if needed.
	ctx := item.Ctx
	if ctx == nil {
		// Fallback, though context should always be provided with the WorkItem.
		log.Printf("Warning: WorkItem for %s (%d-%d) has nil context, using background.", item.LogURL, item.Start, item.End)
		ctx = context.Background()
	}

	downloadStart := time.Now()
	// certlib.DownloadEntries handles its own retries internally based on its configuration.
	entriesResponse, err := certlib.DownloadEntries(ctx, logInfo, int(item.Start), int(item.End))
	downloadDuration := time.Since(downloadStart)

	if err != nil {
		numEntriesInBlock := item.End - item.Start + 1
		de.stats.FailedEntries.Add(numEntriesInBlock)
		// Do not spam logs if context was cancelled (expected during shutdown).
		if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrDownloadCancelled) {
			log.Printf("Worker failed to download entries for %s (%d-%d) in %v (attempt %d): %v",
				item.LogURL, item.Start, item.End, downloadDuration, item.Attempt+1, err)
		}
		return fmt.Errorf("failed to download entries %d-%d for %s (attempt %d): %w",
			item.Start, item.End, item.LogURL, item.Attempt+1, err)
	}

	// 2. Find the Output Writer for this log.
	writerUntyped, ok := de.outputMap.Load(item.LogURL)
	if !ok {
		// This indicates a programming error: a writer should have been set up for every log URL.
		de.stats.FailedEntries.Add(int64(len(entriesResponse.Entries))) // Count these entries as failed.
		return fmt.Errorf("internal error: output writer not found for log %s", item.LogURL)
	}
	// Type assertion MUST be to a pointer (*lockedWriter).
	lw, ok := writerUntyped.(*lockedWriter)
	if !ok || lw == nil {
		de.stats.FailedEntries.Add(int64(len(entriesResponse.Entries)))
		return fmt.Errorf("internal error: invalid writer type in outputMap for log %s", item.LogURL)
	}

	// 3. Process Entries in the downloaded block.
	processLoopStart := time.Now()
	// Use a strings.Builder from a sync.Pool to efficiently build the batch of CSV lines.
	// This significantly reduces string concatenation overhead and allocations.
	sbInterface := de.stringPool.Get()
	sb := sbInterface.(strings.Builder) // Type assertion.
	sb.Reset()                          // Ensure builder is clean.
	// Pre-allocate a reasonable buffer size for the string builder.
	// Average line length can vary, estimate ~200-500 bytes per CSV line.
	sb.Grow(len(entriesResponse.Entries) * 300) // Adjust estimate as needed.

	var domainsFoundInBlock int64
	var successfullyProcessedInBlock int64
	var parsingFailuresInBlock int64

	for i, entry := range entriesResponse.Entries {
		certIndex := item.Start + int64(i)
		// certlib.ParseCertificateEntry handles decoding and parsing of the certificate.
		certData, parseErr := certlib.ParseCertificateEntry(entry.LeafInput, entry.ExtraData, item.LogURL)
		if parseErr != nil {
			// Log parsing errors but continue processing other entries in the block.
			// Avoid excessive logging for common, less critical parsing issues (e.g., Precert TBS).
			if !strings.Contains(parseErr.Error(), "skipped parsing Precert TBS") {
				log.Printf("[Worker] Error parsing certificate entry %d from %s: %v", certIndex, item.LogURL, parseErr)
			}
			de.stats.FailedEntries.Add(1) // Count this specific entry as failed.
			parsingFailuresInBlock++
			continue // Skip to the next entry.
		}

		// Format the extracted certificate data into a CSV line.
		csvLine := certData.ToDomainsCSVLine(int(certIndex))
		if csvLine != "" { // Ensure a non-empty line is produced.
			sb.WriteString(csvLine)
			domainsFoundInBlock += int64(len(certData.AllDomains))
			successfullyProcessedInBlock++
		} else {
			// This case might indicate an issue with ToDomainsCSVLine or unexpected certData.
			log.Printf("[Worker] Warning: Empty CSV line generated for cert %d from %s (Type: %s, CN: '%s')",
				certIndex, item.LogURL, certData.Type, certData.Subject.CN)
			de.stats.FailedEntries.Add(1) // Consider this a failed entry for stats.
			parsingFailuresInBlock++
		}
	}
	processLoopDuration := time.Since(processLoopStart)

	// Get the complete string of CSV lines for this batch.
	outputBatch := sb.String()
	// Return the strings.Builder to the pool for reuse.
	sb.Reset() // Good practice to reset before putting back.
	de.stringPool.Put(sb)

	// 4. Write Batch to Output Buffer.
	// Lock the writer for the duration of the batch write to ensure atomicity for this block's data.
	writeStart := time.Now()
	lw.mu.Lock()
	bytesWritten, writeErr := lw.writer.WriteString(outputBatch)
	lw.mu.Unlock()
	writeDuration := time.Since(writeStart)

	if writeErr != nil {
		// If writing fails, mark all entries intended for this batch as failed.
		de.stats.FailedEntries.Add(successfullyProcessedInBlock) // Add only those that were successfully parsed but failed to write.
		return fmt.Errorf("error writing domain data to output buffer for %s: %w", item.LogURL, writeErr)
	}

	// 5. Update Statistics (atomically).
	de.stats.ProcessedEntries.Add(successfullyProcessedInBlock)
	de.stats.TotalDomainsFound.Add(domainsFoundInBlock)
	de.stats.OutputBytesWritten.Add(int64(bytesWritten))

	// Track first-attempt success
	if !isRetry {
		de.stats.SuccessFirstTry.Add(1)
	}

	// Optional: More detailed performance logging per block for debugging.
	log.Printf("[Worker] Finished block %s (%d-%d): Entries=%d, ParsedOK=%d, FailedParse=%d, Domains=%d. Times: Total=%v (Down:%v, ProcLoop:%v, Write:%v)",
		item.LogURL, item.Start, item.End,
		len(entriesResponse.Entries), successfullyProcessedInBlock, parsingFailuresInBlock, domainsFoundInBlock,
		time.Since(startTime), downloadDuration, processLoopDuration, writeDuration)

	return nil // Success for this block.
}

// Shutdown gracefully cancels the DomainExtractor's context, signals the scheduler to shut down
// (which waits for active workers to complete their current tasks), and then flushes and closes
// all output file writers.
// This method ensures that all resources are properly released and pending data is persisted.
//
// Operation: Signals for cancellation are non-blocking. Scheduler shutdown can block until workers finish.
// File operations (flush, close, rename) can block briefly on I/O.
// This method is idempotent; calling it multiple times will not cause issues.
func (de *DomainExtractor) Shutdown() {
	// Check if already shutting down or shut down by inspecting the context.
	if de.ctx.Err() != nil {
		return
	}
	log.Println("Shutting down Domain Extractor...")
	de.cancel() // Signal all operations using this DomainExtractor's context to stop.

	if de.scheduler != nil {
		// This will cancel worker contexts and wait for them to finish their current items.
		de.scheduler.Shutdown()
	}

	log.Println("Flushing and closing output writers...")
	var successCount, errorCount int
	// Iterate over all output writers and flush/close them.
	de.outputMap.Range(func(key, value interface{}) bool {
		if value == nil { // Should not happen with proper map usage.
			return true
		}
		lw, ok := value.(*lockedWriter)
		if !ok || lw == nil {
			log.Printf("Warning: Invalid type found in outputMap for key %v during shutdown", key)
			return true
		}

		// Perform close operations under lock for each writer.
		func() {
			lw.mu.Lock()
			defer lw.mu.Unlock()

			var opErrors []string

			// Flush the primary buffered writer.
			if lw.writer != nil {
				if err := lw.writer.Flush(); err != nil {
					msg := fmt.Sprintf("Error flushing writer for %s: %v", key.(string), err)
					log.Println(msg)
					opErrors = append(opErrors, msg)
				}
			}
			// Close the gzip writer if it exists (this also flushes it).
			if lw.gzWriter != nil {
				if err := lw.gzWriter.Close(); err != nil {
					msg := fmt.Sprintf("Error closing gzip writer for %s: %v", key.(string), err)
					log.Println(msg)
					opErrors = append(opErrors, msg)
				}
			}
			// Close the underlying file.
			if lw.file != nil {
				if err := lw.file.Close(); err != nil {
					msg := fmt.Sprintf("Error closing file for %s: %v", key.(string), err)
					log.Println(msg)
					opErrors = append(opErrors, msg)
				}
			}

			// Rename the temporary file to its final name only if all ops were successful and setup was complete.
			if len(opErrors) == 0 && de.setupComplete.Load() && lw.filePath != "" && lw.finalPath != "" {
				if err := os.Rename(lw.filePath, lw.finalPath); err != nil {
					log.Printf("Error renaming temp file %s to %s: %v", lw.filePath, lw.finalPath, err)
					errorCount++
				} else {
					successCount++
				}
			} else if len(opErrors) > 0 {
				errorCount++
				// If there were errors, attempt to remove the temporary file to avoid leaving corrupt data.
				if lw.filePath != "" {
					if removeErr := os.Remove(lw.filePath); removeErr != nil {
						log.Printf("Warning: Failed to remove temporary file %s after errors: %v", lw.filePath, removeErr)
					}
				}
			}
		}()
		return true // Continue iterating over the map.
	})
	log.Printf("Domain Extractor shutdown complete. Finalized %d files with %d errors.", successCount, errorCount)
}

// GetStats returns a pointer to the DomainExtractorStats struct, allowing callers to read current statistics.
// The stats themselves are updated atomically, so direct field access (after Load()) is safe.
func (de *DomainExtractor) GetStats() *DomainExtractorStats { return de.stats }
