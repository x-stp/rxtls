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

import (
	"bufio"
	"context"
	"os"
	"sync"
	"time"

	"github.com/x-stp/rxtls/internal/certlib"
)

// Common constants used across the core package.
// These values configure aspects like worker queue capacities, scheduler behavior, and retry policies.
const (
	// WorkerQueueCapacity defines the maximum number of work items that can be buffered in a single worker's queue.
	// A larger capacity can absorb more bursty workloads but consumes more memory.
	WorkerQueueCapacity = 500000

	// MaxShardQueueSize is the maximum size of a shard's queue in the scheduler.
	// This is used when initializing workers and their individual limiter burst sizes.
	// It defines how many items can be enqueued for a specific shard (log URL hash) before backpressure occurs.
	MaxShardQueueSize = 1000

	// WorkerMultiplier determines the number of worker goroutines relative to the number of CPU cores.
	// For example, a multiplier of 2 on an 8-core machine would create 16 workers.
	WorkerMultiplier = 2

	// RetryBaseDelay is the initial delay before the first retry attempt for a failed operation.
	// Subsequent retries use exponential backoff based on this delay.
	RetryBaseDelay = 125 * time.Millisecond
	// RetryMaxDelay is the maximum delay between retry attempts, capping the exponential backoff.
	RetryMaxDelay = 30 * time.Second
	// RetryBackoffMultiplier is the factor by which the retry delay increases after each failed attempt.
	RetryBackoffMultiplier = 1.5
	// RetryJitterFactor introduces randomness to retry delays to prevent thundering herd problems.
	// The actual jitter is calculated as a percentage of the current delay (e.g., 0.2 means +/- 20% jitter).
	RetryJitterFactor = 0.2
)

// WorkItem represents a discrete unit of work to be processed by a worker in the scheduler.
// It encapsulates all necessary information for a task, including the target log, entry range,
// callback function, and retry state.
// WorkItems are typically pooled and reused to reduce allocations.
type WorkItem struct {
	// Immutable fields, set at creation and not changed during the WorkItem's lifecycle.

	// LogURL is the URL of the Certificate Transparency log server for this work item.
	LogURL string
	// LogInfo provides detailed metadata about the CT log, such as its tree size and block size.
	// This is a pointer to a shared certlib.CTLogInfo struct.
	LogInfo *certlib.CTLogInfo
	// Start is the starting index of the certificate entry range for this work item.
	Start int64
	// End is the ending index (inclusive) of the certificate entry range.
	End int64
	// Callback is the function that will be executed by a worker to process this WorkItem.
	// It takes the WorkItem itself as an argument and returns an error if processing fails.
	Callback WorkCallback
	// Ctx is the context associated with this specific work item. It can be used for cancellation
	// that is specific to this item, separate from the broader scheduler or worker context.
	Ctx context.Context
	// CreatedAt records the time when the WorkItem was initially created or retrieved from a pool.
	// Useful for tracking queue latency or item age.
	CreatedAt time.Time

	// Mutable fields, potentially modified during processing or retry attempts.

	// Attempt an_integer_representing_the_number_of_times_this_WorkItem_has_been_attempted.
	// Starts at 0 for the first attempt.
	Attempt int
	// Error stores any error encountered during the execution of the Callback function.
	// It is nil if the callback was successful.
	Error error
}

// WorkCallback defines the signature for functions that can process a WorkItem.
// These functions are executed by the scheduler's worker goroutines.
// The WorkItem itself is passed as an argument, allowing the callback to access
// log information, entry ranges, and its own context.
// An error should be returned if the processing fails, which may trigger retry logic.
type WorkCallback func(item *WorkItem) error

// lockedWriter provides a thread-safe wrapper around a bufio.Writer, typically used for
// writing output to files concurrently from multiple goroutines.
// It embeds a sync.Mutex to protect access to the underlying writer and associated file resources.
//
// Fields for filePath and finalPath are included to support atomic-like file operations
// where data is written to a temporary file and then renamed to its final destination upon
// successful completion, preventing partially written or corrupt files from being visible.
type lockedWriter struct {
	// writer is the buffered writer used for efficient I/O.
	writer *bufio.Writer
	// gzWriter is an optional gzip.Writer, used if output compression is enabled.
	// It implements the io.Closer interface for proper resource release.
	gzWriter interface{ Close() error }
	// file is the underlying os.File being written to.
	file *os.File
	// mu is the mutex protecting concurrent access to the writer, gzWriter, and file.
	mu sync.Mutex
	// filePath is the path to the temporary file being written.
	filePath string
	// finalPath is the intended final path for the file after all writes are complete and successful.
	finalPath string
}
