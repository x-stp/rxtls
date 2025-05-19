/*
Package core constants that are not specific to a single manager/component but are shared across the core logic.
This file centralizes various configurable parameters related to memory management, networking behavior,
CT log interaction defaults, disk I/O, and observability.

These constants are intended to provide sensible defaults and can be tuned for different performance profiles
or operational environments. They are distinct from the very fundamental constants defined in common.go
(like worker multipliers or base retry delays) and focus more on higher-level application behavior settings.
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
	"time"
)

// Application-wide constants for tuning performance and behavior.
const (
	// --- Memory ---

	// MaxWorkers defines the absolute upper limit on the number of concurrent worker goroutines
	// that the scheduler will create. This acts as a safeguard regardless of CPU core count or multipliers.
	MaxWorkers = 2048

	// DefaultShards specifies the default number of shards used by the scheduler for distributing
	// work based on log URL hashing. This helps in balancing load across workers.
	// This value is not directly used by the current scheduler implementation, which shards by numWorkers.
	DefaultShards = 32 // TODO: Re-evaluate or remove if scheduler sharding remains worker-based.

	// CacheLineSize is a common CPU cache line size in bytes. It's used as a guideline for padding
	// in data structures to help prevent false sharing when multiple CPU cores access adjacent memory locations.
	CacheLineSize = 64

	// DefaultNetworkBufferSize is the default size for buffers used in network read operations.
	// Larger buffers can reduce the number of read syscalls but increase memory footprint.
	DefaultNetworkBufferSize = 256 * 1024 // 256KB

	// DefaultDiskBufferSize is the default size for `bufio.Writer` instances used for disk I/O.
	// Similar to network buffers, this trades memory for potentially fewer write syscalls.
	DefaultDiskBufferSize = 256 * 1024 // 256KB

	// CertProcessingBatchSize dictates how many certificates are grouped together for logical processing steps,
	// such as batching writes to disk or updating progress metrics.
	CertProcessingBatchSize = 1024 * 10

	// --- Networking ---

	// MaxNetworkRetries specifies the maximum number of times a failed network operation
	// (like fetching STH or log entries) will be retried by components in `certlib`.
	MaxNetworkRetries = 6

	// MaxSubmitRetries is the maximum number of times a component (like DownloadManager or DomainExtractor)
	// will attempt to submit a work item to a worker's queue if it's initially full (ErrQueueFull).
	// This is for retrying the *submission* to the queue, not the work item execution itself.
	MaxSubmitRetries = 2 // Reduced from 5 as queue full should be handled by rate limiting ideally.

	// DialTimeout limits the time spent establishing a new TCP connection to a remote server.
	DialTimeout = 10 * time.Second

	// RequestTimeout sets the maximum duration for an entire HTTP request, encompassing
	// connection establishment, sending the request, and receiving the full response body.
	// This is typically applied at the http.Client level.
	RequestTimeout = 15 * time.Second

	// KeepAliveTimeout defines the keep-alive period for an active network connection.
	// This is used by the net.Dialer to configure TCP keep-alives.
	KeepAliveTimeout = 60 * time.Second

	// ReadTimeout is the maximum duration for reading the next chunk of data from a connection
	// after a successful connection and request send. Not directly used by client, but a common HTTP server setting.
	ReadTimeout = 15 * time.Second // Typically a server-side setting or per-request on client.

	// IdleConnTimeout is the maximum amount of time an idle (keep-alive) connection will remain
	// in the HTTP client's connection pool before being closed.
	IdleConnTimeout = 120 * time.Second

	// ResponseHeaderTimeout limits the time spent waiting to receive the complete response headers
	// from the server after the request has been sent.
	ResponseHeaderTimeout = 15 * time.Second

	// MaxIdleConnsPerHost controls the maximum number of idle connections that will be maintained
	// in the pool for any single host. This helps prevent resource exhaustion when interacting
	// with many different hosts.
	MaxIdleConnsPerHost = 55

	// DefaultRequestTimeout is a general default timeout for HTTP requests, potentially used
	// by components that don't have a more specific timeout configured.
	// It's similar to RequestTimeout but might be used as a fallback.
	DefaultRequestTimeout = 30 * time.Second

	// --- CT Log Specific ---

	// DefaultLogEntryBlockSize is the number of entries to request in a single `get-entries`
	// call if the CT log does not specify its own preferred block size (max_entries_per_get).
	DefaultLogEntryBlockSize = 64

	// DefaultBatchSize defines a common batch size for fetching entries from CT logs.
	// This is often a multiple of the log's block size.
	DefaultBatchSize = 1024 * 4

	// DefaultMaxParallelBatches sets a soft limit on how many batches of log entries
	// might be processed in parallel by the application. This can help manage memory and CPU load.
	DefaultMaxParallelBatches = 50 // This constant appears to be for higher-level batching strategy.

	// MaxConcurrentDownloadsPerHost limits how many concurrent `get-entries` requests rxtls
	// will make to a single CT log server host. This is crucial for being a good network citizen.
	// This would typically be enforced by the HTTP client's MaxConnsPerHost or similar, or custom logic.
	MaxConcurrentDownloadsPerHost = 50

	// MaxRetries defines the maximum number of retries for failed network operations.
	// This is similar to MaxNetworkRetries but might be used by different components with different retry policies.
	MaxRetries = 5

	// --- Disk I/O ---

	// DiskFlushBatchSize indicates how many *processed* certificate entries should trigger
	// a flush of the output file buffer to disk. This helps ensure data is persisted regularly.
	DiskFlushBatchSize = CertProcessingBatchSize

	// --- Observability ---

	// RequestHistorySize is the number of recent network request details to retain in memory
	// for observability or debugging purposes (e.g., for a live dashboard or error analysis).
	RequestHistorySize = 1000 // Currently not implemented, but a common pattern.

	// LogHistorySize determines the number of recent log messages to keep in an in-memory buffer
	// for potential display or inspection, especially in UIs or diagnostic tools.
	LogHistorySize = 5000 // Currently not implemented.

	// StatsReportInterval specifies how frequently summary statistics (e.g., download progress,
	// processing rates) should be reported, typically to standard output or a log file.
	StatsReportInterval = 10 * time.Second

	// MinimumProgressLoggingInterval defines the minimum time that must elapse between
	// progress log updates to avoid flooding logs with too frequent updates.
	MinimumProgressLoggingInterval = 5 * time.Second
)
