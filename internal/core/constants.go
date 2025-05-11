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

// Constants for memory, networking, etc. that aren't defined in common.go
const (
	// --- Memory ---

	// MaxWorkers is the maximum number of workers
	MaxWorkers = 1024

	// DefaultShards is the default number of shards
	DefaultShards = 16

	// CacheLineSize is used for struct padding to prevent false sharing between cores.
	CacheLineSize = 64

	// DefaultNetworkBufferSize sets the size for pooled network read buffers.
	DefaultNetworkBufferSize = 128 * 1024 // 128KB

	// DefaultDiskBufferSize sets the size for `bufio.Writer` instances.
	DefaultDiskBufferSize = 256 * 1024 // 256KB

	// CertProcessingBatchSize dictates how many certs are processed logically together.
	CertProcessingBatchSize = 1024

	// --- Networking ---

	// MaxNetworkRetries defines how many times to retry a failed network op (STH/entries).
	MaxNetworkRetries = 3

	// MaxSubmitRetries defines how many times to retry submitting work to a worker queue.
	MaxSubmitRetries = 2

	// DialTimeout limits time spent establishing a TCP connection.
	DialTimeout = 10 * time.Second

	// RequestTimeout limits the *total* time for an HTTP request (connect, send, receive headers/body).
	RequestTimeout = 15 * time.Second

	// KeepAliveTimeout determines how long idle connections are kept open in the pool.
	KeepAliveTimeout = 60 * time.Second

	// ReadTimeout limits time spent waiting for bytes after connection success.
	ReadTimeout = 45 * time.Second

	// IdleConnTimeout is the max time conns stay idle in pool before closing.
	IdleConnTimeout = 60 * time.Second

	// ResponseHeaderTimeout limits time waiting for response headers.
	ResponseHeaderTimeout = 15 * time.Second

	// MaxIdleConnsPerHost limits idle connections kept for a single host.
	MaxIdleConnsPerHost = 25

	// DefaultRequestTimeout is the default timeout for HTTP requests.
	DefaultRequestTimeout = 60 * time.Second

	// --- CT Log Specific ---

	// DefaultLogEntryBlockSize is used if a CT log doesn't provide its preferred block size.
	DefaultLogEntryBlockSize = 64

	// DefaultBatchSize is the default batch size for GET entries.
	DefaultBatchSize = 1000

	// DefaultMaxParallelBatches controls how many batches we process concurrently.
	DefaultMaxParallelBatches = 50

	// MaxConcurrentDownloadsPerHost limits concurrent outbound connections to a log server.
	MaxConcurrentDownloadsPerHost = 50

	// MaxRetries defines the maximum number of retries for failed network operations.
	MaxRetries = 5

	// --- Disk I/O ---

	// DiskFlushBatchSize dictates how many *processed* entries trigger a buffer flush.
	DiskFlushBatchSize = CertProcessingBatchSize

	// --- Observability ---

	// RequestHistorySize is the number of recent requests to keep for observability.
	RequestHistorySize = 1000

	// LogHistorySize is the number of log messages to keep in memory.
	LogHistorySize = 5000

	// StatsReportInterval is how often to report stats to stdout/log.
	StatsReportInterval = 5 * time.Second

	// MinimumProgressLoggingInterval is the minimum interval for progress updates.
	MinimumProgressLoggingInterval = 1 * time.Second
)
