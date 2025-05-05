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

// Constants tuned for maximum throughput on modern Linux.
// These values dictate concurrency, memory usage, and network behaviour.
// They should be revisited based on profiling and target hardware.
const (
	// --- Concurrency ---

	// WorkerMultiplier determines goroutine count relative to CPU cores.
	// Goal: Keep CPUs saturated without excessive context switching.
	// Value `4` assumes some I/O wait allows more goroutines than cores.
	// Constraint: Must be >= 1.
	WorkerMultiplier = 4

	// MaxShardQueueSize limits buffered work per worker queue.
	// Goal: Provide backpressure to prevent OOM if producers are faster than consumers.
	// Constraint: Affects memory usage (numWorkers * MaxShardQueueSize * sizeof(WorkItem)).
	MaxShardQueueSize = 1024

	// --- Memory ---

	// CacheLineSize is used for struct padding to prevent false sharing between cores.
	// Goal: Improve atomic/concurrent access performance.
	// Constraint: Assumed value, might need arch-specific detection via `unsafe` if critical.
	CacheLineSize = 64

	// DefaultNetworkBufferSize sets the size for pooled network read buffers.
	// Goal: Reduce allocs during network reads, fit typical CT entry batches.
	// Constraint: Affects memory pool size.
	DefaultNetworkBufferSize = 128 * 1024 // 128KB

	// DefaultDiskBufferSize sets the size for `bufio.Writer` instances.
	// Goal: Reduce syscalls (write) by batching disk I/O.
	// Constraint: Affects memory usage per active output file.
	DefaultDiskBufferSize = 256 * 1024 // 256KB

	// CertProcessingBatchSize dictates how many certs are processed logically together.
	// Goal: Amortize costs like locking or flushing.
	// Constraint: Larger batches increase latency for individual cert results.
	CertProcessingBatchSize = 1024

	// --- Networking ---

	// MaxConcurrentDownloadsPerHost limits simultaneous connections *per target CT log host*.
	// Goal: Avoid overwhelming single log servers, respect implicit rate limits.
	// Constraint: Overall concurrency also limited by global scheduler workers.
	// TODO: This needs actual implementation, likely via a per-host semaphore map.
	// MaxConcurrentDownloadsPerHost = 128

	// MaxNetworkRetries defines how many times to retry a failed network op (STH/entries).
	// Goal: Handle transient network errors gracefully.
	// Constraint: Increases latency on failure.
	MaxNetworkRetries = 2

	// BaseRetryDelay is the initial wait time before the first retry.
	// Goal: Avoid immediate hammering on failure. Used with exponential backoff.
	// Constraint: Affects minimum failure recovery time.
	BaseRetryDelay = 250 * time.Millisecond

	// DialTimeout limits time spent establishing a TCP connection.
	// Goal: Fail fast on unresponsive hosts.
	// Constraint: Needs tuning based on expected network conditions.
	DialTimeout = 5 * time.Second

	// RequestTimeout limits the *total* time for an HTTP request (connect, send, receive headers/body).
	// Goal: Prevent goroutines from hanging indefinitely on slow servers.
	// Constraint: Must be longer than DialTimeout + expected processing time.
	RequestTimeout = 15 * time.Second

	// KeepAliveTimeout determines how long idle connections are kept open in the pool.
	// Goal: Reuse TCP connections to reduce handshake latency.
	// Constraint: Higher values consume resources for longer.
	KeepAliveTimeout = 60 * time.Second

	// --- Disk I/O ---

	// DiskFlushBatchSize dictates how many *processed* entries trigger a buffer flush.
	// Goal: Balance latency (seeing results on disk) vs. I/O efficiency.
	// Constraint: Tied to CertProcessingBatchSize for simplicity here.
	DiskFlushBatchSize = CertProcessingBatchSize

	// --- CT Log Specific ---

	// DefaultLogEntryBlockSize is used if a CT log doesn't provide its preferred block size.
	// Goal: Sensible default for fetching entries.
	// Constraint: Performance might vary depending on the log server.
	DefaultLogEntryBlockSize = 64
)

// TODO (Self-Correction): Remove this file later if constants become highly localized
// or are better derived dynamically (e.g., CacheLineSize via unsafe).
// For now, centralizing helps overview during rewrite.
