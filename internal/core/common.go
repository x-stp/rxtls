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

package core

import (
	"bufio"
	"context"
	"os"
	"sync"
	"time"

	"github.com/x-stp/rxtls/internal/certlib"
)

// Common constants
const (
	// WorkerQueueCapacity is the capacity of a worker's queue
	WorkerQueueCapacity = 1000

	// MaxShardQueueSize is the maximum size of a shard's queue
	MaxShardQueueSize = 1000

	// WorkerMultiplier is the multiplier for the number of workers
	WorkerMultiplier = 2

	// Retry constants
	RetryBaseDelay         = 125 * time.Millisecond
	RetryMaxDelay          = 30 * time.Second
	RetryBackoffMultiplier = 1.5
	RetryJitterFactor      = 0.2
)

// WorkItem represents a unit of work to be processed by the scheduler
type WorkItem struct {
	// Immutable fields
	LogURL    string
	LogInfo   *certlib.CTLogInfo
	Start     int64
	End       int64
	Callback  WorkCallback
	Ctx       context.Context
	CreatedAt time.Time

	// Mutable fields
	Attempt int
	Error   error
}

// WorkCallback is the function signature for work item callbacks
type WorkCallback func(item *WorkItem) error

// lockedWriter is a thread-safe writer with mutex
type lockedWriter struct {
	writer   *bufio.Writer
	gzWriter interface{ Close() error }
	file     *os.File
	mu       sync.Mutex
}
