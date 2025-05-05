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
	"os"
	"sync"
)

// lockedWriter wraps a bufio.Writer and its underlying closers with a Mutex.
// This is used to allow concurrent writes from different goroutines to the
// same underlying file buffer, ensuring atomicity at the batch level.
type lockedWriter struct {
	mu       sync.Mutex
	writer   *bufio.Writer
	gzWriter *gzip.Writer // Keep track if gzip is used
	file     *os.File     // Keep track of the file handle
}

// Stats interfaces removed for simplicity.
