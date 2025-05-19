/*
Package core provides the central logic for rxtls, including the scheduler, download manager,
and domain extractor. It defines common data structures and constants used across these components.
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
	"fmt"

	"github.com/x-stp/rxtls/internal/certlib"
)

// ListCTLogs retrieves the list of available Certificate Transparency (CT) logs.
// It serves as a simple wrapper around `certlib.GetCTLogs`, which encapsulates the logic
// for fetching the log list either from a remote source (e.g., Google's JSON list) or
// from a local file cache, depending on the `certlib.UseLocalLogs` global setting.
//
// This function is primarily used by command-line interface (CLI) commands that need to
// display available logs or allow users to select logs for processing.
//
// Performance Note: This function itself does not perform detailed STH (Signed Tree Head)
// fetching for each log to determine its size or state, as that would be too slow for
// a simple listing operation. The `certlib.GetCTLogs` function focuses on retrieving the
// basic log metadata (URL, description, operator).
//
// Returns:
//   - A slice of `certlib.CTLogInfo` structs, each representing a known CT log.
//   - An error if retrieving or parsing the log list fails.
func ListCTLogs() ([]certlib.CTLogInfo, error) {
	ctlogs, err := certlib.GetCTLogs()
	if err != nil {
		// Wrap the error from certlib to provide more context.
		return nil, fmt.Errorf("error retrieving CT logs list: %w", err)
	}
	return ctlogs, nil
}
