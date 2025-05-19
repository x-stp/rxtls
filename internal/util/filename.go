/*
Package util provides miscellaneous utility functions used across the rxtls application.
These functions are typically small, self-contained, and offer common helper functionalities
that don't belong to a more specific package like `core` or `client`.
*/
package util

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

import "strings"

// SanitizeFilename takes an input string (typically a URL or a descriptive name)
// and transforms it into a string that is generally safe to use as a filename
// on common operating systems.
//
// The sanitization process involves:
//  1. Replacing characters that are problematic in filenames (e.g., '/', '\', ':', '*', '?', '"', '<', '>', '|')
//     with underscores ('_').
//  2. Limiting the total length of the filename to a predefined maximum (currently 100 characters)
//     to prevent issues with OS filename length limits.
//
// This function is primarily used when generating output filenames based on CT log URLs
// to ensure that the resulting names are valid and do not cause filesystem errors.
//
// Performance: For its intended use (generating a few filenames at the start of processing a log),
// the performance of this function is not critical. It uses standard string manipulation functions.
//
// Parameters:
//   input: The string to be sanitized into a filename-safe format.
//
// Returns:
//   A sanitized string suitable for use as a filename.
func SanitizeFilename(input string) string {
	// Replace common problematic characters with an underscore.
	// This set can be expanded if other problematic characters are identified.
	replaced := strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|': // Common invalid filename chars on Windows/Unix.
			return '_'
		}
		return r // Keep other characters as they are.
	}, input)

	// Limit filename length to avoid issues with operating system limits.
	// A maxLength of 100 is a conservative choice, well within typical FS limits (e.g., 255 bytes).
	const maxLength = 100
	if len(replaced) > maxLength {
		// Truncate the string if it exceeds the maximum length.
		// Note: This is a simple truncation. For multi-byte character sets (UTF-8),
		// this could potentially cut a character in half if not careful. However, for URLs
		// and typical log names, this is often acceptable. More robust truncation would
		// require rune-aware iteration.
		return replaced[:maxLength]
	}
	return replaced
}
