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

// SanitizeFilename creates a filesystem-safe filename from a URL or other string.
// Replaces common problematic characters with underscores and limits length.
// Performance is not critical for this setup utility.
func SanitizeFilename(input string) string {
	// Replace problematic characters with underscore.
	replaced := strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':', '*', '?', '"', '<', '>', '|':
			return '_'
		}
		return r
	}, input)
	// Limit filename length to avoid OS issues.
	maxLength := 100 // Arbitrary limit
	if len(replaced) > maxLength {
		return replaced[:maxLength]
	}
	return replaced
}
