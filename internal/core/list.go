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
	// Use standard log for now
	"github.com/x-stp/rxtls/internal/certlib"
)

// ListCTLogs retrieves the list of available CT logs.
// It relies on certlib.GetCTLogs which handles network/local file logic.
// It intentionally does NOT fetch detailed STH info for speed.
func ListCTLogs() ([]certlib.CTLogInfo, error) {
	ctlogs, err := certlib.GetCTLogs()
	if err != nil {
		return nil, fmt.Errorf("error retrieving CT logs list: %w", err)
	}
	return ctlogs, nil
}
