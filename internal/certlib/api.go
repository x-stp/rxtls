package certlib

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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/x-stp/rxtls/internal/client" // Import shared client package
)

// CTLResponse represents the structure of the JSON log list.
// Used for unmarshalling JSON (allocates).
type CTLResponse struct {
	Operators []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"operators"`
	Logs []struct {
		Description string `json:"description"`
		Key         string `json:"key"`
		URL         string `json:"url"`
		MMD         int    `json:"mmd"`
		State       struct {
			Timestamp string `json:"timestamp"`
		} `json:"state"`
		OperatedBy     []int  `json:"operated_by"`
		DNSAPIEndpoint string `json:"dns_api_endpoint,omitempty"`
	} `json:"logs"`
}

// TreeSizeResponse represents the JSON structure from the get-sth endpoint.
// Used for unmarshalling JSON (allocates).
type TreeSizeResponse struct {
	TreeSize          int    `json:"tree_size"`
	Timestamp         int64  `json:"timestamp"`
	SHA256RootHash    string `json:"sha256_root_hash"`
	TreeHeadSignature string `json:"tree_head_signature"`
}

// EntriesResponse represents the JSON structure from the get-entries endpoint.
// Used for unmarshalling JSON (allocates).
type EntriesResponse struct {
	Entries []struct {
		LeafInput string `json:"leaf_input"` // Base64 encoded MerkleTreeLeaf
		ExtraData string `json:"extra_data"` // Base64 encoded cert chain
	} `json:"entries"`
}

// GetCTLogs retrieves the list of known CT logs, either from a remote URL or a local file.
// Operation: Network or Disk I/O bound. Allocates during HTTP fetch and JSON parsing.
func GetCTLogs() ([]CTLogInfo, error) {
	if UseLocalLogs {
		log.Printf("Using local logs list from %s\n", LocalLogsFile)
		ctlogs, err := loadLocalCTLogs(LocalLogsFile)
		// If local file load fails, DO NOT fall back to network.
		if err != nil {
			return nil, fmt.Errorf("failed to load local logs file '%s': %w", LocalLogsFile, err)
		}
		return ctlogs, nil
	}

	// Network fetch
	log.Println("Fetching CT log list from", CTLListsURL)
	client := &http.Client{
		Timeout: time.Duration(HTTPTimeout) * time.Second,
	}
	resp, err := client.Get(CTLListsURL)
	if err != nil {
		return nil, fmt.Errorf("error retrieving CT logs list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d fetching log list", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading CT log list body: %w", err)
	}

	var ctlResponse CTLResponse
	if err := json.Unmarshal(body, &ctlResponse); err != nil {
		return nil, fmt.Errorf("error parsing CT logs list JSON: %w", err)
	}

	// Process response (uses old format)
	return processOldFormat(&ctlResponse)
}

// loadLocalCTLogs reads and parses the log list from a local JSON file.
// Operation: Disk I/O bound, allocates for file read and JSON parsing.
func loadLocalCTLogs(filename string) ([]CTLogInfo, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("error reading local logs file: %w", err)
	}
	// Attempt V3 format parse first
	var v3Response struct {
		Operators []struct {
			Name string `json:"name"`
			Logs []struct {
				Description string                 `json:"description"`
				URL         string                 `json:"url"`
				State       map[string]interface{} `json:"state"`
			} `json:"logs"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(data, &v3Response); err == nil {
		// Process V3 format
		var ctlogs []CTLogInfo
		for _, operator := range v3Response.Operators {
			for _, logEntry := range operator.Logs {
				if logEntry.URL == "" {
					continue
				}
				url := cleanLogURL(logEntry.URL)
				if isLogUsable(logEntry.State) {
					ctlogs = append(ctlogs, CTLogInfo{
						URL:         url,
						Description: logEntry.Description,
						OperatedBy:  operator.Name,
						BlockSize:   64, // Default
					})
				}
			}
		}
		log.Printf("Found %d usable CT logs in local file (V3 format)", len(ctlogs))
		return ctlogs, nil
	}
	// Fallback to V2/older format
	log.Printf("Failed to parse local logs as V3, trying older format: %v", err)
	var ctlResponse CTLResponse
	if errFallback := json.Unmarshal(data, &ctlResponse); errFallback != nil {
		return nil, fmt.Errorf("error parsing local logs file with known formats: %w (primary V3 err) / %w (fallback V2 err)", err, errFallback)
	}
	return processOldFormat(&ctlResponse)
}

// cleanLogURL helper
func cleanLogURL(rawURL string) string {
	url := rawURL
	if strings.HasPrefix(url, "https://") {
		url = url[8:]
	} else if strings.HasPrefix(url, "http://") {
		url = url[7:]
	}
	if strings.HasSuffix(url, "/") {
		url = url[:len(url)-1]
	}
	return url
}

// isLogUsable helper
func isLogUsable(state map[string]interface{}) bool {
	if _, ok := state["rejected"]; ok {
		return false
	}
	if _, ok := state["retired"]; ok {
		return false
	}
	logType, _ := state["log_type"].(string)
	return logType != "test"
}

// processOldFormat handles the fallback parsing scenario.
// Operation: Similar allocation patterns to the main processing loop (slice append, string ops).
func processOldFormat(ctlResponse *CTLResponse) ([]CTLogInfo, error) {
	operatorNames := make(map[int]string)
	for _, operator := range ctlResponse.Operators {
		operatorNames[operator.ID] = operator.Name
	}
	var ctlogs []CTLogInfo
	for _, logEntry := range ctlResponse.Logs {
		if logEntry.URL == "" {
			continue
		}
		url := cleanLogURL(logEntry.URL)
		operatedBy := ""
		if len(logEntry.OperatedBy) > 0 {
			operatedBy = operatorNames[logEntry.OperatedBy[0]]
		}
		ctlog := CTLogInfo{
			URL:         url,
			Description: logEntry.Description,
			OperatedBy:  operatedBy,
			BlockSize:   64,
		}
		if ctlog.IsResolvable() { // Simple parse check
			ctlogs = append(ctlogs, ctlog)
		}
	}
	log.Printf("Found %d usable CT logs in local file (Fallback format)", len(ctlogs))
	return ctlogs, nil
}

// GetLogInfo fetches the Signed Tree Head (STH) for a specific log to get its size.
// Operation: Network I/O bound. Allocates for HTTP client, request, response, JSON parsing.
func GetLogInfo(ctlog *CTLogInfo) error {
	client := client.GetSharedClient() // Get shared client
	// Clone transport for per-log TLS config
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = ctlog.GetTLSConfig()
	tempClient := &http.Client{Transport: transport, Timeout: client.Timeout}

	url := fmt.Sprintf(CTLInfoURLTemplate, ctlog.URL)
	resp, err := tempClient.Get(url) // Use temp client
	if err != nil {
		return fmt.Errorf("error retrieving STH for %s: %w", ctlog.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("HTTP error %d fetching STH for %s. Body: %s", resp.StatusCode, ctlog.URL, string(bodyBytes))
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error reading STH response body for %s: %w", ctlog.URL, err)
	}
	var treeSize TreeSizeResponse
	if err := json.Unmarshal(body, &treeSize); err != nil {
		bodySnippet := string(body)
		if len(bodySnippet) > 100 {
			bodySnippet = bodySnippet[:100] + "..."
		}
		return fmt.Errorf("error parsing STH JSON for %s: %w. Body prefix: %s", ctlog.URL, err, bodySnippet)
	}
	ctlog.TreeSize = treeSize.TreeSize
	if ctlog.IsDigiCert() {
		ctlog.BlockSize = 32
	} else {
		ctlog.BlockSize = 64
	}
	return nil
}

// DownloadEntries fetches a block of entries from a specific CT log.
// It now accepts a parent context to enable cancellation.
func DownloadEntries(ctx context.Context, ctlog *CTLogInfo, start, end int) (*EntriesResponse, error) {
	client := client.GetSharedClient() // Get shared client
	// Clone transport for per-log TLS config
	transport := client.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = ctlog.GetTLSConfig()
	tempClient := &http.Client{Transport: transport, Timeout: client.Timeout}

	url := fmt.Sprintf(DownloadURLTemplate, ctlog.URL, start, end)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request for %s (%d-%d): %w", ctlog.URL, start, end, err)
	}

	resp, err := tempClient.Do(req) // Use temp client
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err // Return context error directly
		}
		return nil, fmt.Errorf("error downloading entries %s (%d-%d): %w", ctlog.URL, start, end, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d GET %s (%d-%d)", resp.StatusCode, ctlog.URL, start, end)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading entries response body for %s (%d-%d): %w", ctlog.URL, start, end, err)
	}
	var entries EntriesResponse
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("error parsing entries JSON for %s (%d-%d): %w", ctlog.URL, start, end, err)
	}
	return &entries, nil
}

// ParseCertificateEntry decodes the MerkleTreeLeaf framing and parses the inner certificate data.
// Handles Version 0, LeafType 0 (TimestampedEntry) containing X.509 or Precert.
func ParseCertificateEntry(leafInput, extraData, logURL string) (*CertificateData, error) {
	leafBytes, err := base64.StdEncoding.DecodeString(leafInput)
	if err != nil {
		return nil, fmt.Errorf("failed to decode leaf input base64: %w", err)
	}

	// --- Check CT Framing Prefix ---
	if len(leafBytes) < 2 {
		return nil, fmt.Errorf("leaf input too short for CT framing (len %d)", len(leafBytes))
	}
	version := uint8(leafBytes[0])
	leafType := uint8(leafBytes[1])
	if version != 0 {
		return nil, fmt.Errorf("unsupported MerkleTreeLeaf version: %d", version)
	}
	if leafType != 0 {
		return nil, fmt.Errorf("unsupported MerkleLeafType: %d", leafType)
	}
	// --------------------------------

	// --- Manually Parse TimestampedEntry ---
	r := bytes.NewReader(leafBytes[2:]) // Reader for the payload after framing

	var timestamp uint64
	if err := binary.Read(r, binary.BigEndian, &timestamp); err != nil {
		return nil, fmt.Errorf("failed to read timestamp: %w", err)
	}

	var entryTypeUint16 uint16
	if err := binary.Read(r, binary.BigEndian, &entryTypeUint16); err != nil {
		return nil, fmt.Errorf("failed to read entry type: %w", err)
	}
	entryTypeString := "Unknown"

	var certDER []byte

	switch entryTypeUint16 {
	case 0: // x509_entry
		entryTypeString = "X509LogEntry"
		// Read the 3-byte length field for the certificate
		var certLenBytes [3]byte
		if _, err := io.ReadFull(r, certLenBytes[:]); err != nil {
			return nil, fmt.Errorf("failed to read x509 entry length: %w", err)
		}
		certLen := uint32(certLenBytes[0])<<16 | uint32(certLenBytes[1])<<8 | uint32(certLenBytes[2])

		// Check for unreasonable length
		if certLen > uint32(r.Len()) {
			return nil, fmt.Errorf("x509 entry length (%d) exceeds remaining data (%d)", certLen, r.Len())
		}

		// Read the certificate bytes
		certDER = make([]byte, certLen)
		if _, err := io.ReadFull(r, certDER); err != nil {
			return nil, fmt.Errorf("failed to read x509 entry data: %w", err)
		}

	case 1: // precert_entry
		entryTypeString = "PrecertLogEntry"
		// Read Issuer Key Hash (32 bytes) - we don't use it currently, but need to consume it.
		var issuerKeyHash [32]byte
		if _, err := io.ReadFull(r, issuerKeyHash[:]); err != nil {
			return nil, fmt.Errorf("failed to read precert issuer key hash: %w", err)
		}

		// Read the 3-byte length field for the TBS certificate
		var tbsCertLenBytes [3]byte
		if _, err := io.ReadFull(r, tbsCertLenBytes[:]); err != nil {
			return nil, fmt.Errorf("failed to read precert TBS length: %w", err)
		}
		tbsCertLen := uint32(tbsCertLenBytes[0])<<16 | uint32(tbsCertLenBytes[1])<<8 | uint32(tbsCertLenBytes[2])

		// Check length
		if tbsCertLen > uint32(r.Len()) {
			return nil, fmt.Errorf("precert TBS length (%d) exceeds remaining data (%d)", tbsCertLen, r.Len())
		}

		// Read the TBS certificate bytes
		certDER = make([]byte, tbsCertLen)
		if _, err := io.ReadFull(r, certDER); err != nil {
			return nil, fmt.Errorf("failed to read precert TBS data: %w", err)
		}

	default:
		return nil, fmt.Errorf("unknown TimestampedEntry.EntryType: %d", entryTypeUint16)
	}

	// Extensions follow the signed_entry; read their length (2 bytes) and consume them.
	// We don't parse extensions in this version, but must read past them.
	var extensionsLen uint16
	if err := binary.Read(r, binary.BigEndian, &extensionsLen); err != nil {
		// Allow EOF here if extensions are truly absent, although spec implies length should be present.
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			log.Printf("Warning: Failed to read extensions length for %s (%d-%d): %v. Remaining bytes: %d", logURL, 0, 0, err, r.Len()) // Need index context here if possible
		}
	} else if extensionsLen > 0 {
		if extensionsLen > uint16(r.Len()) {
			return nil, fmt.Errorf("extensions length (%d) exceeds remaining data (%d)", extensionsLen, r.Len())
		}
		// Consume extension bytes
		extensionBytes := make([]byte, extensionsLen)
		if _, err := io.ReadFull(r, extensionBytes); err != nil {
			return nil, fmt.Errorf("failed to read extensions data: %w", err)
		}
	}
	// --------------------------------------

	if len(certDER) == 0 {
		return nil, fmt.Errorf("no certificate DER data extracted for entry type %d", entryTypeUint16)
	}

	// --- Parse the final DER bytes ---
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		if entryTypeString == "PrecertLogEntry" {
			// Known failure mode for TBS certs
			return nil, fmt.Errorf("skipped parsing Precert TBS: %w", err)
		}
		return nil, fmt.Errorf("failed to parse certificate DER (type %s): %w", entryTypeString, err)
	}

	// Convert to our internal struct
	cd := CertificateFromX509(cert, logURL)
	cd.Type = entryTypeString // Set the correct type
	return cd, nil
}
