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
	"strings"
	"testing"
)

// TestNormalizeDomain provides table-driven tests for various domain formats and edge cases.
// Goal: Ensure NormalizeDomain behaves correctly for diverse inputs.
// Uses t.Parallel() to allow tests within this function to run concurrently.
func TestNormalizeDomain(t *testing.T) {
	t.Parallel() // Mark this test function as safe to run in parallel with others.
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{"Simple domain", "example.com", "example.com"},
		{"Subdomain", "www.example.com", "www.example.com"},
		{"Uppercase", "EXAMPLE.COM", "example.com"},
		{"Mixed case", "Www.Example.Com", "www.example.com"},
		{"Trailing dot", "example.com.", "example.com"},
		{"Multiple trailing dots", "example.com...", "example.com"},
		{"Leading dot", ".example.com", "example.com"},
		{"Leading/Trailing dots", ".example.com.", "example.com"},
		{"Leading/Trailing spaces", "  example.com  ", "example.com"},
		{"Wildcard", "*.example.com", "*.example.com"},
		{"Wildcard uppercase", "*.EXAMPLE.COM", "*.example.com"},
		{"Wildcard trailing dot", "*.example.com.", "*.example.com"},
		{"Multiple wildcards", "*.*.example.com", "*.*.example.com"},           // Assuming this is valid/desired
		{"Punycode", "xn--bcher-kva.example.com", "xn--bcher-kva.example.com"}, // bücher.example.com
		{"Punycode uppercase", "XN--BCHER-KVA.EXAMPLE.COM", "xn--bcher-kva.example.com"},
		{"Empty string", "", ""},
		{"Just spaces", "   ", ""},
		{"Just dots", "...", ""},
		{"IP Address v4", "192.168.1.1", "192.168.1.1"},                                            // Should probably remain unchanged or be identified
		{"IP Address v6", "::1", "::1"},                                                            // Should probably remain unchanged or be identified
		{"Domain with port", "example.com:443", "example.com:443"},                                 // Should likely remain unchanged
		{"Internal spaces", "example test.com", "example test.com"},                                // Junk, expect no change or specific handling
		{"Leading dash", "-example.com", "-example.com"},                                           // Technically invalid label, expect no change
		{"Trailing dash", "example-.com", "example-.com"},                                          // Technically invalid label, expect no change
		{"Very long domain", strings.Repeat("a.", 100) + "com", strings.Repeat("a.", 100) + "com"}, // Keep as is
	}

	for _, tc := range testCases {
		// Capture range variable for parallel execution.
		tc := tc
		// Run each test case as a parallel subtest.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			actual := NormalizeDomain(tc.input)
			if actual != tc.expected {
				t.Errorf("NormalizeDomain(%q) = %q; want %q", tc.input, actual, tc.expected)
			}
		})
	}
}

// BenchmarkNormalizeDomainSimple measures performance for a common, simple domain.
// Goal: Establish baseline performance.
// Operation: Runs NormalizeDomain repeatedly in a loop.
func BenchmarkNormalizeDomainSimple(b *testing.B) {
	domain := "www.example.com"
	// b.N is adjusted by the testing framework to achieve stable measurements.
	for i := 0; i < b.N; i++ {
		_ = NormalizeDomain(domain) // Assign to blank identifier to prevent optimization removal.
	}
}

// BenchmarkNormalizeDomainMixedCaseTrailingDot measures performance for domains needing case and dot normalization.
func BenchmarkNormalizeDomainMixedCaseTrailingDot(b *testing.B) {
	domain := "Www.Example.COM."
	for i := 0; i < b.N; i++ {
		_ = NormalizeDomain(domain)
	}
}

// BenchmarkNormalizeDomainWildcard measures performance for wildcard domains needing normalization.
func BenchmarkNormalizeDomainWildcard(b *testing.B) {
	domain := "*.SubDomain.Example.COM."
	for i := 0; i < b.N; i++ {
		_ = NormalizeDomain(domain)
	}
}

// BenchmarkSortedNormalizedDomains (Placeholder)
// Goal: Measure performance of getting unique, sorted, normalized domains from a CertificateData struct.
// Constraints: Would depend heavily on the number of domains in AllDomains and the sorting algorithm.
// TODO: Implement this benchmark once the corresponding function (e.g., CertificateData.SortedNormalizedDomains) is optimized (uses sort.Strings).
/*
func BenchmarkSortedNormalizedDomains(b *testing.B) {
	// Setup: Create a CertificateData with a large, diverse list of domains.
	size := 1000 // Example size
	allDomains := make([]string, size)
	for i := 0; i < size; i++ {
		// Generate realistic domain variations (mixed case, dots, wildcards, duplicates)
		allDomains[i] = fmt.Sprintf("sub%d.EXAMPLE%d.com.", i%10, i%50)
	}
	certData := &certlib.CertificateData{
		AllDomains: allDomains,
		Subject:    certlib.SubjectData{O: "Test Org"}, // Needed for DomainOrgHash if testing that
	}

b.ResetTimer() // Start timing after setup
	for i := 0; i < b.N; i++ {
		_ = certData.SortedNormalizedDomains() // Call the function under test
	}
}
*/
