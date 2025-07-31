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
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/zeebo/xxh3"
)

// calculateExpectedDomainOrgHash is a test helper using xxh3.
func calculateExpectedDomainOrgHash(domains []string, org string) string {
	uniqueMap := make(map[string]bool)
	var normalizedDomains []string
	for _, d := range domains {
		n := NormalizeDomain(d)
		if n != "" && !uniqueMap[n] {
			uniqueMap[n] = true
			normalizedDomains = append(normalizedDomains, n)
		}
	}
	sort.Strings(normalizedDomains)
	domainsStr := strings.Join(normalizedDomains, ",")
	h := xxh3.HashString(fmt.Sprintf("%s|%s", domainsStr, org))
	return fmt.Sprintf("%x", h)
}

// TestToDomainsCSVLine validates the domain-focused CSV output.
func TestToDomainsCSVLine(t *testing.T) {
	t.Parallel()
	certIndex := 12345
	testCases := []struct {
		name     string
		certData CertificateData
	}{
		{
			name: "Simple CN, single SAN",
			certData: CertificateData{
				Subject:    SubjectData{CN: "example.com", O: "Test Org Inc.", C: "US", ST: "California", L: "Mountain View"},
				Issuer:     SubjectData{CN: "Test CA"},
				AllDomains: []string{"example.com", "www.example.com"},
			},
		},
		{
			name: "Mixed case, trailing dots, duplicate SAN",
			certData: CertificateData{
				Subject:    SubjectData{CN: "EXAMPLE.net.", O: "Another, Org", C: "GB", ST: "", L: "London"},
				Issuer:     SubjectData{CN: "Issuing CA Ltd.", O: "Issuer Org"},
				AllDomains: []string{"EXAMPLE.net.", "WWW.example.net", "www.example.net"},
			},
		},
		{
			name: "Wildcard domain (gets stripped in output list)",
			certData: CertificateData{
				Subject:    SubjectData{CN: "*.example.org", O: "Wild Org", C: "", ST: "", L: ""},
				Issuer:     SubjectData{CN: "Wild CA"},
				AllDomains: []string{"*.example.org", "example.org"},
			},
		},
		{
			name: "No CN, only SANs",
			certData: CertificateData{
				Subject:    SubjectData{CN: "", O: "SAN Org", C: "DE", ST: "Berlin", L: "Berlin"},
				Issuer:     SubjectData{CN: "SAN Issuer"},
				AllDomains: []string{"san1.com", "san2.com"},
			},
		},
		{
			name: "No domains at all",
			certData: CertificateData{
				Subject:    SubjectData{CN: "", O: "Empty Org", C: "JP", ST: "Tokyo", L: "Tokyo"},
				Issuer:     SubjectData{CN: "Empty Issuer"},
				AllDomains: []string{},
			},
		},
		{
			name: "CN needs normalization, SAN is primary",
			certData: CertificateData{
				Subject:    SubjectData{CN: " INVALID CN ", O: "Norm Org", C: "CA", ST: "Ontario", L: "Toronto"},
				Issuer:     SubjectData{CN: "Norm CA"},
				AllDomains: []string{" a.valid.domain ", " INVALID CN "},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			expectedNormalizedCN := NormalizeDomain(tc.certData.Subject.CN)
			normalizedSortedDomains := tc.certData.SortedNormalizedDomains()
			expectedOutputDomains := make([]string, len(normalizedSortedDomains))
			for i, d := range normalizedSortedDomains {
				if strings.HasPrefix(d, "*.") {
					expectedOutputDomains[i] = d[2:]
				} else {
					expectedOutputDomains[i] = d
				}
			}
			expectedOutputDomainsStr := strings.Join(expectedOutputDomains, ",")
			expectedPrimaryDomain := ""
			if len(normalizedSortedDomains) > 0 {
				expectedPrimaryDomain = normalizedSortedDomains[0]
			}
			hashExpected := calculateExpectedDomainOrgHash(tc.certData.AllDomains, tc.certData.Subject.O)
			expectedOutput := fmt.Sprintf("%d,%s,%s,%s,%s,\"%s\",\"%s\",\"%s\",\"%s\",%s\n",
				certIndex, expectedNormalizedCN, expectedPrimaryDomain, expectedOutputDomainsStr,
				tc.certData.Subject.C, tc.certData.Subject.ST, tc.certData.Subject.L, tc.certData.Subject.O,
				tc.certData.Issuer.CN, hashExpected)
			actualOutput := tc.certData.ToDomainsCSVLine(certIndex)
			if actualOutput != expectedOutput {
				t.Errorf("ToDomainsCSVLine() mismatch:\n Input: %+v\n Want: %q\n Got:  %q", tc.certData, expectedOutput, actualOutput)
			}
		})
	}
}

// BenchmarkSortedNormalizedDomains measures performance of getting unique, sorted,
// normalized domains from a CertificateData struct with a large SAN list.
func BenchmarkSortedNormalizedDomains(b *testing.B) {
	size := 100000
	allDomains := make([]string, size)
	for i := range size {
		prefix := ""
		suffix := ".com"
		if i%10 == 0 {
			prefix = "*.Sub."
			suffix = ".NET."
		}
		if i%3 == 0 {
			prefix += " "
		}
		baseDomain := fmt.Sprintf("%sexample-%d-%d%s", prefix, i%1000, i%50, suffix)
		if i > 0 && i%7 == 0 {
			allDomains[i] = allDomains[i-1]
		} else {
			allDomains[i] = baseDomain
		}
	}
	certData := &CertificateData{
		AllDomains: allDomains,
		Subject:    SubjectData{O: "Benchmark Org"},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = certData.SortedNormalizedDomains()
	}
}
