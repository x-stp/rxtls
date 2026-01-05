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
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/zeebo/xxh3"
)

// Constants related to CT log interaction.
const (
	CTLListsURL         = "https://www.gstatic.com/ct/log_list/v3/log_list.json"
	CTLInfoURLTemplate  = "https://%s/ct/v1/get-sth"
	DownloadURLTemplate = "https://%s/ct/v1/get-entries?start=%d&end=%d"
	HTTPTimeout         = 30 // seconds
)

// Global settings influencing certlib behavior.
var (
	UseLocalLogs  = false
	LocalLogsFile = "./all_logs_list.json"
)

// CTLogInfo holds metadata about a single Certificate Transparency log.
type CTLogInfo struct {
	URL         string `json:"url"`
	Description string `json:"description"`
	OperatedBy  string `json:"operated_by"`
	TreeSize    int    `json:"tree_size"`
	BlockSize   int    `json:"block_size"`
}

// IsCloudflare checks if the log URL suggests it's operated by Cloudflare.
func (c *CTLogInfo) IsCloudflare() bool {
	return strings.Contains(c.URL, "cloudflare.com")
}

// IsDigiCert checks if the log URL suggests it's operated by DigiCert.
func (c *CTLogInfo) IsDigiCert() bool {
	return strings.Contains(c.URL, "digicert.com") ||
		strings.Contains(c.URL, "wyvern") ||
		strings.Contains(c.URL, "nessie")
}

// Host extracts the hostname part from the log URL.
func (c *CTLogInfo) Host() string {
	parts := strings.Split(c.URL, "/")
	return parts[0]
}

// IsResolvable checks if the log's hostname can be parsed.
func (c *CTLogInfo) IsResolvable() bool {
	_, err := url.Parse("https://" + c.URL)
	return err == nil
}

// GetTLSConfig provides a TLS configuration optimized for performance.
func (c *CTLogInfo) GetTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		NextProtos: []string{"http/1.1"},
	}
}

// SubjectData holds components of an X.509 Subject or Issuer Name.
type SubjectData struct {
	Aggregated string `json:"aggregated"`
	C          string `json:"C,omitempty"`
	ST         string `json:"ST,omitempty"`
	L          string `json:"L,omitempty"`
	O          string `json:"O,omitempty"`
	OU         string `json:"OU,omitempty"`
	CN         string `json:"CN,omitempty"`
}

// Extensions simplified storage.
type Extensions struct {
	SubjectAltName string `json:"subjectAltName,omitempty"`
}

// CertificateData represents the parsed data from a single certificate entry.
type CertificateData struct {
	Subject    SubjectData
	Issuer     SubjectData
	Extensions map[string]string // Simplified
	NotBefore  int64
	NotAfter   int64
	AsDER      string // Base64 DER
	AllDomains []string
	Type       string
	Source     map[string]string
}

// Chain calculates a NON-CRYPTOGRAPHIC hash (xxh3) of the base64 DER string.
func (c *CertificateData) Chain() string {
	h := xxh3.HashString(c.AsDER)
	return fmt.Sprintf("%x", h)
}

// NormalizedDomainsSet returns a set (map[string]struct{}) of normalized domains.
func (c *CertificateData) NormalizedDomainsSet() map[string]struct{} {
	result := make(map[string]struct{}, len(c.AllDomains))
	for _, domain := range c.AllDomains {
		normalized := NormalizeDomain(domain)
		if normalized != "" {
			result[normalized] = struct{}{}
		}
	}
	return result
}

// SortedNormalizedDomains returns sorted, unique, normalized domains.
func (c *CertificateData) SortedNormalizedDomains() []string {
	domainSet := c.NormalizedDomainsSet()
	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	return domains
}

// calculateDomainOrgHash uses xxh3 hash.
func calculateDomainOrgHash(sortedUniqueNormalizedDomains []string, org string) string {
	estimatedLen := len(org) + 1
	for _, d := range sortedUniqueNormalizedDomains {
		estimatedLen += len(d) + 1
	}
	var sb strings.Builder
	sb.Grow(estimatedLen)
	for i, domain := range sortedUniqueNormalizedDomains {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(domain)
	}
	sb.WriteByte('|')
	sb.WriteString(org)
	h := xxh3.HashString(sb.String())
	return fmt.Sprintf("%x", h)
}

// DomainOrgHash calculates the xxh3 hash based on sorted, unique, normalized domains and Org.
func (c *CertificateData) DomainOrgHash() string {
	return calculateDomainOrgHash(c.SortedNormalizedDomains(), c.Subject.O)
}

// ToCSVLine creates a simple CSV for raw certificate download output.
func (c *CertificateData) ToCSVLine(certIndex int) string {
	return fmt.Sprintf("%s,%d,%s,%s,%s,%d,%d\n",
		c.Source["url"],
		certIndex,
		c.Chain(),
		c.AsDER,
		strings.Join(c.AllDomains, " "),
		c.NotBefore,
		c.NotAfter,
	)
}

// ToDomainsCSVLine creates the specific CSV format for the 'domains' command.
func (c *CertificateData) ToDomainsCSVLine(certIndex int) string {
	normalizedCN := NormalizeDomain(c.Subject.CN)
	normalizedDomains := c.SortedNormalizedDomains()
	outputDomains := make([]string, len(normalizedDomains))
	for i, d := range normalizedDomains {
		if strings.HasPrefix(d, "*.") {
			outputDomains[i] = d[2:]
		} else {
			outputDomains[i] = d
		}
	}
	outputDomainsStr := strings.Join(outputDomains, ",")
	primaryDomain := ""
	if len(normalizedDomains) > 0 {
		primaryDomain = normalizedDomains[0]
	}
	hash := calculateDomainOrgHash(normalizedDomains, c.Subject.O)
	return fmt.Sprintf("%d,%s,%s,%s,%s,\"%s\",\"%s\",\"%s\",\"%s\",%s\n",
		certIndex,
		normalizedCN,
		primaryDomain,
		outputDomainsStr,
		c.Subject.C,
		c.Subject.ST,
		c.Subject.L,
		c.Subject.O,
		c.Issuer.CN,
		hash,
	)
}

// CertificateFromX509 creates a CertificateData from an x509 Certificate.
func CertificateFromX509(cert *x509.Certificate, source string) *CertificateData {
	cd := &CertificateData{
		Type: "X509LogEntry",
		Subject: SubjectData{
			Aggregated: cert.Subject.String(),
			CN:         cert.Subject.CommonName,
		},
		Issuer: SubjectData{
			Aggregated: cert.Issuer.String(),
			CN:         cert.Issuer.CommonName,
		},
		NotBefore:  cert.NotBefore.Unix(),
		NotAfter:   cert.NotAfter.Unix(),
		Source:     map[string]string{"url": source},
		Extensions: make(map[string]string),
	}
	if len(cert.Subject.Country) > 0 {
		cd.Subject.C = cert.Subject.Country[0]
	}
	if len(cert.Subject.Organization) > 0 {
		cd.Subject.O = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		cd.Subject.OU = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.Locality) > 0 {
		cd.Subject.L = cert.Subject.Locality[0]
	}
	if len(cert.Subject.Province) > 0 {
		cd.Subject.ST = cert.Subject.Province[0]
	}
	if len(cert.Issuer.Country) > 0 {
		cd.Issuer.C = cert.Issuer.Country[0]
	}
	if len(cert.Issuer.Organization) > 0 {
		cd.Issuer.O = cert.Issuer.Organization[0]
	}
	derBytes := cert.Raw
	cd.AsDER = base64.StdEncoding.EncodeToString(derBytes)
	domains := make([]string, 0, len(cert.DNSNames)+1)
	if cert.Subject.CommonName != "" {
		domains = append(domains, cert.Subject.CommonName)
	}
	domains = append(domains, cert.DNSNames...)
	seenDomains := make(map[string]bool, len(domains))
	cd.AllDomains = make([]string, 0, len(domains))
	for _, domain := range domains {
		if !seenDomains[domain] {
			seenDomains[domain] = true
			cd.AllDomains = append(cd.AllDomains, domain)
		}
	}
	return cd
}

// NormalizeDomain standardizes domain names.
func NormalizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" || strings.ContainsAny(domain, " \t\n") {
		if strings.ContainsAny(domain, " :/") || domain == "::1" || strings.HasPrefix(domain, "-") {
			return domain
		}
		return ""
	}
	domain = strings.ToLower(domain)
	for strings.HasPrefix(domain, ".") {
		domain = domain[1:]
	}
	for strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	if domain == "" {
		return ""
	}

	// Preserve wildcard labels. We normalize case/dots but do not strip leading "*.".
	// This keeps inputs like "*.example.com" stable, while still rejecting clearly invalid labels below.
	parts := strings.SplitSeq(domain, ".")
	for part := range parts {
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return domain // Invalid label structure
		}
		if strings.HasPrefix(part, "*") && part != "*" {
			return domain // Invalid label structure after potential stripping
		}
	}
	return domain
}
