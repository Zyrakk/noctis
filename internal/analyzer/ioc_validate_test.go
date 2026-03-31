package analyzer

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/models"
)

// mockResolver is a test double for DNS lookups.
type mockResolver struct {
	results map[string][]string // host → addrs; missing key = NXDOMAIN
}

func (m *mockResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	addrs, ok := m.results[host]
	if !ok {
		return nil, fmt.Errorf("lookup %s: no such host", host)
	}
	return addrs, nil
}

func newTestValidator(dnsResults map[string][]string) *IOCValidator {
	return &IOCValidator{
		dnsTimeout:    3 * time.Second,
		maxConcurrent: 10,
		resolver:      &mockResolver{results: dnsResults},
	}
}

func TestRejectByPattern(t *testing.T) {
	v := NewIOCValidator(3 * time.Second)

	tests := []struct {
		name   string
		ioc    models.IOC
		reject bool
	}{
		// Spaces
		{
			name:   "reject URL with spaces",
			ioc:    models.IOC{Type: models.IOCTypeURL, Value: "http://C2 server URL"},
			reject: true,
		},
		{
			name:   "reject domain with tab",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "evil\t.com"},
			reject: true,
		},

		// Wildcards
		{
			name:   "reject URL with wildcard",
			ioc:    models.IOC{Type: models.IOCTypeURL, Value: "http://*.zip"},
			reject: true,
		},
		{
			name:   "reject domain with wildcard",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "*.evil.com"},
			reject: true,
		},

		// Defanged brackets
		{
			name:   "reject defanged domain",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "gamaredon[.]com"},
			reject: true,
		},
		{
			name:   "reject defanged URL",
			ioc:    models.IOC{Type: models.IOCTypeURL, Value: "http://evil[.]com/update"},
			reject: true,
		},
		{
			name:   "reject defanged IPv6 bracket",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "fe80[:]1"},
			reject: true,
		},

		// RFC reserved domains
		{
			name:   "reject example.com domain",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "example.com"},
			reject: true,
		},
		{
			name:   "reject example.org domain",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "example.org"},
			reject: true,
		},
		{
			name:   "reject example.net domain",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "example.net"},
			reject: true,
		},
		{
			name:   "reject subdomain of example.com",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "c2.example.com"},
			reject: true,
		},
		{
			name:   "reject URL containing example.com",
			ioc:    models.IOC{Type: models.IOCTypeURL, Value: "http://phish.example.com/login"},
			reject: true,
		},

		// RFC reserved TLDs
		{
			name:   "reject .test TLD",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "malware.test"},
			reject: true,
		},
		{
			name:   "reject .invalid TLD",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "something.invalid"},
			reject: true,
		},
		{
			name:   "reject .localhost TLD",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "db.localhost"},
			reject: true,
		},
		{
			name:   "reject .example TLD",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "anything.example"},
			reject: true,
		},

		// Private/reserved IPs
		{
			name:   "reject private IP 10.x",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "10.0.0.1"},
			reject: true,
		},
		{
			name:   "reject private IP 172.16.x",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "172.16.0.1"},
			reject: true,
		},
		{
			name:   "reject private IP 192.168.x",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "192.168.1.1"},
			reject: true,
		},
		{
			name:   "reject loopback",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "127.0.0.1"},
			reject: true,
		},
		{
			name:   "reject IPv6 loopback",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "::1"},
			reject: true,
		},
		{
			name:   "reject link-local",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "169.254.1.1"},
			reject: true,
		},
		{
			name:   "reject unspecified",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "0.0.0.0"},
			reject: true,
		},
		{
			name:   "reject unparseable IP",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "not-an-ip"},
			reject: true,
		},

		// Valid IOCs should pass
		{
			name:   "pass valid domain",
			ioc:    models.IOC{Type: models.IOCTypeDomain, Value: "evil-c2.xyz"},
			reject: false,
		},
		{
			name:   "pass valid IP",
			ioc:    models.IOC{Type: models.IOCTypeIP, Value: "198.51.100.1"},
			reject: false,
		},
		{
			name:   "pass valid URL",
			ioc:    models.IOC{Type: models.IOCTypeURL, Value: "http://evil-c2.xyz/payload.bin"},
			reject: false,
		},
		{
			name:   "pass hash (no pattern checks)",
			ioc:    models.IOC{Type: models.IOCTypeHashSHA256, Value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
			reject: false,
		},
		{
			name:   "pass CVE",
			ioc:    models.IOC{Type: models.IOCTypeCVE, Value: "CVE-2024-12345"},
			reject: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v.rejectByPattern(tt.ioc)
			if got != tt.reject {
				t.Errorf("rejectByPattern(%+v) = %v, want %v", tt.ioc, got, tt.reject)
			}
		})
	}
}

func TestFilterByDNS(t *testing.T) {
	dns := map[string][]string{
		"real-c2.xyz":     {"93.184.216.34"},
		"legit-evil.com":  {"1.2.3.4"},
		"deadsite.onion":  {}, // shouldn't matter — .onion is skipped
	}
	v := newTestValidator(dns)
	ctx := context.Background()

	tests := []struct {
		name string
		ioc  models.IOC
		keep bool
	}{
		{
			name: "domain resolves — keep",
			ioc:  models.IOC{Type: models.IOCTypeDomain, Value: "real-c2.xyz"},
			keep: true,
		},
		{
			name: "domain NXDOMAIN — reject",
			ioc:  models.IOC{Type: models.IOCTypeDomain, Value: "nonexistent-domain-12345.xyz"},
			keep: false,
		},
		{
			name: "URL domain resolves — keep",
			ioc:  models.IOC{Type: models.IOCTypeURL, Value: "http://legit-evil.com/payload"},
			keep: true,
		},
		{
			name: "URL domain NXDOMAIN — reject",
			ioc:  models.IOC{Type: models.IOCTypeURL, Value: "http://fakefake-nope.net/x"},
			keep: false,
		},
		{
			name: ".onion skipped — keep",
			ioc:  models.IOC{Type: models.IOCTypeDomain, Value: "deadsite.onion"},
			keep: true,
		},
		{
			name: "IP-in-domain skipped — keep",
			ioc:  models.IOC{Type: models.IOCTypeURL, Value: "http://93.184.216.34/evil"},
			keep: true,
		},
		{
			name: "hash type — no DNS, keep",
			ioc:  models.IOC{Type: models.IOCTypeHashSHA256, Value: "abcd1234"},
			keep: true,
		},
		{
			name: "IP type — no DNS, keep",
			ioc:  models.IOC{Type: models.IOCTypeIP, Value: "8.8.8.8"},
			keep: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := v.filterByDNS(ctx, []models.IOC{tt.ioc})
			got := len(result) > 0
			if got != tt.keep {
				t.Errorf("filterByDNS(%+v): kept=%v, want kept=%v", tt.ioc, got, tt.keep)
			}
		})
	}
}

func TestFilterValidIOCs_Integration(t *testing.T) {
	dns := map[string][]string{
		"real-c2.xyz": {"93.184.216.34"},
	}
	v := newTestValidator(dns)
	ctx := context.Background()

	input := []models.IOC{
		{Type: models.IOCTypeDomain, Value: "real-c2.xyz"},              // pass both layers
		{Type: models.IOCTypeDomain, Value: "example.com"},             // rejected by pattern
		{Type: models.IOCTypeURL, Value: "http://C2 server URL"},       // rejected by pattern (spaces)
		{Type: models.IOCTypeDomain, Value: "nxdomain-fake-9999.xyz"},  // pass pattern, fail DNS
		{Type: models.IOCTypeIP, Value: "127.0.0.1"},                   // rejected by pattern (loopback)
		{Type: models.IOCTypeHashSHA256, Value: "aabbccdd"},            // pass (no checks for hashes beyond pattern)
		{Type: models.IOCTypeDomain, Value: "gamaredon[.]com"},         // rejected by pattern (defanged)
		{Type: models.IOCTypeURL, Value: "http://*.zip"},               // rejected by pattern (wildcard)
		{Type: models.IOCTypeDomain, Value: "secret.onion"},            // pass pattern, DNS skipped (.onion)
	}

	result := v.FilterValidIOCs(ctx, input)

	// Expected survivors: real-c2.xyz, aabbccdd, secret.onion
	expected := map[string]bool{
		"real-c2.xyz":  true,
		"aabbccdd":     true,
		"secret.onion": true,
	}

	if len(result) != len(expected) {
		t.Fatalf("FilterValidIOCs: got %d IOCs, want %d. Got: %+v", len(result), len(expected), result)
	}

	for _, ioc := range result {
		if !expected[ioc.Value] {
			t.Errorf("FilterValidIOCs: unexpected IOC in output: %+v", ioc)
		}
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		name    string
		val     string
		iocType string
		want    string
	}{
		{"plain domain", "evil.com", models.IOCTypeDomain, "evil.com"},
		{"domain with port", "evil.com:8080", models.IOCTypeDomain, "evil.com"},
		{"full URL", "http://evil.com/path", models.IOCTypeURL, "evil.com"},
		{"URL with port", "https://evil.com:443/path", models.IOCTypeURL, "evil.com"},
		{"URL no scheme", "evil.com/path", models.IOCTypeURL, "evil.com"},
		{"URL with IP", "http://1.2.3.4/path", models.IOCTypeURL, "1.2.3.4"},
		{"empty", "", models.IOCTypeDomain, ""},
		{"IP type returns empty", "1.2.3.4", models.IOCTypeIP, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDomain(tt.val, tt.iocType)
			if got != tt.want {
				t.Errorf("extractDomain(%q, %q) = %q, want %q", tt.val, tt.iocType, got, tt.want)
			}
		})
	}
}
