package analyzer

import (
	"context"
	"log"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Zyrakk/noctis/internal/models"
)

// reservedDomains are RFC 2606/6761 reserved second-level domains.
var reservedDomains = map[string]bool{
	"example.com": true,
	"example.org": true,
	"example.net": true,
}

// reservedTLDs are RFC 6761 reserved top-level domains.
var reservedTLDs = []string{".test", ".invalid", ".localhost", ".example"}

// IOCValidator filters out placeholder/fake IOCs using deterministic pattern
// checks and optional DNS resolution.
type IOCValidator struct {
	dnsTimeout    time.Duration
	maxConcurrent int
	resolver      resolver
}

// resolver abstracts DNS lookups for testing.
type resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// NewIOCValidator creates a validator with the given DNS lookup timeout.
func NewIOCValidator(dnsTimeout time.Duration) *IOCValidator {
	return &IOCValidator{
		dnsTimeout:    dnsTimeout,
		maxConcurrent: 10,
		resolver:      &net.Resolver{},
	}
}

// FilterValidIOCs removes placeholder/fake IOCs from the slice.
// Layer 1: deterministic pattern rejection (no network).
// Layer 2: DNS resolution for domain/url types — NXDOMAIN = reject.
func (v *IOCValidator) FilterValidIOCs(ctx context.Context, iocs []models.IOC) []models.IOC {
	// Layer 1 — pattern rejection.
	var passed []models.IOC
	for _, ioc := range iocs {
		if !v.rejectByPattern(ioc) {
			passed = append(passed, ioc)
		}
	}

	// Layer 2 — DNS resolution for domain/url types.
	return v.filterByDNS(ctx, passed)
}

// rejectByPattern returns true if the IOC should be filtered out based on
// deterministic checks that require no network access.
func (v *IOCValidator) rejectByPattern(ioc models.IOC) bool {
	val := ioc.Value

	// Reject values containing spaces (descriptions like "http://C2 server URL").
	if strings.ContainsAny(val, " \t") {
		return true
	}

	// Reject values containing wildcards.
	if strings.Contains(val, "*") {
		return true
	}

	// Reject defanged brackets — report artifacts, not stored IOCs.
	if strings.Contains(val, "[.]") || strings.Contains(val, "[:]") {
		return true
	}

	// Reject private/reserved/loopback IPs for type "ip".
	if ioc.Type == models.IOCTypeIP {
		ip := net.ParseIP(val)
		if ip == nil {
			return true // unparseable IP
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return true
		}
	}

	// For domain/url types, check RFC reserved domains and TLDs.
	if ioc.Type == models.IOCTypeDomain || ioc.Type == models.IOCTypeURL {
		domain := extractDomain(val, ioc.Type)
		if domain == "" {
			return true
		}
		lower := strings.ToLower(domain)

		// RFC 2606 reserved second-level domains.
		if reservedDomains[lower] {
			return true
		}
		// Subdomains of reserved domains (e.g. c2.example.com).
		for rd := range reservedDomains {
			if strings.HasSuffix(lower, "."+rd) {
				return true
			}
		}

		// RFC 6761 reserved TLDs.
		for _, tld := range reservedTLDs {
			if strings.HasSuffix(lower, tld) {
				return true
			}
		}
	}

	return false
}

// filterByDNS resolves domain/url IOCs via DNS and rejects NXDOMAIN results.
// Uses bounded concurrency via a semaphore.
func (v *IOCValidator) filterByDNS(ctx context.Context, iocs []models.IOC) []models.IOC {
	type indexedResult struct {
		index int
		keep  bool
	}

	sem := make(chan struct{}, v.maxConcurrent)
	var wg sync.WaitGroup
	results := make(chan indexedResult, len(iocs))

	for i, ioc := range iocs {
		if ioc.Type != models.IOCTypeDomain && ioc.Type != models.IOCTypeURL {
			results <- indexedResult{i, true}
			continue
		}

		domain := extractDomain(ioc.Value, ioc.Type)
		if domain == "" {
			results <- indexedResult{i, false}
			continue
		}

		// Skip .onion domains — can't resolve via clearnet DNS.
		if strings.HasSuffix(strings.ToLower(domain), ".onion") {
			results <- indexedResult{i, true}
			continue
		}

		// Skip if the domain is already an IP address.
		if net.ParseIP(domain) != nil {
			results <- indexedResult{i, true}
			continue
		}

		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			dnsCtx, cancel := context.WithTimeout(ctx, v.dnsTimeout)
			defer cancel()

			addrs, err := v.resolver.LookupHost(dnsCtx, host)
			if err != nil {
				// NXDOMAIN or any lookup failure = reject.
				log.Printf("ioc_validate: DNS reject %q: %v", host, err)
				results <- indexedResult{idx, false}
				return
			}
			if len(addrs) == 0 {
				results <- indexedResult{idx, false}
				return
			}
			results <- indexedResult{idx, true}
		}(i, domain)
	}

	// Close results channel after all goroutines finish.
	go func() {
		wg.Wait()
		close(results)
	}()

	keep := make(map[int]bool, len(iocs))
	for r := range results {
		keep[r.index] = r.keep
	}

	out := make([]models.IOC, 0, len(iocs))
	for i, ioc := range iocs {
		if keep[i] {
			out = append(out, ioc)
		}
	}
	return out
}

// extractDomain extracts the hostname from a value based on IOC type.
// For URLs it uses url.Parse; for domains it returns the value directly.
func extractDomain(val, iocType string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}

	if iocType == models.IOCTypeDomain {
		// Strip any trailing port.
		host, _, err := net.SplitHostPort(val)
		if err == nil && host != "" {
			return host
		}
		return val
	}

	// For URL type, parse with url.Parse.
	if iocType == models.IOCTypeURL {
		// Ensure we have a scheme so url.Parse works correctly.
		u := val
		if !strings.Contains(u, "://") {
			u = "http://" + u
		}
		parsed, err := url.Parse(u)
		if err == nil && parsed.Hostname() != "" {
			return parsed.Hostname()
		}
		// Manual fallback: strip scheme, take everything before first /.
		after := val
		if idx := strings.Index(after, "://"); idx >= 0 {
			after = after[idx+3:]
		}
		if idx := strings.Index(after, "/"); idx >= 0 {
			after = after[:idx]
		}
		// Strip port.
		if host, _, err := net.SplitHostPort(after); err == nil && host != "" {
			return host
		}
		return after
	}

	return ""
}
