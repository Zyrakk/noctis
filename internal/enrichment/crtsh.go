package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// CRTShProvider enriches domains using crt.sh certificate transparency logs.
// No API key required. No hard rate limit but be polite.
type CRTShProvider struct {
	httpClient *http.Client
}

// NewCRTShProvider creates a crt.sh provider.
func NewCRTShProvider() *CRTShProvider {
	return &CRTShProvider{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (p *CRTShProvider) Name() string            { return "crtsh" }
func (p *CRTShProvider) SupportedTypes() []string { return []string{"domain"} }
func (p *CRTShProvider) RateLimit() time.Duration { return 5 * time.Second }

type crtshEntry struct {
	IssuerName string `json:"issuer_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	CommonName string `json:"common_name"`
}

func (p *CRTShProvider) Enrich(ctx context.Context, iocType, value string) (*EnrichmentResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://crt.sh/?q=%s&output=json", value), nil)
	if err != nil {
		return nil, fmt.Errorf("crtsh: request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("crtsh: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crtsh: status %d", resp.StatusCode)
	}

	var entries []crtshEntry
	if err := json.NewDecoder(resp.Body).Decode(&entries); err != nil {
		return nil, fmt.Errorf("crtsh: decode: %w", err)
	}

	// Collect unique issuers.
	issuers := make(map[string]bool)
	for _, e := range entries {
		issuers[e.IssuerName] = true
	}
	issuerList := make([]string, 0, len(issuers))
	for k := range issuers {
		issuerList = append(issuerList, k)
	}

	var firstCert, lastCert string
	if len(entries) > 0 {
		firstCert = entries[len(entries)-1].NotBefore
		lastCert = entries[0].NotBefore
	}

	return &EnrichmentResult{
		Provider: "crtsh",
		Data: map[string]any{
			"certificate_count": len(entries),
			"issuers":           issuerList,
			"first_cert":        firstCert,
			"last_cert":         lastCert,
		},
	}, nil
}
