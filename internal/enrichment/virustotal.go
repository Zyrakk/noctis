package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// VirusTotalProvider enriches IPs, domains, and hashes using the VirusTotal API.
// Free tier: 500 lookups/day, 4 lookups/minute.
// Note: URL lookups are excluded — VT requires base64 encoding and a POST.
type VirusTotalProvider struct {
	apiKey     string
	httpClient *http.Client
}

// NewVirusTotalProvider creates a provider with the given API key.
func NewVirusTotalProvider(apiKey string) *VirusTotalProvider {
	return &VirusTotalProvider{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (p *VirusTotalProvider) Name() string { return "virustotal" }
func (p *VirusTotalProvider) SupportedTypes() []string {
	return []string{"ip", "domain", "hash_md5", "hash_sha256"}
}
func (p *VirusTotalProvider) RateLimit() time.Duration { return 15 * time.Second }

type vtResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Harmless   int `json:"harmless"`
				Undetected int `json:"undetected"`
			} `json:"last_analysis_stats"`
			Reputation int `json:"reputation"`
		} `json:"attributes"`
	} `json:"data"`
}

func (p *VirusTotalProvider) Enrich(ctx context.Context, iocType, value string) (*EnrichmentResult, error) {
	endpoint := p.buildEndpoint(iocType, value)
	if endpoint == "" {
		return nil, fmt.Errorf("virustotal: unsupported type %s", iocType)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("virustotal: request: %w", err)
	}
	req.Header.Set("x-apikey", p.apiKey)

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("virustotal: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// IOC not in VT database — not an error.
		return &EnrichmentResult{
			Provider: "virustotal",
			Data:     map[string]any{"status": "not_found"},
		}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("virustotal: status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp vtResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("virustotal: decode: %w", err)
	}

	stats := apiResp.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Harmless + stats.Undetected

	var score float64
	if total > 0 {
		score = float64(stats.Malicious) / float64(total)
	}
	malicious := stats.Malicious > 5

	return &EnrichmentResult{
		Provider:  "virustotal",
		Malicious: &malicious,
		Score:     &score,
		Data: map[string]any{
			"malicious":  stats.Malicious,
			"suspicious": stats.Suspicious,
			"harmless":   stats.Harmless,
			"undetected": stats.Undetected,
			"reputation": apiResp.Data.Attributes.Reputation,
		},
	}, nil
}

func (p *VirusTotalProvider) buildEndpoint(iocType, value string) string {
	base := "https://www.virustotal.com/api/v3"
	switch iocType {
	case "ip":
		return base + "/ip_addresses/" + value
	case "domain":
		return base + "/domains/" + value
	case "hash_md5", "hash_sha256":
		return base + "/files/" + value
	default:
		return ""
	}
}
