package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// AbuseIPDBProvider enriches IP addresses using the AbuseIPDB API.
// Free tier: 1000 checks/day.
type AbuseIPDBProvider struct {
	apiKey     string
	httpClient *http.Client
}

// NewAbuseIPDBProvider creates a provider with the given API key.
func NewAbuseIPDBProvider(apiKey string) *AbuseIPDBProvider {
	return &AbuseIPDBProvider{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

func (p *AbuseIPDBProvider) Name() string            { return "abuseipdb" }
func (p *AbuseIPDBProvider) SupportedTypes() []string { return []string{"ip"} }
func (p *AbuseIPDBProvider) RateLimit() time.Duration { return 2 * time.Second }

type abuseIPDBResponse struct {
	Data struct {
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		TotalReports         int    `json:"totalReports"`
		CountryCode          string `json:"countryCode"`
		ISP                  string `json:"isp"`
		UsageType            string `json:"usageType"`
		Domain               string `json:"domain"`
	} `json:"data"`
}

func (p *AbuseIPDBProvider) Enrich(ctx context.Context, iocType, value string) (*EnrichmentResult, error) {
	req, err := http.NewRequestWithContext(ctx, "GET",
		fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", value), nil)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb: request: %w", err)
	}
	req.Header.Set("Key", p.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("abuseipdb: status %d: %s", resp.StatusCode, string(body))
	}

	var apiResp abuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("abuseipdb: decode: %w", err)
	}

	score := float64(apiResp.Data.AbuseConfidenceScore) / 100.0
	malicious := apiResp.Data.AbuseConfidenceScore > 50

	return &EnrichmentResult{
		Provider:  "abuseipdb",
		Malicious: &malicious,
		Score:     &score,
		Data: map[string]any{
			"abuse_confidence": apiResp.Data.AbuseConfidenceScore,
			"total_reports":    apiResp.Data.TotalReports,
			"country":          apiResp.Data.CountryCode,
			"isp":              apiResp.Data.ISP,
			"usage_type":       apiResp.Data.UsageType,
			"domain":           apiResp.Data.Domain,
		},
	}, nil
}
