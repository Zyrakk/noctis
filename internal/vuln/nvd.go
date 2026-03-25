package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
)

const nvdBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// nvdResponse is the top-level NVD API response.
type nvdResponse struct {
	TotalResults   int              `json:"totalResults"`
	StartIndex     int              `json:"startIndex"`
	ResultsPerPage int              `json:"resultsPerPage"`
	Vulnerabilities []nvdVulnWrapper `json:"vulnerabilities"`
}

type nvdVulnWrapper struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string          `json:"id"`
	Published      string          `json:"published"`
	LastModified   string          `json:"lastModified"`
	Descriptions   []nvdLangString `json:"descriptions"`
	Metrics        nvdMetrics      `json:"metrics"`
	Weaknesses     []nvdWeakness   `json:"weaknesses"`
	Configurations []nvdConfig     `json:"configurations"`
	References     []nvdReference  `json:"references"`
}

type nvdLangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetrics struct {
	CvssMetricV31 []nvdCVSSMetric `json:"cvssMetricV31"`
}

type nvdCVSSMetric struct {
	CvssData nvdCVSSData `json:"cvssData"`
}

type nvdCVSSData struct {
	BaseScore    float64 `json:"baseScore"`
	VectorString string  `json:"vectorString"`
	BaseSeverity string  `json:"baseSeverity"`
}

type nvdWeakness struct {
	Description []nvdLangString `json:"description"`
}

type nvdConfig struct {
	Nodes []nvdConfigNode `json:"nodes"`
}

type nvdConfigNode struct {
	CpeMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Criteria string `json:"criteria"`
}

type nvdReference struct {
	URL string `json:"url"`
}

// fetchNVDUpdates fetches CVEs modified since lastPoll from the NVD API.
// On first run (lastPoll is zero), fetches CVEs modified in the last 30 days.
// Returns the number of CVEs processed.
func (v *VulnIngestor) fetchNVDUpdates(ctx context.Context, lastPoll time.Time) (int, error) {
	if lastPoll.IsZero() {
		lastPoll = time.Now().UTC().Add(-30 * 24 * time.Hour)
	}
	end := time.Now().UTC()

	var totalProcessed int
	startIndex := 0

	for {
		if ctx.Err() != nil {
			return totalProcessed, ctx.Err()
		}

		params := url.Values{}
		params.Set("lastModStartDate", lastPoll.Format("2006-01-02T15:04:05.000Z"))
		params.Set("lastModEndDate", end.Format("2006-01-02T15:04:05.000Z"))
		params.Set("startIndex", fmt.Sprintf("%d", startIndex))
		params.Set("resultsPerPage", "2000")

		reqURL := nvdBaseURL + "?" + params.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
		if err != nil {
			return totalProcessed, fmt.Errorf("vuln: nvd request: %w", err)
		}
		if v.cfg.NVDAPIKey != "" {
			req.Header.Set("apiKey", v.cfg.NVDAPIKey)
		}

		// Rate limit: wait before each request.
		v.nvdRateLimit()

		resp, err := v.httpClient.Do(req)
		if err != nil {
			return totalProcessed, fmt.Errorf("vuln: nvd fetch: %w", err)
		}

		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			log.Printf("vuln: nvd rate limited (status %d), waiting 30s", resp.StatusCode)
			select {
			case <-time.After(30 * time.Second):
				continue
			case <-ctx.Done():
				return totalProcessed, ctx.Err()
			}
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
			resp.Body.Close()
			return totalProcessed, fmt.Errorf("vuln: nvd status %d: %s", resp.StatusCode, string(body))
		}

		var nvdResp nvdResponse
		if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
			resp.Body.Close()
			return totalProcessed, fmt.Errorf("vuln: nvd decode: %w", err)
		}
		resp.Body.Close()

		for _, item := range nvdResp.Vulnerabilities {
			vuln := nvdToVulnerability(item.CVE)
			if err := v.archive.UpsertVulnerability(ctx, vuln); err != nil {
				log.Printf("vuln: nvd upsert %s error: %v", vuln.CVEID, err)
				continue
			}
			totalProcessed++
		}

		// Check if more pages.
		if startIndex+nvdResp.ResultsPerPage >= nvdResp.TotalResults {
			break
		}
		startIndex += nvdResp.ResultsPerPage
	}

	return totalProcessed, nil
}

// nvdToVulnerability converts an NVD CVE to our Vulnerability struct.
func nvdToVulnerability(cve nvdCVE) *archive.Vulnerability {
	vuln := &archive.Vulnerability{
		CVEID: cve.ID,
	}

	// Description (English).
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			vuln.Description = &d.Value
			break
		}
	}

	// CVSS v3.1.
	if len(cve.Metrics.CvssMetricV31) > 0 {
		m := cve.Metrics.CvssMetricV31[0].CvssData
		vuln.CVSSV31Score = &m.BaseScore
		vuln.CVSSV31Vector = &m.VectorString
		vuln.CVSSSeverity = &m.BaseSeverity
	}

	// CWE IDs.
	for _, w := range cve.Weaknesses {
		for _, d := range w.Description {
			if d.Value != "" && d.Value != "NVD-CWE-Other" && d.Value != "NVD-CWE-noinfo" {
				vuln.CWEIDs = append(vuln.CWEIDs, d.Value)
			}
		}
	}

	// Affected products (CPE criteria).
	var products []any
	for _, cfg := range cve.Configurations {
		for _, node := range cfg.Nodes {
			for _, cpe := range node.CpeMatch {
				products = append(products, cpe.Criteria)
			}
		}
	}
	vuln.AffectedProducts = products

	// References.
	var refs []any
	for _, r := range cve.References {
		refs = append(refs, r.URL)
	}
	vuln.ReferenceURLs = refs

	// Timestamps.
	if t, err := time.Parse(time.RFC3339Nano, cve.Published); err == nil {
		vuln.PublishedAt = &t
	}
	if t, err := time.Parse(time.RFC3339Nano, cve.LastModified); err == nil {
		vuln.LastModifiedAt = &t
	}

	return vuln
}

// nvdRateLimit enforces NVD API rate limits.
// With API key: ~1 request per 0.6 seconds. Without: 1 per 6 seconds.
func (v *VulnIngestor) nvdRateLimit() {
	delay := 6 * time.Second
	if v.cfg.NVDAPIKey != "" {
		delay = 650 * time.Millisecond
	}
	time.Sleep(delay)
}
