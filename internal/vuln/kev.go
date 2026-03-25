package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
)

const kevURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type kevResponse struct {
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

type kevEntry struct {
	CVEID                      string `json:"cveID"`
	DateAdded                  string `json:"dateAdded"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// updateKEVData downloads the CISA KEV catalog and updates matching vulnerabilities.
func (v *VulnIngestor) updateKEVData(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", kevURL, nil)
	if err != nil {
		return 0, fmt.Errorf("vuln: kev request: %w", err)
	}

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("vuln: kev fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("vuln: kev status %d", resp.StatusCode)
	}

	var kevResp kevResponse
	if err := json.NewDecoder(resp.Body).Decode(&kevResp); err != nil {
		return 0, fmt.Errorf("vuln: kev decode: %w", err)
	}

	var totalUpdated int

	for _, entry := range kevResp.Vulnerabilities {
		if ctx.Err() != nil {
			return totalUpdated, ctx.Err()
		}

		vuln := &archive.Vulnerability{
			CVEID:            entry.CVEID,
			KEVListed:        true,
			KEVRansomwareUse: strings.EqualFold(entry.KnownRansomwareCampaignUse, "Known"),
		}

		if t, err := time.Parse("2006-01-02", entry.DateAdded); err == nil {
			vuln.KEVDateAdded = &t
		}
		if t, err := time.Parse("2006-01-02", entry.DueDate); err == nil {
			vuln.KEVDueDate = &t
		}

		// KEV = automatic critical priority.
		priorityScore := 1.0
		priorityLabel := "critical"
		vuln.PriorityScore = &priorityScore
		vuln.PriorityLabel = &priorityLabel

		if err := v.archive.UpsertVulnerability(ctx, vuln); err != nil {
			log.Printf("vuln: kev upsert %s error: %v", entry.CVEID, err)
			continue
		}
		totalUpdated++
	}

	return totalUpdated, nil
}
