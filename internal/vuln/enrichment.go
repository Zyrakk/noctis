package vuln

import (
	"context"
	"fmt"
	"log"

	"github.com/Zyrakk/noctis/internal/archive"
)

// crossReferenceNoctisData links vulnerability records with Noctis IOC and finding data.
func (v *VulnIngestor) crossReferenceNoctisData(ctx context.Context) (int, error) {
	var totalEnriched int

	// 1. Find CVE-type IOCs and increment mention counts.
	rows, err := v.archive.Pool().Query(ctx, `
		SELECT DISTINCT value FROM iocs WHERE type = 'cve'`)
	if err != nil {
		return 0, fmt.Errorf("vuln: enrichment ioc query: %w", err)
	}
	defer rows.Close()

	var cveIOCs []string
	for rows.Next() {
		var cveID string
		if err := rows.Scan(&cveID); err != nil {
			continue
		}
		cveIOCs = append(cveIOCs, cveID)
	}

	for _, cveID := range cveIOCs {
		if ctx.Err() != nil {
			return totalEnriched, ctx.Err()
		}

		// Count sightings for this CVE.
		var sightingCount int
		v.archive.Pool().QueryRow(ctx, `
			SELECT COUNT(*) FROM ioc_sightings WHERE ioc_type = 'cve' AND ioc_value = $1`,
			cveID).Scan(&sightingCount)

		if sightingCount > 0 {
			// Reset mention count and set to actual sighting count.
			_, err := v.archive.Pool().Exec(ctx, `
				UPDATE vulnerabilities
				SET dark_web_mentions = $2,
				    last_seen_noctis = NOW(),
				    first_seen_noctis = COALESCE(first_seen_noctis, NOW())
				WHERE cve_id = $1`, cveID, sightingCount)
			if err != nil {
				log.Printf("vuln: enrichment update mentions %s: %v", cveID, err)
				continue
			}
			totalEnriched++
		}
	}

	// 2. Check for exploit availability based on finding sub-categories.
	_, err = v.archive.Pool().Exec(ctx, `
		UPDATE vulnerabilities v
		SET exploit_available = TRUE
		WHERE EXISTS (
			SELECT 1 FROM iocs i
			JOIN raw_content rc ON rc.id = i.source_content_id
			WHERE i.type = 'cve' AND i.value = v.cve_id
			AND rc.sub_category IN ('exploit_poc', 'exploit_weaponized')
		) AND v.exploit_available = FALSE`)
	if err != nil {
		log.Printf("vuln: enrichment exploit check error: %v", err)
	}

	return totalEnriched, nil
}

// recomputePriorities recalculates priority scores for all vulnerabilities
// that have been updated recently.
func (v *VulnIngestor) recomputePriorities(ctx context.Context) (int, error) {
	vulns, _, err := v.archive.FetchVulnerabilities(ctx, archive.VulnFilter{
		Limit: 500,
	})
	if err != nil {
		return 0, fmt.Errorf("vuln: fetch for priority: %w", err)
	}

	var updated int
	for _, vuln := range vulns {
		if ctx.Err() != nil {
			return updated, ctx.Err()
		}

		score, label := ComputePriority(&vuln)

		// Skip if priority hasn't changed.
		if vuln.PriorityScore != nil && *vuln.PriorityScore == score {
			continue
		}

		_, err := v.archive.Pool().Exec(ctx, `
			UPDATE vulnerabilities
			SET priority_score = $2, priority_label = $3, updated_at = NOW()
			WHERE cve_id = $1`, vuln.CVEID, score, label)
		if err != nil {
			log.Printf("vuln: priority update %s error: %v", vuln.CVEID, err)
			continue
		}
		updated++
	}

	return updated, nil
}
