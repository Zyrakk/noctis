package archive

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Vulnerability represents a CVE record enriched with EPSS, KEV, and Noctis data.
type Vulnerability struct {
	ID               string     `json:"id"`
	CVEID            string     `json:"cve_id"`
	Description      *string    `json:"description,omitempty"`
	CVSSV31Score     *float64   `json:"cvss_v31_score,omitempty"`
	CVSSV31Vector    *string    `json:"cvss_v31_vector,omitempty"`
	CVSSSeverity     *string    `json:"cvss_severity,omitempty"`
	CWEIDs           []string   `json:"cwe_ids"`
	AffectedProducts []any      `json:"affected_products"`
	ReferenceURLs    []any      `json:"reference_urls"`
	PublishedAt      *time.Time `json:"published_at,omitempty"`
	LastModifiedAt   *time.Time `json:"last_modified_at,omitempty"`
	EPSSScore        *float64   `json:"epss_score,omitempty"`
	EPSSPercentile   *float64   `json:"epss_percentile,omitempty"`
	EPSSUpdatedAt    *time.Time `json:"epss_updated_at,omitempty"`
	KEVListed        bool       `json:"kev_listed"`
	KEVDateAdded     *time.Time `json:"kev_date_added,omitempty"`
	KEVDueDate       *time.Time `json:"kev_due_date,omitempty"`
	KEVRansomwareUse bool       `json:"kev_ransomware_use"`
	ExploitAvailable bool       `json:"exploit_available"`
	DarkWebMentions  int        `json:"dark_web_mentions"`
	FirstSeenNoctis  *time.Time `json:"first_seen_noctis,omitempty"`
	LastSeenNoctis   *time.Time `json:"last_seen_noctis,omitempty"`
	PriorityScore    *float64   `json:"priority_score,omitempty"`
	PriorityLabel    *string    `json:"priority_label,omitempty"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

// VulnFilter controls which vulnerabilities are returned.
type VulnFilter struct {
	MinPriority *float64
	KEVOnly     bool
	MinEPSS     *float64
	HasExploit  bool
	HasMentions bool
	Query       string // CVE ID search
	Limit       int
	Offset      int
}

// UpsertVulnerability inserts or updates a vulnerability record.
func (s *Store) UpsertVulnerability(ctx context.Context, vuln *Vulnerability) error {
	affectedJSON, err := json.Marshal(vuln.AffectedProducts)
	if err != nil {
		return fmt.Errorf("archive: marshal affected_products: %w", err)
	}
	refsJSON, err := json.Marshal(vuln.ReferenceURLs)
	if err != nil {
		return fmt.Errorf("archive: marshal reference_urls: %w", err)
	}

	cweIDs := vuln.CWEIDs
	if cweIDs == nil {
		cweIDs = []string{}
	}

	const query = `
	INSERT INTO vulnerabilities (
		cve_id, description, cvss_v31_score, cvss_v31_vector, cvss_severity,
		cwe_ids, affected_products, reference_urls, published_at, last_modified_at,
		epss_score, epss_percentile, epss_updated_at,
		kev_listed, kev_date_added, kev_due_date, kev_ransomware_use,
		priority_score, priority_label, updated_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,NOW())
	ON CONFLICT (cve_id) DO UPDATE SET
		description = COALESCE(EXCLUDED.description, vulnerabilities.description),
		cvss_v31_score = COALESCE(EXCLUDED.cvss_v31_score, vulnerabilities.cvss_v31_score),
		cvss_v31_vector = COALESCE(EXCLUDED.cvss_v31_vector, vulnerabilities.cvss_v31_vector),
		cvss_severity = COALESCE(EXCLUDED.cvss_severity, vulnerabilities.cvss_severity),
		epss_score = COALESCE(EXCLUDED.epss_score, vulnerabilities.epss_score),
		epss_percentile = COALESCE(EXCLUDED.epss_percentile, vulnerabilities.epss_percentile),
		epss_updated_at = COALESCE(EXCLUDED.epss_updated_at, vulnerabilities.epss_updated_at),
		kev_listed = COALESCE(EXCLUDED.kev_listed, vulnerabilities.kev_listed),
		kev_date_added = COALESCE(EXCLUDED.kev_date_added, vulnerabilities.kev_date_added),
		kev_due_date = COALESCE(EXCLUDED.kev_due_date, vulnerabilities.kev_due_date),
		kev_ransomware_use = COALESCE(EXCLUDED.kev_ransomware_use, vulnerabilities.kev_ransomware_use),
		priority_score = EXCLUDED.priority_score,
		priority_label = EXCLUDED.priority_label,
		updated_at = NOW()
	RETURNING id`

	err = s.pool.QueryRow(ctx, query,
		vuln.CVEID, vuln.Description, vuln.CVSSV31Score, vuln.CVSSV31Vector, vuln.CVSSSeverity,
		cweIDs, affectedJSON, refsJSON, vuln.PublishedAt, vuln.LastModifiedAt,
		vuln.EPSSScore, vuln.EPSSPercentile, vuln.EPSSUpdatedAt,
		vuln.KEVListed, vuln.KEVDateAdded, vuln.KEVDueDate, vuln.KEVRansomwareUse,
		vuln.PriorityScore, vuln.PriorityLabel,
	).Scan(&vuln.ID)
	if err != nil {
		return fmt.Errorf("archive: upsert vulnerability (%s): %w", vuln.CVEID, err)
	}
	return nil
}

// IncrementVulnMentions increments dark web mention count for a CVE and updates timestamps.
func (s *Store) IncrementVulnMentions(ctx context.Context, cveID string) error {
	const query = `
	UPDATE vulnerabilities
	SET dark_web_mentions = dark_web_mentions + 1,
		last_seen_noctis = NOW(),
		first_seen_noctis = COALESCE(first_seen_noctis, NOW())
	WHERE cve_id = $1`

	_, err := s.pool.Exec(ctx, query, cveID)
	if err != nil {
		return fmt.Errorf("archive: increment vuln mentions (%s): %w", cveID, err)
	}
	return nil
}

// FetchVulnerabilities returns prioritized vulnerabilities matching the filter.
func (s *Store) FetchVulnerabilities(ctx context.Context, filter VulnFilter) ([]Vulnerability, int64, error) {
	limit := normalizeLimit(filter.Limit)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}

	var (
		conditions []string
		args       []any
		argIdx     int
	)

	nextArg := func() string {
		argIdx++
		return fmt.Sprintf("$%d", argIdx)
	}

	if filter.MinPriority != nil {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("priority_score >= %s", p))
		args = append(args, *filter.MinPriority)
	}
	if filter.KEVOnly {
		conditions = append(conditions, "kev_listed = TRUE")
	}
	if filter.MinEPSS != nil {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("epss_score >= %s", p))
		args = append(args, *filter.MinEPSS)
	}
	if filter.HasExploit {
		conditions = append(conditions, "exploit_available = TRUE")
	}
	if filter.HasMentions {
		conditions = append(conditions, "dark_web_mentions > 0")
	}
	if filter.Query != "" {
		p := nextArg()
		conditions = append(conditions, fmt.Sprintf("cve_id ILIKE '%%' || %s || '%%'", p))
		args = append(args, filter.Query)
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int64
	countSQL := "SELECT COUNT(*) FROM vulnerabilities " + where
	if err := s.pool.QueryRow(ctx, countSQL, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("archive: count vulns: %w", err)
	}

	limitP := nextArg()
	offsetP := nextArg()
	sql := fmt.Sprintf(`
	SELECT id, cve_id, description, cvss_v31_score, cvss_v31_vector, cvss_severity,
	       cwe_ids, affected_products, reference_urls, published_at, last_modified_at,
	       epss_score, epss_percentile, epss_updated_at,
	       kev_listed, kev_date_added, kev_due_date, kev_ransomware_use,
	       exploit_available, dark_web_mentions, first_seen_noctis, last_seen_noctis,
	       priority_score, priority_label, created_at, updated_at
	FROM vulnerabilities %s
	ORDER BY priority_score DESC NULLS LAST
	LIMIT %s OFFSET %s`, where, limitP, offsetP)
	args = append(args, limit, offset)

	rows, err := s.pool.Query(ctx, sql, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("archive: fetch vulns: %w", err)
	}
	defer rows.Close()

	var results []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var affectedJSON, refsJSON []byte

		err := rows.Scan(
			&v.ID, &v.CVEID, &v.Description, &v.CVSSV31Score, &v.CVSSV31Vector, &v.CVSSSeverity,
			&v.CWEIDs, &affectedJSON, &refsJSON, &v.PublishedAt, &v.LastModifiedAt,
			&v.EPSSScore, &v.EPSSPercentile, &v.EPSSUpdatedAt,
			&v.KEVListed, &v.KEVDateAdded, &v.KEVDueDate, &v.KEVRansomwareUse,
			&v.ExploitAvailable, &v.DarkWebMentions, &v.FirstSeenNoctis, &v.LastSeenNoctis,
			&v.PriorityScore, &v.PriorityLabel, &v.CreatedAt, &v.UpdatedAt,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("archive: scan vuln: %w", err)
		}

		if len(affectedJSON) > 0 {
			json.Unmarshal(affectedJSON, &v.AffectedProducts)
		}
		if len(refsJSON) > 0 {
			json.Unmarshal(refsJSON, &v.ReferenceURLs)
		}

		results = append(results, v)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("archive: fetch vulns rows: %w", err)
	}

	return results, total, nil
}
