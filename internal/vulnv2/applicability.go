package vulnv2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

type truth int

const (
	unknown truth = iota
	no
	yes
)

type cpeMatch struct {
	Vulnerable     bool   `json:"vulnerable"`
	Criteria       string `json:"criteria"`
	StartIncluding string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}
type configNode struct {
	Operator string       `json:"operator"`
	Negate   bool         `json:"negate"`
	Matches  []cpeMatch   `json:"cpeMatch"`
	Nodes    []configNode `json:"nodes"`
	Children []configNode `json:"children"`
}

func numericVersion(v string) ([]uint64, bool) {
	if len(v) > 128 {
		return nil, false
	}
	parts := strings.Split(v, ".")
	out := make([]uint64, len(parts))
	for i, p := range parts {
		n, e := strconv.ParseUint(p, 10, 64)
		if e != nil {
			return nil, false
		}
		out[i] = n
	}
	return out, true
}
func compareVersion(a, b string) (int, bool) {
	aa, ok := numericVersion(a)
	if !ok {
		return 0, false
	}
	bb, ok := numericVersion(b)
	if !ok {
		return 0, false
	}
	for i := 0; i < max(len(aa), len(bb)); i++ {
		var x, y uint64
		if i < len(aa) {
			x = aa[i]
		}
		if i < len(bb) {
			y = bb[i]
		}
		if x < y {
			return -1, true
		}
		if x > y {
			return 1, true
		}
	}
	return 0, true
}
func matchVersion(m cpeMatch, cpe, version string) truth {
	parts := strings.Split(m.Criteria, ":")
	asset := strings.Split(cpe, ":")
	if len(parts) != 13 || len(asset) != 13 || parts[0] != "cpe" || parts[1] != "2.3" || asset[0] != "cpe" || asset[1] != "2.3" {
		return unknown
	}
	for i := 2; i < 13; i++ {
		if i == 5 {
			continue
		}
		if strings.ContainsAny(parts[i], `\?`) {
			return unknown
		}
		if parts[i] != "*" && parts[i] != asset[i] {
			if i <= 4 {
				return no
			}
			return unknown
		}
	}
	if !m.Vulnerable {
		return unknown
	}
	if version == "" {
		return unknown
	}
	if _, ok := numericVersion(version); !ok {
		return unknown
	}
	if parts[5] != "*" {
		cmp, ok := compareVersion(version, parts[5])
		if !ok {
			return unknown
		}
		if cmp != 0 {
			return no
		}
	}
	bounds := []struct {
		value string
		kind  int
	}{{m.StartIncluding, 0}, {m.StartExcluding, 1}, {m.EndIncluding, 2}, {m.EndExcluding, 3}}
	for _, b := range bounds {
		if b.value == "" {
			continue
		}
		cmp, ok := compareVersion(version, b.value)
		if !ok {
			return unknown
		}
		if b.kind == 0 && cmp < 0 || b.kind == 1 && cmp <= 0 || b.kind == 2 && cmp > 0 || b.kind == 3 && cmp >= 0 {
			return no
		}
	}
	return yes
}
func combine(items []truth, operator string) truth {
	if len(items) == 0 {
		return unknown
	}
	hasUnknown := false
	for _, v := range items {
		if v == unknown {
			hasUnknown = true
		}
		if operator == "AND" && v == no {
			return no
		}
		if operator == "OR" && v == yes {
			return yes
		}
	}
	if hasUnknown {
		return unknown
	}
	if operator == "AND" {
		return yes
	}
	if operator == "OR" {
		return no
	}
	return unknown
}
func evalNode(n configNode, cpe, version string, depth int) truth {
	if depth > 8 || len(n.Matches) > 1000 {
		return unknown
	}
	items := []truth{}
	for _, m := range n.Matches {
		items = append(items, matchVersion(m, cpe, version))
	}
	for _, child := range append(n.Nodes, n.Children...) {
		items = append(items, evalNode(child, cpe, version, depth+1))
	}
	operator := n.Operator
	if operator == "" {
		operator = "OR"
	}
	v := combine(items, operator)
	if n.Negate {
		if v == yes {
			return no
		}
		if v == no {
			return yes
		}
	}
	return v
}

// Evaluate supports numeric dotted versions and explicit CPE 2.3 predicates.
// Unsupported versions, complex CPE escaping and missing inventory stay unknown.
func Evaluate(body json.RawMessage, cpe, version string) (string, string) {
	var record struct {
		Configurations []configNode `json:"configurations"`
	}
	if json.Unmarshal(body, &record) != nil {
		return "unknown", "invalid_nvd_record"
	}
	if version == "" {
		return "unknown", "asset_version_unknown"
	}
	items := []truth{}
	for _, n := range record.Configurations {
		items = append(items, evalNode(n, cpe, version, 0))
	}
	switch combine(items, "OR") {
	case yes:
		return "affected_version", "supported_numeric_cpe_range_matches_inventory; exposure_unknown"
	case no:
		return "not_affected_version", "supported_numeric_cpe_range_excludes_inventory; exposure_unknown"
	default:
		return "unknown", "unsupported_or_incomplete_configuration; exposure_unknown"
	}
}
func RefreshApplicabilityTx(ctx context.Context, tx pgx.Tx, cve string) error {
	if e := intelligence.LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	rows, e := tx.Query(ctx, `SELECT f.snapshot_id::text,f.body,s.expires_at,a.id::text,a.revision,a.cpe,COALESCE(a.version,'') FROM noctis_v2.vulnerability_facts f JOIN noctis_v2.feed_snapshots s ON s.id=f.snapshot_id CROSS JOIN (SELECT DISTINCT ON(id) * FROM noctis_v2.asset_versions ORDER BY id,revision DESC)a WHERE f.cve=$1 AND s.kind='nvd' ORDER BY s.as_of DESC LIMIT 1000`, cve)
	if e != nil {
		return e
	}
	type result struct {
		snapshot, asset, status, reason string
		revision                        int
	}
	results := []result{}
	for rows.Next() {
		var r result
		var body []byte
		var cpe, version string
		var expires time.Time
		if e = rows.Scan(&r.snapshot, &body, &expires, &r.asset, &r.revision, &cpe, &version); e != nil {
			rows.Close()
			return e
		}
		r.status, r.reason = Evaluate(body, cpe, version)
		if !expires.After(time.Now().UTC()) {
			r.status = "unknown"
			r.reason = "feed_snapshot_stale"
		}
		results = append(results, r)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	if len(results) >= 1000 {
		return errors.New("applicability projection limit reached")
	}
	for _, r := range results {
		tag, err := tx.Exec(ctx, `INSERT INTO noctis_v2.local_applicability(snapshot_id,cve,asset_id,asset_revision,status,reason) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, r.snapshot, cve, r.asset, r.revision, r.status, r.reason)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 && r.status == "affected_version" {
			if e = publishApplicabilityTx(ctx, tx, cve, r.snapshot, r.asset, r.revision); e != nil {
				return e
			}
		}
	}
	return nil
}

func publishApplicabilityTx(ctx context.Context, tx pgx.Tx, cve, snapshot, asset string, assetRevision int) error {
	rows, e := tx.Query(ctx, `SELECT ic.id::text,ic.revision,cr.body,ob.observation_id::text,ob.evidence FROM noctis_v2.intelligence_cases ic JOIN noctis_v2.case_revisions cr ON cr.case_id=ic.id AND cr.revision=ic.revision CROSS JOIN LATERAL(SELECT s.observation_id,s.evidence FROM noctis_v2.case_memberships m JOIN noctis_v2.observable_sightings s ON s.observation_id=m.observation_id WHERE m.case_id=ic.id AND s.observable_type='cve' AND s.value=$1 ORDER BY s.observation_id LIMIT 1)ob ORDER BY ic.id FOR UPDATE OF ic`, cve)
	if e != nil {
		return e
	}
	type target struct {
		id, obs   string
		revision  int64
		body, ref []byte
	}
	targets := []target{}
	for rows.Next() {
		var t target
		if e = rows.Scan(&t.id, &t.revision, &t.body, &t.obs, &t.ref); e != nil {
			rows.Close()
			return e
		}
		targets = append(targets, t)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	for _, t := range targets {
		key := fmt.Sprintf("applicability:%s:%s:%s:%d:affected_version", t.id, cve, asset, assetRevision)
		description := "The inventory version matches an affected range in the NVD advisory. Local exposure and compromise are unknown; KEV describes global exploitation."
		changeID := uuid.NewString()
		change, _ := json.Marshal(map[string]any{"id": changeID, "case_id": t.id, "kind": "local_applicability", "title": cve + ": inventory version in affected range", "description": description, "citations": []json.RawMessage{json.RawMessage(t.ref)}, "snapshot_id": snapshot, "asset_id": asset, "asset_revision": assetRevision, "local_exposure": "unknown", "priority_reason": "inventory_version_matches_published_range"})
		tag, e := tx.Exec(ctx, `INSERT INTO noctis_v2.case_changes(id,case_id,observation_id,body,material_key) VALUES($1,$2,$3,$4,$5) ON CONFLICT(material_key) DO NOTHING`, changeID, t.id, t.obs, string(change), key)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			continue
		}
		var body map[string]any
		if e = json.Unmarshal(t.body, &body); e != nil {
			return e
		}
		body["revision"] = fmt.Sprint(t.revision + 1)
		body["supersedes"] = fmt.Sprint(t.revision)
		body["local_applicability"] = "affected_version"
		body["local_exposure"] = "unknown"
		body["priority_reason"] = "inventory_version_matches_published_range"
		body["applicability_snapshot_id"] = snapshot
		raw, _ := json.Marshal(body)
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.case_revisions(case_id,revision,body) VALUES($1,$2,$3)`, t.id, t.revision+1, string(raw)); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE noctis_v2.intelligence_cases SET revision=$2,updated_at=clock_timestamp() WHERE id=$1`, t.id, t.revision+1); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE noctis_v2.briefs SET invalidated=true WHERE body::text LIKE '%'||$1||'%'`, t.obs); e != nil {
			return e
		}
	}
	return nil
}
