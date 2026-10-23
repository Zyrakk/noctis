package runtimev2

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/legacyimport"
	"github.com/Zyrakk/noctis/internal/vulnv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type pageCursor struct {
	Kind string    `json:"kind"`
	ID   string    `json:"id"`
	At   time.Time `json:"at"`
}

func pageRequest(r *http.Request, kind string) (pageCursor, int, error) {
	cursor := pageCursor{Kind: kind}
	limit := 50
	if s := r.URL.Query().Get("limit"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > 200 {
			return cursor, 0, errors.New("invalid page limit")
		}
		limit = n
	}
	if s := r.URL.Query().Get("cursor"); s != "" {
		raw, e := base64.RawURLEncoding.DecodeString(s)
		if e != nil || len(raw) > 2048 {
			return cursor, 0, errors.New("invalid cursor")
		}
		if e = json.Unmarshal(raw, &cursor); e != nil || cursor.Kind != kind || cursor.ID == "" {
			return cursor, 0, errors.New("cursor scope mismatch")
		}
	}
	return cursor, limit, nil
}
func pageResponse(w http.ResponseWriter, data any, next *pageCursor) {
	var cursor any
	if next != nil {
		raw, _ := json.Marshal(next)
		cursor = base64.RawURLEncoding.EncodeToString(raw)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(map[string]any{"data": data, "meta": map[string]any{"generated_at": time.Now().UTC(), "coverage": "partial; independence_unknown", "degraded": true, "next_cursor": cursor}})
}
func jsonPage(ctx context.Context, w http.ResponseWriter, r *http.Request, c *pgx.Conn, path, query string, args ...any) error {
	cursor, limit, e := pageRequest(r, path)
	if e != nil {
		failure(w, 400, "invalid_pagination")
		return nil
	}
	args = append(args, cursor.ID, limit+1)
	rows, e := c.Query(ctx, query, args...)
	if e != nil {
		return e
	}
	defer rows.Close()
	data := []json.RawMessage{}
	ids := []string{}
	for rows.Next() {
		var id string
		var body []byte
		if e = rows.Scan(&id, &body); e != nil {
			return e
		}
		ids = append(ids, id)
		data = append(data, json.RawMessage(body))
	}
	if e = rows.Err(); e != nil {
		return e
	}
	var next *pageCursor
	if len(data) > limit {
		next = &pageCursor{Kind: path, ID: ids[limit-1]}
		data = data[:limit]
	}
	pageResponse(w, data, next)
	return nil
}

func (a *API) readDomain(w http.ResponseWriter, r *http.Request, c *pgx.Conn, path string) (bool, error) {
	ctx := r.Context()
	switch {
	case path == "assets":
		return true, jsonPage(ctx, w, r, c, path, `SELECT id::text,to_jsonb(a) FROM (SELECT DISTINCT ON(id) * FROM noctis_v2.asset_versions ORDER BY id,revision DESC)a WHERE ($1='' OR id::text>$1) ORDER BY id LIMIT $2`)
	case path == "applicability":
		return true, jsonPage(ctx, w, r, c, path, `SELECT snapshot_id::text||':'||cve||':'||asset_id::text||':'||asset_revision::text,to_jsonb(a)||jsonb_build_object('effective_status',CASE WHEN s.expires_at>clock_timestamp() THEN status ELSE 'unknown' END,'local_exposure','unknown','freshness',CASE WHEN s.expires_at>clock_timestamp() THEN 'current' ELSE 'stale' END) FROM noctis_v2.local_applicability a JOIN noctis_v2.feed_snapshots s ON s.id=a.snapshot_id WHERE ($1='' OR snapshot_id::text||':'||cve||':'||asset_id::text||':'||asset_revision::text>$1) ORDER BY snapshot_id::text||':'||cve||':'||asset_id::text||':'||asset_revision::text LIMIT $2`)
	case path == "enrichment-policies":
		return true, jsonPage(ctx, w, r, c, path, `SELECT provider,to_jsonb(p) FROM noctis_v2.enrichment_policies p WHERE ($1='' OR provider>$1) ORDER BY provider LIMIT $2`)
	case path == "changes" || strings.HasPrefix(path, "cases/") && strings.HasSuffix(path, "/timeline"):
		caseID := r.URL.Query().Get("case_id")
		if path != "changes" {
			caseID = strings.TrimSuffix(strings.TrimPrefix(path, "cases/"), "/timeline")
		}
		if caseID != "" {
			if _, e := uuid.Parse(caseID); e != nil {
				return true, pgx.ErrNoRows
			}
		}
		return true, jsonPage(ctx, w, r, c, path+":"+caseID, `SELECT id::text,body||jsonb_build_object('created_at',created_at) FROM noctis_v2.case_changes WHERE ($1='' OR case_id::text=$1) AND ($2='' OR id::text>$2) ORDER BY id LIMIT $3`, caseID)
	case path == "claims":
		return true, jsonPage(ctx, w, r, c, path+":"+r.URL.Query().Get("case_id"), `SELECT id::text,to_jsonb(c)||jsonb_build_object('dependencies',COALESCE((SELECT jsonb_agg(to_jsonb(d)||jsonb_build_object('status',cv.status,'invalidated',cv.invalidated)) FROM noctis_v2.claim_dependencies d JOIN noctis_v2.claim_versions cv ON cv.id=d.dependency_id AND cv.revision=d.dependency_revision WHERE d.claim_id=c.id AND d.claim_revision=c.revision),'[]')) FROM (SELECT DISTINCT ON(id) * FROM noctis_v2.claim_versions ORDER BY id,revision DESC) c WHERE ($1='' OR c.case_id::text=$1) AND ($2='' OR id::text>$2) ORDER BY id LIMIT $3`, r.URL.Query().Get("case_id"))
	case path == "entities":
		return true, jsonPage(ctx, w, r, c, path, `SELECT e.id::text,jsonb_build_object('id',e.id,'kind',e.kind,'aliases',COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM (SELECT * FROM noctis_v2.entity_aliases WHERE entity_id=e.id AND NOT revoked ORDER BY id LIMIT 10) a),'[]'::jsonb)) FROM noctis_v2.entities e WHERE ($1='' OR e.id::text>$1) ORDER BY e.id LIMIT $2`)
	case strings.HasPrefix(path, "entities/") && (strings.HasSuffix(path, "/aliases") || strings.HasSuffix(path, "/hypotheses")):
		parts := strings.Split(path, "/")
		if len(parts) != 3 {
			return true, pgx.ErrNoRows
		}
		if _, e := uuid.Parse(parts[1]); e != nil {
			return true, pgx.ErrNoRows
		}
		if parts[2] == "aliases" {
			return true, jsonPage(ctx, w, r, c, path, `SELECT id::text,to_jsonb(a) FROM noctis_v2.entity_aliases a WHERE entity_id=$1 AND ($2='' OR id::text>$2) ORDER BY id LIMIT $3`, parts[1])
		}
		return true, jsonPage(ctx, w, r, c, path, `SELECT id::text,to_jsonb(h) FROM noctis_v2.entity_hypotheses h WHERE (left_id=$1 OR right_id=$1) AND ($2='' OR id::text>$2) ORDER BY id LIMIT $3`, parts[1])
	case strings.HasPrefix(path, "entities/") && strings.HasSuffix(path, "/dossier"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "entities/"), "/dossier")
		if _, e := uuid.Parse(id); e != nil {
			return true, pgx.ErrNoRows
		}
		var raw []byte
		e := c.QueryRow(ctx, `SELECT jsonb_build_object('id',e.id,'kind',e.kind,'aliases',COALESCE((SELECT jsonb_agg(to_jsonb(a)) FROM (SELECT * FROM noctis_v2.entity_aliases WHERE entity_id=e.id ORDER BY id LIMIT 50) a),'[]'::jsonb),'hypotheses',COALESCE((SELECT jsonb_agg(to_jsonb(h)) FROM (SELECT * FROM noctis_v2.entity_hypotheses WHERE left_id=e.id OR right_id=e.id ORDER BY id LIMIT 50) h),'[]'::jsonb),'identity_status','unresolved') FROM noctis_v2.entities e WHERE e.id=$1`, id).Scan(&raw)
		if e != nil {
			return true, e
		}
		response(w, json.RawMessage(raw))
		return true, nil
	case path == "graph":
		id := r.URL.Query().Get("root")
		if _, e := uuid.Parse(id); e != nil {
			failure(w, 400, "graph_root_required")
			return true, nil
		}
		hops := 1
		if s := r.URL.Query().Get("hops"); s != "" {
			n, e := strconv.Atoi(s)
			if e != nil || n < 1 || n > 2 {
				failure(w, 400, "graph_hops_invalid")
				return true, nil
			}
			hops = n
		}
		rows, e := c.Query(ctx, `WITH RECURSIVE walk(id,depth) AS (SELECT $1::uuid,0 UNION SELECT CASE WHEN h.left_id=w.id THEN h.right_id ELSE h.left_id END,w.depth+1 FROM walk w CROSS JOIN LATERAL (SELECT * FROM noctis_v2.entity_hypotheses h WHERE (h.left_id=w.id OR h.right_id=w.id) AND h.status='unresolved' ORDER BY h.id LIMIT 20) h WHERE w.depth<$2) SELECT e.id::text,to_jsonb(e) FROM noctis_v2.entities e WHERE e.id IN(SELECT id FROM walk) ORDER BY e.id LIMIT 101`, id, hops)
		if e != nil {
			return true, e
		}
		nodes := []json.RawMessage{}
		ids := []string{}
		for rows.Next() {
			var id string
			var raw []byte
			if e = rows.Scan(&id, &raw); e != nil {
				rows.Close()
				return true, e
			}
			ids = append(ids, id)
			nodes = append(nodes, json.RawMessage(raw))
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return true, e
		}
		truncated := len(nodes) > 100
		if truncated {
			nodes = nodes[:100]
			ids = ids[:100]
		}
		rows, e = c.Query(ctx, `SELECT to_jsonb(h) FROM noctis_v2.entity_hypotheses h WHERE h.left_id::text=ANY($1) AND h.right_id::text=ANY($1) ORDER BY h.id LIMIT 201`, ids)
		if e != nil {
			return true, e
		}
		edges := []json.RawMessage{}
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				rows.Close()
				return true, e
			}
			edges = append(edges, json.RawMessage(raw))
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return true, e
		}
		if len(edges) > 200 {
			edges = edges[:200]
			truncated = true
		}
		var neighborTruncated bool
		if e = c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM unnest($1::text[]) n(id) WHERE (SELECT count(*) FROM noctis_v2.entity_hypotheses h WHERE (h.left_id::text=n.id OR h.right_id::text=n.id) AND h.status='unresolved')>20)`, ids).Scan(&neighborTruncated); e != nil {
			return true, e
		}
		reasons := []string{}
		if truncated {
			reasons = append(reasons, "node_or_edge_limit")
		}
		if neighborTruncated {
			reasons = append(reasons, "neighbor_limit")
		}
		response(w, map[string]any{"nodes": nodes, "edges": edges, "truncated": truncated || neighborTruncated, "max_nodes": 100, "max_edges": 200, "max_neighbors": 20, "truncation_reasons": reasons, "window": "current unresolved hypotheses", "max_hops": hops, "identity_status": "hypotheses_only"})
		return true, nil
	case path == "indicators":
		return true, jsonPage(ctx, w, r, c, path, `SELECT id::text,to_jsonb(i)||jsonb_build_object('effective_status',CASE WHEN status='revoked' THEN 'revoked' WHEN valid_until<=clock_timestamp() THEN 'expired' WHEN valid_from>clock_timestamp() THEN 'not_yet_valid' ELSE 'active' END,'sightings',(SELECT count(*) FROM noctis_v2.observable_sightings s WHERE s.observable_type=i.observable_type AND s.value=i.value)) FROM (SELECT DISTINCT ON(id) * FROM noctis_v2.indicator_versions ORDER BY id,revision DESC)i WHERE ($1='' OR id::text>$1) ORDER BY id LIMIT $2`)
	case path == "feeds":
		return true, jsonPage(ctx, w, r, c, path, `SELECT id::text,to_jsonb(f)-'payload'||jsonb_build_object('status',CASE WHEN expires_at<=clock_timestamp() THEN 'stale' ELSE 'available' END) FROM noctis_v2.feed_snapshots f WHERE ($1='' OR id::text>$1) ORDER BY id LIMIT $2`)
	case strings.HasPrefix(path, "vulnerabilities/"):
		id := strings.ToUpper(strings.TrimPrefix(path, "vulnerabilities/"))
		return true, jsonPage(ctx, w, r, c, path, `SELECT f.snapshot_id::text,jsonb_build_object('cve',f.cve,'kind',s.kind,'body',f.body,'snapshot_id',s.id,'hash',s.hash,'as_of',s.as_of,'expires_at',s.expires_at,'status',CASE WHEN s.expires_at<=clock_timestamp() THEN 'stale' ELSE 'available' END,'local_applicability','unknown','local_exposure','unknown') FROM noctis_v2.vulnerability_facts f JOIN noctis_v2.feed_snapshots s ON s.id=f.snapshot_id WHERE f.cve=$1 AND ($2='' OR f.snapshot_id::text>$2) ORDER BY f.snapshot_id LIMIT $3`, id)
	case path == "source-imports":
		return true, jsonPage(ctx, w, r, c, path, `SELECT manifest_id,to_jsonb(i)-'manifest' FROM noctis_v2.source_imports i WHERE ($1='' OR manifest_id>$1) ORDER BY manifest_id LIMIT $2`)
	case path == "source-dispositions":
		return true, jsonPage(ctx, w, r, c, path, `SELECT identity,to_jsonb(d) FROM noctis_v2.source_dispositions d WHERE ($1='' OR identity>$1) ORDER BY identity LIMIT $2`)
	case path == "history":
		return true, jsonPage(ctx, w, r, c, path, `SELECT archive_digest||':'||table_name||':'||legacy_id,to_jsonb(h)||jsonb_build_object('epistemic_status','legacy_unvalidated') FROM noctis_v2.legacy_records h WHERE ($1='' OR archive_digest||':'||table_name||':'||legacy_id>$1) ORDER BY archive_digest||':'||table_name||':'||legacy_id LIMIT $2`)
	}
	return false, nil
}

func decodeMutation(r *http.Request, out any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, (4<<20)+1))
	d.DisallowUnknownFields()
	if e := d.Decode(out); e != nil {
		return e
	}
	var trailing any
	if e := d.Decode(&trailing); e != io.EOF {
		return errors.New("trailing JSON input")
	}
	return nil
}
func (a *API) mutateDomain(w http.ResponseWriter, r *http.Request, c *pgx.Conn, path, username string) (bool, error) {
	ctx := r.Context()
	if path == "source-imports" {
		var input struct {
			Manifest legacyimport.SourceManifest `json:"manifest"`
			DryRun   bool                        `json:"dry_run"`
		}
		if e := decodeMutation(r, &input); e != nil {
			return true, e
		}
		receipt, e := (legacyimport.Store{DSN: a.cfg.DatabaseURL}).ImportManifest(ctx, input.Manifest, input.DryRun)
		if e == nil {
			response(w, receipt)
		}
		return true, e
	}
	if path == "history-imports" {
		var input struct {
			Batch  legacyimport.HistoryBatch `json:"batch"`
			DryRun bool                      `json:"dry_run"`
		}
		if e := decodeMutation(r, &input); e != nil {
			return true, e
		}
		receipt, e := (legacyimport.Store{DSN: a.cfg.DatabaseURL}).ImportHistory(ctx, input.Batch, input.DryRun)
		if e == nil {
			response(w, receipt)
		}
		return true, e
	}
	switch path {
	case "claims/judge", "indicators", "indicators/revoke", "entities/hypotheses", "entities/hypotheses/retract", "entities/aliases/revoke", "assets", "enrichment-policies":
	default:
		return false, nil
	}
	tx, e := c.Begin(ctx)
	if e != nil {
		return true, e
	}
	defer tx.Rollback(context.Background())
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return true, e
	}
	var result any = map[string]bool{"applied": true}
	switch path {
	case "assets":
		var input struct {
			ID               string         `json:"id"`
			ExpectedRevision int            `json:"expected_revision"`
			CPE              string         `json:"cpe"`
			Version          *string        `json:"version"`
			Refs             []evidence.Ref `json:"refs"`
		}
		if e = decodeMutation(r, &input); e != nil {
			return true, e
		}
		if _, e = uuid.Parse(input.ID); e != nil {
			return true, e
		}
		if len(input.CPE) > 512 || !strings.HasPrefix(input.CPE, "cpe:2.3:") || input.ExpectedRevision < 0 {
			return true, errors.New("invalid inventory asset")
		}
		if e = intelligence.ValidateEvidenceTx(ctx, tx, input.Refs); e != nil {
			return true, e
		}
		if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,13))`, input.ID); e != nil {
			return true, e
		}
		var revision int
		if e = tx.QueryRow(ctx, `SELECT COALESCE(max(revision),0) FROM noctis_v2.asset_versions WHERE id=$1`, input.ID).Scan(&revision); e != nil {
			return true, e
		}
		if revision != input.ExpectedRevision {
			return true, errors.New("asset revision conflict")
		}
		refs, _ := json.Marshal(input.Refs)
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.asset_versions(id,revision,cpe,version,evidence,producer) VALUES($1,$2,$3,$4,$5,$6)`, input.ID, revision+1, input.CPE, input.Version, string(refs), "operator:"+username); e != nil {
			return true, e
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT cve FROM noctis_v2.vulnerability_facts ORDER BY cve LIMIT 1001`)
		if err != nil {
			return true, err
		}
		cves := []string{}
		for rows.Next() {
			var cve string
			if e = rows.Scan(&cve); e != nil {
				rows.Close()
				return true, e
			}
			cves = append(cves, cve)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return true, e
		}
		if len(cves) > 1000 {
			return true, errors.New("inventory refresh limit exceeded")
		}
		for _, cve := range cves {
			if e = vulnv2.RefreshApplicabilityTx(ctx, tx, cve); e != nil {
				return true, e
			}
		}
		result = map[string]any{"id": input.ID, "revision": revision + 1}
	case "enrichment-policies":
		var input struct {
			Provider        string   `json:"provider"`
			Version         string   `json:"version"`
			ExpectedVersion string   `json:"expected_version"`
			Enabled         bool     `json:"enabled"`
			DataClasses     []string `json:"data_classes"`
			Quota           int      `json:"quota_per_day"`
			TTL             int      `json:"ttl_seconds"`
		}
		if e = decodeMutation(r, &input); e != nil {
			return true, e
		}
		if (input.Provider != "virustotal" && input.Provider != "abuseipdb" && input.Provider != "crtsh") || input.Version == "" || input.Version == input.ExpectedVersion || input.Quota < 0 || input.Quota > 100000 || input.TTL < 1 || input.TTL > 604800 || len(input.DataClasses) > 16 {
			return true, errors.New("invalid provider policy")
		}
		for _, class := range input.DataClasses {
			if class != "public" && class != "organization" && class != "restricted" {
				return true, errors.New("invalid export data class")
			}
		}
		classes, _ := json.Marshal(input.DataClasses)
		var tag pgconn.CommandTag
		var err error
		if input.ExpectedVersion == "" {
			tag, err = tx.Exec(ctx, `INSERT INTO noctis_v2.enrichment_policies(provider,version,enabled,data_classes,quota_per_day,ttl_seconds) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, input.Provider, input.Version, input.Enabled, string(classes), input.Quota, input.TTL)
		} else {
			tag, err = tx.Exec(ctx, `UPDATE noctis_v2.enrichment_policies SET version=$2,enabled=$3,data_classes=$4,quota_per_day=$5,ttl_seconds=$6 WHERE provider=$1 AND version=$7`, input.Provider, input.Version, input.Enabled, string(classes), input.Quota, input.TTL, input.ExpectedVersion)
		}
		e = err
		if e == nil && tag.RowsAffected() != 1 {
			e = errors.New("provider policy revision conflict")
		}
		if e == nil {
			_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.enrichment_policy_revisions(provider,version,body) SELECT provider,version,to_jsonb(p) FROM noctis_v2.enrichment_policies p WHERE provider=$1`, input.Provider)
		}
	case "claims/judge":
		var input struct {
			Claim  intelligence.ClaimVersion `json:"claim"`
			Status string                    `json:"status"`
			Reason string                    `json:"reason"`
			Refs   []evidence.Ref            `json:"refs"`
		}
		if e = decodeMutation(r, &input); e != nil {
			return true, e
		}
		e = intelligence.JudgeClaimTx(ctx, tx, input.Claim, input.Status, "operator:"+username, input.Reason, input.Refs)
	case "indicators":
		var input intelligence.Indicator
		if e = decodeMutation(r, &input); e != nil {
			return true, e
		}
		input.Producer = "operator:" + username
		e = intelligence.CreateIndicatorTx(ctx, tx, input)
	case "indicators/revoke":
		var input struct {
			ID       string `json:"id"`
			Revision int    `json:"revision"`
			Reason   string `json:"reason"`
		}
		if e = decodeMutation(r, &input); e != nil {
			return true, e
		}
		e = intelligence.RevokeIndicatorTx(ctx, tx, input.ID, input.Revision, "operator:"+username, input.Reason)
	case "entities/hypotheses":
		var input struct {
			Left     string         `json:"left"`
			Right    string         `json:"right"`
			Relation string         `json:"relation"`
			Refs     []evidence.Ref `json:"refs"`
		}
		if e = decodeMutation(r, &input); e != nil {
			return true, e
		}
		var id string
		id, e = intelligence.ProposeIdentityTx(ctx, tx, input.Left, input.Right, input.Relation, input.Refs)
		result = map[string]string{"id": id, "status": "unresolved"}
	case "entities/aliases/revoke":
		var input struct {
			ID string `json:"id"`
		}
		if e = decodeMutation(r, &input); e != nil {
			return true, e
		}
		e = intelligence.RevokeEntityAliasTx(ctx, tx, input.ID)
	case "entities/hypotheses/retract":
		var input struct {
			ID string `json:"id"`
		}
		if e = decodeMutation(r, &input); e != nil {
			return true, e
		}
		tag, err := tx.Exec(ctx, `UPDATE noctis_v2.entity_hypotheses SET status='retracted' WHERE id=$1 AND status='unresolved'`, input.ID)
		e = err
		if e == nil && tag.RowsAffected() != 1 {
			e = errors.New("hypothesis unavailable")
		}
	}
	if e != nil {
		return true, e
	}
	audit, _ := json.Marshal(result)
	if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.domain_audit(id,actor,action,result) VALUES($1,$2,$3,$4)`, uuid.NewString(), username, path, string(audit)); e != nil {
		return true, e
	}
	if e = tx.Commit(ctx); e != nil {
		return true, e
	}
	response(w, result)
	return true, nil
}
