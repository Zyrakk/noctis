package runtimev2

import (
	"context"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func retentionTx(ctx context.Context, tx pgx.Tx, in operationInput) (any, error) {
	if _, e := uuid.Parse(in.SourceID); e != nil {
		return nil, reject(400, "source_required")
	}
	if in.DataClass == "" || len(in.DataClass) > 64 {
		return nil, reject(400, "data_class_required")
	}
	switch in.Action {
	case "policy":
		if in.RetainSeconds < 0 || in.RetainSeconds > 10*365*24*3600 {
			return nil, reject(400, "invalid_retention")
		}
		var current int64
		e := tx.QueryRow(ctx, `SELECT revision FROM noctis_v2.retention_policies WHERE source_id=$1 AND data_class=$2`, in.SourceID, in.DataClass).Scan(&current)
		if e != nil && e != pgx.ErrNoRows {
			return nil, e
		}
		if current != in.ExpectedRevision {
			return nil, &operationError{409, "stale_revision", current}
		}
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.retention_policies(source_id,data_class,retain_seconds) VALUES($1,$2,$3) ON CONFLICT(source_id,data_class) DO UPDATE SET retain_seconds=excluded.retain_seconds,revision=noctis_v2.retention_policies.revision+1`, in.SourceID, in.DataClass, in.RetainSeconds)
		return map[string]any{"revision": current + 1}, e
	case "run":
		var revision int64
		var seconds int64
		e := tx.QueryRow(ctx, `SELECT revision,retain_seconds FROM noctis_v2.retention_policies WHERE source_id=$1 AND data_class=$2`, in.SourceID, in.DataClass).Scan(&revision, &seconds)
		if e != nil {
			return nil, e
		}
		var count int64
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations WHERE source_id=$1 AND data_class=$2 AND retention_expired_at IS NULL AND collected_at<clock_timestamp()-make_interval(secs=>$3)`, in.SourceID, in.DataClass, float64(seconds)).Scan(&count); e != nil {
			return nil, e
		}
		if in.DryRun {
			return map[string]any{"dry_run": true, "eligible": count, "policy_revision": revision}, nil
		}
		if in.ExpectedRevision != revision {
			return nil, &operationError{409, "stale_revision", revision}
		}
		id := uuid.NewString()
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.retention_runs(id,source_id,data_class,policy_revision,cutoff) VALUES($1,$2,$3,$4,clock_timestamp()-make_interval(secs=>$5))`, id, in.SourceID, in.DataClass, revision, float64(seconds))
		return map[string]any{"run_id": id, "eligible": count, "state": "active", "next_action": "batch"}, e
	case "batch":
		if in.Limit < 1 || in.Limit > 200 {
			return nil, reject(400, "batch_limit_required")
		}
		var state string
		var policyCurrent bool
		if e := tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.retention_runs r JOIN noctis_v2.retention_policies p ON p.source_id=r.source_id AND p.data_class=r.data_class WHERE r.id::text=$1 AND r.policy_revision=p.revision)`, in.RunID).Scan(&policyCurrent); e != nil {
			return nil, e
		}
		if !policyCurrent {
			return nil, reject(409, "retention_policy_changed_or_run_unavailable")
		}
		if e := tx.QueryRow(ctx, `SELECT state FROM noctis_v2.retention_runs WHERE id::text=$1 AND source_id=$2 AND data_class=$3 FOR UPDATE`, in.RunID, in.SourceID, in.DataClass).Scan(&state); e != nil {
			return nil, e
		}
		if state == "complete" {
			return map[string]any{"run_id": in.RunID, "state": "complete", "processed": 0}, nil
		}
		rows, e := tx.Query(ctx, `SELECT o.id::text FROM noctis_v2.observations o JOIN noctis_v2.retention_runs r ON r.id::text=$1 WHERE o.source_id=r.source_id AND o.data_class=r.data_class AND o.collected_at<r.cutoff AND o.retention_expired_at IS NULL ORDER BY o.id LIMIT $2 FOR UPDATE OF o`, in.RunID, in.Limit)
		if e != nil {
			return nil, e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return nil, e
			}
			ids = append(ids, id)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return nil, e
		}
		if e = intelligence.InvalidateProjectionTx(ctx, tx, nil, ids, "retention_expired"); e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.retention_tombstones(observation_id,source_id,hash,representation,run_id) SELECT id,source_id,hash,representation,$2 FROM noctis_v2.observations WHERE id::text=ANY($1::text[]) ON CONFLICT DO NOTHING`, ids, in.RunID)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `UPDATE noctis_v2.observations SET retention_expired_at=clock_timestamp() WHERE id::text=ANY($1::text[])`, ids)
		if e != nil {
			return nil, e
		}
		if e = redactRetentionTx(ctx, tx, ids); e != nil {
			return nil, e
		}
		// Blob rows preserve hash references. Bytes are physically cleared only when
		// no nonexpired observation retains the shared content.
		_, e = tx.Exec(ctx, `UPDATE noctis_v2.content_blobs b SET payload=''::bytea WHERE EXISTS(SELECT FROM noctis_v2.observations o WHERE o.hash=b.hash AND o.representation=b.representation AND o.id::text=ANY($1::text[])) AND NOT EXISTS(SELECT FROM noctis_v2.observations o WHERE o.hash=b.hash AND o.representation=b.representation AND o.retention_expired_at IS NULL)`, ids)
		if e != nil {
			return nil, e
		}
		if len(ids) < in.Limit {
			state = "complete"
		}
		_, e = tx.Exec(ctx, `UPDATE noctis_v2.retention_runs SET processed=processed+$2,state=$3 WHERE id::text=$1`, in.RunID, len(ids), state)
		return map[string]any{"run_id": in.RunID, "state": state, "processed": len(ids), "tombstones": ids}, e
	default:
		return nil, reject(400, "invalid_retention_action")
	}
}

func redactRetentionTx(ctx context.Context, tx pgx.Tx, ids []string) error {
	rows, e := tx.Query(ctx, `SELECT ic.id::text FROM noctis_v2.intelligence_cases ic JOIN noctis_v2.case_revisions cr ON cr.case_id=ic.id AND cr.revision=ic.revision WHERE cr.body->>'invalidation_reason'='retention_expired'`)
	if e != nil {
		return e
	}
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return e
	}
	// All externally served derived forms are redacted, including snapshots and
	// exports; reference hashes/IDs remain as explicit unavailable provenance.
	queries := []string{
		`UPDATE noctis_v2.legacy_records h SET body=jsonb_build_object('archive_digest',h.archive_digest,'table',h.table_name,'legacy_id',h.legacy_id,'source_id',h.source_id,'published_at',h.body->'published_at','availability','retention_expired','epistemic_status','legacy_unvalidated') WHERE EXISTS(SELECT FROM noctis_v2.observations o WHERE o.source_id=h.source_id AND o.native_id='legacy:'||h.archive_digest||':'||h.table_name||':'||h.legacy_id AND o.id::text=ANY($1::text[]))`,
		`UPDATE noctis_v2.ai_jobs j SET result=NULL,snapshot='{}',state=CASE WHEN state='cancelled' THEN state ELSE 'dependency_blocked' END,error_code='retention_expired',lease_until=NULL WHERE EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE j.snapshot::text LIKE '%'||o.id||'%')`,
		`UPDATE noctis_v2.ai_products p SET result='{}',dependencies='{}' WHERE EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE p.dependencies::text LIKE '%'||o.id||'%')`,
		`UPDATE noctis_v2.ai_query_results q SET plan='{}',rows='[]',dependencies='[]' WHERE EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE q.dependencies::text LIKE '%'||o.id||'%')`,
		`UPDATE noctis_v2.claim_versions c SET subject='unavailable',predicate='retention_expired',object='unavailable',reason='retention_expired',invalidated=true WHERE c.case_id::text=ANY($1::text[]) OR EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE c.evidence::text LIKE '%'||o.id||'%')`,
		`UPDATE noctis_v2.case_revisions cr SET body=jsonb_build_object('id',cr.case_id,'revision',cr.revision::text,'summary','Evidence expired; content removed','status','unavailable','requires_review',true) WHERE EXISTS(SELECT FROM noctis_v2.case_memberships m WHERE m.case_id=cr.case_id AND (m.observation_id::text=ANY($1::text[]) OR m.case_id::text=ANY($1::text[])))`,
		`UPDATE noctis_v2.intelligence_cases ic SET title='Evidence expired' WHERE EXISTS(SELECT FROM noctis_v2.case_memberships m WHERE m.case_id=ic.id AND (m.observation_id::text=ANY($1::text[]) OR m.case_id::text=ANY($1::text[])))`,
		`UPDATE noctis_v2.case_changes c SET body=jsonb_build_object('id',c.id,'case_id',c.case_id,'kind','retention_expired','title','Content removed by retention policy') WHERE c.observation_id::text=ANY($1::text[]) OR c.case_id::text=ANY($1::text[]) OR EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE c.body::text LIKE '%'||o.id||'%')`,
		`UPDATE noctis_v2.briefs b SET body=jsonb_build_object('period',b.period,'invalidated',true,'invalidation_reason','retention_expired','summary','Content removed by retention policy'),invalidated=true WHERE b.body->>'invalidation_reason'='retention_expired' OR EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE b.body::text LIKE '%'||o.id||'%')`,
		`UPDATE noctis_v2.outbox b SET body=jsonb_build_object('unavailable','retention_expired'),state=CASE WHEN state IN('delivered','uncertain') THEN state ELSE 'blocked' END,blocked_reason='retention_expired' WHERE EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE b.body::text LIKE '%'||o.id||'%')`,
		`UPDATE noctis_v2.private_exports e SET body='{}',expires_at=clock_timestamp() WHERE EXISTS(SELECT FROM noctis_v2.case_memberships m WHERE m.case_id=e.case_id AND (m.observation_id::text=ANY($1::text[]) OR m.case_id::text=ANY($1::text[])))`,
		`UPDATE noctis_v2.analysis_results a SET body='{}' WHERE EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE a.body::text LIKE '%'||o.id||'%')`,
		`UPDATE noctis_v2.analyses SET observables='[]' WHERE observation_id::text=ANY($1::text[])`,
		`UPDATE noctis_v2.observable_sightings SET value='unavailable:'||gen_random_uuid()::text,evidence=jsonb_build_object('observation_id',observation_id,'revision',revision,'availability','retention_expired') WHERE observation_id::text=ANY($1::text[])`,
		`UPDATE noctis_v2.indicator_versions i SET value='unavailable',scope='unavailable',reason='retention_expired',status='revoked' WHERE EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE i.evidence::text LIKE '%'||o.id||'%')`,
		`UPDATE noctis_v2.entity_aliases a SET alias='unavailable',revoked=true WHERE EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE a.evidence::text LIKE '%'||o.id||'%')`,
	}
	for _, q := range queries {
		if _, e := tx.Exec(ctx, q, ids); e != nil {
			return e
		}
	}
	// Receipts may contain prior export/action bodies; only metadata is retained.
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.action_receipts a SET result=jsonb_build_object('unavailable','retention_expired') WHERE EXISTS(SELECT FROM unnest($1::text[]) o(id) WHERE a.result::text LIKE '%'||o.id||'%')`, ids)
	return e
}
