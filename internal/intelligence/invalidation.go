package intelligence

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
)

// InvalidateProjectionTx closes the entire support graph while publication is
// fenced by the same transaction lock. Historical versions remain attributable.
func InvalidateProjectionTx(ctx context.Context, tx pgx.Tx, roots []ClaimVersion, observations []string, reason string) error {
	if err := LockProjectionTx(ctx, tx); err != nil {
		return err
	}
	if roots == nil {
		roots = []ClaimVersion{}
	}
	if observations == nil {
		observations = []string{}
	}
	raw, _ := json.Marshal(roots)
	rows, err := tx.Query(ctx, `WITH RECURSIVE affected(id,revision) AS (
 SELECT id,revision FROM jsonb_to_recordset($1::jsonb) AS r(id uuid,revision integer)
 UNION SELECT c.id,c.revision FROM noctis_v2.claim_versions c WHERE EXISTS(SELECT FROM unnest($2::text[]) o(id) WHERE c.evidence::text LIKE '%'||o.id||'%')
 UNION SELECT d.claim_id,d.claim_revision FROM noctis_v2.claim_dependencies d JOIN affected a ON d.dependency_id=a.id AND d.dependency_revision=a.revision WHERE d.relation IN('supports','depends_on')),
 invalid AS(UPDATE noctis_v2.claim_versions c SET invalidated=true FROM affected a WHERE c.id=a.id AND c.revision=a.revision RETURNING c.case_id)
 SELECT DISTINCT case_id::text FROM invalid UNION SELECT case_id::text FROM noctis_v2.case_memberships WHERE observation_id::text=ANY($2)`, string(raw), observations)
	if err != nil {
		return err
	}
	cases := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		cases = append(cases, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `WITH updated AS(UPDATE noctis_v2.intelligence_cases SET revision=revision+1,updated_at=clock_timestamp() WHERE id::text=ANY($1::text[]) RETURNING id,revision)
 INSERT INTO noctis_v2.case_revisions(case_id,revision,body) SELECT u.id,u.revision,old.body||jsonb_build_object('revision',u.revision::text,'supersedes',(u.revision-1)::text,'claims_status','needs_revalidation','requires_review',true,'current_for_alerts',false,'invalidation_reason',$2::text) FROM updated u JOIN noctis_v2.case_revisions old ON old.case_id=u.id AND old.revision=u.revision-1`, cases, reason)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE noctis_v2.briefs b SET invalidated=true,body=body||jsonb_build_object('invalidated',true,'requires_review',true,'current_for_alerts',false,'invalidation_reason',$3::text) WHERE EXISTS(SELECT FROM noctis_v2.case_memberships m WHERE m.case_id::text=ANY($1::text[]) AND b.body::text LIKE '%'||m.observation_id::text||'%') OR EXISTS(SELECT FROM unnest($2::text[]) o(id) WHERE b.body::text LIKE '%'||o.id||'%')`, cases, observations, reason)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE noctis_v2.outbox b SET state='blocked',blocked_reason=$3 WHERE state='queued' AND (EXISTS(SELECT FROM noctis_v2.case_memberships m WHERE m.case_id::text=ANY($1::text[]) AND b.body::text LIKE '%'||m.observation_id::text||'%') OR EXISTS(SELECT FROM unnest($2::text[]) o(id) WHERE b.body::text LIKE '%'||o.id||'%'))`, cases, observations, reason)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE noctis_v2.case_attention SET revision=revision+1,mode='automatic',reason=$2,silent_until=NULL,exception=NULL WHERE case_id::text=ANY($1::text[])`, cases, reason)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.invalidated_products(job_id,reason) SELECT p.job_id,$3 FROM noctis_v2.ai_products p WHERE EXISTS(SELECT FROM unnest($1::text[]||$2::text[]) affected(id) WHERE p.dependencies::text LIKE '%'||affected.id||'%') ON CONFLICT DO NOTHING`, cases, observations, reason)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.case_changes(id,case_id,observation_id,body,material_key) SELECT gen_random_uuid(),ic.id,m.observation_id,jsonb_build_object('case_id',ic.id,'kind','support_invalidated','title','Revalidación necesaria','description',$2::text,'revision',ic.revision), 'invalidation:'||ic.id::text||':'||ic.revision::text FROM noctis_v2.intelligence_cases ic JOIN LATERAL(SELECT observation_id FROM noctis_v2.case_memberships WHERE case_id=ic.id ORDER BY observation_id LIMIT 1)m ON true WHERE ic.id::text=ANY($1::text[]) ON CONFLICT DO NOTHING`, cases, reason)
	return err
}
