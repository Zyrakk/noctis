package vulnv2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EvaluateCurrentPairTx publishes only the current input identity. The caller owns
// its durable lease and commits this result together with page progress.
// Empty expected identity captures the latest input inside the publication guard.
func EvaluateCurrentPairTx(ctx context.Context, tx pgx.Tx, cve, assetID, expectedGeneration string, expectedAssetRevision int) (bool, error) {
	if err := intelligence.LockProjectionTx(ctx, tx); err != nil {
		return false, err
	}
	var snapshot, generation, selectionReason string
	var body, refsRaw []byte
	var expires time.Time
	var nvdRevision *time.Time
	err := tx.QueryRow(ctx, `SELECT snapshot_id::text,body,nvd_revision,generation,expires_at,selection_reason FROM noctis_v2.nvd_current_selection WHERE cve=$1`, cve).Scan(&snapshot, &body, &nvdRevision, &generation, &expires, &selectionReason)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if expectedGeneration != "" && expectedGeneration != generation {
		return false, nil
	}
	var revision int
	var cpe, version string
	err = tx.QueryRow(ctx, `SELECT revision,cpe,COALESCE(version,''),evidence FROM noctis_v2.asset_versions WHERE id=$1 ORDER BY revision DESC LIMIT 1 FOR SHARE`, assetID).Scan(&revision, &cpe, &version, &refsRaw)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if expectedAssetRevision != 0 && revision != expectedAssetRevision {
		return false, nil
	}
	status, reason := Evaluate(body, cpe, version)
	if selectionReason != "" {
		status, reason = "unknown", selectionReason
	} else if !expires.After(time.Now().UTC()) {
		status, reason = "unknown", "feed_snapshot_stale"
	}
	var refs []evidence.Ref
	if err = json.Unmarshal(refsRaw, &refs); err != nil {
		return false, err
	}
	if err = intelligence.ValidateEvidenceTx(ctx, tx, refs); err != nil {
		// Missing/superseded evidence is an unknown result, not proof of exclusion.
		if !errors.Is(err, pgx.ErrNoRows) {
			var available bool
			if e := tx.QueryRow(ctx, `SELECT noctis_v2.applicability_evidence_current($1::jsonb)`, string(refsRaw)).Scan(&available); e != nil {
				return false, e
			}
			if available {
				return false, err
			}
		}
		status, reason = "unknown", "asset_evidence_unavailable"
	}
	_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.local_applicability(snapshot_id,cve,asset_id,asset_revision,status,reason) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, snapshot, cve, assetID, revision, status, reason)
	if err != nil {
		return false, err
	}
	tag, err := tx.Exec(ctx, `INSERT INTO noctis_v2.applicability_current(cve,asset_id,asset_revision,snapshot_id,nvd_revision,generation,status,reason,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(cve,asset_id) DO UPDATE SET asset_revision=EXCLUDED.asset_revision,snapshot_id=EXCLUDED.snapshot_id,nvd_revision=EXCLUDED.nvd_revision,generation=EXCLUDED.generation,status=EXCLUDED.status,reason=EXCLUDED.reason,expires_at=EXCLUDED.expires_at,calculated_at=clock_timestamp() WHERE (applicability_current.asset_revision,applicability_current.generation,applicability_current.status,applicability_current.reason) IS DISTINCT FROM (EXCLUDED.asset_revision,EXCLUDED.generation,EXCLUDED.status,EXCLUDED.reason)`, cve, assetID, revision, snapshot, nvdRevision, generation, status, reason, expires)
	if err != nil {
		return false, err
	}
	if tag.RowsAffected() > 0 {
		_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.applicability_transitions(cve,asset_id,asset_revision,snapshot_id,generation,status,reason) VALUES($1,$2,$3,$4,$5,$6,$7)`, cve, assetID, revision, snapshot, generation, status, reason)
	}
	return true, err
}

// PublishApplicabilityCaseTx aggregates all current pairs, including incomplete
// coverage. It never enumerates other cases; durable execution pages those.
func PublishApplicabilityCaseTx(ctx context.Context, tx pgx.Tx, caseID string) error {
	if err := intelligence.LockProjectionTx(ctx, tx); err != nil {
		return err
	}
	var revision int64
	var old, projection []byte
	err := tx.QueryRow(ctx, `SELECT ic.revision,cr.body,noctis_v2.case_applicability(ic.id) FROM noctis_v2.intelligence_cases ic JOIN noctis_v2.case_revisions cr ON cr.case_id=ic.id AND cr.revision=ic.revision WHERE ic.id=$1 FOR UPDATE OF ic`, caseID).Scan(&revision, &old, &projection)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var state struct {
		Generation string `json:"applicability_generation"`
		Status     string `json:"local_applicability"`
	}
	if err = json.Unmarshal(projection, &state); err != nil {
		return err
	}
	var previous string
	var transition int64
	err = tx.QueryRow(ctx, `SELECT generation,transition FROM noctis_v2.case_applicability_projection WHERE case_id=$1`, caseID).Scan(&previous, &transition)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if previous == state.Generation {
		return nil
	}
	// Retractions may cite withdrawn historical membership; availability is checked
	// by the aggregate, so the citation cannot restore an affirmative state.
	var observation string
	var ref []byte
	err = tx.QueryRow(ctx, `SELECT m.observation_id::text,s.evidence FROM noctis_v2.case_memberships m JOIN noctis_v2.observable_sightings s ON s.observation_id=m.observation_id WHERE m.case_id=$1 AND s.observable_type='cve' ORDER BY m.observation_id,s.value LIMIT 1`, caseID).Scan(&observation, &ref)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(ctx, `SELECT observation_id::text,body->'citations'->0 FROM noctis_v2.case_changes WHERE case_id=$1 ORDER BY created_at,id LIMIT 1`, caseID).Scan(&observation, &ref)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	transition++
	changeID := uuid.NewString()
	change, _ := json.Marshal(map[string]any{"id": changeID, "case_id": caseID, "kind": "local_applicability", "title": "Inventory applicability: " + state.Status, "description": "Current inventory applicability is " + state.Status + ". Local exposure and compromise are unknown.", "citations": []json.RawMessage{ref}, "local_applicability": state.Status, "local_exposure": "unknown", "applicability_generation": state.Generation})
	_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.case_changes(id,case_id,observation_id,body,material_key) VALUES($1,$2,$3,$4,$5)`, changeID, caseID, observation, string(change), fmt.Sprintf("applicability:%s:%d", caseID, transition))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.case_revisions(case_id,revision,body) VALUES($1,$2,$3::jsonb||$4::jsonb||jsonb_build_object('revision',$2::bigint::text,'supersedes',($2::bigint-1)::text))`, caseID, revision+1, string(old), string(projection))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE noctis_v2.intelligence_cases SET revision=$2,updated_at=clock_timestamp() WHERE id=$1`, caseID, revision+1)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.case_applicability_projection(case_id,generation,transition,body) VALUES($1,$2,$3,$4) ON CONFLICT(case_id) DO UPDATE SET generation=EXCLUDED.generation,transition=EXCLUDED.transition,body=EXCLUDED.body`, caseID, state.Generation, transition, string(projection))
	// Briefs use support identities at read/regeneration time; no unbounded update
	// over every historical brief is needed in this publication transaction.
	return err
}

// RefreshApplicabilityTx is retained for explicit synchronous repairs. Runtime
// ingestion uses the durable paginated machinery rather than this helper.
func RefreshApplicabilityTx(ctx context.Context, tx pgx.Tx, cve string) error {
	if err := intelligence.LockProjectionTx(ctx, tx); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT id::text FROM noctis_v2.asset_versions ORDER BY id::text`)
	if err != nil {
		return err
	}
	assets := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		assets = append(assets, id)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	for _, id := range assets {
		if _, err = EvaluateCurrentPairTx(ctx, tx, cve, id, "", 0); err != nil {
			return err
		}
	}
	rows, err = tx.Query(ctx, `SELECT DISTINCT m.case_id::text FROM noctis_v2.case_memberships m JOIN noctis_v2.observable_sightings s ON s.observation_id=m.observation_id WHERE s.observable_type='cve' AND s.value=$1 ORDER BY m.case_id::text`, cve)
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
	for _, id := range cases {
		if err = PublishApplicabilityCaseTx(ctx, tx, id); err != nil {
			return err
		}
	}
	return nil
}
