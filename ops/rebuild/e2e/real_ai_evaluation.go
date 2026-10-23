package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func validateLatestAuditBinary(state campaignState, digest string) error {
	// Append order is the audit chain. Older binary digests describe older fixes
	// and must remain intact when a later uncertain attempt needs another fix.
	selected := ""
	if state.LatestAudit != nil {
		if state.LatestAudit.Kind == "uncertain" {
			for _, q := range state.Quarantines {
				if q.Attempt == state.LatestAudit.Attempt {
					selected = q.BinarySHA
				}
			}
		}
		if state.LatestAudit.Kind == "settled_publication_rejected" {
			for _, p := range state.Publications {
				if p.Attempt == state.LatestAudit.Attempt {
					selected = p.BinarySHA
				}
			}
		}
		if selected == "" {
			return errors.New("latest audit reference incompatible")
		}
	} else if len(state.Quarantines) > 0 {
		selected = state.Quarantines[len(state.Quarantines)-1].BinarySHA
	}
	if selected != "" && selected != digest {
		return errors.New("resume binary differs from latest audited correction")
	}
	return nil
}

// Resolve by the exact linked job function set, never audit count/order. Two
// uncertain evaluations for the same consumer are ambiguous and reject.
func (g *realGuard) quarantinedEvaluation(ctx context.Context, c *pgx.Conn, wanted []inference.Function) (string, error) {
	rows, err := c.Query(ctx, `SELECT a.id::text,a.state,j.function_id,j.actor,j.state FROM noctis_v2.ai_attempts a JOIN noctis_v2.ai_attempt_jobs aj ON aj.attempt_id=a.id JOIN noctis_v2.ai_jobs j ON j.id=aj.job_id WHERE a.id::text=ANY($1::text[]) ORDER BY a.id,j.id`, g.quarantineIDs())
	if err != nil {
		return "", err
	}
	defer rows.Close()
	groups := map[string][]inference.Function{}
	bad := map[string]bool{}
	want := map[inference.Function]bool{}
	for _, f := range wanted {
		if want[f] {
			return "", errors.New("duplicate evaluation function")
		}
		want[f] = true
	}
	for rows.Next() {
		var id, state, actor, jobState string
		var f inference.Function
		if err = rows.Scan(&id, &state, &f, &actor, &jobState); err != nil {
			return "", err
		}
		groups[id] = append(groups[id], f)
		if state != "uncertain" || actor != "operator" || jobState != "dependency_blocked" {
			bad[id] = true
		}
	}
	if err = rows.Err(); err != nil {
		return "", err
	}
	return resolveQuarantinedFunctions(groups, bad, wanted)
}
func resolveQuarantinedFunctions(groups map[string][]inference.Function, bad map[string]bool, wanted []inference.Function) (string, error) {
	want := map[inference.Function]bool{}
	if len(wanted) == 0 {
		return "", errors.New("explicit evaluation functions required")
	}
	for _, f := range wanted {
		if want[f] {
			return "", errors.New("duplicate evaluation function")
		}
		want[f] = true
	}
	found := ""
	for id, fs := range groups {
		relevant := false
		seen := map[inference.Function]bool{}
		valid := !bad[id] && len(fs) == len(wanted)
		for _, f := range fs {
			if want[f] {
				relevant = true
			}
			if !want[f] || seen[f] {
				valid = false
			}
			seen[f] = true
		}
		if !relevant {
			continue
		}
		if !valid || found != "" {
			return "", errors.New("quarantined function evaluation ambiguous or incompatible")
		}
		found = id
	}
	return found, nil
}

func (g *realGuard) newIdentityInput(ctx context.Context, c *pgx.Conn, old string) (inference.Input, error) {
	var raw []byte
	if err := c.QueryRow(ctx, `SELECT j.input FROM noctis_v2.ai_jobs j JOIN noctis_v2.ai_attempt_jobs aj ON aj.job_id=j.id WHERE aj.attempt_id=$1 AND j.function_id='identity.disambiguate' AND j.actor='operator' AND j.state='dependency_blocked'`, old).Scan(&raw); err != nil {
		return inference.Input{}, errors.New("original identity input unavailable")
	}
	var prior inference.Input
	if json.Unmarshal(raw, &prior) != nil || prior.Kind != "identity" || uuid.Validate(prior.ID) != nil || uuid.Validate(prior.RightID) != nil || prior.ID == prior.RightID {
		return inference.Input{}, errors.New("original identity input invalid")
	}
	policy := "ai-new-identity-" + old
	native := "synthetic-new-identity-after-" + old
	var source, epoch, obs, revision, caseID, hash string
	err := c.QueryRow(ctx, `SELECT id::text,epoch::text FROM noctis_v2.sources WHERE native_id=$1`, native).Scan(&source, &epoch)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, err = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES($1,'[{"type":"keyword","value":"LYRA"}]') ON CONFLICT DO NOTHING`, policy); err != nil {
			return inference.Input{}, err
		}
		source, epoch = uuid.NewString(), uuid.NewString()
		if _, err = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,name,enabled,policy_version,epoch,activated_at) VALUES($1,'rss',$2,'SYNTHETIC independent identity evaluation',true,$3,$4,clock_timestamp()-interval '1 hour')`, source, native, policy, epoch); err != nil {
			return inference.Input{}, err
		}
		payload := "SYNTHETIC LYRA identity evaluation: lyra-lab is a handle in laboratory scope A and lyra-lab is a handle in unrelated laboratory scope B. Equal spelling alone does not establish identity. Prior uncertain identity evaluation: " + old
		now := time.Now().UTC()
		hash = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(payload)))
		_, err = (capture.Store{DSN: g.store.DSN}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: source, Epoch: epoch, Mode: capture.Live, Items: []capture.Item{{NativeID: "independent-identity-notice", Revision: "1", Hash: hash, Payload: []byte(payload), Representation: "text/plain;utf8;v1", CollectedAt: now, PublishedAt: &now}}, Expected: capture.Checkpoint{Value: json.RawMessage(`null`)}, Next: capture.Checkpoint{Version: 1, Value: json.RawMessage(`1`)}})
		if err != nil {
			return inference.Input{}, err
		}
		if err = (intelligence.Worker{DSN: g.store.DSN, Owner: "new-identity-evaluation"}).Once(ctx); err != nil {
			return inference.Input{}, err
		}
	} else if err != nil {
		return inference.Input{}, err
	}
	var payload []byte
	if err = c.QueryRow(ctx, `SELECT o.id::text,o.revision,o.hash,b.payload,m.case_id::text FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) JOIN noctis_v2.case_memberships m ON m.observation_id=o.id WHERE o.source_id=$1`, source).Scan(&obs, &revision, &hash, &payload, &caseID); err != nil {
		return inference.Input{}, err
	}
	var overlaps bool
	if err = c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.entity_aliases a CROSS JOIN LATERAL jsonb_array_elements(a.evidence) ref LEFT JOIN noctis_v2.case_memberships m ON m.observation_id::text=ref->>'observation_id' WHERE a.entity_id::text=ANY($1::text[]) AND (ref->>'observation_id'=$2 OR m.case_id::text=$3))`, []string{prior.ID, prior.RightID}, obs, caseID).Scan(&overlaps); err != nil || overlaps {
		return inference.Input{}, errors.New("new identity evidence must use distinct observation and case")
	}
	ref := evidence.Ref{ObservationID: obs, Revision: revision, Hash: hash, Representation: "text/plain;utf8;v1", End: len(payload)}
	refs, _ := json.Marshal([]evidence.Ref{ref})
	left := uuid.NewSHA1(uuid.NameSpaceOID, []byte(native+":entity:A")).String()
	right := uuid.NewSHA1(uuid.NameSpaceOID, []byte(native+":entity:B")).String()
	if left == prior.ID || left == prior.RightID || right == prior.ID || right == prior.RightID {
		return inference.Input{}, errors.New("identity evaluation must use distinct entities")
	}
	tx, err := c.Begin(ctx)
	if err != nil {
		return inference.Input{}, err
	}
	defer tx.Rollback(context.Background())
	if err = intelligence.LockProjectionTx(ctx, tx); err != nil {
		return inference.Input{}, err
	}
	if err = intelligence.ValidateEvidenceTx(ctx, tx, []evidence.Ref{ref}); err != nil {
		return inference.Input{}, err
	}
	for _, side := range []struct{ id, label string }{{left, "A"}, {right, "B"}} {
		scope := native + ":" + side.label
		aliasID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(scope+":alias")).String()
		if _, err = tx.Exec(ctx, `INSERT INTO noctis_v2.entities(id,kind) VALUES($1,'handle') ON CONFLICT DO NOTHING`, side.id); err != nil {
			return inference.Input{}, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO noctis_v2.entity_aliases(id,entity_id,alias,scope,language,evidence) VALUES($1,$2,'lyra-lab',$3,'und',$4) ON CONFLICT DO NOTHING`, aliasID, side.id, scope, string(refs)); err != nil {
			return inference.Input{}, err
		}
		var valid bool
		if err = tx.QueryRow(ctx, `SELECT e.kind='handle' AND a.entity_id=e.id AND a.alias='lyra-lab' AND a.scope=$3 AND a.language='und' AND a.evidence=$4::jsonb AND NOT a.revoked FROM noctis_v2.entities e JOIN noctis_v2.entity_aliases a ON a.id=$2 WHERE e.id=$1`, side.id, aliasID, scope, string(refs)).Scan(&valid); err != nil || !valid {
			return inference.Input{}, errors.New("retained identity evaluation differs")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return inference.Input{}, err
	}
	g.identityEvaluation = map[string]any{"prior_uncertain_attempt": old, "new_source_id": source, "new_observation_id": obs, "new_case_id": caseID, "new_left_entity_id": left, "new_right_entity_id": right, "new_policy_version": policy, "request_id": "new-identity-evaluation-after-" + old, "old_jobs_unchanged": true}
	if err = g.receipt(); err != nil {
		return inference.Input{}, err
	}
	return inference.Input{Kind: "identity", ID: left, RightID: right}, nil
}
