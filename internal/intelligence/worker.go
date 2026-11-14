package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"time"
	"unicode/utf8"
)

type Worker struct {
	DSN   string
	Owner string
}

func (w Worker) Once(ctx context.Context) (result error) {
	store := jobs.Store{DSN: w.DSN}
	j, e := store.Claim(ctx, w.Owner, time.Minute)
	if e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(ctx)
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		tick := time.NewTicker(15 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if store.Heartbeat(ctx, j, time.Minute) != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		cancel()
		<-heartbeatDone
		if result != nil && !errors.Is(result, jobs.ErrLeaseLost) {
			failCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			if err := store.Fail(failCtx, j, "processing_failed", false); err != nil && !errors.Is(err, jobs.ErrLeaseLost) {
				result = errors.Join(result, err)
			}
		}
	}()
	c, e := pgx.Connect(ctx, w.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	var text []byte
	var hash, rep, mode, epoch, sourceEpoch string
	var published, activated *time.Time
	var obsolete bool
	e = c.QueryRow(ctx, `SELECT b.payload,o.hash,o.representation,o.mode,o.epoch::text,s.epoch::text,o.published_at,s.activated_at,o.source_deleted OR o.superseded_by IS NOT NULL OR o.retention_expired_at IS NOT NULL FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) JOIN noctis_v2.sources s ON s.id=o.source_id WHERE o.id=$1 AND o.revision=$2`, j.InputID, j.InputRevision).Scan(&text, &hash, &rep, &mode, &epoch, &sourceEpoch, &published, &activated, &obsolete)
	if e != nil {
		_ = store.Fail(ctx, j, "input_unavailable", false)
		return e
	}
	ref := evidence.Ref{ObservationID: j.InputID, Revision: j.InputRevision, Hash: hash, Representation: rep, Start: 0, End: len(text)}
	observables, e := Extract(text, ref)
	if e != nil {
		_ = store.Fail(ctx, j, "invalid_utf8", true)
		return e
	}
	var termsRaw []byte
	e = c.QueryRow(ctx, `SELECT terms FROM noctis_v2.policies WHERE version=$1`, j.PolicyVersion).Scan(&termsRaw)
	if errors.Is(e, pgx.ErrNoRows) {
		_ = store.Fail(ctx, j, "policy_unavailable", true)
		return errors.New("policy unavailable")
	}
	if e != nil {
		return e
	}
	var terms []Term
	if e = json.Unmarshal(termsRaw, &terms); e != nil {
		return e
	}
	gate := Gate(text, observables, terms)
	return store.Finish(ctx, j, func(tx pgx.Tx) error {
		if e := LockProjectionTx(ctx, tx); e != nil {
			return e
		}
		var paused bool
		if e := tx.QueryRow(ctx, `SELECT o.source_deleted OR o.superseded_by IS NOT NULL OR o.retention_expired_at IS NOT NULL OR EXISTS(SELECT FROM noctis_v2.discovery_proposals dp WHERE dp.source_id=s.id AND dp.permission_status<>'authorized') OR s.policy_version<>$3 OR (o.mode='live' AND o.epoch<>s.epoch) ,NOT `+SourceAuthorizedSQL+` FROM noctis_v2.observations o JOIN noctis_v2.sources s ON s.id=o.source_id WHERE o.id=$1 AND o.revision=$2 FOR SHARE OF o,s`, j.InputID, j.InputRevision, j.PolicyVersion).Scan(&obsolete, &paused); e != nil {
			return e
		}
		// Input may have been purged or authorization changed after parsing in RAM.
		// Fence every derived write, including sightings and analysis rows.
		if obsolete {
			return nil
		}
		if paused {
			return jobs.ErrSourcePaused
		}
		if e := recordSightingsTx(ctx, tx, observables); e != nil {
			return e
		}
		raw, _ := json.Marshal(observables)
		_, e := tx.Exec(ctx, `INSERT INTO noctis_v2.analyses(observation_id,policy_version,gate,observables,stage,input_revision,schema_version) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, j.InputID, j.PolicyVersion, gate, string(raw), j.Stage, j.InputRevision, j.SchemaVersion)
		if e != nil {
			return e
		}
		if gate != "relevant" || len(text) == 0 || obsolete {
			return nil
		}
		// Group exact copies, or explicit revisions of the same source-native document.
		group := hash + ":" + rep
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(source_id::text||':'||native_id,1)) FROM noctis_v2.observations WHERE id=$1`, j.InputID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,2))`, hash+":"+rep); e != nil {
			return e
		}
		var existing, contentCase string
		e = tx.QueryRow(ctx, `SELECT ch.case_id::text FROM noctis_v2.case_memberships ch JOIN noctis_v2.observations old ON old.id=ch.observation_id JOIN noctis_v2.observations current ON current.id=$1 WHERE old.source_id=current.source_id AND old.native_id=current.native_id ORDER BY ch.created_at,ch.case_id LIMIT 1`, j.InputID).Scan(&existing)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		e = tx.QueryRow(ctx, `SELECT m.case_id::text FROM noctis_v2.case_memberships m JOIN noctis_v2.observations o ON o.id=m.observation_id WHERE o.hash=$1 AND o.representation=$2 ORDER BY m.created_at,m.case_id LIMIT 1`, hash, rep).Scan(&contentCase)
		if e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		exactCopy := contentCase != ""
		if existing != "" && contentCase != "" && existing != contentCase {
			_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.case_group_conflicts(observation_id,native_case,content_case) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, j.InputID, existing, contentCase)
			if e != nil {
				return e
			}
		}
		if existing == "" {
			existing = contentCase
		}
		title := strings.TrimSpace(strings.SplitN(string(text), "\n", 2)[0])
		if utf8.RuneCountInString(title) > 160 {
			title = string([]rune(title)[:160])
		}
		id := uuid.NewString()
		if existing != "" {
			id = existing
		} else {
			_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.intelligence_cases(id,group_key,title) VALUES($1,$2,$3) ON CONFLICT(group_key) DO NOTHING`, id, group, title)
			if e != nil {
				return e
			}
			e = tx.QueryRow(ctx, `SELECT id::text FROM noctis_v2.intelligence_cases WHERE group_key=$1`, group).Scan(&id)
			if e != nil {
				return e
			}
		}
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.case_memberships(case_id,observation_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, id, j.InputID); e != nil {
			return e
		}
		// Membership records every appearance. Only new content creates a material event.
		var alreadyMaterial bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.case_changes WHERE observation_id=$1)`, j.InputID).Scan(&alreadyMaterial); e != nil {
			return e
		}
		if exactCopy || alreadyMaterial {
			return nil
		}
		var revision int64
		e = tx.QueryRow(ctx, `UPDATE noctis_v2.intelligence_cases SET revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING revision`, id).Scan(&revision)
		if e != nil {
			return e
		}
		// Each immutable revision includes every source appearance and labels independence unknown.
		refs := []evidence.Ref{}
		rows, e := tx.Query(ctx, `SELECT o.id::text,o.revision,o.hash,o.representation,octet_length(b.payload) FROM noctis_v2.case_memberships ch JOIN noctis_v2.observations o ON o.id=ch.observation_id JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE ch.case_id=$1 AND o.id<>$2`, id, j.InputID)
		if e != nil {
			return e
		}
		for rows.Next() {
			var r evidence.Ref
			if e = rows.Scan(&r.ObservationID, &r.Revision, &r.Hash, &r.Representation, &r.End); e != nil {
				rows.Close()
				return e
			}
			refs = append(refs, r)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return e
		}
		refs = append(refs, ref)
		summary := "The source published content matching a watchlist. Source independence is unknown; copies do not provide corroboration."
		body, _ := json.Marshal(map[string]any{"id": id, "title": title, "revision": fmt.Sprint(revision), "supersedes": fmt.Sprint(revision - 1), "status": "source_claim", "summary": summary, "citations": refs, "policy_version": j.PolicyVersion, "independence": "unknown"})
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.case_revisions(case_id,revision,body) VALUES($1,$2,$3)`, id, revision, string(body))
		if e != nil {
			return e
		}
		changeID := uuid.NewString()
		change, _ := json.Marshal(map[string]any{"id": changeID, "case_id": id, "title": title, "description": summary, "text": summary, "kind": "source_observation", "citations": []evidence.Ref{ref}})
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.case_changes(id,case_id,observation_id,body,material_key) VALUES($1,$2,$3,$4,$5)`, changeID, id, j.InputID, string(change), "observation:"+j.InputID)
		if e != nil {
			return e
		}
		if !exactCopy && mode == "live" && epoch == sourceEpoch && published != nil && activated != nil && !published.Before(*activated) && !published.After(time.Now().UTC().Add(5*time.Minute)) {
			key := fmt.Sprintf("%x", sha256.Sum256([]byte(id+":"+changeID+":default:"+j.PolicyVersion)))
			_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.outbox(id,delivery_key,body,state,policy_version) SELECT $1,$2,$3,'queued',$5 FROM noctis_v2.observations o JOIN noctis_v2.sources s ON s.id=o.source_id WHERE o.id=$4 AND `+SourceAuthorizedSQL+` AND s.policy_version=$5 AND o.epoch=s.epoch AND NOT o.source_deleted AND o.superseded_by IS NULL ON CONFLICT DO NOTHING`, uuid.NewString(), key, string(change), j.InputID, j.PolicyVersion)
			if e != nil {
				return e
			}
		}
		return nil
	})
}
func (w Worker) Brief(ctx context.Context, period, policy string) error {
	if _, e := time.Parse("2006-01-02", period); e != nil {
		return e
	}
	c, e := pgx.Connect(ctx, w.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if e = LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	rows, e := tx.Query(ctx, `SELECT ch.body,o.source_deleted OR o.superseded_by IS NOT NULL OR o.retention_expired_at IS NOT NULL OR EXISTS(SELECT FROM noctis_v2.claim_versions cv WHERE cv.case_id=ch.case_id AND (cv.invalidated OR cv.status IN ('contradicted','retracted','unresolved')) AND cv.revision=(SELECT max(revision) FROM noctis_v2.claim_versions current WHERE current.id=cv.id)) FROM noctis_v2.case_changes ch JOIN noctis_v2.observations o ON o.id=ch.observation_id WHERE ch.created_at >= $1::date AND ch.created_at < $1::date+1 ORDER BY ch.created_at,ch.id`, period)
	if e != nil {
		return e
	}
	defer rows.Close()
	text := "Automated brief. Source coverage is limited to feed windows; independence is unknown.\n"
	refs := []evidence.Ref{}
	needsReview := false
	for rows.Next() {
		var raw []byte
		var invalid bool
		if e = rows.Scan(&raw, &invalid); e != nil {
			return e
		}
		var ch struct {
			Title       string         `json:"title"`
			Description string         `json:"description"`
			Citations   []evidence.Ref `json:"citations"`
		}
		if e = json.Unmarshal(raw, &ch); e != nil {
			return e
		}
		text += "• " + ch.Title + ": " + ch.Description + "\n"
		if invalid {
			needsReview = true
			text += "  Evidence withdrawn, superseded, or derived evidence invalidated: this entry requires review and does not confirm the claim.\n"
		}
		refs = append(refs, ch.Citations...)
	}
	if e = rows.Err(); e != nil {
		return e
	}
	rows.Close()
	status := "current"
	if needsReview {
		status = "requires_review"
	}
	raw, _ := json.Marshal(map[string]any{"text": text, "citations": refs, "status": status, "current_for_alerts": !needsReview})
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.briefs(period,policy_version,body,invalidated) VALUES($1,$2,$3,$4) ON CONFLICT(period,policy_version) DO UPDATE SET body=EXCLUDED.body,invalidated=EXCLUDED.invalidated WHERE noctis_v2.briefs.invalidated`, period, policy, string(raw), needsReview)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
