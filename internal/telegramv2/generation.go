package telegramv2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func ReadGenerationTransition(path string) (GenerationTransition, error) {
	var r GenerationTransition
	if e := protectedPath(path, true); e != nil {
		return r, e
	}
	info, e := os.Stat(path)
	if e != nil || info.Size() > 64<<10 {
		return r, ErrOwnership
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return r, e
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF {
		return r, ErrOwnership
	}
	return r, r.validate()
}

// GenerationTransition is an operator-reviewed CAS, including the closed
// owner's fence. FromGeneration can already equal ToGeneration when repairing
// the legacy account-B/consent-A state; ConsentGeneration must differ.
type GenerationTransition struct {
	ID                string `json:"id"`
	Account           string `json:"account"`
	FromGeneration    string `json:"from_generation"`
	ConsentGeneration string `json:"consent_generation"`
	ToGeneration      string `json:"to_generation"`
	ConsentID         string `json:"consent_id"`
	ConsentRevision   int64  `json:"consent_revision"`
	OwnerFence        int64  `json:"owner_fence"`
	Actor             string `json:"actor"`
	Reason            string `json:"reason"`
}

func (r GenerationTransition) validate() error {
	for _, id := range []string{r.ID, r.FromGeneration, r.ConsentGeneration, r.ToGeneration, r.ConsentID} {
		if _, e := uuid.Parse(id); e != nil {
			return ErrOwnership
		}
	}
	if r.Account == "" || r.Actor == "" || len(r.Actor) > 256 || r.Reason == "" || len(r.Reason) > 4096 || r.ConsentRevision < 1 || r.OwnerFence < 1 || r.ConsentGeneration == r.ToGeneration {
		return ErrOwnership
	}
	return nil
}

// Called only after Telegram verified the account identity. Production auth
// prepares a generation without changing the installed account/consent pair.
// The row marker fences both native policy versions until explicit transition.
func (s Store) prepareAuthenticatedGeneration(ctx context.Context, o Owner, actual string) error {
	if _, e := uuid.Parse(actual); e != nil {
		return ErrOwnership
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tag, e := c.Exec(ctx, `UPDATE noctis_v2.telegram_accounts a SET
 prepared_auth_generation=CASE WHEN a.active_capture_consent IS NOT NULL AND (a.auth_generation<>$5 OR EXISTS(SELECT FROM noctis_v2.telegram_capture_consents b WHERE b.id=a.active_capture_consent AND b.auth_generation<>$5)) THEN $5::uuid ELSE NULL END,
 auth_generation=CASE WHEN a.active_capture_consent IS NULL THEN $5::uuid ELSE a.auth_generation END,
 state=CASE WHEN a.active_capture_consent IS NULL AND a.auth_generation<>$5 THEN '{"pts":0,"qts":0,"date":0,"seq":0}'::jsonb ELSE a.state END,
 gap=CASE WHEN a.active_capture_consent IS NULL AND a.auth_generation<>$5 THEN true ELSE a.gap END
 WHERE a.id=$1 AND a.owner=$2 AND a.owner_fence=$3 AND a.auth_generation=$4 AND NOT a.closed AND a.authentication_in_progress AND a.lease_expires_at>clock_timestamp() AND a.active_capture_budget IS NULL AND a.pending_generation_transition IS NULL AND (a.prepared_auth_generation IS NULL OR a.prepared_auth_generation=$5) AND a.capture_failure_revision=a.capture_resume_revision`, o.Account, o.ID, o.Fence, o.Generation, actual)
	if e == nil && tag.RowsAffected() != 1 {
		return ErrOwnership
	}
	return e
}

func (s Store) ProposeGenerationTransition(ctx context.Context, account, actor, reason, path string) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	r := GenerationTransition{ID: uuid.NewString(), Account: account, Actor: actor, Reason: reason}
	e = c.QueryRow(ctx, `SELECT a.auth_generation::text,b.auth_generation::text,a.prepared_auth_generation::text,b.id::text,a.consent_revision,a.owner_fence FROM noctis_v2.telegram_accounts a JOIN noctis_v2.telegram_capture_consents b ON b.id=a.active_capture_consent WHERE a.id=$1 AND a.closed AND a.owner IS NULL AND a.lease_expires_at IS NULL AND NOT a.authentication_in_progress AND a.active_capture_budget IS NULL AND a.pending_generation_transition IS NULL AND a.capture_failure_revision=a.capture_resume_revision`, account).Scan(&r.FromGeneration, &r.ConsentGeneration, &r.ToGeneration, &r.ConsentID, &r.ConsentRevision, &r.OwnerFence)
	if e != nil {
		return errors.Join(ErrOwnership, e)
	}
	if e = r.validate(); e != nil {
		return e
	}
	raw, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		return e
	}
	return protectedWrite(path, append(raw, '\n'))
}

// TransitionGeneration never opens a transport. Local exclusion covers the
// session check and SQL commit; closed/owner/lease and exact fence prove the
// last transport returned. A lease timeout cannot satisfy that proof.
func (s Store) TransitionGeneration(ctx context.Context, sessionFile string, r GenerationTransition) error {
	if e := r.validate(); e != nil {
		return e
	}
	unlock, e := lockSession(sessionFile)
	if e != nil {
		return e
	}
	defer unlock()
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	// Every transition and consent installer serializes on the same account row.
	var account string
	if e = tx.QueryRow(ctx, `SELECT id FROM noctis_v2.telegram_accounts WHERE id=$1 FOR UPDATE`, r.Account).Scan(&account); e != nil {
		return e
	}
	raw, _ := json.Marshal(r)
	hash := sha256.Sum256(raw)
	digest := hex.EncodeToString(hash[:])
	var existing string
	e = tx.QueryRow(ctx, `SELECT request_digest FROM noctis_v2.telegram_generation_transitions WHERE id=$1`, r.ID).Scan(&existing)
	if e == nil {
		if existing != digest {
			return ErrOwnership
		}
		return tx.Commit(ctx)
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	actual, e := (&ProtectedSession{Path: sessionFile}).Generation(ctx)
	if e != nil || actual != r.ToGeneration {
		return errors.Join(ErrOwnership, e)
	}
	var priorRaw []byte
	e = tx.QueryRow(ctx, `SELECT b.policy FROM noctis_v2.telegram_accounts a JOIN noctis_v2.telegram_capture_consents b ON b.id=a.active_capture_consent AND b.account_id=a.id WHERE a.id=$1 AND a.auth_generation=$2 AND b.auth_generation=$3 AND a.prepared_auth_generation=$4 AND b.id=$5 AND a.consent_revision=$6 AND b.revision=$6 AND a.owner_fence=$7 AND a.closed AND a.owner IS NULL AND a.lease_expires_at IS NULL AND NOT a.authentication_in_progress AND a.pending_generation_transition IS NULL AND a.active_capture_budget IS NULL AND a.capture_failure_revision=a.capture_resume_revision`, r.Account, r.FromGeneration, r.ConsentGeneration, r.ToGeneration, r.ConsentID, r.ConsentRevision, r.OwnerFence).Scan(&priorRaw)
	if e != nil {
		return errors.Join(ErrOwnership, e)
	}
	var prior CapturePolicy
	if strictCapturePolicy(priorRaw, &prior) != nil || prior.Version != 2 || prior.Generation != r.ConsentGeneration {
		return ErrBudget
	}
	var notBefore time.Time
	// Losing the remaining quota of this hour is intentional. Never move an
	// existing quota/FloodWait deadline backwards or copy/decrease old usage.
	e = tx.QueryRow(ctx, `SELECT GREATEST(date_bin(make_interval(secs=>$2),clock_timestamp(),$3::timestamptz)+make_interval(secs=>$2),quota_wait_until,retry_at) FROM noctis_v2.telegram_accounts WHERE id=$1`, r.Account, prior.WindowSeconds, prior.PeriodAnchor).Scan(&notBefore)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_generation_transitions(id,account_id,from_generation,consent_generation,to_generation,consent_id,consent_revision,owner_fence,actor,reason,request_digest,capture_not_before) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, r.ID, r.Account, r.FromGeneration, r.ConsentGeneration, r.ToGeneration, r.ConsentID, r.ConsentRevision, r.OwnerFence, r.Actor, r.Reason, digest, notBefore)
	if e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE noctis_v2.telegram_capture_consents SET revoked_at=clock_timestamp() WHERE id=$1 AND revoked_at IS NULL`, r.ConsentID); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET auth_generation=$2,prepared_auth_generation=NULL,pending_generation_transition=$3,active_capture_consent=NULL,state='{"pts":0,"qts":0,"date":0,"seq":0}',gap=true,quota_wait_until=$4,quota_wait_reason=CASE WHEN quota_wait_until>=$4 THEN quota_wait_reason ELSE 'generation_transition' END WHERE id=$1`, r.Account, r.ToGeneration, r.ID, notBefore)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
