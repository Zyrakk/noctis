package telegramv2

import (
	"context"
	"errors"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/gotd/td/tgerr"
	"github.com/jackc/pgx/v5"
	"time"
)

// Inspect every leaf: errors.Join(planned, unknown) is never a planned close.
func everyError(err error, allowed func(error) bool) bool {
	if err == nil {
		return true
	}
	if _, ok := err.(*quotaDenial); ok {
		return allowed(err)
	}
	if _, ok := err.(*causalCancellation); ok {
		return allowed(err)
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range many.Unwrap() {
			if !everyError(child, allowed) {
				return false
			}
		}
		return true
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return everyError(one.Unwrap(), allowed)
	}
	return allowed(err)
}
func pureCancellation(err error) bool {
	return everyError(err, func(e error) bool { return e == context.Canceled || e == context.DeadlineExceeded })
}
func pureProcessClose(err error) bool {
	return err != nil && everyError(err, func(e error) bool { return e == errProcessWindow })
}
func safeProductionClose(parent context.Context, err error, status string, retry *time.Time) bool {
	return everyError(err, func(e error) bool {
		if e == errProcessWindow {
			return true
		}
		if c, ok := e.(*causalCancellation); ok {
			return c.cause == errProcessWindow || c.shutdown && (c.cause == context.Canceled || c.cause == context.DeadlineExceeded)
		}
		if _, ok := e.(*quotaDenial); ok {
			return true
		}
		if status == "flood_wait" && retry != nil {
			_, ok := tgerr.AsFloodWait(e)
			return ok
		}
		return false
	})
}

// Failure fencing and closure commit together. If persistence fails, closed
// remains false and a replacement process cannot assume transport closure.
func (s Store) closeOwned(ctx context.Context, c *pgx.Conn, o Owner, parent context.Context, result error) error {
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	var consent *string
	var generation string
	var revision int64
	var status string
	var retry *time.Time
	e = tx.QueryRow(ctx, `SELECT active_capture_consent::text,capture_failure_revision,status,retry_at,auth_generation::text FROM noctis_v2.telegram_accounts WHERE id=$1 AND owner=$2 AND owner_fence=$3 AND NOT closed FOR UPDATE`, o.Account, o.ID, o.Fence).Scan(&consent, &revision, &status, &retry, &generation)
	if e != nil {
		return errors.Join(ErrOwnership, e)
	}
	if consent != nil && !safeProductionClose(parent, result, status, retry) {
		revision++
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_capture_failures(account_id,revision,auth_generation,consent_id,reason) VALUES($1,$2,$3,$4,'unplanned_client_failure')`, o.Account, revision, generation, *consent); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,authentication_in_progress=false,status=CASE WHEN status='running' THEN 'paused' ELSE status END,capture_failure_revision=$4 WHERE id=$1 AND owner=$2 AND owner_fence=$3`, o.Account, o.ID, o.Fence, revision)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// Manual resume acknowledges one exact failure revision, using current
// protected consent and explicit audit fields. It changes no capture data.
func (s Store) ResumeProduction(ctx context.Context, p CapturePolicy, revision int64, actor, reason string) error {
	if p.Version != 2 || p.validate() != nil || revision < 1 || actor == "" || reason == "" || len(actor) > 256 || len(reason) > 4096 {
		return ErrOwnership
	}
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
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	_, digest := policyBytes(p)
	var allowed bool
	e = tx.QueryRow(ctx, `SELECT true FROM noctis_v2.telegram_accounts a JOIN noctis_v2.telegram_capture_consents b ON b.id=a.active_capture_consent JOIN noctis_v2.telegram_capture_failures f ON f.account_id=a.id AND f.revision=a.capture_failure_revision WHERE a.id=$1 AND a.auth_generation=$2 AND b.id=$3 AND b.policy_digest=$4 AND a.closed AND a.owner IS NULL AND a.lease_expires_at IS NULL AND a.capture_failure_revision=$5 AND a.capture_resume_revision<$5 AND f.auth_generation=a.auth_generation AND b.auth_generation=a.auth_generation AND b.revoked_at IS NULL AND b.expires_at>clock_timestamp() AND a.status<>'revoked' FOR UPDATE OF a`, p.Account, p.Generation, p.BudgetID, digest, revision).Scan(&allowed)
	if e != nil {
		return errors.Join(ErrOwnership, e)
	}
	if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_capture_resumes(account_id,failure_revision,auth_generation,consent_id,actor,reason) VALUES($1,$2,$3,$4,$5,$6)`, p.Account, revision, p.Generation, p.BudgetID, actor, reason); e != nil {
		return e
	}
	if _, e = tx.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET capture_resume_revision=$2 WHERE id=$1`, p.Account, revision); e != nil {
		return e
	}
	return tx.Commit(ctx)
}
