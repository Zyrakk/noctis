package intelligence

import (
	"bytes"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"time"
)

var ErrDeliveryBlocked = errors.New("delivery blocked by current source policy or evidence state")

// DispatchOnce records sending before network I/O. A crash or ambiguous response
// leaves uncertain delivery: receivers without proven idempotency are never retried.
// DSN must target direct PostgreSQL or session pooling, never transaction/statement
// pooling. The global projection guard serializes dispatch with fetch/publication/
// revocation through body close and ACK recording, within a 15-second total
// deadline (including lock acquisition). A lost DB session releases its lock;
// remote acceptance remains uncertain and cannot be undone by later revocation.
func (w Worker) DispatchOnce(ctx context.Context, endpoint string, client *http.Client) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	c, e := pgx.Connect(ctx, w.DSN)
	if e != nil {
		return e
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = c.Close(cleanup)
	}()
	// A session lock survives the durable uncertain-state commit. Revocation and
	// purge take this same lock, so they either win before admission (zero I/O),
	// or wait for the admitted request. Connection close always releases it.
	if _, e = c.Exec(ctx, `SELECT pg_advisory_lock(76238451003)`); e != nil {
		return e
	}
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_ = tx.Rollback(cleanup)
	}()
	if e = LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	var id, key string
	var body []byte
	var policy *string
	e = tx.QueryRow(ctx, `SELECT id::text,delivery_key,body,policy_version FROM noctis_v2.outbox WHERE state='queued' ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&id, &key, &body, &policy)
	if e != nil {
		return e
	}
	var valid bool
	e = tx.QueryRow(ctx, `SELECT $2::text IS NOT NULL AND jsonb_typeof($1::jsonb->'citations')='array' AND jsonb_array_length(COALESCE($1::jsonb->'citations','[]'))>0 AND NOT EXISTS(SELECT FROM jsonb_array_elements(COALESCE($1::jsonb->'citations','[]')) r LEFT JOIN noctis_v2.observations o ON o.id::text=r->>'observation_id' AND o.revision=r->>'revision' AND o.hash=r->>'hash' AND o.representation=r->>'representation' LEFT JOIN noctis_v2.sources s ON s.id=o.source_id WHERE o.id IS NULL OR NOT `+SourceAuthorizedSQL+` OR s.policy_version IS DISTINCT FROM $2 OR o.epoch IS DISTINCT FROM s.epoch OR o.mode<>'live' OR o.source_deleted OR o.superseded_by IS NOT NULL OR o.retention_expired_at IS NOT NULL OR o.published_at IS NULL OR s.activated_at IS NULL OR o.published_at<s.activated_at OR o.published_at>clock_timestamp()+interval '5 minutes')`, string(body), policy).Scan(&valid)
	if e != nil {
		return e
	}
	if !valid {
		if _, e = tx.Exec(ctx, `UPDATE noctis_v2.outbox SET state='blocked',blocked_reason='source_policy_or_evidence_revoked' WHERE id=$1`, id); e != nil {
			return e
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
		return ErrDeliveryBlocked
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.outbox SET state='uncertain' WHERE id=$1`, id)
	if e != nil {
		return e
	}
	if e = tx.Commit(ctx); e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(body))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", key)
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	res, e := client.Do(req)
	if e != nil {
		return e
	}
	io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
	res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return errors.New("delivery not acknowledged; uncertain")
	}
	_, e = c.Exec(ctx, `UPDATE noctis_v2.outbox SET state='delivered' WHERE id=$1 AND state='uncertain'`, id)
	return e
}
