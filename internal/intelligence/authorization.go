package intelligence

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"
)

// SourceAuthorizedSQL expects the source alias s. A PIR pause is independent
// of the source's own enabled flag, so resuming a PIR never unpauses a source.
const SourceAuthorizedSQL = `(s.enabled AND NOT EXISTS(SELECT FROM noctis_v2.question_sources qs JOIN noctis_v2.questions q ON q.id=qs.question_id WHERE qs.source_id=s.id AND NOT q.enabled) AND NOT EXISTS(SELECT FROM noctis_v2.discovery_proposals dp WHERE dp.source_id=s.id AND dp.permission_status<>'authorized'))`

// GuardProjectionIO orders a bounded fetch against revocation. c must be a
// dedicated direct PostgreSQL connection or a proxy with session pooling;
// transaction/statement pooling cannot preserve this authorization boundary.
// Callers revalidate permission within fn and again in their commit transaction.
// The global projection guard serializes fetch, dispatch, publication and
// revocation for at most the 20-second total fetch deadline. Session loss releases
// PostgreSQL's lock: bytes already admitted to a remote peer cannot be recalled.
func GuardProjectionIO(ctx context.Context, c *pgx.Conn, fn func(context.Context) error) (result error) {
	return GuardProjectionIOWithBudget(ctx, c, 20*time.Second, fn)
}

// GuardProjectionIOWithBudget preserves the same authorization boundary for
// explicitly bounded operations. Revocation can wait for the selected budget,
// up to 120 seconds; an earlier parent deadline or cancellation still wins.
func GuardProjectionIOWithBudget(ctx context.Context, c *pgx.Conn, budget time.Duration, fn func(context.Context) error) (result error) {
	if budget <= 0 || budget > 120*time.Second {
		return errors.New("invalid projection IO budget")
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if _, e := c.Exec(ctx, `SELECT pg_advisory_lock(76238451003)`); e != nil {
		return e
	}
	defer func() {
		// pgx closes a session when a canceled query cannot be resynchronized.
		// Its session lock is already gone. Do not turn a proven cancellation
		// into a second, artificial "conn closed" failure by executing unlock.
		if c.IsClosed() && ctx.Err() != nil && pureIOCancellation(result) {
			return
		}
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, e := c.Exec(cleanup, `SELECT pg_advisory_unlock(76238451003)`)
		result = errors.Join(result, e)
		if e != nil {
			_ = c.Close(cleanup)
		}
	}()
	return fn(ctx)
}

func pureIOCancellation(err error) bool {
	if err == nil {
		return false
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		children := many.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !pureIOCancellation(child) {
				return false
			}
		}
		return true
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return pureIOCancellation(one.Unwrap())
	}
	return err == context.Canceled || err == context.DeadlineExceeded
}
