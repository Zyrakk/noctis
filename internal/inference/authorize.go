package inference

import (
	"context"
	"errors"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/jackc/pgx/v5"
	"time"
)

func (s Store) authorize(ctx context.Context, x execution) error {
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
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(76238451004)`); e != nil {
		return e
	}
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	return s.authorizeTx(ctx, tx, x)
}

func (s Store) authorizeTx(ctx context.Context, tx pgx.Tx, x execution) error {
	cfg, e := readConfig(ctx, tx)
	if e != nil {
		return e
	}
	if cfg.Revision != x.Revision {
		return errors.New("configuration changed")
	}
	b, conn, e := findBinding(cfg, x.Function)
	if e != nil || !allowedClass(conn, x.Snapshot.Input.DataClass) || !compatible(b, x.Binding) {
		return errors.New("route revoked")
	}
	key, e := s.decrypt(ctx, tx, cfg.Revision, conn.ID)
	if e != nil || key == "" || key != x.Key {
		return errors.New("credential changed")
	}
	var ok bool
	if e = tx.QueryRow(ctx, `SELECT true FROM noctis_v2.ai_jobs WHERE id=$1 AND fence=$2 AND state='running' AND lease_until>clock_timestamp()`, x.ID, x.Fence).Scan(&ok); e != nil {
		return e
	}
	return validateSnapshot(ctx, tx, x.Snapshot, x.Actor)
}

// Keep both session locks through response close. Dedicated direct PostgreSQL
// (or session pooling) is required. The order matches AI config then projection.
func (s Store) authorizedWire(ctx context.Context, x execution) (out GatewayResult, result error) {
	if x.Binding.Limits.DeadlineMS <= 0 || x.Binding.Limits.DeadlineMS > 120000 {
		return out, ErrInvalid
	}
	budget := time.Duration(x.Binding.Limits.DeadlineMS) * time.Millisecond
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return out, e
	}
	defer c.Close(context.Background())
	if _, e = c.Exec(ctx, `SELECT pg_advisory_lock(76238451004)`); e != nil {
		return out, e
	}
	defer func() {
		cleanup, end := context.WithTimeout(context.Background(), 5*time.Second)
		defer end()
		_, e := c.Exec(cleanup, `SELECT pg_advisory_unlock(76238451004)`)
		result = errors.Join(result, e)
	}()
	result = intelligence.GuardProjectionIOWithBudget(ctx, c, budget, func(ioCtx context.Context) error {
		tx, e := c.Begin(ioCtx)
		if e != nil {
			return e
		}
		e = s.authorizeTx(ioCtx, tx, x)
		if endErr := tx.Rollback(ioCtx); e == nil {
			e = endErr
		}
		if e != nil {
			return &GatewayError{"authorization_changed", true, false, 0}
		}
		out, e = s.wire(ioCtx, x.Binding, x.Connection, x.Key, x.Attempt, x.Snapshot, x.Functions, func(context.Context) error { return nil })
		return e
	})
	return out, result
}
