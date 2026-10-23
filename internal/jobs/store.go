package jobs

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"math/rand/v2"
	"time"
)

var ErrLeaseLost = errors.New("job lease lost")

// ErrSourcePaused parks an interrupted claim without consuming its retry budget.
// Callbacks must return this before any derived writes.
var ErrSourcePaused = errors.New("source temporarily paused")

type Job struct {
	ID string
	Key
	Lease
	Attempts int
}
type Store struct{ DSN string }

func (s Store) Claim(ctx context.Context, owner string, duration time.Duration, stages ...string) (Job, error) {
	var j Job
	if owner == "" || duration <= 0 {
		return j, errors.New("owner and positive duration required")
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return j, e
	}
	defer c.Close(context.Background())
	if len(stages) == 0 {
		stages = []string{"parse"}
	}
	e = c.QueryRow(ctx, `WITH stale AS (UPDATE noctis_v2.jobs SET state='quarantined',last_error_code='retry_horizon_exceeded',lease_owner=NULL,lease_expires_at=NULL WHERE stage=ANY($3) AND last_error_code IS DISTINCT FROM 'source_resumed' AND (attempts>=5 OR created_at<clock_timestamp()-interval '24 hours') AND (state IN ('queued','retry_wait') OR (state='leased' AND lease_expires_at<=clock_timestamp()))), candidate AS (SELECT id FROM noctis_v2.jobs WHERE stage=ANY($3) AND attempts<5 AND (created_at>=clock_timestamp()-interval '24 hours' OR last_error_code='source_resumed') AND (state='queued' OR (state='retry_wait' AND retry_at<=clock_timestamp()) OR (state='leased' AND lease_expires_at<=clock_timestamp())) ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE noctis_v2.jobs j SET state='leased',lease_owner=$1,lease_expires_at=clock_timestamp()+$2::interval,fence=fence+1,attempts=attempts+1,last_error_code=CASE WHEN last_error_code='source_resumed' THEN NULL ELSE last_error_code END FROM candidate WHERE j.id=candidate.id RETURNING j.id,stage,input_id,input_revision,policy_version,schema_version,lease_owner,lease_expires_at,fence,attempts`, owner, duration.String(), stages).Scan(&j.ID, &j.Stage, &j.InputID, &j.InputRevision, &j.PolicyVersion, &j.SchemaVersion, &j.Owner, &j.ExpiresAt, &j.Fence, &j.Attempts)
	return j, e
}
func (s Store) Finish(ctx context.Context, j Job, write func(pgx.Tx) error) error {
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
	if e = FinishTx(ctx, tx, j, write); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// FinishTx composes a fenced domain publication with another durable transaction.
// The caller commits; any error requires rolling back the whole transaction.
func FinishTx(ctx context.Context, tx pgx.Tx, j Job, write func(pgx.Tx) error) error {
	var ok bool
	e := tx.QueryRow(ctx, `SELECT true FROM noctis_v2.jobs WHERE id=$1 AND state='leased' AND lease_owner=$2 AND fence=$3 AND lease_expires_at>clock_timestamp() FOR UPDATE`, j.ID, j.Owner, j.Fence).Scan(&ok)
	if errors.Is(e, pgx.ErrNoRows) {
		return ErrLeaseLost
	}
	if e != nil {
		return e
	}
	if e = write(tx); errors.Is(e, ErrSourcePaused) {
		tag, parkErr := tx.Exec(ctx, `UPDATE noctis_v2.jobs SET state='dependency_blocked',last_error_code='source_paused',attempts=GREATEST(attempts-1,0),retry_at=NULL,lease_owner=NULL,lease_expires_at=NULL WHERE id=$1 AND fence=$2 AND lease_expires_at>clock_timestamp()`, j.ID, j.Fence)
		if parkErr != nil {
			return parkErr
		}
		if tag.RowsAffected() != 1 {
			return ErrLeaseLost
		}
		return nil
	} else if e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `UPDATE noctis_v2.jobs SET state='succeeded',lease_owner=NULL,lease_expires_at=NULL WHERE id=$1 AND fence=$2 AND lease_expires_at>clock_timestamp()`, j.ID, j.Fence)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return nil
}
func (s Store) Heartbeat(ctx context.Context, j Job, d time.Duration) error {
	return s.transition(ctx, j, `UPDATE noctis_v2.jobs SET lease_expires_at=clock_timestamp()+$4::interval WHERE id=$1 AND lease_owner=$2 AND fence=$3 AND state='leased' AND lease_expires_at>clock_timestamp()`, d.String())
}
func (s Store) Fail(ctx context.Context, j Job, code string, permanent bool) error {
	state := "retry_wait"
	if permanent || j.Attempts >= 5 {
		state = "quarantined"
	}
	shift := min(max(j.Attempts-1, 0), 8)
	base := time.Second * time.Duration(1<<shift)
	delay := base + time.Duration(rand.Int64N(int64(base)))
	return s.transition(ctx, j, `UPDATE noctis_v2.jobs SET state=CASE WHEN created_at<clock_timestamp()-interval '24 hours' THEN 'quarantined' ELSE $4 END,last_error_code=$5,retry_at=clock_timestamp()+$6::interval,lease_owner=NULL,lease_expires_at=NULL WHERE id=$1 AND lease_owner=$2 AND fence=$3 AND state='leased' AND lease_expires_at>clock_timestamp()`, state, code, delay.String())
}
func (s Store) transition(ctx context.Context, j Job, q string, args ...any) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	a := []any{j.ID, j.Owner, j.Fence}
	a = append(a, args...)
	tag, e := c.Exec(ctx, q, a...)
	if e == nil && tag.RowsAffected() != 1 {
		return ErrLeaseLost
	}
	return e
}
func (s Store) Replay(ctx context.Context, id string) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tag, e := c.Exec(ctx, `UPDATE noctis_v2.jobs SET state='queued',last_error_code=NULL,retry_at=NULL,attempts=0,created_at=clock_timestamp() WHERE id=$1 AND state IN ('quarantined','dependency_blocked','budget_blocked','cancelled')`, id)
	if e == nil && tag.RowsAffected() != 1 {
		return errors.New("job not replayable")
	}
	return e
}

func (s Store) Cancel(ctx context.Context, id string) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tag, e := c.Exec(ctx, `UPDATE noctis_v2.jobs SET state='cancelled',lease_owner=NULL,lease_expires_at=NULL,fence=fence+1 WHERE id=$1 AND state NOT IN ('succeeded','cancelled')`, id)
	if e == nil && tag.RowsAffected() != 1 {
		return errors.New("job not cancellable")
	}
	return e
}
