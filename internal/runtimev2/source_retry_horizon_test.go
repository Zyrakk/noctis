package runtimev2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/jobs"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type retryFixture struct {
	dsn, source, observation, job string
	c                             *pgx.Conn
	store                         jobs.Store
}

func newRetryFixture(t *testing.T) retryFixture {
	t.Helper()
	f := retryFixture{dsn: productDB(t), source: uuid.NewString(), observation: uuid.NewString(), job: uuid.NewString()}
	var err error
	f.c, err = pgx.Connect(context.Background(), f.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.c.Close(context.Background()) })
	f.store = jobs.Store{DSN: f.dsn}
	coreExec(t, f.c, `INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version,epoch) VALUES($1,'rss','retry-fixture',true,'p1',$2)`, f.source, uuid.NewString())
	coreExec(t, f.c, `INSERT INTO noctis_v2.content_blobs(hash,representation,payload) VALUES('retry-fixture','text/plain;utf8;v1','synthetic')`)
	coreExec(t, f.c, `INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) SELECT $1,id,'retry-fixture','1','retry-fixture','text/plain;utf8;v1',epoch,'live',clock_timestamp() FROM noctis_v2.sources WHERE id=$2`, f.observation, f.source)
	coreExec(t, f.c, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES($1,'parse',$2,'1','p1','1')`, f.job, f.observation)
	return f
}

func (f retryFixture) toggleTx(t *testing.T, tx pgx.Tx, enabled bool) {
	t.Helper()
	ctx := context.Background()
	if _, err := tx.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=$2 WHERE id=$1`, f.source, enabled); err != nil {
		t.Fatal(err)
	}
	var err error
	if enabled {
		err = resumeSourceParseTx(ctx, tx, f.source)
	} else {
		err = pauseSourceParseTx(ctx, tx, f.source)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func (f retryFixture) toggle(t *testing.T, enabled bool) {
	t.Helper()
	ctx := context.Background()
	tx, err := f.c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = intelligence.LockProjectionTx(ctx, tx); err != nil {
		t.Fatal(err)
	}
	f.toggleTx(t, tx, enabled)
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func (f retryFixture) assert(t *testing.T, predicate string) {
	t.Helper()
	var ok bool
	if err := f.c.QueryRow(context.Background(), `SELECT `+predicate+` FROM noctis_v2.jobs WHERE id=$1`, f.job).Scan(&ok); err != nil || !ok {
		t.Fatalf("job predicate %s: ok=%v err=%v", predicate, ok, err)
	}
}

func (f retryFixture) claim(t *testing.T) jobs.Job {
	t.Helper()
	j, err := f.store.Claim(context.Background(), "retry-test", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func TestSourceRetryLongPausePreservesRemainingHorizonPostgres(t *testing.T) {
	f := newRetryFixture(t)
	ctx := context.Background()
	coreExec(t, f.c, `UPDATE noctis_v2.jobs SET state='retry_wait',attempts=2,last_error_code='temporary_failure',created_at=clock_timestamp()-interval '23 hours',retry_deadline_at=clock_timestamp()+interval '1 hour',retry_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.job)
	f.toggle(t, false)
	f.assert(t, `state='dependency_blocked' AND attempts=2 AND source_paused_at IS NOT NULL AND retry_at IS NOT NULL`)
	// Move all clock anchors together: the parked job has one hour left after
	// a documented 48-hour pause, without granting a fresh 24-hour horizon.
	coreExec(t, f.c, `UPDATE noctis_v2.jobs SET created_at=created_at-interval '48 hours',retry_deadline_at=retry_deadline_at-interval '48 hours',source_paused_at=source_paused_at-interval '48 hours' WHERE id=$1`, f.job)
	var pausedAt time.Time
	if err := f.c.QueryRow(ctx, `SELECT source_paused_at FROM noctis_v2.jobs WHERE id=$1`, f.job).Scan(&pausedAt); err != nil {
		t.Fatal(err)
	}
	f.toggle(t, false)
	var samePause bool
	if err := f.c.QueryRow(ctx, `SELECT source_paused_at=$2 FROM noctis_v2.jobs WHERE id=$1`, f.job, pausedAt).Scan(&samePause); err != nil || !samePause {
		t.Fatal("repeated pause reset its anchor", err)
	}
	f.toggle(t, true)
	f.assert(t, `state='queued' AND attempts=2 AND source_paused_at IS NULL AND last_error_code IS NULL AND created_at<clock_timestamp()-interval '70 hours' AND retry_deadline_at BETWEEN clock_timestamp()+interval '59 minutes' AND clock_timestamp()+interval '61 minutes'`)
	var deadline time.Time
	if err := f.c.QueryRow(ctx, `SELECT retry_deadline_at FROM noctis_v2.jobs WHERE id=$1`, f.job).Scan(&deadline); err != nil {
		t.Fatal(err)
	}
	f.toggle(t, true)
	var unchanged bool
	if err := f.c.QueryRow(ctx, `SELECT retry_deadline_at=$2 FROM noctis_v2.jobs WHERE id=$1`, f.job, deadline).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("repeated resume added budget", err)
	}
	j := f.claim(t)
	if err := f.store.Fail(ctx, j, "transient_after_pause", false); err != nil {
		t.Fatal(err)
	}
	f.assert(t, `state='retry_wait' AND attempts=3 AND last_error_code='transient_after_pause' AND retry_deadline_at>clock_timestamp()`)
	// A new pause preserves an already pending backoff and adds only its own
	// duration. Repeated pause/resume never replenish the remaining hour.
	coreExec(t, f.c, `UPDATE noctis_v2.jobs SET retry_at=clock_timestamp()+interval '2 hours' WHERE id=$1`, f.job)
	f.toggle(t, false)
	coreExec(t, f.c, `UPDATE noctis_v2.jobs SET retry_deadline_at=retry_deadline_at-interval '30 hours',source_paused_at=source_paused_at-interval '30 hours' WHERE id=$1`, f.job)
	f.toggle(t, true)
	f.assert(t, `state='retry_wait' AND attempts=3 AND retry_at>clock_timestamp()+interval '119 minutes' AND retry_deadline_at BETWEEN clock_timestamp()+interval '59 minutes' AND clock_timestamp()+interval '61 minutes'`)
	if _, err := f.store.Claim(ctx, "backoff", time.Minute); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("pause advanced pending backoff", err)
	}
}

func TestSourceRetryExhaustionAndReplayPostgres(t *testing.T) {
	for _, scenario := range []string{"exhausted_before_pause", "fifth_failure", "permanent_failure", "finish_expired", "unknown_replay", "marker_no_budget"} {
		t.Run(scenario, func(t *testing.T) {
			f := newRetryFixture(t)
			ctx := context.Background()
			switch scenario {
			case "exhausted_before_pause":
				coreExec(t, f.c, `UPDATE noctis_v2.jobs SET retry_deadline_at=clock_timestamp()-interval '1 second',attempts=2 WHERE id=$1`, f.job)
				f.toggle(t, false)
				f.toggle(t, true)
				f.assert(t, `state='quarantined' AND source_paused_at IS NULL AND attempts=2`)
			case "fifth_failure", "permanent_failure":
				if scenario == "fifth_failure" {
					coreExec(t, f.c, `UPDATE noctis_v2.jobs SET attempts=4 WHERE id=$1`, f.job)
				}
				j := f.claim(t)
				f.toggle(t, false)
				if err := f.store.Fail(ctx, j, "real_failure", scenario == "permanent_failure"); err != nil {
					t.Fatal(err)
				}
				f.toggle(t, true)
				f.assert(t, `state='quarantined' AND last_error_code='real_failure' AND source_paused_at IS NULL`)
				if scenario == "fifth_failure" {
					f.assert(t, `attempts=5`)
				} else {
					f.assert(t, `attempts=1`)
				}
			case "finish_expired":
				j := f.claim(t)
				coreExec(t, f.c, `UPDATE noctis_v2.jobs SET retry_deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.job)
				if err := f.store.Finish(ctx, j, func(pgx.Tx) error { return jobs.ErrSourcePaused }); err != nil {
					t.Fatal(err)
				}
				f.toggle(t, true)
				f.assert(t, `state='quarantined' AND source_paused_at IS NULL AND attempts=0`)
			case "unknown_replay":
				coreExec(t, f.c, `UPDATE noctis_v2.jobs SET state='dependency_blocked',last_error_code='retry_horizon_unknown',created_at=clock_timestamp()-interval '2 days',retry_deadline_at=clock_timestamp()-interval '1 day',attempts=4 WHERE id=$1`, f.job)
				f.toggle(t, true)
				f.assert(t, `state='dependency_blocked' AND attempts=4`)
			case "marker_no_budget":
				coreExec(t, f.c, `UPDATE noctis_v2.jobs SET last_error_code='source_resumed',retry_deadline_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.job)
				if _, err := f.store.Claim(ctx, "old-marker", time.Minute); !errors.Is(err, pgx.ErrNoRows) {
					t.Fatal("error marker granted retry budget", err)
				}
				f.assert(t, `state='quarantined' AND attempts=0`)
			}
			if err := f.store.Replay(ctx, f.job); err != nil {
				t.Fatal(err)
			}
			f.assert(t, `state='queued' AND attempts=0 AND last_error_code IS NULL AND source_paused_at IS NULL AND retry_deadline_at=created_at+interval '24 hours' AND created_at>clock_timestamp()-interval '1 minute'`)
			f.claim(t)
		})
	}
}

func TestSourceRetryExpiredLeaseParksWithoutNewAttemptPostgres(t *testing.T) {
	f := newRetryFixture(t)
	ctx := context.Background()
	j := f.claim(t)
	f.toggle(t, false)
	coreExec(t, f.c, `UPDATE noctis_v2.jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.job)
	if _, err := f.store.Claim(ctx, "recover", time.Minute); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("expired lease from paused source was retried", err)
	}
	f.assert(t, `state='dependency_blocked' AND attempts=1 AND source_paused_at IS NOT NULL AND lease_owner IS NULL`)
	if err := f.store.Fail(ctx, j, "stale", false); !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatal("old owner failed parked job", err)
	}
	if err := f.store.Finish(ctx, j, func(pgx.Tx) error { t.Fatal("old owner published"); return nil }); !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatal("old owner finished parked job", err)
	}
	f.toggle(t, true)
	next := f.claim(t)
	if next.Attempts != 2 || next.Fence <= j.Fence {
		t.Fatal("recovery lost consumed attempt or fence", next)
	}
}

func TestSourceRetryPauseResumeRacesPostgres(t *testing.T) {
	for _, operation := range []string{"fail", "finish", "expired_lease"} {
		for _, enabled := range []bool{false, true} {
			name := operation + "/pause"
			if enabled {
				name = operation + "/resume"
			}
			t.Run(name, func(t *testing.T) {
				f := newRetryFixture(t)
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				j := f.claim(t)
				if enabled {
					f.toggle(t, false)
				}
				if operation == "expired_lease" {
					coreExec(t, f.c, `UPDATE noctis_v2.jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.job)
				}
				actor, err := pgx.Connect(ctx, f.dsn)
				if err != nil {
					t.Fatal(err)
				}
				defer actor.Close(context.Background())
				tx, err := actor.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer tx.Rollback(context.Background())
				if err = intelligence.LockProjectionTx(ctx, tx); err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() {
					switch operation {
					case "fail":
						done <- f.store.Fail(ctx, j, "failed_during_transition", false)
					case "finish":
						done <- f.store.Finish(ctx, j, func(writeTx pgx.Tx) error {
							if e := intelligence.LockProjectionTx(ctx, writeTx); e != nil {
								return e
							}
							var active bool
							if e := writeTx.QueryRow(ctx, `SELECT enabled FROM noctis_v2.sources WHERE id=$1`, f.source).Scan(&active); e != nil {
								return e
							}
							if !active {
								return jobs.ErrSourcePaused
							}
							return nil
						})
					case "expired_lease":
						_, e := f.store.Claim(ctx, "recover-race", time.Minute)
						done <- e
					}
				}()
				coreWaitLock(t, f.c, "SELECT pg_advisory_xact_lock(76238451003)%")
				f.toggleTx(t, tx, enabled) // SKIP LOCKED must not deadlock Fail/Finish.
				if err = tx.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				err = <-done
				if operation == "expired_lease" && !enabled {
					if !errors.Is(err, pgx.ErrNoRows) {
						t.Fatal(err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				if !enabled {
					f.assert(t, `state='dependency_blocked' AND source_paused_at IS NOT NULL`)
					if operation == "finish" {
						f.assert(t, `attempts=0`)
					} else {
						f.assert(t, `attempts=1`)
					}
					f.toggle(t, true)
					f.assert(t, `state IN ('queued','retry_wait') AND source_paused_at IS NULL`)
				} else {
					f.assert(t, `state IN ('retry_wait','succeeded','leased') AND source_paused_at IS NULL`)
				}
			})
		}
	}
}

func TestSourceRetryMigrationConservativeBackfillPostgres(t *testing.T) {
	f := newRetryFixture(t)
	ctx := context.Background()
	// Reconstruct the pre-012 shape in this isolated database, then migrate
	// ordinary rows and every legacy marker without guessing a pause date.
	coreExec(t, f.c, `DROP TRIGGER initialize_job_retry_deadline ON noctis_v2.jobs; DROP FUNCTION noctis_v2.initialize_job_retry_deadline(); ALTER TABLE noctis_v2.jobs DROP COLUMN retry_deadline_at,DROP COLUMN source_paused_at; DELETE FROM noctis_v2.jobs`)
	for _, row := range []struct{ schema, state, code, age string }{
		{"normal", "queued", "", "2 hours"},
		{"paused_positive", "dependency_blocked", "source_paused", "2 hours"},
		{"paused_expired", "dependency_blocked", "source_paused", "2 days"},
		{"resumed_expired", "queued", "source_resumed", "2 days"},
		{"resumed_positive", "queued", "source_resumed", "2 hours"},
		{"cancelled", "cancelled", "source_paused", "2 days"},
		{"quarantined", "quarantined", "source_paused", "2 days"},
	} {
		coreExec(t, f.c, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version,state,last_error_code,created_at,attempts) VALUES($1,'parse',$2,'1','p1',$3,$4,NULLIF($5,''),clock_timestamp()-$6::interval,2)`, uuid.NewString(), f.observation, row.schema, row.state, row.code, row.age)
	}
	sql, err := migrations.Files.ReadFile("012_job_retry_pause.sql")
	if err != nil {
		t.Fatal(err)
	}
	coreExec(t, f.c, string(sql))
	var count int
	if err = f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.jobs WHERE retry_deadline_at=created_at+interval '24 hours' AND attempts=2`).Scan(&count); err != nil || count != 7 {
		t.Fatal("migration reset budgets", count, err)
	}
	if err = f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.jobs WHERE state='dependency_blocked' AND last_error_code='retry_horizon_unknown' AND source_paused_at IS NULL`).Scan(&count); err != nil || count != 2 {
		t.Fatal("ambiguous legacy work not blocked", count, err)
	}
	if err = f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.jobs WHERE source_paused_at BETWEEN clock_timestamp()-interval '1 minute' AND clock_timestamp() AND schema_version='paused_positive'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("migration invented historical pause", count, err)
	}
	f.toggle(t, true)
	if err = f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.jobs WHERE state='queued' AND source_paused_at IS NULL AND last_error_code IS NULL AND retry_deadline_at<clock_timestamp()+interval '23 hours'`).Scan(&count); err != nil || count != 3 {
		t.Fatal("legacy positive balances did not survive conservatively", count, err)
	}
	if err = f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.jobs WHERE state IN ('cancelled','quarantined') AND attempts=2`).Scan(&count); err != nil || count != 2 {
		t.Fatal("migration revived terminal job", count, err)
	}
	coreExec(t, f.c, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version,created_at) VALUES($1,'parse',$2,'1','p1','old_insert',clock_timestamp()-interval '2 days')`, f.job, f.observation)
	f.assert(t, `retry_deadline_at=created_at+interval '24 hours' AND retry_deadline_at<clock_timestamp()`)
}
