package telegramv2

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestCaptureDiagnosticDoesNotExposeErrors(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, nil)))
	defer slog.SetDefault(previous)
	secret := errors.New("PRIVACY_CANARY postgres://user:password@host SQL payload")
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(errLeaseLoss)
	lease := cancellationAt(ctx, context.Canceled, stageLease)
	logCaptureFailure(errors.Join(lease, secret), stageRun, time.Now())
	got := output.String()
	if strings.Contains(got, "PRIVACY_CANARY") || !strings.Contains(got, `"cause":"lease_loss"`) || !strings.Contains(got, `"kind":"mixed_failure"`) {
		t.Fatal("unsafe/incomplete diagnostic", got)
	}
	output.Reset()
	process, end := context.WithCancelCause(context.Background())
	end(errProcessWindow)
	logCaptureFailure(errors.Join(cancellationAt(process, process.Err(), stageInvoke), lease), stageRun, time.Now())
	if !strings.Contains(output.String(), `"cause":"mixed"`) || strings.Contains(output.String(), `"kind":"process_window"`) {
		t.Fatal("different causes mislabeled", output.String())
	}
}

func TestProductionGuardCanceledConsentLockPostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	closeProductionFixture(t, f)
	lock, e := f.c.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback(context.Background())
	if _, e = lock.Exec(context.Background(), `SELECT id FROM noctis_v2.telegram_capture_consents FOR UPDATE`); e != nil {
		t.Fatal(e)
	}
	observer, e := pgx.Connect(context.Background(), f.DSN)
	if e != nil {
		t.Fatal(e)
	}
	defer observer.Close(context.Background())
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	done := make(chan error, 1)
	go func() {
		done <- f.RunOwned(ctx, f.policy.Account, func(run context.Context, o Owner) error {
			return f.guardAPI(run, o, "live", "", nil, nil, func(context.Context) error { t.Error("canceled admission invoked RPC"); return nil })
		})
	}()
	waitNativeLock(t, observer, "SELECT b.policy,b.policy_digest,b.expires_at%")
	cancel(errProcessWindow)
	if err := <-done; !pureProcessClose(err) {
		t.Fatal("process cancellation not preserved through guard cleanup", err)
	}
	lock.Rollback(context.Background())
	var revision int64
	var closed bool
	if e = f.c.QueryRow(context.Background(), `SELECT capture_failure_revision,closed FROM noctis_v2.telegram_accounts`).Scan(&revision, &closed); e != nil || revision != 0 || !closed {
		t.Fatal("planned cancellation fenced", revision, closed, e)
	}
	var available bool
	if e = f.c.QueryRow(context.Background(), `SELECT pg_try_advisory_lock(76238451003)`).Scan(&available); e != nil || !available {
		t.Fatal("guard leaked", e)
	}
	f.exec(t, `SELECT pg_advisory_unlock(76238451003)`)
}

func TestProductionExternalShutdownAndSDKCancellationPostgres(t *testing.T) {
	for _, external := range []bool{false, true} {
		f := newProductionFixture(t, 10)
		closeProductionFixture(t, f)
		ctx, cancel := context.WithCancel(context.Background())
		err := f.RunOwned(ctx, f.policy.Account, func(run context.Context, o Owner) error {
			if external {
				cancel()
			} else {
				sdk, done := context.WithCancel(run)
				done()
				return cancellationAt(sdk, sdk.Err(), stageCallback)
			}
			return cancellationAt(run, run.Err(), stageCallback)
		})
		cancel()
		if !errors.Is(err, context.Canceled) {
			t.Fatal("shutdown result lost", err)
		}
		var revision int64
		if e := f.c.QueryRow(context.Background(), `SELECT capture_failure_revision FROM noctis_v2.telegram_accounts`).Scan(&revision); e != nil || (revision == 0) != external {
			t.Fatal("shutdown fence", external, revision, e)
		}
	}
}

// Uses only pre-patch symbols so the exact test can run against the snapshot.
func TestProductionCanceledBudgetDoesNotInventDenialPostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(context.Canceled)
	locker, e := pgx.Connect(context.Background(), f.DSN)
	if e != nil {
		t.Fatal(e)
	}
	defer locker.Close(context.Background())
	lock, e := locker.Begin(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Rollback(context.Background())
	if _, e = lock.Exec(context.Background(), `SELECT id FROM noctis_v2.telegram_capture_consents FOR UPDATE`); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() {
		c, err := pgx.Connect(ctx, f.DSN)
		if err != nil {
			done <- err
			return
		}
		defer c.Close(context.Background())
		tx, err := c.Begin(ctx)
		if err != nil {
			done <- err
			return
		}
		defer tx.Rollback(context.Background())
		_, err = productionBudgetTx(ctx, tx, f.owner)
		done <- err
	}()
	waitNativeLock(t, f.c, "SELECT b.policy,b.policy_digest,b.expires_at%")
	cancel(errProcessWindow)
	err := <-done
	if !errors.Is(err, context.Canceled) || errors.Is(err, ErrBudget) {
		t.Fatalf("canceled SQL invented a budget denial: %v", err)
	}
}

func TestCausalCancellationNeverRelabelsLateParent(t *testing.T) {
	parent, end := context.WithCancelCause(context.Background())
	defer end(context.Canceled)
	unproven := cancellationAt(parent, context.DeadlineExceeded, stageInvoke)
	operation, cancel := context.WithTimeoutCause(parent, time.Nanosecond, errOperationTimeout)
	defer cancel()
	<-operation.Done()
	err := cancellationAt(operation, operation.Err(), stageInvoke)
	end(errProcessWindow)
	if safeProductionClose(parent, cancellationAt(parent, unproven, stageRun), "running", nil) || pureProcessClose(processClose(unproven)) {
		t.Fatal("unproven origin relabeled")
	}
	err = cancellationAt(parent, err, stageRun)
	if pureProcessClose(processClose(err)) || safeProductionClose(parent, err, "running", nil) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("operation timer relabeled as planned", err)
	}
	process, stop := context.WithCancelCause(context.Background())
	stop(errProcessWindow)
	planned := cancellationAt(process, context.Canceled, stageBudget)
	if !pureProcessClose(processClose(planned)) {
		t.Fatal("process timer not planned")
	}
	for _, other := range []error{ErrBudget, ErrOwnership, pgx.ErrNoRows, &pgconn.PgError{Code: "42501"}, errors.New("unknown cleanup")} {
		mixed := errors.Join(planned, other)
		if pureProcessClose(processClose(mixed)) || safeProductionClose(process, mixed, "running", nil) || !errors.Is(mixed, other) {
			t.Fatal("real failure hidden", mixed)
		}
		if errors.Is(queryFailure(process, errors.Join(context.Canceled, other), ErrBudget, stageBudget), errProcessWindow) {
			t.Fatal("mixed query relabeled")
		}
	}
	if safeProductionClose(parent, context.DeadlineExceeded, "running", nil) {
		t.Fatal("unproven cancellation accepted")
	}
	root := context.Background()
	sdk, closeSDK := context.WithCancel(context.WithValue(root, captureRootKey{}, root))
	closeSDK()
	if safeProductionClose(root, cancellationAt(sdk, sdk.Err(), stageCallback), "running", nil) {
		t.Fatal("SDK self cancellation accepted as root shutdown")
	}
}

func TestProductionGuardTimerCausalityAndFencePostgres(t *testing.T) {
	for _, mode := range []string{"process", "operation", "late_parent", "mixed"} {
		t.Run(mode, func(t *testing.T) {
			f := newProductionFixture(t, 10)
			closeProductionFixture(t, f)
			ctx, end := context.WithCancelCause(context.Background())
			defer end(context.Canceled)
			unknown := &pgconn.PgError{Code: "42501"}
			err := f.RunOwned(ctx, f.policy.Account, func(run context.Context, o Owner) error {
				budget := time.Second
				if mode != "process" && mode != "mixed" {
					budget = 10 * time.Millisecond
				}
				err := f.guardAPIWithTimeout(run, o, "live", "", nil, nil, budget, func(io context.Context) error {
					if mode == "mixed" {
						return errors.Join(context.Canceled, unknown)
					}
					if mode == "process" {
						end(errProcessWindow)
					}
					<-io.Done()
					return io.Err()
				})
				if mode == "late_parent" {
					end(errProcessWindow)
				}
				return err
			})
			if err == nil {
				t.Fatal("failure lost")
			}
			var revision int64
			var closed bool
			if e := f.c.QueryRow(context.Background(), `SELECT capture_failure_revision,closed FROM noctis_v2.telegram_accounts`).Scan(&revision, &closed); e != nil {
				t.Fatal(e)
			}
			if !closed || (revision == 0) != (mode == "process") {
				t.Fatal("incorrect durable fence", mode, revision, closed, err)
			}
			if mode == "mixed" && !errors.Is(err, unknown) {
				t.Fatal("PostgreSQL error lost")
			}
			restartProductionProcess(t, f, mode != "process")
		})
	}
}

func TestProductionHeartbeatCancellationAndLossPostgres(t *testing.T) {
	for _, loss := range []bool{false, true} {
		f := newProductionFixture(t, 10)
		closeProductionFixture(t, f)
		ctx, end := context.WithCancelCause(context.Background())
		err := f.runOwnedWithHeartbeat(ctx, f.policy.Account, time.Millisecond, func(run context.Context, o Owner) error {
			if loss {
				f.exec(t, `UPDATE noctis_v2.telegram_accounts SET status='paused'`)
			} else {
				lock, e := f.c.Begin(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				defer lock.Rollback(context.Background())
				if _, e = lock.Exec(context.Background(), `SELECT id FROM noctis_v2.telegram_accounts FOR UPDATE`); e != nil {
					t.Fatal(e)
				}
				// This separate observer avoids querying the lock-holding session.
				observer, e := pgx.Connect(context.Background(), f.DSN)
				if e != nil {
					t.Fatal(e)
				}
				defer observer.Close(context.Background())
				waitNativeLock(t, observer, "UPDATE noctis_v2.telegram_accounts SET lease_expires_at%")
				end(errProcessWindow)
			}
			<-run.Done()
			return run.Err()
		})
		end(context.Canceled)
		if loss && !errors.Is(err, ErrOwnership) || !loss && !pureProcessClose(err) {
			t.Fatal("heartbeat cause lost", loss, err)
		}
		var revision int64
		if e := f.c.QueryRow(context.Background(), `SELECT capture_failure_revision FROM noctis_v2.telegram_accounts`).Scan(&revision); e != nil {
			t.Fatal(e)
		}
		if (revision != 0) != loss {
			t.Fatal("heartbeat fence", loss, revision)
		}
	}
}
