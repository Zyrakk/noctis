package telegramv2

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/gotd/td/tg"
	"github.com/jackc/pgx/v5"
)

func waitNativeLock(t *testing.T, c *pgx.Conn, pattern string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		var waiting bool
		if e := c.QueryRow(context.Background(), `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE $1)`, pattern).Scan(&waiting); e != nil {
			t.Fatal(e)
		}
		if waiting {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("SQL barrier not reached", pattern)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
func revokeNative(t *testing.T, f *budgetFixture, done chan<- error) {
	t.Helper()
	ctx := context.Background()
	c, e := pgx.Connect(ctx, f.DSN)
	if e != nil {
		done <- e
		return
	}
	defer c.Close(ctx)
	tx, e := c.Begin(ctx)
	if e != nil {
		done <- e
		return
	}
	defer tx.Rollback(ctx)
	if e = intelligence.LockProjectionTx(ctx, tx); e == nil {
		_, e = tx.Exec(ctx, `UPDATE noctis_v2.sources SET enabled=false,policy_revision=policy_revision+1 WHERE id=$1`, f.policy.Peers[0].SourceID)
	}
	if e == nil {
		e = tx.Commit(ctx)
	}
	done <- e
}

func TestNativeAdmissionRevocationResponseAndCancellationPostgres(t *testing.T) {
	f := newBudgetFixture(t, nil)
	ctx := context.Background()
	source := f.policy.Peers[0].SourceID
	admitted := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	var snapshot SourceAuthorizations
	go func() {
		finished <- f.guardAPI(ctx, f.owner, "live", source, nil, nil, func(ioCtx context.Context) error {
			snapshot = authorizationFrom(ioCtx)
			close(admitted)
			<-release
			return nil
		})
	}()
	<-admitted
	revoked := make(chan error, 1)
	go revokeNative(t, f, revoked)
	waitNativeLock(t, f.c, "SELECT pg_advisory_xact_lock(76238451003)%")
	select {
	case e := <-revoked:
		t.Fatal("revocation passed admitted IO", e)
	default:
	}
	close(release)
	if e := <-finished; e != nil {
		t.Fatal(e)
	}
	if e := <-revoked; e != nil {
		t.Fatal(e)
	}
	var reads atomic.Int32
	e1 := nativeEvent(1, "discarded")
	e1.Text = func() ([]byte, error) { reads.Add(1); return []byte("discarded"), nil }
	batch := nativeBatch(e1)
	batch.Authorization = snapshot
	if _, e := f.CommitUpdates(ctx, f.owner, batch); e == nil || reads.Load() != 0 {
		t.Fatal("revoked response published/read", e, reads.Load())
	}
	calls := 0
	if e := f.guardAPI(ctx, f.owner, "live", source, nil, nil, func(context.Context) error { calls++; return nil }); e == nil || calls != 0 {
		t.Fatal("revocation winner invoked", e)
	}
	// A pause/resume cannot make the older response valid again.
	f.exec(t, `UPDATE noctis_v2.sources SET enabled=true,policy_revision=policy_revision+1 WHERE id=$1`, source)
	if _, e := f.CommitUpdates(ctx, f.owner, batch); e == nil || reads.Load() != 0 {
		t.Fatal("pause/resume revived response", e)
	}
	// A later RPC under the new analytic policy is allowed with the same budget.
	if e := f.guardAPI(ctx, f.owner, "live", source, nil, nil, func(ioCtx context.Context) error { snapshot = authorizationFrom(ioCtx); return nil }); e != nil {
		t.Fatal(e)
	}
	batch = nativeBatch(nativeEvent(2, "current"))
	batch.Authorization = snapshot
	if _, e := f.CommitUpdates(ctx, f.owner, batch); e != nil {
		t.Fatal(e)
	}
	f.exec(t, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p2','[]'); UPDATE noctis_v2.sources SET policy_version='p2',policy_revision=policy_revision+1`)
	batch = nativeBatch(nativeEvent(3, "old policy"))
	batch.Authorization = snapshot
	if _, e := f.CommitUpdates(ctx, f.owner, batch); e == nil {
		t.Fatal("analytic policy changed response published")
	}
	// Cancellation during admitted IO releases the stable guard.
	started := make(chan struct{})
	cancelCtx, cancel := context.WithCancel(ctx)
	go func() {
		finished <- f.guardAPI(cancelCtx, f.owner, "live", source, nil, nil, func(ioCtx context.Context) error { close(started); <-ioCtx.Done(); return ioCtx.Err() })
	}()
	<-started
	cancel()
	if e := <-finished; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	var unlocked bool
	if e := f.c.QueryRow(ctx, `SELECT pg_try_advisory_lock(76238451003)`).Scan(&unlocked); e != nil || !unlocked {
		t.Fatal("cancel leaked guard", e)
	}
	// Cancellation while waiting never reserves or invokes.
	before := f.counters(t)["live"].API
	waitingCtx, stop := context.WithCancel(ctx)
	go func() {
		finished <- f.guardAPI(waitingCtx, f.owner, "live", source, nil, nil, func(context.Context) error { calls++; return nil })
	}()
	waitNativeLock(t, f.c, "SELECT pg_advisory_lock(76238451003)%")
	stop()
	if e := <-finished; !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	f.exec(t, `SELECT pg_advisory_unlock(76238451003)`)
	if f.counters(t)["live"].API != before || calls != 0 {
		t.Fatal("cancelled waiter admitted")
	}
}

type nativeChannelFixture struct {
	RPC
	calls atomic.Int32
}

func (f *nativeChannelFixture) UpdatesGetChannelDifference(context.Context, *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
	f.calls.Add(1)
	return &tg.UpdatesChannelDifference{Pts: 1, Final: false}, nil
}

func TestNativeChannelRevokedBetweenPagesAndHistoryIdentityPostgres(t *testing.T) {
	f := newBudgetFixture(t, nil)
	ctx := context.Background()
	// Stop page one in its atomic native commit. Revoke queues behind projection,
	// and therefore wins admission ahead of page two when the commit releases it.
	f.exec(t, `CREATE FUNCTION noctis_v2.page_barrier() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_advisory_xact_lock(76238451886);RETURN NEW;END$$;CREATE TRIGGER page_barrier BEFORE INSERT ON noctis_v2.telegram_commits FOR EACH ROW EXECUTE FUNCTION noctis_v2.page_barrier();SELECT pg_advisory_lock(76238451886)`)
	rpc := &nativeChannelFixture{}
	co := Coordinator{Store: f.Store, Owner: f.owner, RPC: rpc}
	done := make(chan error, 1)
	go func() { done <- co.ChannelDifference(ctx, &tg.InputChannel{ChannelID: 77, AccessHash: 123}, 0) }()
	waitNativeLock(t, f.c, "INSERT INTO noctis_v2.telegram_commits%")
	revoked := make(chan error, 1)
	go revokeNative(t, f, revoked)
	waitNativeLock(t, f.c, "SELECT pg_advisory_xact_lock(76238451003)%")
	f.exec(t, `SELECT pg_advisory_unlock(76238451886)`)
	if e := <-revoked; e != nil {
		t.Fatal(e)
	}
	if e := <-done; e == nil || rpc.calls.Load() != 1 {
		t.Fatal("next channel page invoked", e, rpc.calls.Load())
	}
	if _, e := co.HistoryPage(ctx, &tg.InputPeerChannel{ChannelID: 77, AccessHash: 123}, 0, 100); e == nil {
		t.Fatal("revoked direct history invoked")
	}
	f.exec(t, `UPDATE noctis_v2.sources SET enabled=true,policy_revision=policy_revision+1`)
	if _, e := co.HistoryPage(ctx, &tg.InputPeerChannel{ChannelID: 999, AccessHash: 123}, 0, 100); e == nil {
		t.Fatal("outside peer history invoked")
	}
	if _, e := co.HistoryPage(ctx, &tg.InputPeerChannel{ChannelID: 77, AccessHash: 321}, 0, 100); e == nil {
		t.Fatal("wrong access binding history invoked")
	}
	wrong := f.owner
	wrong.Generation = uuid.NewString()
	if e := f.guardAPI(ctx, wrong, "live", "", nil, nil, func(context.Context) error { t.Fatal("wrong generation invoked"); return nil }); !errors.Is(e, ErrOwnership) {
		t.Fatal(e)
	}
	f.exec(t, `UPDATE noctis_v2.sources SET epoch=$1`, uuid.NewString())
	if _, e := f.BindCapturePolicy(ctx, f.policy); e == nil {
		t.Fatal("restart accepted changed epoch")
	}
	if e := f.guardAPI(ctx, f.owner, "live", "", nil, nil, func(context.Context) error { t.Fatal("new epoch invoked"); return nil }); e == nil {
		t.Fatal("epoch mutation admitted")
	}
}

func TestNativeBudgetDowntimeExpiryAndAtomicFailurePostgres(t *testing.T) {
	f := newBudgetFixture(t, func(p *CapturePolicy) { p.WindowSeconds = 1 })
	ctx := context.Background()
	f.exec(t, `CREATE FUNCTION noctis_v2.budget_fault() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic before native commit'; END$$;CREATE TRIGGER budget_fault BEFORE INSERT ON noctis_v2.telegram_commits FOR EACH ROW EXECUTE FUNCTION noctis_v2.budget_fault()`)
	if _, e := f.CommitUpdates(ctx, f.owner, nativeBatch(nativeEvent(1, "must roll back"))); e == nil {
		t.Fatal("fault not injected")
	}
	if f.counters(t)["live"] != (CaptureLimits{}) {
		t.Fatal("precommit fault charged")
	}
	var n int
	if e := f.c.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.observations)+(SELECT count(*) FROM noctis_v2.telegram_inbox)+(SELECT count(*) FROM noctis_v2.checkpoints)`).Scan(&n); e != nil || n != 0 {
		t.Fatal("precommit partial persistence", n, e)
	}
	time.Sleep(1100 * time.Millisecond)
	if _, e := f.BindCapturePolicy(ctx, f.policy); !errors.Is(e, ErrBudget) {
		t.Fatal("downtime reset window", e)
	}
	if e := f.guardAPI(ctx, f.owner, "live", "", nil, nil, func(context.Context) error { t.Fatal("expired window invoked"); return nil }); !errors.Is(e, ErrBudget) {
		t.Fatal(e)
	}
}

func TestAuthenticationModeCannotInvokeCaptureOrPersistUpdates(t *testing.T) {
	// RPC is nil and DSN is invalid: any capture attempt would fail or panic.
	// The coordinator wired for explicit auth must exit before either boundary.
	ctx := context.Background()
	co := Coordinator{authenticationOnly: true, Store: Store{DSN: "invalid"}}
	if e := co.Handle(ctx, &tg.UpdatesTooLong{}); e != nil {
		t.Fatal(e)
	}
	if e := co.Difference(ctx); !errors.Is(e, ErrCaptureDisabled) {
		t.Fatal(e)
	}
	if e := co.ChannelDifference(ctx, &tg.InputChannel{ChannelID: 77}, 0); !errors.Is(e, ErrCaptureDisabled) {
		t.Fatal(e)
	}
	if _, e := co.HistoryPage(ctx, &tg.InputPeerChannel{ChannelID: 77}, 0, 100); !errors.Is(e, ErrCaptureDisabled) {
		t.Fatal(e)
	}
	if _, e := co.DialogsPage(ctx, 0, 0, 0, &tg.InputPeerEmpty{}); !errors.Is(e, ErrCaptureDisabled) {
		t.Fatal(e)
	}
	if e := co.ResolveSource(ctx, uuid.NewString(), "synthetic"); !errors.Is(e, ErrCaptureDisabled) {
		t.Fatal(e)
	}
	if _, e := co.BackfillPage(ctx, uuid.NewString(), 100); !errors.Is(e, ErrCaptureDisabled) {
		t.Fatal(e)
	}
}
