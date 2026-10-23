package telegramv2

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/dcs"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
	"github.com/gotd/td/tgtest/cluster"
	"github.com/gotd/td/transport"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

type countingNativeResolver struct {
	dcs.Resolver
	calls     atomic.Int32
	entered   chan struct{}
	onPrimary func(string)
	err       error
}

// Test-only deterministic entropy stabilizes randomized PQ proof-of-work.
// Both clients still complete fresh MTProto handshakes with empty storage.
// SDK goroutines share entropy, so the fixture reader must serialize access.
type startupFixtureRandom struct {
	mu     sync.Mutex
	random *rand.Rand
}

func (r *startupFixtureRandom) Read(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.random.Read(p)
}

func (r *countingNativeResolver) Primary(ctx context.Context, dc int, list dcs.List) (transport.Conn, error) {
	if r.onPrimary != nil {
		r.onPrimary("resolver_begin")
		defer r.onPrimary("resolver_end")
	}
	r.calls.Add(1)
	if r.entered != nil {
		close(r.entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if r.Resolver == nil {
		if r.err != nil {
			return nil, r.err
		}
		return nil, errors.New("unexpected base resolver invocation")
	}
	return r.Resolver.Primary(ctx, dc, list)
}

func TestNativeStartupRejectsBeforeRealRunResolverPostgres(t *testing.T) {
	for _, mode := range []string{"exhausted", "expired", "missing", "dbdown"} {
		t.Run(mode, func(t *testing.T) {
			f := newBudgetFixture(t, func(p *CapturePolicy) {
				if mode == "expired" {
					p.WindowSeconds = 1
				}
			})
			switch mode {
			case "exhausted":
				f.exec(t, `UPDATE noctis_v2.telegram_capture_budgets SET counters=jsonb_set(counters,'{control,api}','256')`)
			case "expired":
				f.exec(t, `SELECT pg_sleep(GREATEST(0,extract(epoch from (expires_at-clock_timestamp())))+0.01) FROM noctis_v2.telegram_capture_budgets`)
			case "missing":
				f.exec(t, `ALTER TABLE noctis_v2.telegram_accounts DISABLE TRIGGER native_budget_binding; UPDATE noctis_v2.telegram_accounts SET active_capture_budget=NULL; ALTER TABLE noctis_v2.telegram_accounts ENABLE TRIGGER native_budget_binding`)
			case "dbdown":
				f.Store.DSN = "postgres://localhost:1/unavailable?connect_timeout=1"
			}
			r := &countingNativeResolver{}
			e := f.runCaptureClient(context.Background(), f.owner, 1, "synthetic", telegram.Options{Resolver: r}, func(context.Context, *telegram.Client) error { t.Error("callback admitted"); return nil })
			if e == nil || r.calls.Load() != 0 {
				t.Fatalf("rejected startup: err=%v connections=%d", e, r.calls.Load())
			}
		})
	}
}

func TestNativeStartupRetainsCallbackFailureSwallowedBySDKPostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	closeProductionFixture(t, f)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	q := cluster.NewCluster(cluster.Options{})
	q.Dispatch(2, "local")
	q.Common().Vector(tg.UsersGetUsersRequestTypeID, &tg.User{ID: 123})
	done := make(chan error, 1)
	go func() { done <- q.Up(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-q.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	unknown := errors.New("synthetic callback uncertainty")
	err := f.RunOwned(ctx, f.policy.Account, func(run context.Context, owner Owner) error {
		return f.runCaptureClient(run, owner, 1, "synthetic", telegram.Options{
			Resolver: q.Resolver(), PublicKeys: q.Keys(), DCList: q.List(), SessionStorage: &session.StorageMemory{},
			Random: &startupFixtureRandom{random: rand.New(rand.NewSource(8))}, MaxRetries: 1,
		}, func(context.Context, *telegram.Client) error {
			// gotd Run intentionally returns nil for any error matching Canceled,
			// including this mixed error; our retained callback result must survive.
			return errors.Join(context.Canceled, unknown)
		})
	})
	if !errors.Is(err, unknown) || !errors.Is(err, context.Canceled) {
		t.Fatal("SDK swallowed callback failure", err)
	}
	var revision int64
	if e := f.c.QueryRow(context.Background(), `SELECT capture_failure_revision FROM noctis_v2.telegram_accounts`).Scan(&revision); e != nil || revision != 1 {
		t.Fatal("callback failure not fenced", revision, e)
	}
}

func TestProductionStartupCancellationRetainsRootCausePostgres(t *testing.T) {
	for _, cause := range []error{context.Canceled, errProcessWindow} {
		f := newProductionFixture(t, 10)
		closeProductionFixture(t, f)
		ctx, cancel := context.WithCancelCause(context.Background())
		resolver := &countingNativeResolver{entered: make(chan struct{})}
		done := make(chan error, 1)
		go func() {
			done <- f.RunOwned(ctx, f.policy.Account, func(run context.Context, owner Owner) error {
				return f.runCaptureClient(run, owner, 1, "synthetic", telegram.Options{Resolver: resolver}, func(context.Context, *telegram.Client) error {
					t.Error("canceled startup callback invoked")
					return nil
				})
			})
		}()
		select {
		case <-resolver.entered:
		case <-time.After(5 * time.Second):
			cancel(context.Canceled)
			t.Fatal("startup did not enter resolver")
		}
		cancel(cause)
		err := <-done
		if cause == errProcessWindow && !pureProcessClose(err) || cause == context.Canceled && !errors.Is(err, context.Canceled) {
			t.Fatal("startup cancellation cause lost", err)
		}
		var revision int64
		if e := f.c.QueryRow(context.Background(), `SELECT capture_failure_revision FROM noctis_v2.telegram_accounts`).Scan(&revision); e != nil || revision != 0 {
			t.Fatal("root startup shutdown fenced", revision, e)
		}
	}
}

func TestNativeStartupRealRunSelfAndDurableControlPostgres(t *testing.T) {
	started := time.Now()
	stage := func(name string, attempt int, fields map[string]any) {
		if fields == nil {
			fields = map[string]any{}
		}
		fields["stage"] = name
		fields["attempt"] = attempt
		fields["elapsed_ms"] = time.Since(started).Milliseconds()
		raw, _ := json.Marshal(fields)
		t.Log(string(raw))
	}
	f := newBudgetFixture(t, nil)
	stage("database_fixture_ready", -1, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	stage("rsa_dispatch_begin", -1, nil)
	q := cluster.NewCluster(cluster.Options{})
	q.Dispatch(2, "local")
	stage("rsa_dispatch_end", -1, nil)
	q.Common().Vector(tg.UsersGetUsersRequestTypeID, &tg.User{ID: 123})
	done := make(chan error, 1)
	go func() { done <- q.Up(ctx) }()
	t.Cleanup(func() {
		stage("cleanup_begin", -1, nil)
		cancel()
		err := <-done
		stage("cleanup_end", -1, map[string]any{"cluster_error": err != nil})
	})
	select {
	case <-q.Ready():
		stage("cluster_ready", -1, nil)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	r := &countingNativeResolver{Resolver: q.Resolver()}
	for attempt := 0; attempt < 2; attempt++ {
		attempt := attempt
		r.onPrimary = func(name string) { stage(name, attempt, nil) }
		logsCore, logs := observer.New(zap.DebugLevel)
		logExchange := func() {
			for _, entry := range logs.All() {
				switch entry.Message {
				case "Sending ReqPqMultiRequest", "Received server ResPQ", "PQ decomposing complete", "Sending ReqDHParamsRequest", "Received server ServerDHParams", "Sending SetClientDHParamsRequest", "Received server DhGen":
					fields := map[string]any{"message": entry.Message, "event_elapsed_ms": entry.Time.Sub(started).Milliseconds()}
					if took, ok := entry.ContextMap()["took"]; ok {
						fields["pq_took_ns"] = took
					}
					stage("exchange", attempt, fields)
				}
			}
		}
		deadline, _ := ctx.Deadline()
		seed := [2]int64{8, 15}[attempt]
		stage("attempt_begin", attempt, map[string]any{"remaining_ms": time.Until(deadline).Milliseconds(), "fixture_seed": seed})
		selfComplete := make(chan struct{})
		e := f.runCaptureClient(ctx, f.owner, 1, "synthetic", telegram.Options{Random: &startupFixtureRandom{random: rand.New(rand.NewSource(seed))}, Logger: zap.New(logsCore), Resolver: r, PublicKeys: q.Keys(), DCList: q.List(), SessionStorage: &session.StorageMemory{}, UpdateHandler: telegram.UpdateHandlerFunc(func(context.Context, tg.UpdatesClass) error { return nil }), OnSelfSuccess: func(*tg.User) { stage("self_success", attempt, nil); close(selfComplete) }, OnSelfError: func(_ context.Context, e error) error {
			stage("self_error", attempt, map[string]any{"cancelled": errors.Is(e, context.Canceled), "deadline": errors.Is(e, context.DeadlineExceeded)})
			return nil
		}, MaxRetries: 1}, func(ctx context.Context, c *telegram.Client) error {
			stage("callback_ready", attempt, nil)
			// Self also runs concurrently inside real gotd. Both must pass the
			// startup barrier, then obtain separate public API reservations.
			select {
			case <-selfComplete:
			case <-ctx.Done():
				return ctx.Err()
			}
			_, e := c.API().UsersGetUsers(ctx, []tg.InputUserClass{&tg.InputUserSelf{}})
			stage("public_self_end", attempt, map[string]any{"error": e != nil})
			return e
		})
		logExchange()
		stage("attempt_end", attempt, map[string]any{"error": e != nil, "remaining_ms": time.Until(deadline).Milliseconds()})
		if e != nil {
			t.Fatal(e)
		}
		if got := f.counters(t)["control"].API; got < int64((attempt+1)*3) {
			t.Fatalf("startup and public Self not charged: %d", got)
		} else {
			stage("control_counter", attempt, map[string]any{"api": got})
		}
	}
	if r.calls.Load() != 2 {
		t.Fatal("restart resolver calls", r.calls.Load())
	}
}

func TestNativeStartupRealRunCancelClosesBeforeGuardReleasePostgres(t *testing.T) {
	for _, mode := range []string{"cancel", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			f := newBudgetFixture(t, nil)
			r := &countingNativeResolver{entered: make(chan struct{})}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				done <- f.runCaptureClient(ctx, f.owner, 1, "synthetic", telegram.Options{Resolver: r}, func(context.Context, *telegram.Client) error { return nil })
			}()
			<-r.entered
			if mode == "cancel" {
				cancel()
			}
			want := context.Canceled
			if mode == "timeout" {
				want = context.DeadlineExceeded
			}
			if e := <-done; !errors.Is(e, want) {
				t.Fatalf("canceled establishment lost cause: %v", e)
			}
			var locked bool
			if e := f.c.QueryRow(context.Background(), `SELECT pg_try_advisory_lock(76238451003)`).Scan(&locked); e != nil || !locked {
				t.Fatal("guard retained", e)
			}
			f.exec(t, `SELECT pg_advisory_unlock(76238451003)`)
			if f.counters(t)["control"].API != 1 {
				t.Fatal("uncertain establishment refunded")
			}
		})
	}
}

func TestNativeStartupRealRunRejectsReconnectBeforeBaseResolverPostgres(t *testing.T) {
	f := newBudgetFixture(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	baseErr := errors.New("synthetic primary failure")
	r := &countingNativeResolver{err: baseErr}
	e := f.runCaptureClient(ctx, f.owner, 1, "synthetic", telegram.Options{Resolver: r, ReconnectionBackoff: func() backoff.BackOff { return backoff.NewConstantBackOff(0) }}, func(context.Context, *telegram.Client) error { t.Error("failed transport became ready"); return nil })
	if !errors.Is(e, errCaptureEstablishmentDenied) || !errors.Is(e, baseErr) || r.calls.Load() != 1 {
		t.Fatalf("reconnect reached base resolver: %d %v", r.calls.Load(), e)
	}
	if f.counters(t)["control"].API != 1 {
		t.Fatal("establishment control count changed")
	}
}

func TestNativeStartupResolverRejectsAdditionalEstablishments(t *testing.T) {
	for _, mode := range []string{"primary", "media", "cdn"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			base := &countingNativeResolver{entered: make(chan struct{})}
			r := &captureResolver{base: base, cancel: cancel, used: true}
			var e error
			switch mode {
			case "primary":
				_, e = r.Primary(ctx, 2, dcs.List{})
			case "media":
				_, e = r.MediaOnly(ctx, 2, dcs.List{})
			case "cdn":
				_, e = r.CDN(ctx, 2, dcs.List{})
			}
			if !errors.Is(e, errCaptureEstablishmentDenied) || !errors.Is(r.error(), errCaptureEstablishmentDenied) || base.calls.Load() != 0 || !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatal("second establishment admitted")
			}
		})
	}
}

func TestNativeStartupResolverPreservesPrimaryFailure(t *testing.T) {
	for _, mode := range []string{"primary", "media", "cdn"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			baseErr := errors.New("synthetic primary failure")
			base := &countingNativeResolver{err: baseErr}
			r := &captureResolver{base: base, cancel: cancel}
			if _, err := r.Primary(ctx, 2, dcs.List{}); !errors.Is(err, baseErr) || !errors.Is(r.error(), baseErr) {
				t.Fatalf("primary failure lost: %v", err)
			}
			if ctx.Err() != nil {
				t.Fatal("first primary failure canceled the run")
			}
			var err error
			switch mode {
			case "primary":
				_, err = r.Primary(ctx, 2, dcs.List{})
			case "media":
				_, err = r.MediaOnly(ctx, 2, dcs.List{})
			case "cdn":
				_, err = r.CDN(ctx, 2, dcs.List{})
			}
			if !errors.Is(err, baseErr) || !errors.Is(err, errCaptureEstablishmentDenied) || !errors.Is(r.error(), baseErr) || !errors.Is(r.error(), errCaptureEstablishmentDenied) || base.calls.Load() != 1 || !errors.Is(ctx.Err(), context.Canceled) {
				t.Fatalf("denial lost primary cause or reached base: calls=%d err=%v", base.calls.Load(), err)
			}
		})
	}
}

type resolveFailureRPC struct {
	RPC
	err    error
	calls  int
	cancel context.CancelFunc
}

func (r *resolveFailureRPC) ContactsResolveUsername(context.Context, *tg.ContactsResolveUsernameRequest) (*tg.ContactsResolvedPeer, error) {
	r.calls++
	if r.cancel != nil {
		r.cancel()
	}
	return nil, r.err
}

func TestNativeResolveFailurePersistsPauseAndAdmissionPostgres(t *testing.T) {
	for _, kind := range []string{"FLOOD_WAIT_60", "AUTH_KEY_UNREGISTERED"} {
		t.Run(kind, func(t *testing.T) {
			f := newBudgetFixture(t, nil)
			f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused'`)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r := &resolveFailureRPC{err: tgerr.New(420, kind), cancel: cancel}
			e := f.RunOwned(ctx, f.policy.Account, func(ctx context.Context, o Owner) error {
				return (&Coordinator{Store: f.Store, Owner: o, RPC: r}).ResolveSource(ctx, f.policy.Peers[0].SourceID, "synthetic")
			})
			if e == nil || !errors.Is(e, r.err) || r.calls != 1 {
				t.Fatal("resolve error lost", e)
			}
			var status string
			var retry *time.Time
			var closed bool
			var hash int64
			if e = f.c.QueryRow(context.Background(), `SELECT status,retry_at,closed FROM noctis_v2.telegram_accounts WHERE id=$1`, f.policy.Account).Scan(&status, &retry, &closed); e != nil {
				t.Fatal(e)
			}
			want := "revoked"
			if kind == "FLOOD_WAIT_60" {
				want = "flood_wait"
				if retry == nil || !retry.After(time.Now()) {
					t.Fatal("retry_at lost")
				}
			}
			if status != want || !closed || f.counters(t)["control"].API != 1 {
				t.Fatalf("pause/charge lost: %s %v", status, closed)
			}
			if _, e = f.Acquire(context.Background(), f.policy.Account, "restart", time.Minute); e == nil {
				t.Fatal("pause allowed restart")
			}
			if e = f.c.QueryRow(context.Background(), `SELECT access_hash FROM noctis_v2.telegram_peers WHERE account_id=$1`, f.policy.Account).Scan(&hash); e != nil || hash != 123 {
				t.Fatal("failed resolve changed binding", e)
			}
			st, e := f.State(context.Background(), f.policy.Account)
			if e != nil || st != (State{}) {
				t.Fatal("failed resolve changed cursor", e)
			}
		})
	}
}
