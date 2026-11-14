package telegramv2

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"encoding/json"
	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/google/uuid"
	"github.com/gotd/td/tg"
	"github.com/jackc/pgx/v5"
	"net/url"
)

type productionTooLongRPC struct {
	RPC
	calls int
}

func TestProductionRuntimeRoleAdmissionAndAtomicCommitPostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	ctx := context.Background()
	role := "production_runtime_" + uuid.NewString()[:8]
	ident := pgx.Identifier{role}.Sanitize()
	for _, q := range []string{"CREATE ROLE " + ident + " LOGIN", "GRANT USAGE ON SCHEMA noctis_v2 TO " + ident, "GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA noctis_v2 TO " + ident} {
		f.exec(t, q)
	}
	defer func() { f.c.Exec(ctx, "DROP OWNED BY "+ident); f.c.Exec(ctx, "DROP ROLE "+ident) }()
	u, e := url.Parse(f.DSN)
	if e != nil {
		t.Fatal(e)
	}
	u.User = url.User(role)
	f.Store.DSN = u.String()
	if e = productionCharge(f, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	event := Event{Peer: Peer{Type: "channel", ID: 77}, MessageID: 99, Revision: "live-runtime", Kind: "message", Text: func() ([]byte, error) { return []byte("synthetic live payload"), nil }}
	receipt, e := f.CommitUpdates(ctx, f.owner, Envelope{BatchID: uuid.NewString(), Expected: State{}, Next: State{}, Mode: capture.Live, Difference: true, Events: []Event{event}})
	if e != nil || receipt.Included != 1 {
		t.Fatal(receipt, e)
	}
	restricted, e := pgx.Connect(ctx, f.DSN)
	if e != nil {
		t.Fatal(e)
	}
	defer restricted.Close(ctx)
	if _, e = restricted.Exec(ctx, `CREATE TABLE noctis_v2.production_forbidden(id int)`); e == nil {
		t.Fatal("runtime DDL allowed")
	}
	closeProductionFixture(t, f)
	if e = f.RunOwned(ctx, f.policy.Account, func(context.Context, Owner) error { return errors.New("synthetic runtime uncertainty") }); e == nil {
		t.Fatal("runtime failed to report uncertainty")
	}
	if e = f.ResumeProduction(ctx, f.policy, 1, "runtime-operator", "diagnosed synthetic failure"); e != nil {
		t.Fatal("runtime role cannot audit manual resume", e)
	}
}

func (f *productionTooLongRPC) UpdatesGetChannelDifference(context.Context, *tg.UpdatesGetChannelDifferenceRequest) (tg.UpdatesChannelDifferenceClass, error) {
	f.calls++
	return &tg.UpdatesChannelDifferenceTooLong{Final: true, Dialog: &tg.Dialog{Pts: 200}, Messages: []tg.MessageClass{&tg.Message{ID: 22, Message: "historical snapshot must not become evidence", PeerID: &tg.PeerChannel{ChannelID: 77}}}}, nil
}

func TestProductionNoHistoryBeforePayloadAndTooLongPostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	ctx := context.Background()
	var payload, metadata int
	event := Event{Peer: Peer{Type: "channel", ID: 77}, MessageID: 20, Revision: "historical", Kind: "message", Text: func() ([]byte, error) { payload++; return []byte("forbidden"), nil }, Metadata: func() (json.RawMessage, error) { metadata++; return json.RawMessage(`{}`), nil }}
	_, e := f.CommitUpdates(ctx, f.owner, Envelope{BatchID: uuid.NewString(), Expected: State{}, Next: State{}, Mode: capture.Bootstrap, Difference: true, Events: []Event{event}})
	if e != nil {
		t.Fatal(e)
	}
	if payload != 0 || metadata != 0 {
		t.Fatal("bootstrap materialized", payload, metadata)
	}
	rpc := &productionTooLongRPC{}
	co := Coordinator{Store: f.Store, Owner: f.owner, RPC: rpc}
	if e = co.ChannelDifference(ctx, &tg.InputChannel{ChannelID: 77, AccessHash: 123}, 100); e == nil {
		t.Fatal("historical snapshot accepted")
	}
	if rpc.calls != 1 {
		t.Fatal(rpc.calls)
	}
	var pts, count int
	f.c.QueryRow(ctx, `SELECT pts FROM noctis_v2.telegram_channel_states WHERE account_id=$1 AND channel_id=77`, f.policy.Account).Scan(&pts)
	f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations`).Scan(&count)
	if pts != 100 || count != 0 {
		t.Fatal("history changed cursor/evidence", pts, count)
	}
	if e = co.ChannelDifference(ctx, &tg.InputChannel{ChannelID: 77, AccessHash: 123}, 0); e == nil || rpc.calls != 1 {
		t.Fatal("zero baseline contacted RPC", e, rpc.calls)
	}
	if _, e = co.HistoryPage(ctx, &tg.InputPeerChannel{ChannelID: 77, AccessHash: 123}, 0, 10); e == nil {
		t.Fatal("production history RPC accepted")
	}
}

func newProductionFixture(t *testing.T, cap int64, mutations ...func(*CapturePolicy)) *budgetFixture {
	t.Helper()
	f := newNativeFixture(t, nil, false)
	prepareProductionPeers(t, f)
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused'`)
	p := f.policy
	p.Version = 2
	p.BudgetID = uuid.NewString()
	p.Revision = 1
	p.WindowSeconds = 3600
	p.Actor = "synthetic-test"
	p.Reason = "explicit production consent"
	p.PeriodAnchor = time.Now().UTC().Add(-time.Minute).Truncate(time.Microsecond)
	p.ExpiresAt = time.Now().UTC().Add(time.Hour)
	p.Global.API = cap
	p.Phases["bootstrap"] = CaptureLimits{API: 1, MetadataBytes: 4 << 20}
	for _, mutate := range mutations {
		mutate(&p)
	}
	f.policy = p
	if e := f.InstallProductionConsent(context.Background(), p); e != nil {
		t.Fatal(e)
	}
	if e := f.InstallProductionConsent(context.Background(), p); e != nil {
		t.Fatal("idempotent install", e)
	}
	o, e := f.Acquire(context.Background(), p.Account, "production-test", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	f.owner = o
	return f
}

func TestProductionRejectedBatchDurableWaitRestartAndRolloverPostgres(t *testing.T) {
	f := newProductionFixture(t, 10, func(p *CapturePolicy) {
		p.Global.PayloadBytes = 10
		live := p.Phases["live"]
		live.PayloadBytes = 10
		p.Phases["live"] = live
		p.PeriodAnchor = time.Now().UTC().Add(-time.Hour + 2*time.Second).Truncate(time.Microsecond)
	})
	ctx := context.Background()
	batch := func(id int) Envelope {
		return Envelope{BatchID: uuid.NewString(), Expected: State{}, Next: State{}, Difference: true, Mode: capture.Live, Events: []Event{{Peer: Peer{Type: "channel", ID: 77}, MessageID: id, Revision: "quota-wait", Kind: "message", Text: func() ([]byte, error) { return []byte("123456"), nil }}}}
	}
	if _, e := f.CommitUpdates(ctx, f.owner, batch(1)); e != nil {
		t.Fatal(e)
	}
	denied := batch(2)
	if _, e := f.CommitUpdates(ctx, f.owner, denied); !errors.Is(e, ErrQuota) {
		t.Fatal(e)
	}
	status, e := f.CaptureBudgetStatus(ctx, f.policy)
	if e != nil {
		t.Fatal(e)
	}
	counters := status["counters"].(map[string]CaptureLimits)
	if status["state"] != "exhausted" || status["quota_wait_until"] == nil || status["quota_wait_reason"] == nil || counters["live"].PayloadBytes != 6 || counters["live"].Observations != 1 {
		t.Fatal(status)
	}
	var observations, inbox, receipts int
	f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations`).Scan(&observations)
	f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.telegram_inbox WHERE message_id=2`).Scan(&inbox)
	f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.telegram_commits WHERE batch_id=$1`, denied.BatchID).Scan(&receipts)
	if observations != 1 || inbox != 0 || receipts != 0 {
		t.Fatal("failed batch survived rollback", observations, inbox, receipts)
	}
	if e = productionCharge(f, func(context.Context) error { t.Fatal("durable wait invoked RPC"); return nil }); e == nil {
		t.Fatal("wait admission accepted")
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused'`)
	restarted := Store{DSN: f.DSN}
	waitCtx, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	if e = restarted.superviseProduction(waitCtx, ClientConfig{}, f.policy); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("restart opened client during wait", e)
	}
	cancel()
	// Expired wait records remain audit metadata, but cannot exhaust a new period.
	if e = waitUntil(ctx, status["next_period_at"].(time.Time).Add(20*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	status, e = restarted.CaptureBudgetStatus(ctx, f.policy)
	if e != nil || status["state"] != "active" {
		t.Fatal(status, e)
	}
	f.owner, e = f.Acquire(ctx, f.policy.Account, "after-denied-period", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if e = productionCharge(f, func(context.Context) error { return nil }); e != nil {
		t.Fatal("expired wait blocked next period", e)
	}
	if _, e = f.CommitUpdates(ctx, f.owner, batch(2)); e != nil {
		t.Fatal("rejected batch could not retry next period", e)
	}
}

func prepareProductionPeers(t *testing.T, f *budgetFixture) {
	t.Helper()
	id := uuid.NewString()
	p := f.policy.Peers[0]
	if e := f.SaveInventorySnapshot(context.Background(), f.owner, id, "synthetic", []DialogCandidate{{Account: f.policy.Account, Type: "channel", ID: "77", Name: "Private channel without username", AccessHash: 123, Pts: 100}}); e != nil {
		t.Fatal(e)
	}
	f.exec(t, `UPDATE noctis_v2.telegram_peers SET inventory_snapshot=$1`, id)
	f.exec(t, `INSERT INTO noctis_v2.telegram_channel_states(account_id,channel_id,pts) VALUES($1,$2,100) ON CONFLICT DO NOTHING`, f.policy.Account, p.ID)
}
func productionCharge(f *budgetFixture, fn func(context.Context) error) error {
	return f.guardAPI(context.Background(), f.owner, "live", "", nil, nil, fn)
}
func TestProductionRenewalRestartAndUncertainNoResetPostgres(t *testing.T) {
	f := newProductionFixture(t, 2)
	ctx := context.Background()
	uncertain := errors.New("uncertain transport")
	if e := productionCharge(f, func(context.Context) error { return uncertain }); !errors.Is(e, uncertain) {
		t.Fatal(e)
	}
	p := f.policy
	p.Predecessor = p.BudgetID
	p.BudgetID = uuid.NewString()
	p.Revision = 2
	p.ExpiresAt = p.ExpiresAt.Add(time.Hour)
	if e := f.InstallProductionConsent(ctx, p); e == nil {
		t.Fatal("renewed without owner closure")
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET lease_expires_at=clock_timestamp()-interval '1 second'`)
	if e := f.InstallProductionConsent(ctx, p); e == nil {
		t.Fatal("lease expiry substituted for closure")
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused'`)
	if e := f.InstallProductionConsent(ctx, p); e != nil {
		t.Fatal(e)
	}
	f.policy = p
	o, e := f.Acquire(ctx, p.Account, "restarted", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	f.owner = o
	if e = productionCharge(f, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if e = productionCharge(f, func(context.Context) error { t.Fatal("quota reset by renewal"); return nil }); !errors.Is(e, ErrQuota) {
		t.Fatal(e)
	}
	var rows int
	if e = f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.telegram_capture_usage`).Scan(&rows); e != nil || rows != 1 {
		t.Fatal(rows, e)
	}
	if _, e = f.c.Exec(ctx, `UPDATE noctis_v2.telegram_capture_usage SET counters=jsonb_set(counters,'{live,api}','0')`); e == nil {
		t.Fatal("counter decrease accepted")
	}
}

func TestProductionRenewalCASAndExhaustedSupervisorNoClientPostgres(t *testing.T) {
	f := newProductionFixture(t, 1)
	ctx := context.Background()
	if e := productionCharge(f, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused'`)
	left := f.policy
	left.Predecessor = left.BudgetID
	left.BudgetID = uuid.NewString()
	left.Revision = 2
	right := left
	right.BudgetID = uuid.NewString()
	var wins atomic.Int32
	var wg sync.WaitGroup
	for _, p := range []CapturePolicy{left, right} {
		wg.Add(1)
		go func(p CapturePolicy) {
			defer wg.Done()
			if f.InstallProductionConsent(ctx, p) == nil {
				wins.Add(1)
			}
		}(p)
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatal("CAS installed more than one successor", wins.Load())
	}
	var current string
	if e := f.c.QueryRow(ctx, `SELECT active_capture_consent::text FROM noctis_v2.telegram_accounts`).Scan(&current); e != nil {
		t.Fatal(e)
	}
	p := left
	if current == right.BudgetID {
		p = right
	}
	waitCtx, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	// Invalid credentials/session would fail immediately if a client were opened.
	if e := f.superviseProduction(waitCtx, ClientConfig{}, p); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("exhaustion opened client or failed to wait", e)
	}
	if _, e := f.BindCapturePolicy(ctx, f.policy); e == nil {
		t.Fatal("old consent remained current after CAS")
	}
}
func TestProductionConcurrentFinalAdmissionAndRolloverPostgres(t *testing.T) {
	f := newProductionFixture(t, 1)
	ctx := context.Background()
	var calls atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 8; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = productionCharge(f, func(context.Context) error { calls.Add(1); return nil })
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
	// A different already-persisted period retains its own counters. The account,
	// generation and DB clock choose the current row, independent of consent ID.
	f.exec(t, `INSERT INTO noctis_v2.telegram_capture_usage SELECT account_id,auth_generation,period_start-interval '1 hour',counters FROM noctis_v2.telegram_capture_usage`)
	status, e := f.CaptureBudgetStatus(ctx, f.policy)
	if e != nil || status["state"] != "exhausted" {
		t.Fatal(status, e)
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused'`)
	// Test actual anchored rollover using a new account/generation fixture rather
	// than changing an installed anchor or resetting any row.
	g := newNativeFixture(t, nil, false)
	prepareProductionPeers(t, g)
	g.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused'`)
	p := f.policy
	p.Account = g.policy.Account
	p.Generation = g.policy.Generation
	p.Peers = g.policy.Peers
	p.BudgetID = uuid.NewString()
	p.PeriodAnchor = time.Now().UTC().Add(-time.Hour + 1500*time.Millisecond).Truncate(time.Microsecond)
	if e = g.InstallProductionConsent(ctx, p); e != nil {
		t.Fatal(e)
	}
	g.policy = p
	g.owner, e = g.Acquire(ctx, p.Account, "rollover", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	if e = productionCharge(g, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	status, e = g.CaptureBudgetStatus(ctx, p)
	if e != nil {
		t.Fatal(e)
	}
	if e = waitUntil(ctx, status["next_period_at"].(time.Time).Add(20*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	if e = productionCharge(g, func(context.Context) error { return nil }); e != nil {
		t.Fatal("next period unavailable", e)
	}
	var rows int
	g.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.telegram_capture_usage`).Scan(&rows)
	if rows != 2 {
		t.Fatal(rows)
	}
}
func TestProductionExpiryRevocationWrongGenerationAndDBDownPostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	ctx := context.Background()
	wrong := f.owner
	wrong.Generation = uuid.NewString()
	if e := f.guardAPI(ctx, wrong, "live", "", nil, nil, func(context.Context) error { t.Fatal("wrong generation invoked"); return nil }); e == nil {
		t.Fatal("wrong generation accepted")
	}
	if e := f.RevokeProductionConsent(ctx, f.policy.Account, f.policy.BudgetID, f.policy.Revision); e != nil {
		t.Fatal(e)
	}
	if e := productionCharge(f, func(context.Context) error { t.Fatal("revoked invoked"); return nil }); e == nil {
		t.Fatal("revoked accepted")
	}
	dead := Store{DSN: "postgres://127.0.0.1:1/noctis_v2_missing?connect_timeout=1"}
	if e := dead.guardAPI(ctx, f.owner, "live", "", nil, nil, func(context.Context) error { t.Fatal("DB down invoked"); return nil }); e == nil {
		t.Fatal("DB down accepted")
	}
	g := newNativeFixture(t, nil, false)
	prepareProductionPeers(t, g)
	g.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused'`)
	p := f.policy
	p.Account = g.policy.Account
	p.Generation = g.policy.Generation
	p.Peers = g.policy.Peers
	p.BudgetID = uuid.NewString()
	p.ExpiresAt = time.Now().UTC().Add(300 * time.Millisecond)
	if e := g.InstallProductionConsent(ctx, p); e != nil {
		t.Fatal(e)
	}
	g.owner, _ = g.Acquire(ctx, p.Account, "expiry", time.Minute)
	waitUntil(ctx, p.ExpiresAt.Add(20*time.Millisecond))
	if e := productionCharge(g, func(context.Context) error { t.Fatal("expired invoked"); return nil }); e == nil {
		t.Fatal("expired accepted")
	}
}
