package telegramv2

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	db "github.com/Zyrakk/noctis/internal/database/v2"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/gotd/td/bin"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/tg"
	"github.com/jackc/pgx/v5"
)

type budgetFixture struct {
	Store
	c      *pgx.Conn
	policy CapturePolicy
	owner  Owner
}

func newBudgetFixture(t *testing.T, mutate func(*CapturePolicy)) *budgetFixture {
	return newNativeFixture(t, mutate, true)
}

func newNativeFixture(t *testing.T, mutate func(*CapturePolicy), pilot bool) *budgetFixture {
	t.Helper()
	ctx := context.Background()
	dsn := os.Getenv("NOCTIS_V2_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := "noctis_v2_budget_" + uuid.NewString()[:8]
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(dsn)
	u.Path = "/" + name
	t.Cleanup(func() {
		admin.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
		admin.Close(ctx)
	})
	ms, e := db.Load(migrations.Files)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(ctx, u.String(), ms); e != nil {
		t.Fatal(e)
	}
	c, e := pgx.Connect(ctx, u.String())
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(ctx) })
	p := CapturePolicy{Version: 1, BudgetID: uuid.NewString(), Account: "123", Generation: uuid.NewString(), WindowSeconds: 600, ProcessSeconds: 300, Global: CaptureLimits{API: 256, Observations: 1000, PayloadBytes: 64 << 20, MetadataBytes: 4 << 20}, Phases: map[string]CaptureLimits{}, Peers: []CapturePeer{{SourceID: uuid.NewString(), Type: "channel", ID: 77, LiveEpoch: uuid.NewString(), BootstrapEpoch: uuid.NewString()}}}
	for _, phase := range []string{"control", "bootstrap", "live"} {
		p.Phases[phase] = p.Global
	}
	if mutate != nil {
		mutate(&p)
	}
	f := &budgetFixture{Store: Store{DSN: u.String()}, c: c, policy: p}
	f.exec(t, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p1','[]')`)
	f.exec(t, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES($1,$2)`, p.Account, p.Generation)
	for _, peer := range p.Peers {
		f.exec(t, `INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,epoch,policy_version) VALUES($1,'telegram',$2,true,$3,'p1')`, peer.SourceID, p.Account+":"+peer.Type+":"+strconv.FormatInt(peer.ID, 10), peer.LiveEpoch)
		f.exec(t, `INSERT INTO noctis_v2.telegram_peers(account_id,peer_type,peer_id,source_id,auth_generation,access_hash,allowed,bootstrap_epoch) VALUES($1,$2,$3,$4,$5,123,true,$6)`, p.Account, peer.Type, peer.ID, peer.SourceID, p.Generation, peer.BootstrapEpoch)
	}
	if pilot {
		if _, e = f.BindCapturePolicy(ctx, p); e != nil {
			t.Fatal(e)
		}
	}
	f.owner, e = f.Acquire(ctx, p.Account, "budget-fixture", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func (f *budgetFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, e := f.c.Exec(context.Background(), sql, args...); e != nil {
		t.Fatal(e)
	}
}
func (f *budgetFixture) counters(t *testing.T) map[string]CaptureLimits {
	t.Helper()
	var raw []byte
	if e := f.c.QueryRow(context.Background(), `SELECT counters FROM noctis_v2.telegram_capture_budgets WHERE id=$1`, f.policy.BudgetID).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var v map[string]CaptureLimits
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func nativeEvent(id int, text string) Event {
	return Event{Peer: Peer{Type: "channel", ID: 77}, MessageID: id, Revision: "1", Kind: "message", Text: func() ([]byte, error) { return []byte(text), nil }}
}
func nativeBatch(events ...Event) Envelope {
	return Envelope{BatchID: uuid.NewString(), Expected: State{}, Next: State{}, Difference: true, Mode: capture.Live, Events: events}
}

func TestNativeBudgetAtomicCapsReplayAndMetadataPostgres(t *testing.T) {
	f := newBudgetFixture(t, func(p *CapturePolicy) {
		p.Global.Observations = 2
		p.Global.PayloadBytes = 6
		p.Phases["live"] = CaptureLimits{API: 256, Observations: 2, PayloadBytes: 6, MetadataBytes: 1024}
	})
	ctx := context.Background()
	b := nativeBatch(nativeEvent(1, "abc"))
	if _, e := f.CommitUpdates(ctx, f.owner, b); e != nil {
		t.Fatal(e)
	}
	first := f.counters(t)["live"]
	if first.Observations != 1 || first.PayloadBytes != 3 || first.MetadataBytes == 0 {
		t.Fatal(first)
	}
	if _, e := f.CommitUpdates(ctx, f.owner, b); e != nil {
		t.Fatal(e)
	}
	if got := f.counters(t)["live"]; got != first {
		t.Fatal("receipt replay charged", got)
	}
	replay := nativeBatch(nativeEvent(1, "abc"))
	if _, e := f.CommitUpdates(ctx, f.owner, replay); e != nil {
		t.Fatal(e)
	}
	if got := f.counters(t)["live"]; got != first {
		t.Fatal("inbox duplicate charged", got)
	}
	bad := nativeBatch(nativeEvent(2, "def"), nativeEvent(3, "x"))
	if _, e := f.CommitUpdates(ctx, f.owner, bad); !errors.Is(e, ErrBudget) {
		t.Fatal("overbatch accepted", e)
	}
	var count int
	if e := f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations`).Scan(&count); e != nil || count != 1 {
		t.Fatal("partial overbatch commit", count, e)
	}
	if got := f.counters(t)["live"]; got != first {
		t.Fatal("overbatch charged", got)
	}
	if _, e := f.CommitUpdates(ctx, f.owner, nativeBatch(nativeEvent(2, "def"))); e != nil {
		t.Fatal(e)
	}
	if _, e := f.CommitUpdates(ctx, f.owner, nativeBatch(nativeEvent(4, ""))); !errors.Is(e, ErrBudget) {
		t.Fatal("observation cap bypass", e)
	}
	// Missing binding and excluded peers must fail/skip before payload callbacks.
	var reads atomic.Int32
	excluded := nativeEvent(10, "unused")
	excluded.Peer.ID = 999
	excluded.Text = func() ([]byte, error) { reads.Add(1); return nil, errors.New("must not read") }
	excluded.Metadata = func() (json.RawMessage, error) { reads.Add(1); return nil, errors.New("must not read") }
	if _, e := f.CommitUpdates(ctx, f.owner, nativeBatch(excluded)); e != nil {
		t.Fatal(e)
	}
	if reads.Load() != 0 {
		t.Fatal("excluded payload callback")
	}
}

func TestNativeBudgetAPIAllPhasesRestartAndUncertainPostgres(t *testing.T) {
	f := newBudgetFixture(t, func(p *CapturePolicy) {
		p.Global.API = 4
		p.Phases["bootstrap"] = CaptureLimits{API: 1, Observations: 1000, PayloadBytes: 64 << 20, MetadataBytes: 4 << 20}
	})
	ctx := context.Background()
	var invoked atomic.Int32
	invoke := func(ctx context.Context) error { invoked.Add(1); return errors.New("uncertain simulated transport") }
	for _, phase := range []string{"bootstrap", "live", "control", "live"} {
		if e := f.guardAPI(ctx, f.owner, phase, "", nil, nil, invoke); e == nil {
			t.Fatal("transport failure hidden")
		}
	}
	if invoked.Load() != 4 {
		t.Fatal(invoked.Load())
	}
	if e := f.guardAPI(ctx, f.owner, "bootstrap", "", nil, nil, invoke); !errors.Is(e, ErrBudget) {
		t.Fatal(e)
	}
	if e := f.guardAPI(ctx, f.owner, "live", "", nil, nil, invoke); !errors.Is(e, ErrBudget) {
		t.Fatal(e)
	}
	if invoked.Load() != 4 {
		t.Fatal("global counter treated as channel local")
	}
	// Two process restarts revalidate immutable identity and retain the same usage.
	for n := 0; n < 2; n++ {
		fresh := Store{DSN: f.DSN}
		if _, e := fresh.BindCapturePolicy(ctx, f.policy); e != nil {
			t.Fatal(e)
		}
		f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL WHERE id=$1`, f.policy.Account)
		var e error
		f.owner, e = fresh.Acquire(ctx, f.policy.Account, uuid.NewString(), time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if e = fresh.guardAPI(ctx, f.owner, "live", "", nil, nil, invoke); !errors.Is(e, ErrBudget) {
			t.Fatal("restart reset quota", e)
		}
	}
	changed := f.policy
	changed.BudgetID = uuid.NewString()
	if _, e := f.BindCapturePolicy(ctx, changed); !errors.Is(e, ErrBudget) {
		t.Fatal("budget ID swap", e)
	}
	changed = f.policy
	changed.ProcessSeconds--
	if _, e := f.BindCapturePolicy(ctx, changed); !errors.Is(e, ErrBudget) {
		t.Fatal("limit mutation", e)
	}
	if _, e := f.c.Exec(ctx, `UPDATE noctis_v2.telegram_capture_budgets SET counters=jsonb_set(counters,'{live,api}','0') WHERE id=$1`, f.policy.BudgetID); e == nil {
		t.Fatal("durable counter reset allowed")
	}
	if _, e := f.c.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET active_capture_budget=NULL WHERE id=$1`, f.policy.Account); e == nil {
		t.Fatal("binding reset allowed")
	}
}

func TestNativeBudgetMiddlewareStartupAndNestedAdmissionsPostgres(t *testing.T) {
	f := newBudgetFixture(t, func(p *CapturePolicy) { p.Global.API = 3 })
	ctx := context.Background()
	calls := 0
	next := telegram.InvokeFunc(func(context.Context, bin.Encoder, bin.Decoder) error { calls++; return nil })
	invoke := f.captureMiddleware(f.owner).Handle(next)
	if e := invoke(ctx, &tg.HelpGetConfigRequest{}, nil); e != nil {
		t.Fatal(e)
	}
	if e := f.guardAPI(ctx, f.owner, "bootstrap", "", nil, nil, func(ioCtx context.Context) error {
		if e := invoke(ioCtx, &tg.UpdatesGetDifferenceRequest{}, nil); e != nil {
			return e
		}
		return invoke(ioCtx, &tg.HelpGetConfigRequest{}, nil)
	}); e != nil {
		t.Fatal(e)
	}
	if calls != 3 {
		t.Fatal(calls)
	}
	if e := invoke(ctx, &tg.UsersGetUsersRequest{}, nil); !errors.Is(e, ErrBudget) {
		t.Fatal(e)
	}
	if e := invoke(ctx, &tg.ChannelsJoinChannelRequest{}, nil); e == nil {
		t.Fatal("membership admitted")
	}
	counters := f.counters(t)
	if counters["control"].API != 1 || counters["bootstrap"].API != 2 {
		t.Fatal(counters)
	}
}

func TestNativeBudgetConcurrentFinalAdmissionAndDBDownPostgres(t *testing.T) {
	f := newBudgetFixture(t, func(p *CapturePolicy) { p.Global.API = 1 })
	var calls atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = f.guardAPI(context.Background(), f.owner, "live", "", nil, nil, func(context.Context) error { calls.Add(1); return nil })
		}()
	}
	wg.Wait()
	if calls.Load() != 1 || f.counters(t)["live"].API != 1 {
		t.Fatal("concurrent cap bypass", calls.Load())
	}
	dead := Store{DSN: "postgres://127.0.0.1:1/noctis_v2_missing?connect_timeout=1"}
	if e := dead.guardAPI(context.Background(), f.owner, "live", "", nil, nil, func(context.Context) error { calls.Add(1); return nil }); e == nil || calls.Load() != 1 {
		t.Fatal("DB down invoked", e)
	}
}

func TestNativeBudgetStrictPolicyAndStableSidecar(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "session.json")
	if e := protectedWrite(path, []byte("first")); e != nil {
		t.Fatal(e)
	}
	unlock, e := lockSession(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = protectedWrite(path, []byte("renamed")); e != nil {
		t.Fatal(e)
	}
	if e = RunInventory(context.Background(), ClientConfig{APIID: 1, APIHash: "synthetic", SessionFile: path}, func(context.Context, *Inventory) error { return nil }); e == nil || !strings.Contains(e.Error(), "already in use") {
		t.Fatal("inventory escaped native sidecar after rename", e)
	}
	if e = (Store{DSN: "invalid"}).RunClient(context.Background(), ClientConfig{Account: "123", APIID: 1, APIHash: "synthetic", SessionFile: path}, nil); e == nil || !strings.Contains(e.Error(), "already in use") {
		t.Fatal("native escaped shared sidecar after rename", e)
	}
	if second, e := lockSession(path); e == nil {
		second()
		t.Fatal("rename escaped stable lock")
	}
	unlock()
	second, e := lockSession(path)
	if e != nil {
		t.Fatal(e)
	}
	second()
	os.Remove(path + ".lock")
	if e = os.Symlink(path, path+".lock"); e != nil {
		t.Fatal(e)
	}
	if bad, e := lockSession(path); e == nil {
		bad()
		t.Fatal("symlink lock admitted")
	}
	policyPath := filepath.Join(dir, "capture.json")
	if _, e = ReadCapturePolicy(policyPath); e == nil {
		t.Fatal("missing policy accepted")
	}
	if e = os.WriteFile(policyPath, []byte(`{"version":1,"unknown":true}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadCapturePolicy(policyPath); e == nil {
		t.Fatal("unknown field policy accepted")
	}
	if e = os.Chmod(policyPath, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = ReadCapturePolicy(policyPath); e == nil {
		t.Fatal("unsafe policy accepted")
	}
}

type nativeCrashConfig struct {
	DSN     string
	Owner   Owner
	Mode    string
	BatchID string
	Effect  string
}

func TestNativeBudgetCrashProcessHelper(t *testing.T) {
	path := os.Getenv("NOCTIS_NATIVE_CRASH_FIXTURE")
	if path == "" {
		return
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("private crash fixture unavailable")
	}
	var cfg nativeCrashConfig
	if json.Unmarshal(raw, &cfg) != nil {
		t.Fatal("invalid private crash fixture")
	}
	kill := func() { _ = syscall.Kill(os.Getpid(), syscall.SIGKILL) }
	store := Store{DSN: cfg.DSN}
	ctx := context.Background()
	if cfg.Mode == "before_invoke" || cfg.Mode == "after_invoke" {
		e = store.guardAPI(ctx, cfg.Owner, "live", "", nil, nil, func(context.Context) error {
			if cfg.Mode == "after_invoke" {
				if e := os.WriteFile(cfg.Effect, []byte("fake effect"), 0600); e != nil {
					return e
				}
			}
			kill()
			return nil
		})
	} else {
		batch := nativeBatch(nativeEvent(1, "crash fixture"))
		batch.BatchID = cfg.BatchID
		_, e = store.CommitUpdates(ctx, cfg.Owner, batch)
		if e == nil {
			kill()
		}
	}
	if e != nil {
		t.Fatal("crash fixture did not reach controlled point")
	}
}

func TestNativeBudgetSIGKILLReservationAndCommitBoundariesPostgres(t *testing.T) {
	for _, mode := range []string{"before_invoke", "after_invoke", "before_commit", "after_commit"} {
		t.Run(mode, func(t *testing.T) {
			f := newBudgetFixture(t, nil)
			ctx := context.Background()
			dir := t.TempDir()
			path := filepath.Join(dir, "private.json")
			cfg := nativeCrashConfig{DSN: f.DSN, Owner: f.owner, Mode: mode, BatchID: uuid.NewString(), Effect: filepath.Join(dir, "effect")}
			raw, _ := json.Marshal(cfg)
			if e := os.WriteFile(path, raw, 0600); e != nil {
				t.Fatal(e)
			}
			if mode == "before_commit" {
				f.exec(t, `CREATE FUNCTION noctis_v2.crash_barrier() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN PERFORM pg_advisory_xact_lock(76238451885);RETURN NEW;END$$;CREATE TRIGGER crash_barrier BEFORE INSERT ON noctis_v2.telegram_commits FOR EACH ROW EXECUTE FUNCTION noctis_v2.crash_barrier();SELECT pg_advisory_lock(76238451885)`)
			}
			binary, e := os.Executable()
			if e != nil {
				t.Fatal(e)
			}
			child := exec.Command(binary, "-test.run=^TestNativeBudgetCrashProcessHelper$", "-test.timeout=20s")
			child.Env = append(os.Environ(), "NOCTIS_NATIVE_CRASH_FIXTURE="+path)
			if e = child.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				if child.ProcessState == nil {
					child.Process.Kill()
					child.Wait()
				}
			}()
			if mode == "before_commit" {
				waitNativeLock(t, f.c, "INSERT INTO noctis_v2.telegram_commits%")
				if e = child.Process.Kill(); e != nil {
					t.Fatal(e)
				}
			}
			if e = child.Wait(); e == nil {
				t.Fatal("fixture did not crash")
			}
			if mode == "before_commit" {
				f.exec(t, `SELECT pg_advisory_unlock(76238451885)`)
			}
			// Wait until PostgreSQL notices the dead connection and drops its lock.
			deadline := time.Now().Add(5 * time.Second)
			for {
				var free bool
				if e = f.c.QueryRow(ctx, `SELECT pg_try_advisory_lock(76238451003)`).Scan(&free); e != nil {
					t.Fatal(e)
				}
				if free {
					f.exec(t, `SELECT pg_advisory_unlock(76238451003)`)
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("crash leaked projection guard")
				}
				time.Sleep(5 * time.Millisecond)
			}
			counts := f.counters(t)["live"]
			var obs, receipts int
			if e = f.c.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.observations),(SELECT count(*) FROM noctis_v2.telegram_commits)`).Scan(&obs, &receipts); e != nil {
				t.Fatal(e)
			}
			if mode == "before_invoke" || mode == "after_invoke" {
				if counts.API != 1 || counts.Observations != 0 || obs != 0 || receipts != 0 {
					t.Fatal("reservation lost across crash", counts, obs, receipts)
				}
			}
			if mode == "before_commit" {
				if counts != (CaptureLimits{}) || obs != 0 || receipts != 0 {
					t.Fatal("precommit crash escaped atomic rollback", counts, obs, receipts)
				}
			}
			if mode == "after_commit" {
				if counts.Observations != 1 || obs != 1 || receipts != 1 {
					t.Fatal("committed capture lost", counts, obs, receipts)
				}
				batch := nativeBatch(nativeEvent(1, "crash fixture"))
				batch.BatchID = cfg.BatchID
				if _, e = f.CommitUpdates(ctx, f.owner, batch); e != nil {
					t.Fatal(e)
				}
				if f.counters(t)["live"] != counts {
					t.Fatal("postcrash replay charged")
				}
			}
			_, effectErr := os.Stat(cfg.Effect)
			if (mode == "after_invoke") != (effectErr == nil) {
				t.Fatal("fake external effect boundary incorrect")
			}
			f.exec(t, `UPDATE noctis_v2.telegram_accounts SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, f.owner.Account)
			if _, e = f.Acquire(ctx, f.owner.Account, "automatic-takeover", time.Minute); !errors.Is(e, ErrOwnership) {
				t.Fatal("crash/expired lease falsely proved closure", e)
			}
		})
	}
}

func TestNativeBudgetCompiledCLIValidateStatusAndRequiredPolicyPostgres(t *testing.T) {
	binary := os.Getenv("NOCTIS_V2_TEST_BINARY")
	if binary == "" {
		t.Skip("requires compiled NOCTIS_V2_TEST_BINARY for CLI E2E")
	}
	f := newBudgetFixture(t, nil)
	ctx := context.Background()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	policyFile := filepath.Join(dir, "capture.json")
	raw, _ := json.Marshal(f.policy)
	if e := os.WriteFile(policyFile, raw, 0600); e != nil {
		t.Fatal(e)
	}
	run := func(args ...string) (string, error) {
		cmd := exec.Command(binary, append([]string{"v2", "telegram"}, args...)...)
		out, e := cmd.CombinedOutput()
		return string(out), e
	}
	if out, e := run("capture-policy-validate", "--capture-policy-file", policyFile); e != nil || !strings.Contains(out, `"valid":true`) {
		t.Fatal("compiled policy validation failed")
	}
	// Only SELECT is granted: status cannot initialize a client, bind a budget,
	// mutate counters, or execute migration DDL under this runtime identity.
	role := "native_status_" + uuid.NewString()[:8]
	ident := pgx.Identifier{role}.Sanitize()
	f.exec(t, "CREATE ROLE "+ident+" LOGIN")
	defer func() { f.c.Exec(ctx, "DROP OWNED BY "+ident); f.c.Exec(ctx, "DROP ROLE "+ident) }()
	f.exec(t, "GRANT USAGE ON SCHEMA noctis_v2 TO "+ident)
	f.exec(t, "GRANT SELECT ON ALL TABLES IN SCHEMA noctis_v2 TO "+ident)
	u, _ := url.Parse(f.DSN)
	u.User = url.User(role)
	dsnFile := filepath.Join(dir, "dsn")
	if e := os.WriteFile(dsnFile, []byte(u.String()), 0600); e != nil {
		t.Fatal(e)
	}
	out, e := run("capture-status", "--capture-policy-file", policyFile, "--database-secret-file", dsnFile)
	if e != nil || !strings.Contains(out, `"counters"`) || strings.Contains(out, f.policy.Generation) || strings.Contains(out, "policy_digest") {
		t.Fatal("compiled sanitized read-only status failed")
	}
	if f.counters(t)["live"] != (CaptureLimits{}) {
		t.Fatal("status consumed budget")
	}
	secretFile := filepath.Join(dir, "credential.json")
	if e = os.WriteFile(secretFile, []byte(`{"account":"123","api_id":1,"api_hash":"synthetic-never-used"}`), 0600); e != nil {
		t.Fatal(e)
	}
	sessionFile := filepath.Join(dir, "session.json")
	if e = os.WriteFile(sessionFile, []byte("invalid session must not be loaded"), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(dsnFile, []byte("postgres://127.0.0.1:1/noctis_v2_missing?connect_timeout=1"), 0600); e != nil {
		t.Fatal(e)
	}
	for _, action := range [][]string{{"collect"}, {"backfill", f.policy.Peers[0].SourceID}, {"resolve-source", f.policy.Peers[0].SourceID, "synthetic"}} {
		args := append(action, "--credential-file", secretFile, "--session-file", sessionFile, "--database-secret-file", dsnFile)
		out, e = run(args...)
		if e == nil || !strings.Contains(out, "capture policy requires protected regular mode0600 file") || strings.Contains(out, "authentication required") {
			t.Fatal("capture entrypoint did not fail before session/client/database")
		}
	}
}

func TestNativeBudgetRejectsStoredOldConsentAndMissingBindingPostgres(t *testing.T) {
	f := newBudgetFixture(t, nil)
	ctx := context.Background()
	// Simulate an earlier local, never-activated consent shape. Even with the
	// original digest present, runtime must reject unknown persisted restrictions.
	f.exec(t, `ALTER TABLE noctis_v2.telegram_capture_budgets DISABLE TRIGGER native_budget_immutable`)
	f.exec(t, `UPDATE noctis_v2.telegram_capture_budgets SET policy=jsonb_set(policy,'{peers,0,policy_version}','"p1"')`)
	f.exec(t, `ALTER TABLE noctis_v2.telegram_capture_budgets ENABLE TRIGGER native_budget_immutable`)
	called := false
	if e := f.guardAPI(ctx, f.owner, "live", "", nil, nil, func(context.Context) error { called = true; return nil }); !errors.Is(e, ErrBudget) || called {
		t.Fatal("stored narrowed consent silently relaxed", e)
	}
	_, e := f.c.Exec(ctx, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES('missing-budget',$1)`, uuid.NewString())
	if e != nil {
		t.Fatal(e)
	}
	o, e := f.Acquire(ctx, "missing-budget", "missing", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	event := nativeEvent(1, "never read")
	event.Text = func() ([]byte, error) { called = true; return nil, nil }
	if _, e = f.CommitUpdates(ctx, o, nativeBatch(event)); !errors.Is(e, ErrBudget) || called {
		t.Fatal("missing budget read payload", e)
	}
}

func TestNativeBudgetGlobalPersistedAndPhaseCapsPostgres(t *testing.T) {
	f := newBudgetFixture(t, func(p *CapturePolicy) {
		p.Global.PayloadBytes = 3
		p.Phases["bootstrap"] = CaptureLimits{API: 256, Observations: 1, PayloadBytes: 1, MetadataBytes: 1024}
	})
	ctx := context.Background()
	b := nativeBatch(nativeEvent(1, "bb"))
	b.Mode = capture.Bootstrap
	if _, e := f.CommitUpdates(ctx, f.owner, b); !errors.Is(e, ErrBudget) {
		t.Fatal("bootstrap payload cap bypass", e)
	}
	b = nativeBatch(nativeEvent(1, "a"))
	b.Mode = capture.Bootstrap
	if _, e := f.CommitUpdates(ctx, f.owner, b); e != nil {
		t.Fatal(e)
	}
	if _, e := f.CommitUpdates(ctx, f.owner, nativeBatch(nativeEvent(2, "bb"))); e != nil {
		t.Fatal(e)
	}
	if _, e := f.CommitUpdates(ctx, f.owner, nativeBatch(nativeEvent(3, "x"))); !errors.Is(e, ErrBudget) {
		t.Fatal("global persisted bytes treated as phase local", e)
	}
	b = nativeBatch(nativeEvent(4, ""))
	b.Mode = capture.Bootstrap
	if _, e := f.CommitUpdates(ctx, f.owner, b); !errors.Is(e, ErrBudget) {
		t.Fatal("bootstrap observations cap bypass", e)
	}
	counts := f.counters(t)
	if counts["bootstrap"].Observations != 1 || counts["bootstrap"].PayloadBytes != 1 || counts["live"].Observations != 1 || counts["live"].PayloadBytes != 2 {
		t.Fatal(counts)
	}
	t.Run("metadata", func(t *testing.T) {
		m := newBudgetFixture(t, func(p *CapturePolicy) { p.Global.MetadataBytes = 49 })
		b := nativeBatch(nativeEvent(1, "a"))
		if _, e := m.CommitUpdates(ctx, m.owner, b); e != nil {
			t.Fatal(e)
		}
		if m.counters(t)["live"].MetadataBytes != 49 {
			t.Fatal("retained metadata accounting")
		}
		if _, e := m.CommitUpdates(ctx, m.owner, nativeBatch(nativeEvent(2, "b"))); !errors.Is(e, ErrBudget) {
			t.Fatal("metadata cap bypass", e)
		}
		if m.counters(t)["live"].Observations != 1 {
			t.Fatal("metadata exceed partially persisted observation")
		}
	})
}

func TestNativeBudgetRuntimeRoleAdmissionAndCommitWithoutDDLPostgres(t *testing.T) {
	f := newBudgetFixture(t, nil)
	ctx := context.Background()
	role := "native_runtime_" + uuid.NewString()[:8]
	ident := pgx.Identifier{role}.Sanitize()
	f.exec(t, "CREATE ROLE "+ident+" LOGIN")
	defer func() { f.c.Exec(ctx, "DROP OWNED BY "+ident); f.c.Exec(ctx, "DROP ROLE "+ident) }()
	f.exec(t, "GRANT USAGE ON SCHEMA noctis_v2 TO "+ident)
	f.exec(t, "GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA noctis_v2 TO "+ident)
	u, _ := url.Parse(f.DSN)
	u.User = url.User(role)
	runtime := Store{DSN: u.String()}
	if e := runtime.guardAPI(ctx, f.owner, "live", "", nil, nil, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e := runtime.CommitUpdates(ctx, f.owner, nativeBatch(nativeEvent(1, "restricted runtime"))); e != nil {
		t.Fatal(e)
	}
	c, e := pgx.Connect(ctx, runtime.DSN)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	if _, e = c.Exec(ctx, `CREATE TABLE noctis_v2.forbidden_native_runtime(id int)`); e == nil {
		t.Fatal("runtime permitted DDL")
	}
	counts := f.counters(t)["live"]
	if counts.API != 1 || counts.Observations != 1 {
		t.Fatal("runtime budget consumption", counts)
	}
}
