package telegramv2

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/gotd/td/tgerr"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestProductionRestartProcessHelper(t *testing.T) {
	dsn := os.Getenv("NOCTIS_PRODUCTION_RESTART_DSN")
	if dsn == "" {
		return
	}
	invoked := false
	s := Store{DSN: dsn}
	e := s.RunOwned(context.Background(), "123", func(context.Context, Owner) error { invoked = true; return nil })
	if os.Getenv("NOCTIS_PRODUCTION_EXPECT_BLOCKED") == "1" {
		if invoked || !errors.Is(e, ErrOwnership) {
			t.Fatal("replacement invoked client", invoked, e)
		}
	} else if !invoked || e != nil {
		t.Fatal("explicitly resumed client unavailable", invoked, e)
	}
}
func restartProductionProcess(t *testing.T, f *budgetFixture, blocked bool) {
	t.Helper()
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.Command(binary, "-test.run=^TestProductionRestartProcessHelper$", "-test.timeout=20s")
	expected := "0"
	if blocked {
		expected = "1"
	}
	cmd.Env = append(os.Environ(), "NOCTIS_PRODUCTION_RESTART_DSN="+f.DSN, "NOCTIS_PRODUCTION_EXPECT_BLOCKED="+expected)
	if output, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("replacement process: %v\n%s", e, output)
	}
}
func closeProductionFixture(t *testing.T, f *budgetFixture) {
	t.Helper()
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused'`)
}

func TestProductionUncertaintyDurableAcrossParentRestartAndManualResumePostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	ctx := context.Background()
	if e := productionCharge(f, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET state='{"pts":123,"qts":0,"date":0,"seq":0}'`)
	closeProductionFixture(t, f)
	unknown := errors.New("synthetic unknown transport outcome")
	if e := f.RunOwned(ctx, f.policy.Account, func(context.Context, Owner) error { return unknown }); !errors.Is(e, unknown) {
		t.Fatal(e)
	}
	status, e := f.CaptureBudgetStatus(ctx, f.policy)
	if e != nil || status["state"] != "blocked" || status["failure_revision"] != int64(1) {
		t.Fatal(status, e)
	}
	restartProductionProcess(t, f, true)
	if _, e = f.BindCapturePolicy(ctx, f.policy); e == nil {
		t.Fatal("blocked startup bound consent")
	}
	if e = f.superviseProduction(ctx, ClientConfig{}, f.policy); !errors.Is(e, ErrOwnership) {
		t.Fatal("blocked supervisor tried client", e)
	}
	wrong := f.policy
	wrong.Generation = uuid.NewString()
	if e = f.ResumeProduction(ctx, wrong, 1, "operator", "diagnosed"); e == nil {
		t.Fatal("wrong generation resumed")
	}
	if e = f.ResumeProduction(ctx, f.policy, 2, "operator", "diagnosed"); e == nil {
		t.Fatal("wrong failure CAS resumed")
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=false`)
	if e = f.ResumeProduction(ctx, f.policy, 1, "operator", "diagnosed"); e == nil {
		t.Fatal("resume lacked closure proof")
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true`)
	var successes atomic.Int32
	var wg sync.WaitGroup
	for n := 0; n < 2; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.ResumeProduction(ctx, f.policy, 1, "operator", "diagnosed and explicitly resume") == nil {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("manual resume CAS did not select one acknowledgment", successes.Load())
	}
	status, e = f.CaptureBudgetStatus(ctx, f.policy)
	if e != nil || status["counters"].(map[string]CaptureLimits)["live"].API != 1 {
		t.Fatal("manual resume reset quota", status, e)
	}
	state, e := f.State(ctx, f.policy.Account)
	if e != nil || state.Pts != 123 {
		t.Fatal("manual resume reset cursor", state, e)
	}
	restartProductionProcess(t, f, false)
	var audit int
	f.c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.telegram_capture_resumes WHERE actor='operator' AND failure_revision=1`).Scan(&audit)
	if audit != 1 {
		t.Fatal(audit)
	}
	if e = f.RunOwned(ctx, f.policy.Account, func(context.Context, Owner) error { return errors.New("new uncertainty") }); e == nil {
		t.Fatal("new failure lost")
	}
	restartProductionProcess(t, f, true)
	if e = f.ResumeProduction(ctx, f.policy, 1, "operator", "stale acknowledgment"); e == nil {
		t.Fatal("old acknowledgment cleared new failure")
	}
	if e = f.RevokeProductionConsent(ctx, f.policy.Account, f.policy.BudgetID, f.policy.Revision); e != nil {
		t.Fatal(e)
	}
	if e = f.ResumeProduction(ctx, f.policy, 2, "operator", "cannot resurrect revoked"); e == nil {
		t.Fatal("revoked resumed")
	}
}

func TestProductionPurePlannedCloseAllowedMixedFailureBlockedPostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	ctx := context.Background()
	closeProductionFixture(t, f)
	if !pureProcessClose(errProcessWindow) || pureProcessClose(errors.Join(errProcessWindow, errors.New("unknown"))) || pureCancellation(errors.Join(context.Canceled, errors.New("unknown"))) {
		t.Fatal("mixed result classified as planned")
	}
	if e := f.RunOwned(ctx, f.policy.Account, func(context.Context, Owner) error { return errProcessWindow }); !pureProcessClose(e) {
		t.Fatal(e)
	}
	restartProductionProcess(t, f, false)
	mixed := errors.Join(errProcessWindow, errors.New("unknown close failure"))
	if e := f.RunOwned(ctx, f.policy.Account, func(context.Context, Owner) error { return mixed }); e == nil {
		t.Fatal("mixed failure lost")
	}
	restartProductionProcess(t, f, true)
}

func TestProductionFencePersistenceFailureNeverRecordsClosurePostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	ctx := context.Background()
	closeProductionFixture(t, f)
	f.exec(t, `CREATE FUNCTION noctis_v2.synthetic_fence_unavailable() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RAISE EXCEPTION 'synthetic fence storage unavailable'; END$$`)
	f.exec(t, `CREATE TRIGGER synthetic_fence_unavailable BEFORE INSERT ON noctis_v2.telegram_capture_failures FOR EACH ROW EXECUTE FUNCTION noctis_v2.synthetic_fence_unavailable()`)
	if e := f.RunOwned(ctx, f.policy.Account, func(context.Context, Owner) error { return errors.New("uncertain") }); e == nil {
		t.Fatal("failed fence storage ignored")
	}
	var closed bool
	if e := f.c.QueryRow(ctx, `SELECT closed FROM noctis_v2.telegram_accounts`).Scan(&closed); e != nil || closed {
		t.Fatal("closure recorded without fence", closed, e)
	}
	if _, e := f.Acquire(ctx, f.policy.Account, "replacement", time.Minute); !errors.Is(e, ErrOwnership) {
		t.Fatal("unproven closure reacquired", e)
	}
}

func TestProductionExpiredConsentCannotManualResumePostgres(t *testing.T) {
	f := newProductionFixture(t, 10, func(p *CapturePolicy) { p.ExpiresAt = time.Now().UTC().Add(time.Second) })
	ctx := context.Background()
	closeProductionFixture(t, f)
	if e := f.RunOwned(ctx, f.policy.Account, func(context.Context, Owner) error { return errors.New("uncertain") }); e == nil {
		t.Fatal("failure lost")
	}
	waitUntil(ctx, f.policy.ExpiresAt.Add(20*time.Millisecond))
	if e := f.ResumeProduction(ctx, f.policy, 1, "operator", "must not resurrect expiry"); e == nil {
		t.Fatal("expired resumed")
	}
	status, e := f.CaptureBudgetStatus(ctx, f.policy)
	if e != nil || status["state"] != "expired" {
		t.Fatal(status, e)
	}
}

func TestProductionPersistedFloodWaitAllowsOnlyKnownFailurePostgres(t *testing.T) {
	f := newProductionFixture(t, 10)
	ctx := context.Background()
	closeProductionFixture(t, f)
	if e := f.RunOwned(ctx, f.policy.Account, func(ctx context.Context, o Owner) error {
		return (&Coordinator{Store: f.Store, Owner: o}).failure(ctx, tgerr.New(420, "FLOOD_WAIT_1"))
	}); e == nil {
		t.Fatal("FloodWait lost")
	}
	var failed int64
	var retry time.Time
	f.c.QueryRow(ctx, `SELECT capture_failure_revision,retry_at FROM noctis_v2.telegram_accounts`).Scan(&failed, &retry)
	if failed != 0 {
		t.Fatal("known FloodWait marked uncertain", failed)
	}
	if _, e := f.Acquire(ctx, f.policy.Account, "too-early", time.Minute); !errors.Is(e, ErrOwnership) {
		t.Fatal("FloodWait ignored", e)
	}
	waitUntil(ctx, retry.Add(20*time.Millisecond))
	restartProductionProcess(t, f, false)
}
