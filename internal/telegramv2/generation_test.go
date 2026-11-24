package telegramv2

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gotd/td/session"
)

func generationSession(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "session.json")
	key := make([]byte, 256)
	copy(key, uuid.NewString())
	s := &ProtectedSession{Path: path}
	if e := (&session.Loader{Storage: s}).Save(context.Background(), &session.Data{AuthKey: key}); e != nil {
		t.Fatal(e)
	}
	gen, e := s.Generation(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	return path, gen
}

func preparedTransition(t *testing.T, f *budgetFixture, legacy bool) (string, GenerationTransition) {
	t.Helper()
	ctx := context.Background()
	path, next := generationSession(t)
	closeProductionFixture(t, f)
	if legacy {
		// Reproduce the already-deployed account-B/consent-A inconsistency only.
		f.exec(t, `UPDATE noctis_v2.telegram_accounts SET auth_generation=$1`, next)
	}
	if e := f.runOwnedRequest(ctx, f.policy.Account, time.Hour, ownerRequest{authenticate: true}, func(ctx context.Context, o Owner) error {
		return f.prepareAuthenticatedGeneration(ctx, o, next)
	}); e != nil {
		t.Fatal(e)
	}
	proposal := filepath.Join(filepath.Dir(path), "transition.json")
	if e := f.ProposeGenerationTransition(ctx, f.policy.Account, "synthetic-operator", "replace verified session", proposal); e != nil {
		t.Fatal(e)
	}
	r, e := ReadGenerationTransition(proposal)
	if e != nil || r.ToGeneration != next || r.ConsentID != f.policy.BudgetID || r.ConsentGeneration != f.policy.Generation {
		t.Fatal(r, e)
	}
	if !legacy && r.FromGeneration != f.policy.Generation || legacy && r.FromGeneration != next {
		t.Fatal("authentication changed production generation", r)
	}
	return path, r
}

func TestGenerationTransitionPreparationFencesAndRepairPostgres(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "normal", true: "legacy-mismatch"}[legacy], func(t *testing.T) {
			f := newProductionFixture(t, 2)
			ctx := context.Background()
			if e := productionCharge(f, func(context.Context) error { return nil }); e != nil {
				t.Fatal(e)
			}
			old := f.owner
			path, r := preparedTransition(t, f, legacy)
			if _, e := f.BindCapturePolicy(ctx, f.policy); e == nil {
				t.Fatal("old production policy bound prepared generation")
			}
			if e := f.guardAPI(ctx, old, "live", "", nil, nil, func(context.Context) error { t.Fatal("old owner contacted RPC"); return nil }); e == nil {
				t.Fatal("old owner admitted")
			}
			if _, e := f.acquire(ctx, r.Account, "old-inventory", time.Minute, ownerRequest{inventoryGeneration: r.FromGeneration}); e == nil {
				t.Fatal("old inventory admitted prepared key")
			}
			if e := f.TransitionGeneration(ctx, path, r); e != nil {
				t.Fatal(e)
			}
			if e := f.TransitionGeneration(ctx, path, r); e != nil {
				t.Fatal("idempotent transition", e)
			}
			changed := r
			changed.Reason = "different request"
			if e := f.TransitionGeneration(ctx, path, changed); e == nil {
				t.Fatal("transition id reused with different content")
			}
			var active *string
			var pending, gen string
			var wait time.Time
			var revoked bool
			if e := f.c.QueryRow(ctx, `SELECT active_capture_consent::text,pending_generation_transition::text,auth_generation::text,quota_wait_until FROM noctis_v2.telegram_accounts`).Scan(&active, &pending, &gen, &wait); e != nil || active != nil || pending != r.ID || gen != r.ToGeneration || !wait.After(time.Now()) {
				t.Fatal(active, pending, gen, wait, e)
			}
			if e := f.c.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM noctis_v2.telegram_capture_consents WHERE id=$1`, r.ConsentID).Scan(&revoked); e != nil || !revoked {
				t.Fatal("predecessor not revoked", e)
			}
			pilot := f.policy
			pilot.Version, pilot.Generation, pilot.BudgetID = 1, gen, uuid.NewString()
			pilot.WindowSeconds, pilot.Revision = 600, 0
			pilot.Actor, pilot.Reason, pilot.Predecessor = "", "", ""
			pilot.PeriodAnchor, pilot.ExpiresAt = time.Time{}, time.Time{}
			if _, e := f.BindCapturePolicy(ctx, pilot); e == nil {
				t.Fatal("v1 bypassed pending transition")
			}
			unknown := errors.New("new inventory failed")
			if e := f.runOwnedRequest(ctx, r.Account, time.Hour, ownerRequest{inventoryGeneration: gen}, func(ctx context.Context, o Owner) error {
				if e := f.guardAPI(ctx, o, "live", "", nil, nil, func(context.Context) error { t.Fatal("pending capture invoked RPC"); return nil }); e == nil {
					t.Fatal("pending capture admitted")
				}
				if _, e := f.CommitUpdates(ctx, o, nativeBatch(nativeEvent(1, "forbidden"))); e == nil {
					t.Fatal("pending capture committed payload")
				}
				return unknown
			}); !errors.Is(e, unknown) {
				t.Fatal(e)
			}
			var failures, usage, observations int
			if e := f.c.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.telegram_capture_failures),(SELECT count(*) FROM noctis_v2.telegram_capture_usage),(SELECT count(*) FROM noctis_v2.observations)`).Scan(&failures, &usage, &observations); e != nil || failures != 0 || usage != 1 || observations != 0 {
				t.Fatal("pending inventory attributed failure or changed capture", failures, usage, observations, e)
			}
		})
	}
}

func TestGenerationTransitionCASRollbackAndWaitPostgres(t *testing.T) {
	f := newProductionFixture(t, 1)
	path, r := preparedTransition(t, f, false)
	ctx := context.Background()
	unlock, e := lockSession(path)
	if e != nil {
		t.Fatal(e)
	}
	if e := f.TransitionGeneration(ctx, path, r); e == nil {
		t.Fatal("transition bypassed active session lock")
	}
	unlock()
	for _, mutate := range []func(*GenerationTransition){
		func(r *GenerationTransition) { r.OwnerFence-- },
		func(r *GenerationTransition) { r.ConsentRevision++ },
		func(r *GenerationTransition) { r.FromGeneration = uuid.NewString() },
		func(r *GenerationTransition) { r.ConsentGeneration = uuid.NewString() },
		func(r *GenerationTransition) { r.ConsentID = uuid.NewString() },
		func(r *GenerationTransition) { r.ToGeneration = uuid.NewString() },
	} {
		bad := r
		mutate(&bad)
		if e := f.TransitionGeneration(ctx, path, bad); e == nil {
			t.Fatal("stale CAS accepted", bad)
		}
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=false,lease_expires_at=clock_timestamp()-interval '1 minute'`)
	if e := f.TransitionGeneration(ctx, path, r); e == nil {
		t.Fatal("expired lease accepted as closure")
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET closed=true,lease_expires_at=NULL,capture_failure_revision=1`)
	if e := f.TransitionGeneration(ctx, path, r); e == nil {
		t.Fatal("unacknowledged failure crossed generation")
	}
	f.exec(t, `UPDATE noctis_v2.telegram_accounts SET capture_failure_revision=0`)
	f.exec(t, `CREATE FUNCTION noctis_v2.reject_transition() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN IF NEW.pending_generation_transition IS NOT NULL THEN RAISE EXCEPTION 'synthetic rollback'; END IF; RETURN NEW; END$$; CREATE TRIGGER reject_transition BEFORE UPDATE ON noctis_v2.telegram_accounts FOR EACH ROW EXECUTE FUNCTION noctis_v2.reject_transition()`)
	if e := f.TransitionGeneration(ctx, path, r); e == nil {
		t.Fatal("synthetic rollback ignored")
	}
	var transitions int
	var revoked bool
	if e := f.c.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.telegram_generation_transitions),revoked_at IS NOT NULL FROM noctis_v2.telegram_capture_consents WHERE id=$1`, r.ConsentID).Scan(&transitions, &revoked); e != nil || transitions != 0 || revoked {
		t.Fatal("partial transition survived", transitions, revoked, e)
	}
	f.exec(t, `DROP TRIGGER reject_transition ON noctis_v2.telegram_accounts; UPDATE noctis_v2.telegram_accounts SET quota_wait_until=clock_timestamp()+interval '2 hours',retry_at=clock_timestamp()+interval '3 hours',status='flood_wait'`)
	var retry time.Time
	f.c.QueryRow(ctx, `SELECT retry_at FROM noctis_v2.telegram_accounts`).Scan(&retry)
	// Distinct session copies exercise the row CAS, not only the local flock.
	copyPath := filepath.Join(t.TempDir(), "session.json")
	os.Chmod(filepath.Dir(copyPath), 0700)
	data, _ := os.ReadFile(path)
	if e := protectedWrite(copyPath, data); e != nil {
		t.Fatal(e)
	}
	r2 := r
	r2.ID = uuid.NewString()
	var wg sync.WaitGroup
	errorsCh := make(chan error, 2)
	for i, candidate := range []GenerationTransition{r, r2} {
		wg.Add(1)
		go func(i int, candidate GenerationTransition) {
			defer wg.Done()
			errorsCh <- f.TransitionGeneration(ctx, []string{path, copyPath}[i], candidate)
		}(i, candidate)
	}
	wg.Wait()
	close(errorsCh)
	winners := 0
	for e := range errorsCh {
		if e == nil {
			winners++
		}
	}
	var until time.Time
	if e := f.c.QueryRow(ctx, `SELECT quota_wait_until FROM noctis_v2.telegram_accounts`).Scan(&until); e != nil || winners != 1 || !until.Equal(retry) {
		t.Fatal("CAS or later wait lost", winners, until, retry, e)
	}
}

func TestGenerationPilotAuthenticationPreflightNoMutationPostgres(t *testing.T) {
	f := newBudgetFixture(t, nil)
	closeProductionFixture(t, f)
	path, _ := generationSession(t)
	beforeSession, _ := os.ReadFile(path)
	ctx := context.Background()
	var before, after []byte
	f.c.QueryRow(ctx, `SELECT to_jsonb(a) FROM noctis_v2.telegram_accounts a`).Scan(&before)
	err := f.RunClient(ctx, ClientConfig{Account: f.policy.Account, APIID: 1, APIHash: "synthetic", SessionFile: path, Authenticate: true, QRTokenFile: filepath.Join(filepath.Dir(path), "qr")}, nil)
	if !errors.Is(err, ErrOwnership) {
		t.Fatal("pilot authentication reached transport", err)
	}
	f.c.QueryRow(ctx, `SELECT to_jsonb(a) FROM noctis_v2.telegram_accounts a`).Scan(&after)
	afterSession, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || !bytes.Equal(beforeSession, afterSession) {
		t.Fatal("pilot preflight changed account or session")
	}
}

func TestGenerationSuccessorQuotaRolloverAndRepeatedRotationPostgres(t *testing.T) {
	f := newProductionFixture(t, 1, func(p *CapturePolicy) {
		p.PeriodAnchor = time.Now().UTC().Add(-time.Hour + 12*time.Second).Truncate(time.Microsecond)
	})
	ctx := context.Background()
	if e := productionCharge(f, func(context.Context) error { return nil }); e != nil {
		t.Fatal(e)
	}
	oldID, oldGeneration := f.policy.BudgetID, f.policy.Generation
	var firstBoundary time.Time
	for n := 0; n < 2; n++ {
		path, r := preparedTransition(t, f, false)
		if e := f.TransitionGeneration(ctx, path, r); e != nil {
			t.Fatal(e)
		}
		var boundary time.Time
		f.c.QueryRow(ctx, `SELECT quota_wait_until FROM noctis_v2.telegram_accounts`).Scan(&boundary)
		if n == 0 {
			firstBoundary = boundary
		} else if !boundary.Equal(firstBoundary) {
			t.Fatal("rotation changed original hourly boundary", boundary, firstBoundary)
		}
		f.policy.Generation = r.ToGeneration
		f.policy.Predecessor, f.policy.BudgetID = f.policy.BudgetID, uuid.NewString()
		f.policy.Revision++
		f.policy.TransitionID = r.ID
		if e := f.InstallProductionConsent(ctx, f.policy); e == nil {
			t.Fatal("successor accepted previous-generation inventory")
		}
		// The public inventory/import/policy sequence is covered end-to-end in
		// runtimev2. Seed its result here to isolate consent/quota invariants.
		if e := f.RunOwned(ctx, r.Account, func(ctx context.Context, o Owner) error {
			f.owner = o
			prepareProductionPeers(t, f)
			return nil
		}); e != nil {
			t.Fatal(e)
		}
		f.exec(t, `UPDATE noctis_v2.telegram_peers SET auth_generation=$1`, r.ToGeneration)
		for _, mutate := range []func(*CapturePolicy){
			func(p *CapturePolicy) { p.TransitionID = "" },
			func(p *CapturePolicy) { p.TransitionID = uuid.NewString() },
			func(p *CapturePolicy) { p.Predecessor = uuid.NewString() },
			func(p *CapturePolicy) { p.PeriodAnchor = p.PeriodAnchor.Add(time.Second) },
			func(p *CapturePolicy) { p.Global.API++ },
			func(p *CapturePolicy) {
				phases := make(map[string]CaptureLimits, len(p.Phases))
				for phase, limit := range p.Phases {
					phases[phase] = limit
				}
				live := phases["live"]
				live.API--
				phases["live"] = live
				p.Phases = phases
			},
			func(p *CapturePolicy) { p.WindowSeconds = 1800 },
		} {
			bad := f.policy
			mutate(&bad)
			if e := f.InstallProductionConsent(ctx, bad); e == nil {
				t.Fatal("successor weakened transition/quota CAS", bad)
			}
		}
		if e := f.InstallProductionConsent(ctx, f.policy); e != nil {
			t.Fatal(e)
		}
		if e := f.InstallProductionConsent(ctx, f.policy); e != nil {
			t.Fatal("idempotent successor", e)
		}
		var e error
		f.owner, e = f.Acquire(ctx, r.Account, uuid.NewString(), time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		if e := productionCharge(f, func(context.Context) error { t.Fatal("rotation recovered current-period quota"); return nil }); e == nil {
			t.Fatal("current period admitted")
		}
	}
	if time.Until(firstBoundary) > 15*time.Second {
		t.Fatal("synthetic setup missed intended boundary")
	}
	if e := waitUntil(ctx, firstBoundary.Add(10*time.Millisecond)); e != nil {
		t.Fatal(e)
	}
	if e := productionCharge(f, func(context.Context) error { return nil }); e != nil {
		t.Fatal("next original period unavailable", e)
	}
	var oldUsage, consentCount, transitionCount int
	if e := f.c.QueryRow(ctx, `SELECT (SELECT sum((counters->'live'->>'api')::int) FROM noctis_v2.telegram_capture_usage WHERE auth_generation=$1),(SELECT count(*) FROM noctis_v2.telegram_capture_consents),(SELECT count(*) FROM noctis_v2.telegram_generation_transitions)`, oldGeneration).Scan(&oldUsage, &consentCount, &transitionCount); e != nil || oldUsage != 1 || consentCount != 3 || transitionCount != 2 {
		t.Fatal("history changed", oldID, oldUsage, consentCount, transitionCount, e)
	}
	closeProductionFixture(t, f)
	renewal := f.policy
	renewal.Predecessor, renewal.BudgetID = renewal.BudgetID, uuid.NewString()
	renewal.Revision++
	renewal.TransitionID = ""
	if e := f.InstallProductionConsent(ctx, renewal); e != nil {
		t.Fatal("ordinary same-generation renewal failed", e)
	}
	status, e := f.CaptureBudgetStatus(ctx, renewal)
	if e != nil || status["state"] != "exhausted" {
		t.Fatal("renewal recovered exhausted period", status, e)
	}
}
