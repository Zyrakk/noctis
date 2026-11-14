package runtimev2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/inference"
)

func manualWorkerConfig(f *aiFixture) configv2.Config {
	cfg := configv2.Config{Mode: "worker", DatabaseURL: f.store.DSN, AIKeyFile: f.store.KeyFile, AICAFile: f.store.CAFile, ManualInference: true}
	for authority := range f.store.AllowLocal {
		cfg.AIAuthorities = append(cfg.AIAuthorities, authority)
	}
	return cfg
}

func manualAPI(t *testing.T, f *aiFixture) func(string, string, any, int) map[string]any {
	t.Helper()
	cfg := manualWorkerConfig(f)
	cfg.Mode, cfg.Origin = "api", "https://noctis.example"
	cfg.AdminFile = filepath.Join(t.TempDir(), "admin.json")
	if err := os.WriteFile(cfg.AdminFile, []byte(`{"username":"fixture-admin","password":"synthetic-test-password-only"}`), 0600); err != nil {
		t.Fatal(err)
	}
	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	var csrf string
	request := func(method, path string, body any, want int) map[string]any {
		t.Helper()
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(method, cfg.Origin+"/api/v2/"+path, bytes.NewReader(raw))
		r.Header.Set("Origin", cfg.Origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", csrf)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: status=%d want=%d body=%s", method, path, w.Code, want, w.Body.String())
		}
		var out map[string]any
		if err = json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if path == "auth/login" {
			cookie = w.Result().Cookies()[0]
			csrf = out["data"].(map[string]any)["csrf"].(string)
		}
		return out
	}
	request("POST", "auth/login", map[string]string{"Username": "fixture-admin", "Password": "synthetic-test-password-only"}, http.StatusOK)
	return request
}

func requireManualJobState(t *testing.T, f *aiFixture, id, actor, want string) {
	t.Helper()
	j, err := f.store.Job(context.Background(), id, actor)
	if err != nil || j.State != want {
		t.Fatalf("job %s: state=%s want=%s err=%v", id, j.State, want, err)
	}
}

func TestInferenceWorkerOptInCombinationsPostgres(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		for _, manual := range []bool{false, true} {
			t.Run(fmt.Sprintf("automatic=%t/manual=%t", automatic, manual), func(t *testing.T) {
				f := newAIFixture(t)
				ctx := context.Background()
				api := manualAPI(t, f)
				// The request predates opt-in. Its client-owned ID cannot decide origin.
				in := inference.Submit{Function: "query.plan", Input: f.input(t, "query"), RequestID: "semantic-plan:client-chosen"}
				id := api("POST", "ai/jobs", in, http.StatusAccepted)["data"].(map[string]any)["id"].(string)
				cfg := manualWorkerConfig(f)
				cfg.AutomaticInference, cfg.ManualInference = automatic, manual
				if err := runAutomaticInference(ctx, cfg); err != nil {
					t.Fatal(err)
				}
				wantState, wantCalls, wantPlanned := "queued", int64(0), 0
				if automatic || manual {
					wantState, wantCalls = "succeeded", 1
				}
				if automatic {
					wantPlanned = 5
				}
				requireManualJobState(t, f, id, "fixture-admin", wantState)
				// Fresh stores and repeated planning represent independent worker ticks/restarts.
				for i := 0; i < 2; i++ {
					if err := planAutomaticInference(ctx, cfg); err != nil {
						t.Fatal(err)
					}
				}
				var planned, attempts int
				if err := f.conn.QueryRow(ctx, `SELECT (SELECT count(*) FROM noctis_v2.ai_jobs WHERE actor=$1),(SELECT count(*) FROM noctis_v2.ai_attempts)`, inference.AutomaticActor).Scan(&planned, &attempts); err != nil || planned != wantPlanned || int64(attempts) != wantCalls || f.calls.Load() != wantCalls {
					t.Fatalf("planned=%d attempts=%d calls=%d err=%v", planned, attempts, f.calls.Load(), err)
				}
				for i := 0; i < wantPlanned+1; i++ {
					if err := runAutomaticInference(ctx, cfg); err != nil {
						t.Fatal(err)
					}
				}
				if err := planAutomaticInference(ctx, cfg); err != nil {
					t.Fatal(err)
				}
				var succeeded int
				if err := f.conn.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE state='succeeded') FROM noctis_v2.ai_jobs WHERE actor=$1`, inference.AutomaticActor).Scan(&planned, &succeeded); err != nil || planned != wantPlanned || succeeded != wantPlanned || f.calls.Load() != wantCalls+int64(wantPlanned) {
					t.Fatalf("restart duplicated or skipped work: planned=%d succeeded=%d calls=%d err=%v", planned, succeeded, f.calls.Load(), err)
				}
			})
		}
	}
}

func TestManualInferenceSkipsAllAutomaticBacklogStatesPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	if err := f.store.PlanEligible(ctx); err != nil {
		t.Fatal(err)
	}
	// Older automatic jobs exercise every OR branch in claim's eligibility predicate.
	if _, err := f.conn.Exec(ctx, `UPDATE noctis_v2.ai_jobs SET created_at=clock_timestamp()-interval '1 day',state=CASE function_id WHEN 'semantic.classify' THEN 'retry_wait' WHEN 'semantic.relevance' THEN 'running' ELSE 'queued' END,retry_at=clock_timestamp()-interval '1 second',lease_until=clock_timestamp()-interval '1 second' WHERE actor=$1`, inference.AutomaticActor); err != nil {
		t.Fatal(err)
	}
	api := manualAPI(t, f)
	in := inference.Submit{Function: "semantic.claims", Input: f.input(t, "observation"), RequestID: "manual-after-backlog"}
	id := api("POST", "ai/jobs", in, http.StatusAccepted)["data"].(map[string]any)["id"].(string)
	cfg := manualWorkerConfig(f)
	for i := 0; i < 3; i++ {
		if err := runAutomaticInference(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		if err := planAutomaticInference(ctx, cfg); err != nil {
			t.Fatal(err)
		}
	}
	requireManualJobState(t, f, id, "fixture-admin", "succeeded")
	var automaticJobs, automaticAttempts, changed int
	if err := f.conn.QueryRow(ctx, `SELECT count(*),COALESCE(sum(attempts),0),count(*) FILTER(WHERE state NOT IN ('queued','retry_wait','running')) FROM noctis_v2.ai_jobs WHERE actor=$1`, inference.AutomaticActor).Scan(&automaticJobs, &automaticAttempts, &changed); err != nil || automaticJobs != 5 || automaticAttempts != 0 || changed != 0 || f.calls.Load() != 1 {
		t.Fatalf("automatic backlog consumed: jobs=%d attempts=%d changed=%d calls=%d err=%v", automaticJobs, automaticAttempts, changed, f.calls.Load(), err)
	}
}

func TestManualInferenceCoalescingAndCacheStayWithinActorPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	cfg := f.cfg
	for i := range cfg.Bindings {
		if strings.HasPrefix(string(cfg.Bindings[i].Function), "semantic.") {
			cfg.Bindings[i].Model = "m:compound"
		}
	}
	if _, err := f.store.Save(ctx, cfg, cfg.Revision, "fixture-admin"); err != nil {
		t.Fatal(err)
	}
	submit := func(actor, request string, fn inference.Function) string {
		t.Helper()
		j, err := f.store.Submit(ctx, inference.Submit{Function: fn, Input: f.input(t, "observation"), RequestID: request}, actor)
		if err != nil {
			t.Fatal(err)
		}
		return j.ID
	}
	// A succeeded automatic cache entry must not satisfy a manual job.
	submit(inference.AutomaticActor, "auto-cache", "semantic.classify")
	if err := f.store.Once(ctx); err != nil {
		t.Fatal(err)
	}
	autoQueued := submit(inference.AutomaticActor, "auto-queued", "semantic.relevance")
	manualA := submit("fixture-admin", "manual-a", "semantic.classify")
	manualB := submit("fixture-admin", "manual-b", "semantic.relevance")
	var cacheKeys int
	if err := f.conn.QueryRow(ctx, `SELECT count(DISTINCT cache_key) FROM noctis_v2.ai_jobs`).Scan(&cacheKeys); err != nil || cacheKeys != 1 {
		t.Fatalf("fixture must share cache identity across actors: keys=%d err=%v", cacheKeys, err)
	}
	if err := f.store.OnceManual(ctx); err != nil {
		t.Fatal(err)
	}
	requireManualJobState(t, f, manualA, "fixture-admin", "succeeded")
	requireManualJobState(t, f, manualB, "fixture-admin", "succeeded")
	requireManualJobState(t, f, autoQueued, inference.AutomaticActor, "queued")
	if f.calls.Load() != 2 {
		t.Fatalf("manual cache crossed actor or coalescing failed: calls=%d", f.calls.Load())
	}
	manualCached := submit("fixture-admin", "manual-cached", "semantic.classify")
	if err := f.store.OnceManual(ctx); err != nil {
		t.Fatal(err)
	}
	requireManualJobState(t, f, manualCached, "fixture-admin", "succeeded")
	if f.calls.Load() != 2 {
		t.Fatal("manual cache miss")
	}
	var crossed int
	if err := f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_attempt_jobs aj JOIN noctis_v2.ai_jobs j ON j.id=aj.job_id JOIN noctis_v2.ai_attempts a ON a.id=aj.attempt_id JOIN noctis_v2.ai_jobs parent ON parent.id=a.job_id WHERE j.actor<>parent.actor`).Scan(&crossed); err != nil || crossed != 0 {
		t.Fatalf("physical attempt crossed actors: %d err=%v", crossed, err)
	}
}

func TestManualInferenceReconcilesAutomaticUncertaintyAndRetainsBudgetPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	cfg := f.cfg
	cfg.DailyCap, cfg.MonthlyCap = 67584, 67584
	if _, err := f.store.Save(ctx, cfg, cfg.Revision, "fixture-admin"); err != nil {
		t.Fatal(err)
	}
	auto, err := f.store.Submit(ctx, inference.Submit{Function: "query.plan", Input: f.input(t, "query"), RequestID: "auto-abandoned"}, inference.AutomaticActor)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.store.Once(ctx); err != nil {
		t.Fatal(err)
	}
	// Restore the durable boundary of an abandoned sent attempt with an expired lease.
	if _, err = f.conn.Exec(ctx, `UPDATE noctis_v2.ai_jobs SET state='running',result=NULL,lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, auto.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.conn.Exec(ctx, `UPDATE noctis_v2.ai_attempts SET state='sent',actual_units=NULL,exposure_units=maximum_units WHERE job_id=$1`, auto.ID); err != nil {
		t.Fatal(err)
	}
	manual, err := f.store.Submit(ctx, inference.Submit{Function: "query.plan", Input: f.input(t, "query"), RequestID: "manual-budget"}, "fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = runAutomaticInference(ctx, manualWorkerConfig(f)); err != nil {
			t.Fatal(err)
		}
	}
	requireManualJobState(t, f, auto.ID, inference.AutomaticActor, "dependency_blocked")
	if recovered, err := f.store.Job(ctx, auto.ID, inference.AutomaticActor); err != nil || recovered.Error != "execution_uncertain" {
		t.Fatalf("automatic uncertainty diagnostic lost: job=%+v err=%v", recovered, err)
	}
	requireManualJobState(t, f, manual.ID, "fixture-admin", "budget_blocked")
	var attempts, uncertain int
	var exposure int64
	if err = f.conn.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE state='uncertain'),sum(exposure_units) FROM noctis_v2.ai_attempts`).Scan(&attempts, &uncertain, &exposure); err != nil || attempts != 1 || uncertain != 1 || exposure != 67584 || f.calls.Load() != 1 {
		t.Fatalf("uncertainty replayed or exposure lost: attempts=%d uncertain=%d exposure=%d calls=%d err=%v", attempts, uncertain, exposure, f.calls.Load(), err)
	}
}

func TestManualInferenceRespectsRuntimePauseAndCancellationPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	j, err := f.store.Submit(ctx, inference.Submit{Function: "query.plan", Input: f.input(t, "query"), RequestID: "paused-manual"}, "fixture-admin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.conn.Exec(ctx, `UPDATE noctis_v2.runtime_control SET paused=true`); err != nil {
		t.Fatal(err)
	}
	pausedCtx, cancel := context.WithTimeout(ctx, 1200*time.Millisecond)
	defer cancel()
	if err = Run(pausedCtx, manualWorkerConfig(f)); err != nil {
		t.Fatal(err)
	}
	requireManualJobState(t, f, j.ID, "fixture-admin", "queued")
	var attempts int
	if err = f.conn.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_attempts`).Scan(&attempts); err != nil || attempts != 0 || f.calls.Load() != 0 {
		t.Fatalf("paused worker invoked inference: attempts=%d calls=%d err=%v", attempts, f.calls.Load(), err)
	}
	if _, err = f.conn.Exec(ctx, `UPDATE noctis_v2.runtime_control SET paused=false`); err != nil {
		t.Fatal(err)
	}
	f.mode.Store("waitvalid")
	f.block, f.entered = make(chan struct{}), make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() { done <- runAutomaticInference(ctx, manualWorkerConfig(f)) }()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		close(f.block)
		t.Fatal("manual request did not reach provider after unpause")
	}
	err = f.store.Cancel(ctx, j.ID, "fixture-admin")
	close(f.block)
	if err != nil {
		t.Fatal(err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	requireManualJobState(t, f, j.ID, "fixture-admin", "cancelled")
	var actual int64
	if err = f.conn.QueryRow(ctx, `SELECT actual_units FROM noctis_v2.ai_attempts WHERE job_id=$1`, j.ID).Scan(&actual); err != nil || actual != 140 {
		t.Fatalf("cancellation discarded accounting: actual=%d err=%v", actual, err)
	}
	if err = runAutomaticInference(ctx, manualWorkerConfig(f)); err != nil || f.calls.Load() != 1 {
		t.Fatalf("cancelled job replayed: calls=%d err=%v", f.calls.Load(), err)
	}
}

func TestManualInferenceRejectsClientOriginAndReservedSessionPostgres(t *testing.T) {
	f := newAIFixture(t)
	api := manualAPI(t, f)
	for _, field := range []string{"actor", "origin", "automatic", "manual"} {
		api("POST", "ai/jobs", map[string]any{"function_id": "query.plan", "input": f.input(t, "query"), "request_id": "spoof-" + field, field: inference.AutomaticActor}, http.StatusBadRequest)
	}
	var jobs int
	if err := f.conn.QueryRow(context.Background(), `SELECT count(*) FROM noctis_v2.ai_jobs`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("client origin persisted: jobs=%d err=%v", jobs, err)
	}
	// Even a still-live session from an old colliding admin config fails explicitly.
	if _, err := f.conn.Exec(context.Background(), `UPDATE noctis_v2.sessions SET username=$1`, inference.AutomaticActor); err != nil {
		t.Fatal(err)
	}
	out := api("POST", "ai/jobs", inference.Submit{Function: "query.plan", Input: f.input(t, "query"), RequestID: "reserved-session"}, http.StatusForbidden)
	if out["error"].(map[string]any)["code"] != "reserved_actor_identity" {
		t.Fatal("reserved session diagnostic missing", out)
	}
}

func TestInferenceReservedAdministratorRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	raw, _ := json.Marshal(map[string]string{"username": inference.AutomaticActor, "password": "synthetic-test-password-only"})
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewHandler(configv2.Config{AdminFile: path, Origin: "https://noctis.example"})
	if err == nil || !strings.Contains(err.Error(), inference.AutomaticActor) || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("reserved administrator diagnostic missing: %v", err)
	}
}
