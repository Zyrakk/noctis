package runtimev2

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/telegramv2"
	"github.com/google/uuid"
	"github.com/gotd/td/session"
	"github.com/jackc/pgx/v5"
)

func TestTelegramGenerationTransitionOnboardingPostgresHTTPS(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	store := telegramv2.Store{DSN: dsn}
	call := operationsClient(t, &aiFixture{dsn: dsn, conn: c})
	old := uuid.NewString()
	if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES('rotation',$1)`, old); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('explicit-rotation-pir','[]')`); e != nil {
		t.Fatal(e)
	}
	snapshot := func() string {
		t.Helper()
		id := uuid.NewString()
		if e := store.RunOwned(ctx, "rotation", func(ctx context.Context, o telegramv2.Owner) error {
			return store.SaveInventorySnapshot(ctx, o, id, "operator", []telegramv2.DialogCandidate{{Account: "rotation", Type: "channel", ID: "777", Name: "same stable channel", AccessHash: 987654321, Pts: 100}})
		}); e != nil {
			t.Fatal(e)
		}
		return id
	}
	oldSnapshot := snapshot()
	imported := call("POST", "telegram/import", map[string]any{"snapshot_id": oldSnapshot, "peer_id": 777}, 200)["data"].(map[string]any)
	source := imported["source_id"].(string)
	call("POST", "sources/"+source+"/policy", map[string]any{"expected_revision": 1, "enabled": true, "policy_version": "explicit-rotation-pir"}, 200)
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	policyPath := filepath.Join(dir, "consent.json")
	if e := store.ProposeProductionConsent(ctx, "rotation", "operator", "initial consent", policyPath); e != nil {
		t.Fatal(e)
	}
	prior, e := telegramv2.ReadCapturePolicy(policyPath)
	if e != nil {
		t.Fatal(e)
	}
	if e := store.InstallProductionConsent(ctx, prior); e != nil {
		t.Fatal(e)
	}
	storage := &telegramv2.ProtectedSession{Path: filepath.Join(dir, "session.json")}
	key := make([]byte, 256)
	copy(key, uuid.NewString())
	if e := (&session.Loader{Storage: storage}).Save(ctx, &session.Data{AuthKey: key}); e != nil {
		t.Fatal(e)
	}
	next, e := storage.Generation(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// Seed only the verified-auth boundary; telegramv2 exercises that callback
	// plus closure. Every subsequent generation/onboarding change uses public
	// operator methods and the HTTPS policy API, with no corrective SQL.
	if _, e := c.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET prepared_auth_generation=$1 WHERE id='rotation'`, next); e != nil {
		t.Fatal(e)
	}
	transitionPath := filepath.Join(dir, "transition.json")
	if e := store.ProposeGenerationTransition(ctx, "rotation", "operator", "replace verified session", transitionPath); e != nil {
		t.Fatal(e)
	}
	r, e := telegramv2.ReadGenerationTransition(transitionPath)
	if e != nil {
		t.Fatal(e)
	}
	if e := store.TransitionGeneration(ctx, storage.Path, r); e != nil {
		t.Fatal(e)
	}
	call("POST", "telegram/import", map[string]any{"snapshot_id": oldSnapshot, "peer_id": 777}, 409)
	newSnapshot := snapshot()
	call("POST", "telegram/import", map[string]any{"snapshot_id": newSnapshot, "peer_id": 777}, 200)
	var enabled, allowed bool
	var revision int64
	var generation string
	if e := c.QueryRow(ctx, `SELECT s.enabled,p.allowed,p.auth_generation::text,s.policy_revision FROM noctis_v2.sources s JOIN noctis_v2.telegram_peers p ON p.source_id=s.id WHERE s.id=$1`, source).Scan(&enabled, &allowed, &generation, &revision); e != nil || enabled || allowed || generation != next {
		t.Fatal("generation reimport did not require new authorization", enabled, allowed, generation, e)
	}
	if e := store.ProposeProductionConsent(ctx, "rotation", "operator", "new generation consent", policyPath); e == nil {
		t.Fatal("proposal admitted source without generation-B authorization")
	}
	call("POST", "sources/"+source+"/policy", map[string]any{"expected_revision": revision, "enabled": true, "policy_version": "explicit-rotation-pir"}, 200)
	if e := store.ProposeProductionConsent(ctx, "rotation", "operator", "new generation consent", policyPath); e != nil {
		t.Fatal(e)
	}
	successor, e := telegramv2.ReadCapturePolicy(policyPath)
	if e != nil || successor.TransitionID != r.ID || successor.Predecessor != prior.BudgetID || successor.Generation != next || !successor.PeriodAnchor.Equal(prior.PeriodAnchor) {
		t.Fatal(successor, e)
	}
	if e := store.InstallProductionConsent(ctx, successor); e != nil {
		t.Fatal(e)
	}
	status, e := store.CaptureBudgetStatus(ctx, successor)
	if e != nil || status["state"] != "exhausted" {
		t.Fatal("new key recovered old-period quota", status, e)
	}
	var pending *string
	var pts int
	var notBefore time.Time
	if e := c.QueryRow(ctx, `SELECT a.pending_generation_transition::text,a.quota_wait_until,cs.pts FROM noctis_v2.telegram_accounts a JOIN noctis_v2.telegram_channel_states cs ON cs.account_id=a.id WHERE a.id='rotation'`).Scan(&pending, &notBefore, &pts); e != nil || pending != nil || !notBefore.After(time.Now()) || pts != 100 {
		t.Fatal("successor lost capture fence or channel cursor", pending, notBefore, pts, e)
	}
}
