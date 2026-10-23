package runtimev2

import (
	"context"
	"encoding/json"
	"github.com/Zyrakk/noctis/internal/telegramv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
	"time"
)

func TestTelegramEmptyCandidatesPausedActivateReimportPostgresHTTPS(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	call := operationsClient(t, &aiFixture{dsn: dsn, conn: c})
	if items := call("GET", "telegram/candidates", nil, 200)["data"].([]any); len(items) != 0 {
		t.Fatal(items)
	}
	gen := uuid.NewString()
	if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES('synthetic',$1)`, gen); e != nil {
		t.Fatal(e)
	}
	store := telegramv2.Store{DSN: dsn}
	snapshot := func(pts int) string {
		t.Helper()
		o, e := store.Acquire(ctx, "synthetic", uuid.NewString(), time.Minute)
		if e != nil {
			t.Fatal(e)
		}
		id := uuid.NewString()
		if e = store.SaveInventorySnapshot(ctx, o, id, "fixture-admin", []telegramv2.DialogCandidate{{Account: "synthetic", Type: "channel", ID: "777", Name: "Private without username", AccessHash: 987654321, Pts: pts}}); e != nil {
			t.Fatal(e)
		}
		if _, e = c.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET closed=true,owner=NULL,lease_expires_at=NULL,status='paused' WHERE id='synthetic'`); e != nil {
			t.Fatal(e)
		}
		return id
	}
	id := snapshot(100)
	candidates := call("GET", "telegram/candidates", nil, 200)
	raw, _ := json.Marshal(candidates)
	if strings.Contains(string(raw), "987654321") || strings.Contains(string(raw), "access_hash") || strings.Contains(string(raw), gen) {
		t.Fatal("private identity escaped API", string(raw))
	}
	body := map[string]any{"snapshot_id": id, "peer_id": 777, "request_id": uuid.NewString()}
	first := call("POST", "telegram/import", body, 200)["data"].(map[string]any)
	source := first["source_id"].(string)
	if replay := call("POST", "telegram/import", body, 200)["data"].(map[string]any); replay["source_id"] != source {
		t.Fatal(replay)
	}
	var enabled bool
	var activated *time.Time
	var epoch *string
	if e = c.QueryRow(ctx, `SELECT enabled,activated_at,epoch::text FROM noctis_v2.sources WHERE id=$1`, source).Scan(&enabled, &activated, &epoch); e != nil || enabled || activated != nil || epoch != nil {
		t.Fatal(enabled, activated, epoch, e)
	}
	if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('explicit-pir','[]')`); e != nil {
		t.Fatal(e)
	}
	call("POST", "sources/"+source+"/policy", map[string]any{"expected_revision": 1, "enabled": true, "policy_version": "explicit-pir"}, 200)
	var pts int
	if e = c.QueryRow(ctx, `SELECT pts FROM noctis_v2.telegram_channel_states WHERE account_id='synthetic' AND channel_id=777`).Scan(&pts); e != nil || pts != 100 {
		t.Fatal(pts, e)
	}
	call("POST", "sources/"+source+"/policy", map[string]any{"expected_revision": 2, "enabled": false, "policy_version": "explicit-pir"}, 200)
	id2 := snapshot(120)
	call("POST", "telegram/import", map[string]any{"snapshot_id": id, "peer_id": 777}, 409)
	call("POST", "telegram/import", map[string]any{"snapshot_id": id2, "peer_id": 777}, 200)
	if e = c.QueryRow(ctx, `SELECT enabled FROM noctis_v2.sources WHERE id=$1`, source).Scan(&enabled); e != nil || enabled {
		t.Fatal("reimport activated paused source", e)
	}
	var count int
	c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations`).Scan(&count)
	if count != 0 {
		t.Fatal("inventory captured observations")
	}
	if _, e = c.Exec(ctx, `UPDATE noctis_v2.telegram_accounts SET auth_generation=$1 WHERE id='synthetic'`, uuid.NewString()); e != nil {
		t.Fatal(e)
	}
	call("POST", "telegram/import", map[string]any{"snapshot_id": id2, "peer_id": 777}, 409)
	call("POST", "sources/"+source+"/policy", map[string]any{"expected_revision": 3, "enabled": true, "policy_version": "explicit-pir"}, 409)
}

func TestTelegramMissingBaselineCannotActivatePostgresHTTPS(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	gen, id, source := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES('s',$1)`, []any{gen}},
		{`INSERT INTO noctis_v2.telegram_inventory_snapshots(id,account_id,auth_generation,actor) VALUES($1,'s',$2,'synthetic')`, []any{id, gen}},
		{`INSERT INTO noctis_v2.telegram_inventory_candidates(snapshot_id,peer_type,peer_id,name,access_hash,folder,pts) VALUES($1,'channel',1,'missing baseline',2,0,0)`, []any{id}},
		{`INSERT INTO noctis_v2.policies(version,terms) VALUES('p','[]')`, nil},
	} {
		if _, e = c.Exec(ctx, q.sql, q.args...); e != nil {
			t.Fatal(e)
		}
	}
	call := operationsClient(t, &aiFixture{dsn: dsn, conn: c})
	result := call("POST", "telegram/import", map[string]any{"snapshot_id": id, "peer_id": 1}, 200)["data"].(map[string]any)
	source = result["source_id"].(string)
	body := call("POST", "sources/"+source+"/policy", map[string]any{"expected_revision": 1, "enabled": true, "policy_version": "p"}, 409)
	if body["error"].(map[string]any)["code"] != "current_channel_baseline_required" {
		t.Fatal(body)
	}
}
