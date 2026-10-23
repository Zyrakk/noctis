package runtimev2

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/Zyrakk/noctis/internal/telegramv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Existing native fixtures explicitly opt in to capture. This helper never
// supplies a policy implicitly in production and does not relax any assertions.
func provisionNativeBudget(t *testing.T, dsn string, c *pgx.Conn, account string) telegramv2.CapturePolicy {
	t.Helper()
	ctx := context.Background()
	p := telegramv2.CapturePolicy{Version: 1, BudgetID: uuid.NewString(), Account: account, WindowSeconds: 600, ProcessSeconds: 300, Global: telegramv2.CaptureLimits{API: 256, Observations: 1000, PayloadBytes: 64 << 20, MetadataBytes: 4 << 20}, Phases: map[string]telegramv2.CaptureLimits{}}
	for _, phase := range []string{"control", "bootstrap", "live"} {
		p.Phases[phase] = p.Global
	}
	if e := c.QueryRow(ctx, `SELECT auth_generation::text FROM noctis_v2.telegram_accounts WHERE id=$1`, account).Scan(&p.Generation); e != nil {
		t.Fatal(e)
	}
	rows, e := c.Query(ctx, `SELECT s.id::text,p.peer_type,p.peer_id,s.epoch::text,p.bootstrap_epoch::text FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id WHERE p.account_id=$1`, account)
	if e != nil {
		t.Fatal(e)
	}
	for rows.Next() {
		var peer telegramv2.CapturePeer
		if e = rows.Scan(&peer.SourceID, &peer.Type, &peer.ID, &peer.LiveEpoch, &peer.BootstrapEpoch); e != nil {
			t.Fatal(e)
		}
		p.Peers = append(p.Peers, peer)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
	if _, e = (telegramv2.Store{DSN: dsn}).BindCapturePolicy(ctx, p); e != nil {
		t.Fatal(e)
	}
	return p
}

func nativeCounters(t *testing.T, c *pgx.Conn, account string) map[string]telegramv2.CaptureLimits {
	t.Helper()
	var raw []byte
	if e := c.QueryRow(context.Background(), `SELECT counters FROM noctis_v2.telegram_capture_budgets WHERE account_id=$1`, account).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	var v map[string]telegramv2.CaptureLimits
	if e := json.Unmarshal(raw, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
