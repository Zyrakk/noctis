package runtimev2

import (
	"context"
	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/telegramv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTelegramOnboardingBrowserPostgresHTTPS(t *testing.T) {
	if os.Getenv("NOCTIS_ONBOARDING_BROWSER") != "1" {
		t.Skip("explicit local browser run required")
	}
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	secret := filepath.Join(t.TempDir(), "admin.json")
	if e = os.WriteFile(secret, []byte(`{"username":"fixture-admin","password":"synthetic-only-long-password"}`), 0600); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	handler, e := NewHandler(configv2.Config{DatabaseURL: dsn, Mode: "api", AdminFile: secret, Origin: origin})
	if e != nil {
		t.Fatal(e)
	}
	token := uuid.NewString()
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fixture/inventory" {
			handler.ServeHTTP(w, r)
			return
		}
		if r.Method != "POST" || r.Header.Get("X-Fixture-Token") != token {
			http.Error(w, "denied", 403)
			return
		}
		generation := uuid.NewString()
		if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.telegram_accounts(id,auth_generation) VALUES('synthetic-browser',$1)`, generation); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		store := telegramv2.Store{DSN: dsn}
		e := store.RunOwned(ctx, "synthetic-browser", func(ctx context.Context, o telegramv2.Owner) error {
			return store.SaveInventorySnapshot(ctx, o, uuid.NewString(), "fixture-admin", []telegramv2.DialogCandidate{{Account: "synthetic-browser", Type: "channel", ID: "777", Name: "Canal privado sintético", AccessHash: 987654321, Pts: 100}})
		})
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		w.WriteHeader(204)
	})
	server.StartTLS()
	defer server.Close()
	runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(runCtx, "npx", "playwright", "test", "--config", "playwright.onboarding.config.js")
	cmd.Dir = "../../web"
	cmd.Env = append(os.Environ(), "NOCTIS_ONBOARDING_URL="+origin, "NOCTIS_ONBOARDING_FIXTURE_TOKEN="+token)
	output, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("browser: %v\n%s", e, output)
	}
	t.Log(string(output))
	var observations int
	if e = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.observations`).Scan(&observations); e != nil || observations != 0 {
		t.Fatal(observations, e)
	}
}
