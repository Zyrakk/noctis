package runtimev2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestAIExplicitPriceRejectedWithoutConfigSideEffectsPostgres(t *testing.T) {
	f := newAIFixture(t)
	ctx := context.Background()
	const token, csrf, origin = "synthetic-session", "synthetic-csrf", "https://console.invalid"
	if _, err := f.conn.Exec(ctx, `INSERT INTO noctis_v2.sessions(token_hash,username,csrf,expires_at) VALUES($1,'fixture-admin',$2,clock_timestamp()+interval '1 hour')`, tokenHash(token), csrf); err != nil {
		t.Fatal(err)
	}
	if _, err := f.conn.Exec(ctx, `INSERT INTO noctis_v2.ai_promotions(id,function_id,config_revision,dataset_version,status) VALUES($1,$2,$3,'synthetic-v1','validated')`, uuid.NewString(), f.cfg.Bindings[0].Function, f.cfg.Revision); err != nil {
		t.Fatal(err)
	}
	api := &API{cfg: configv2.Config{DatabaseURL: f.store.DSN, AIKeyFile: f.store.KeyFile, AICAFile: f.store.CAFile, Origin: origin}}
	for authority := range f.store.AllowLocal {
		api.cfg.AIAuthorities = append(api.cfg.AIAuthorities, authority)
	}
	snapshot := func() string {
		t.Helper()
		var state string
		if err := f.conn.QueryRow(ctx, `SELECT jsonb_build_object(
			'configs', (SELECT jsonb_agg(c ORDER BY revision) FROM noctis_v2.ai_configs c),
			'secrets', (SELECT jsonb_agg(s ORDER BY config_revision,connection_id) FROM noctis_v2.ai_secrets s),
			'promotions', (SELECT jsonb_agg(p ORDER BY id) FROM noctis_v2.ai_promotions p))::text`).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return state
	}
	before := snapshot()
	for _, version := range []string{"unconfigured", "UNCONFIGURED", " \tUnconfigured\n\u00a0", "", " \t\n\u00a0"} {
		t.Run(fmt.Sprintf("version_%q", version), func(t *testing.T) {
			cfg := f.cfg
			cfg.Bindings = append([]inference.Binding(nil), f.cfg.Bindings...)
			cfg.Connections = append([]inference.Connection(nil), f.cfg.Connections...)
			cfg.Bindings[0].Price.Version = version
			cfg.Connections[0].SecretAction = "set"
			cfg.Connections[0].APIKey = "synthetic-replacement-api-key"
			raw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			for _, endpoint := range []struct{ method, path string }{
				{http.MethodPost, "/api/v2/ai/validate"},
				{http.MethodPut, "/api/v2/ai/config"},
			} {
				req := httptest.NewRequest(endpoint.method, endpoint.path, bytes.NewReader(raw))
				req.Header.Set("Origin", origin)
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-CSRF-Token", csrf)
				req.Header.Set("If-Match", fmt.Sprintf(`"%d"`, cfg.Revision))
				req.AddCookie(&http.Cookie{Name: "noctis_v2_session", Value: token})
				res := httptest.NewRecorder()
				api.handle(res, req)
				if res.Code != http.StatusBadRequest || !strings.Contains(res.Body.String(), `"code":"ai_request_rejected"`) {
					t.Fatalf("%s returned status %d, expected AI configuration rejection", endpoint.path, res.Code)
				}
				if snapshot() != before {
					t.Fatal("rejection changed configuration revisions, encrypted secrets or promotions")
				}
				if f.calls.Load() != 0 {
					t.Fatal("configuration rejection contacted the provider")
				}
			}
		})
	}
}

func TestAILegacyPriceCanBeDisabledAndExplicitlyReenabledPostgres(t *testing.T) {
	ctx := context.Background()
	s := inference.Store{DSN: productDB(t)}
	c, err := pgx.Connect(ctx, s.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	cfg := inference.DefaultConfig()
	cfg.Revision = 1
	cfg.DailyCap, cfg.MonthlyCap = 100, 100
	cfg.Connections = []inference.Connection{{ID: "local", Provider: "synthetic", Adapter: "openai-chat", URL: "https://fixture.invalid", DataClasses: []string{"private-approved"}}}
	b := &cfg.Bindings[0]
	b.Enabled, b.StructuredJSON = true, true
	b.ConnectionID, b.Model = "local", "synthetic"
	b.DailyCap, b.MonthlyCap = 100, 100
	const marker = " \tUnconfigured\n"
	b.Price.Version = marker
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	// Seed a revision written before explicit tariffs were required.
	if _, err = c.Exec(ctx, `INSERT INTO noctis_v2.ai_configs(revision,body,actor) VALUES($1,$2,'legacy-fixture')`, cfg.Revision, string(raw)); err != nil {
		t.Fatal(err)
	}
	v, err := s.Read(ctx)
	if err != nil || v.Revision != 1 || v.Bindings[0].Price.Version != marker || !v.Bindings[0].Enabled {
		t.Fatal("legacy configuration unreadable or rewritten", err)
	}
	cfg = v.Config
	cfg.Bindings[0].Enabled = false
	v, err = s.Save(ctx, cfg, cfg.Revision, "fixture-admin")
	if err != nil || v.Revision != 2 || v.Bindings[0].Enabled || v.Bindings[0].Price.Version != marker {
		t.Fatal("legacy configuration could not be disabled while preserving the marker", err)
	}
	cfg = v.Config
	cfg.Bindings[0].Enabled = true
	const explicit = " \tFree-Local-V1\n"
	cfg.Bindings[0].Price = inference.Price{Version: explicit}
	v, err = s.Save(ctx, cfg, cfg.Revision, "fixture-admin")
	if err != nil || v.Revision != 3 {
		t.Fatal("explicit free tariff could not be enabled", err)
	}
	v, err = s.Read(ctx)
	if err != nil || v.Revision != 3 || !v.Bindings[0].Enabled || v.Bindings[0].Price != (inference.Price{Version: explicit}) {
		t.Fatal("persisted free tariff or identity changed", err)
	}
}
