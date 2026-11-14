package runtimev2

import (
	"context"
	"github.com/Zyrakk/noctis/internal/configv2"
	db "github.com/Zyrakk/noctis/internal/database/v2"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/url"
	"os"
	"testing"
)

func TestStartupWithoutLLMPostgres(t *testing.T) {
	dsn := os.Getenv("NOCTIS_V2_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx := context.Background()
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer admin.Close(ctx)
	name := "noctis_v2_runtime_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{name}.Sanitize()
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+quoted); e != nil {
		t.Fatal(e)
	}
	defer admin.Exec(ctx, "DROP DATABASE "+quoted+" WITH (FORCE)")
	cfg, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.Path = "/" + name
	dsn = cfg.String()
	if _, e = Check(ctx, dsn, "api"); e == nil {
		t.Fatal("unmigrated database healthy")
	}
	ms, e := db.Load(migrations.Files)
	if e != nil {
		t.Fatal(e)
	}
	if e = db.Migrate(ctx, dsn, ms); e != nil {
		t.Fatal(e)
	}
	t.Setenv("LLM_API_KEY", "")
	h, e := Check(ctx, dsn, "api")
	if e != nil || !h.Schema || h.AIEnabled {
		t.Fatalf("health: %+v %v", h, e)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if e = Run(cancelled, configv2.Config{Mode: "api", DatabaseURL: dsn, Listen: "127.0.0.1:0", Origin: "https://fixture.invalid", AdminFile: httpConfigAdmin(t)}); e == nil {
		t.Fatal("cancelled startup should fail DB check")
	}
}

func TestUnavailableModes(t *testing.T) {
	for _, mode := range []string{"worker", "collector"} {
		if Run(context.Background(), configv2.Config{Mode: mode}) == nil {
			t.Fatalf("%s falsely functional", mode)
		}
	}
}
