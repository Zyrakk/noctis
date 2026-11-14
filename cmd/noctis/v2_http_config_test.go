package main

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	db "github.com/Zyrakk/noctis/internal/database/v2"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestV2MigrateWithoutHTTPConfigurationPostgres(t *testing.T) {
	dsn := os.Getenv("NOCTIS_V2_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	name := "noctis_v2_http_cli_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{name}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE DATABASE "+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP DATABASE "+quoted+" WITH (FORCE)")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	secret := filepath.Join(t.TempDir(), "database")
	if err = os.WriteFile(secret, []byte(u.String()), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := newV2Cmd()
	cmd.SetArgs([]string{"--database-secret-file", secret, "migrate"})
	if err = cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("migrate required API configuration: %v", err)
	}
	c, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	ms, err := db.Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err = c.QueryRow(ctx, `SELECT count(*) FROM public.noctis_v2_migrations`).Scan(&count); err != nil || count != len(ms) {
		t.Fatalf("migrate did not apply the complete ledger: count=%d expected=%d err=%v", count, len(ms), err)
	}
}
