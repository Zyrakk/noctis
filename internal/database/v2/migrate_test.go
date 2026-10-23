package v2

import (
	"context"
	"crypto/sha256"
	"fmt"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"net/url"
	"os"
	"sync"
	"testing"
)

func testDB(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("NOCTIS_V2_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL: NOCTIS_V2_TEST_DATABASE_URL")
	}
	ctx := context.Background()
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := "noctis_v2_test_" + uuid.NewString()[:8]
	if _, e = c.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	cfg, e := url.Parse(dsn)
	if e != nil {
		t.Fatal(e)
	}
	cfg.Path = "/" + name
	t.Cleanup(func() { c.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); c.Close(ctx) })
	return cfg.String()
}
func migration(name, sql string) Migration {
	return Migration{name, sql, fmt.Sprintf("%x", sha256.Sum256([]byte(sql)))}
}
func TestMigrationsPostgres(t *testing.T) {
	dsn := testDB(t)
	ctx := context.Background()
	ms, e := Load(migrations.Files)
	if e != nil {
		t.Fatal(e)
	}
	if e = Migrate(ctx, dsn, ms); e != nil {
		t.Fatal(e)
	}
	upgrade := append(append([]Migration{}, ms...), migration(ms[len(ms)-1].Name+"_upgrade.sql", "CREATE TABLE noctis_v2.upgrade_test(id int)"))
	if e = Migrate(ctx, dsn, upgrade); e != nil {
		t.Fatal(e)
	}
	drift := append([]Migration{}, upgrade...)
	drift[0] = migration(ms[0].Name, ms[0].SQL+"\n-- drift")
	if e = Migrate(ctx, dsn, drift); e == nil {
		t.Fatal("checksum drift accepted")
	}
	broken := append(append([]Migration{}, upgrade...), migration(upgrade[len(upgrade)-1].Name+"_broken.sql", "CREATE TABLE noctis_v2.partial(id int); SELECT missing_column;"))
	if e = Migrate(ctx, dsn, broken); e == nil {
		t.Fatal("partial migration succeeded")
	}
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(ctx) })
	var absent bool
	if e = c.QueryRow(ctx, "SELECT to_regclass('noctis_v2.partial') IS NULL").Scan(&absent); e != nil || !absent {
		t.Fatalf("partial DDL retained: %v", e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- Migrate(ctx, dsn, upgrade) }()
	}
	wg.Wait()
	close(errs)
	for e = range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
}
func TestRuntimeRolePostgres(t *testing.T) {
	dsn := testDB(t)
	ctx := context.Background()
	ms, _ := Load(migrations.Files)
	if e := Migrate(ctx, dsn, ms); e != nil {
		t.Fatal(e)
	}
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(ctx) })
	role := "runtime_" + uuid.NewString()[:8]
	ident := pgx.Identifier{role}.Sanitize()
	t.Cleanup(func() {
		c.Exec(ctx, "RESET ROLE")
		c.Exec(ctx, "DROP OWNED BY "+ident)
		c.Exec(ctx, "DROP ROLE "+ident)
	})
	for _, sql := range []string{"CREATE ROLE " + ident, "REVOKE CREATE ON SCHEMA public FROM PUBLIC", "GRANT USAGE ON SCHEMA noctis_v2 TO " + ident, "GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA noctis_v2 TO " + ident, "CREATE TABLE public.legacy_private(id int)", "SET ROLE " + ident} {
		if _, e = c.Exec(ctx, sql); e != nil {
			t.Fatal(e)
		}
	}
	for _, sql := range []string{"CREATE TABLE noctis_v2.forbidden(id int)", "INSERT INTO public.legacy_private VALUES(1)", "INSERT INTO public.noctis_v2_migrations VALUES('bad','bad',now())"} {
		if _, e = c.Exec(ctx, sql); e == nil {
			t.Fatalf("runtime permitted %s", sql)
		}
	}
}
