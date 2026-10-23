// Package v2 manages only the explicitly selected independent v2 database.
package v2

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/jackc/pgx/v5"
	"io/fs"
	"sort"
	"strings"
)

const LockID int64 = 76238451002

type Migration struct{ Name, SQL, Checksum string }

func Load(fsys fs.FS) ([]Migration, error) {
	names, err := fs.Glob(fsys, "*.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("no v2 migrations")
	}
	out := make([]Migration, 0, len(names))
	for _, name := range names {
		b, e := fs.ReadFile(fsys, name)
		if e != nil {
			return nil, e
		}
		out = append(out, Migration{name, string(b), fmt.Sprintf("%x", sha256.Sum256(b))})
	}
	return out, nil
}

// CheckDatabase refuses the legacy database and any database containing legacy public tables.
func CheckDatabase(ctx context.Context, c *pgx.Conn) error {
	var name string
	var legacy bool
	if err := c.QueryRow(ctx, `SELECT current_database(), EXISTS(SELECT FROM information_schema.tables WHERE table_schema='public' AND table_name IN ('sources','messages','observations','schema_migrations','findings','raw_content','entities','canary_tokens','actor_profiles'))`).Scan(&name, &legacy); err != nil {
		return err
	}
	if !strings.Contains(name, "v2") || legacy {
		return fmt.Errorf("independent v2 database required")
	}
	return nil
}

// Migrate holds a session advisory lock on a dedicated connection. Each file is atomic.
func Migrate(ctx context.Context, dsn string, ms []Migration) error {
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return fmt.Errorf("connect v2 database failed")
	}
	defer c.Close(context.Background())
	if err = CheckDatabase(ctx, c); err != nil {
		return err
	}
	if _, err = c.Exec(ctx, `SELECT pg_advisory_lock($1)`, LockID); err != nil {
		return err
	}
	defer c.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, LockID)
	if _, err = c.Exec(ctx, `CREATE TABLE IF NOT EXISTS public.noctis_v2_migrations(name text PRIMARY KEY, checksum text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	rows, err := c.Query(ctx, `SELECT name,checksum FROM public.noctis_v2_migrations ORDER BY name`)
	if err != nil {
		return err
	}
	applied := map[string]string{}
	for rows.Next() {
		var n, h string
		if err = rows.Scan(&n, &h); err != nil {
			rows.Close()
			return err
		}
		applied[n] = h
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return err
	}
	last := ""
	pending := false
	for _, m := range ms {
		if m.Name <= last || m.Checksum != fmt.Sprintf("%x", sha256.Sum256([]byte(m.SQL))) {
			return fmt.Errorf("invalid migration order/checksum: %s", m.Name)
		}
		last = m.Name
		h, ok := applied[m.Name]
		if ok {
			if h != m.Checksum || pending {
				return fmt.Errorf("migration drift: %s", m.Name)
			}
			delete(applied, m.Name)
		} else {
			pending = true
		}
	}
	if len(applied) > 0 {
		return fmt.Errorf("database contains unknown migrations")
	}
	for _, m := range ms {
		var exists bool
		if err = c.QueryRow(ctx, `SELECT EXISTS(SELECT FROM public.noctis_v2_migrations WHERE name=$1)`, m.Name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			continue
		}
		tx, e := c.Begin(ctx)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, m.SQL); e == nil {
			_, e = tx.Exec(ctx, `INSERT INTO public.noctis_v2_migrations(name,checksum) VALUES($1,$2)`, m.Name, m.Checksum)
		}
		if e != nil {
			tx.Rollback(context.Background())
			return fmt.Errorf("migration %s rolled back: %w", m.Name, e)
		}
		if e = tx.Commit(ctx); e != nil {
			return e
		}
	}
	return nil
}
