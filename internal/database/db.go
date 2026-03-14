// Package database provides helpers for connecting to PostgreSQL and running
// ordered SQL migrations.
package database

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Migration holds the name and SQL body of a single migration file.
type Migration struct {
	// Name is the base filename (e.g. "001_init.sql"). Migrations are applied
	// in lexicographic order of this field.
	Name string

	// SQL is the full content of the migration file.
	SQL string
}

// LoadMigrations reads every *.sql file from dir, sorts them lexicographically
// by filename, and returns the resulting slice. It returns an error if the
// directory cannot be read or any file cannot be opened.
func LoadMigrations(dir string) ([]Migration, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("database: read migrations dir %q: %w", dir, err)
	}

	var migrations []Migration
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}

		path := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("database: read migration file %q: %w", path, err)
		}

		migrations = append(migrations, Migration{
			Name: e.Name(),
			SQL:  string(data),
		})
	}

	// os.ReadDir returns entries in directory order (usually sorted on most
	// filesystems), but we sort explicitly to guarantee deterministic order
	// across all platforms.
	sort.Slice(migrations, func(i, j int) bool {
		return migrations[i].Name < migrations[j].Name
	})

	return migrations, nil
}

// Connect opens a connection pool to the PostgreSQL instance identified by dsn,
// verifies connectivity with a Ping, and returns the pool. The caller is
// responsible for calling pool.Close() when the pool is no longer needed.
func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("database: create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database: ping: %w", err)
	}

	return pool, nil
}

// RunMigrations creates a _migrations tracking table if it does not exist, then
// applies each migration in order, skipping any that have already been recorded.
// Each migration is applied inside its own transaction; a failure rolls back
// that migration and returns an error immediately.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrations []Migration) error {
	// Ensure the tracking table exists.
	const createTracking = `
CREATE TABLE IF NOT EXISTS _migrations (
    name       TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

	if _, err := pool.Exec(ctx, createTracking); err != nil {
		return fmt.Errorf("database: create _migrations table: %w", err)
	}

	for _, m := range migrations {
		// Check whether this migration has already been applied.
		var applied bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM _migrations WHERE name = $1)`, m.Name,
		).Scan(&applied)
		if err != nil {
			return fmt.Errorf("database: check migration %q: %w", m.Name, err)
		}
		if applied {
			continue
		}

		// Apply the migration inside a transaction so a partial failure does
		// not leave the schema in an inconsistent state.
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("database: begin tx for migration %q: %w", m.Name, err)
		}

		if _, err := tx.Exec(ctx, m.SQL); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("database: apply migration %q: %w", m.Name, err)
		}

		if _, err := tx.Exec(ctx,
			`INSERT INTO _migrations (name) VALUES ($1)`, m.Name,
		); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("database: record migration %q: %w", m.Name, err)
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("database: commit migration %q: %w", m.Name, err)
		}
	}

	return nil
}
