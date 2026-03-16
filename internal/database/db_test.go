package database

import (
	"os"
	"path/filepath"
	"testing"
)

// migrationsDir returns the absolute path to the project-level migrations
// directory relative to this test file's location.
func migrationsDir(t *testing.T) string {
	t.Helper()
	// This file lives at internal/database/db_test.go; migrations are at
	// ../../migrations from that position.
	dir := filepath.Join("..", "..", "migrations")
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatalf("could not resolve migrations directory: %v", err)
	}
	return abs
}

// TestMigrationFiles_Exist verifies that the expected SQL migration files are
// present and readable in the migrations directory.
func TestMigrationFiles_Exist(t *testing.T) {
	dir := migrationsDir(t)

	expected := []string{
		"001_init.sql",
		"002_graph.sql",
		"003_pivot.sql",
	}

	for _, name := range expected {
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			t.Errorf("migration file %q not readable: %v", path, err)
			continue
		}
		f.Close()
	}
}

// TestParseMigrations verifies that LoadMigrations returns at least two entries
// and that they are sorted lexicographically by name.
func TestParseMigrations(t *testing.T) {
	dir := migrationsDir(t)

	migrations, err := LoadMigrations(dir)
	if err != nil {
		t.Fatalf("LoadMigrations returned error: %v", err)
	}

	if len(migrations) < 3 {
		t.Fatalf("expected at least 3 migrations, got %d", len(migrations))
	}

	// Verify lexicographic sort order.
	for i := 1; i < len(migrations); i++ {
		if migrations[i].Name < migrations[i-1].Name {
			t.Errorf("migrations out of order: %q comes before %q",
				migrations[i-1].Name, migrations[i].Name)
		}
	}

	// Verify the first two known migrations are present with non-empty SQL.
	for _, m := range migrations[:2] {
		if m.SQL == "" {
			t.Errorf("migration %q has empty SQL", m.Name)
		}
	}

	t.Logf("loaded %d migrations: %v", len(migrations), migrationNames(migrations))
}

func migrationNames(ms []Migration) []string {
	names := make([]string, len(ms))
	for i, m := range ms {
		names[i] = m.Name
	}
	return names
}
