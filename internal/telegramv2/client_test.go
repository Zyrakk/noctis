package telegramv2

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/gotd/td/session"
)

func TestProtectedSessionAtomicPermissionsAndAuthGeneration(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "session.json")
	storage := &ProtectedSession{Path: path}
	loader := session.Loader{Storage: storage}
	first := make([]byte, 256)
	first[0] = 1
	if e := loader.Save(ctx, &session.Data{AuthKey: first}); e != nil {
		t.Fatal(e)
	}
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm() != 0600 {
		t.Fatal("unsafe session mode", e)
	}
	a, e := storage.Generation(ctx)
	if e != nil {
		t.Fatal(e)
	}
	again, e := storage.Generation(ctx)
	if e != nil || a != again {
		t.Fatal("generation unstable", e)
	}
	first[0] = 2
	if e = loader.Save(ctx, &session.Data{AuthKey: first}); e != nil {
		t.Fatal(e)
	}
	b, e := storage.Generation(ctx)
	if e != nil || a == b {
		t.Fatal("key rotation reused generation", e)
	}
	if e = os.Chmod(path, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = storage.LoadSession(ctx); e == nil {
		t.Fatal("world-readable session accepted")
	}
}
