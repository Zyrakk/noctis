package configv2

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWithoutLLM(t *testing.T) {
	t.Setenv("LLM_API_KEY", "")
	p := filepath.Join(t.TempDir(), "dsn")
	if e := os.WriteFile(p, []byte("postgres://local/noctis_v2"), 0600); e != nil {
		t.Fatal(e)
	}
	if cfg, e := Load("api", "127.0.0.1:0", p); e != nil {
		t.Fatal(e)
	} else if cfg.ManualInference || cfg.AutomaticInference {
		t.Fatal("inference must require an explicit worker opt-in")
	}
	if _, e := Load("all", "", p); e == nil {
		t.Fatal("invalid mode accepted")
	}
}
