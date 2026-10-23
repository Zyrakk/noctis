package legacyimport

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInspectOmitsSecrets(t *testing.T) {
	rs, e := Inspect(strings.NewReader("kind: Secret\nmetadata:\n  name: test\ndata:\n  token: NEVER_OUTPUT\n---\nkind: ConfigMap\ndata:\n  config: NEVER_OUTPUT\n"))
	if e != nil {
		t.Fatal(e)
	}
	b, _ := json.Marshal(rs)
	if strings.Contains(string(b), "NEVER_OUTPUT") {
		t.Fatal("secret emitted")
	}
}
