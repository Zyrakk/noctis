package promptsv2

import "testing"

func TestImmutablePromptRegistry(t *testing.T) {
	expected := map[string]string{"1": "f6c57e6cdaf3111015fbb98cf59b19f37fec99b02b6707163e2f3af79562ec48", "2": "cfec25c81badf27c83d704915404d1e5aca84e5cb742a20bda7af3d54bdd2e85"}
	for version, digest := range expected {
		text, got, err := Resolve(version)
		if err != nil || got != digest || text == "" {
			t.Fatal("registered prompt bytes changed", version, err)
		}
	}
	if _, _, err := Resolve("unknown"); err == nil {
		t.Fatal("unknown version accepted")
	}
	old := Instructions
	Instructions += "tamper"
	if _, _, err := Resolve("1"); err == nil {
		t.Error("silent v1 edit accepted")
	}
	Instructions = old
	old = instructionsV2
	instructionsV2 += "tamper"
	if _, _, err := Resolve("2"); err == nil {
		t.Error("silent v2 edit accepted")
	}
	instructionsV2 = old
}
