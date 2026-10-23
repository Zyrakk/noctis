package intelligence

import (
	"crypto/sha256"
	"fmt"
	"github.com/Zyrakk/noctis/internal/evidence"
	"strings"
	"testing"
)

func TestWholeUTF8DocumentAndConservativeGate(t *testing.T) {
	text := []byte(strings.Repeat("ñ界 ", 4000) + "CVE-2026-12345 hxxps://example[.]org/a 2001:4860:4860::8888 999.1.2.3")
	ref := evidence.Ref{ObservationID: "o", Revision: "r", Hash: fmt.Sprintf("sha256:%x", sha256.Sum256(text)), Representation: "text-v1"}
	out, e := Extract(text, ref)
	if e != nil {
		t.Fatal(e)
	}
	found := map[string]bool{}
	for _, o := range out {
		if e = o.Evidence.Validate(text); e != nil {
			t.Fatal(e)
		}
		if string(text[o.Evidence.Start:o.Evidence.End]) != o.Original {
			t.Fatal("span not original")
		}
		found[o.Value] = true
	}
	for _, value := range []string{"CVE-2026-12345", "https://example.org/a", "2001:4860:4860::8888"} {
		if !found[value] {
			t.Fatal(value)
		}
	}
	if found["999.1.2.3"] {
		t.Fatal("invalid IP")
	}
	if Gate(text, out, nil) != "unknown" {
		t.Fatal("unmatched content discarded")
	}
	if Gate(text, out, []Term{{Type: "cve", Value: "CVE-2026-12345"}}) != "relevant" {
		t.Fatal("watchlist")
	}
	if _, e = Extract([]byte{0xff}, ref); e == nil {
		t.Fatal("invalid UTF8 accepted")
	}
}
