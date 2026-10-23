package capture

import (
	"testing"
	"time"
)

func TestAtomIdentityAndRevision(t *testing.T) {
	a := []byte(`<feed xmlns="http://www.w3.org/2005/Atom"><entry><id>urn:stable</id><title>Antes</title><content>á証拠</content><published>2026-10-18T10:00:00Z</published></entry></feed>`)
	first, e := ParseFeed(a, time.Now().UTC())
	if e != nil || len(first) != 1 {
		t.Fatalf("%+v %v", first, e)
	}
	second, e := ParseFeed([]byte(`<feed><entry><id>urn:stable</id><title>Después</title></entry></feed>`), time.Now().UTC())
	if e != nil || second[0].NativeID != first[0].NativeID || second[0].Revision == first[0].Revision {
		t.Fatalf("revision %+v %v", second, e)
	}
	fallback, e := ParseFeed([]byte(`<feed><entry><title>Linked</title><link href="https://example.org/item"/></entry></feed>`), time.Now().UTC())
	if e != nil || fallback[0].NativeID != "https://example.org/item" {
		t.Fatalf("link %+v %v", fallback, e)
	}
	for _, bad := range []string{`<html/>`, `<rss><channel><item><title>no identity</title></item></channel></rss>`, `<feed>`} {
		if _, e = ParseFeed([]byte(bad), time.Now().UTC()); e == nil {
			t.Fatal(bad)
		}
	}
}
