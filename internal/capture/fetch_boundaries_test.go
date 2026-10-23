package capture

import (
	"compress/gzip"
	"context"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchPinsFirstValidatedDNSResolution(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "rebind.fixture" {
			t.Error("hostname not preserved")
		}
		io.WriteString(w, "pinned")
	}))
	defer server.Close()
	lookups, dials := 0, 0
	f := Fetcher{lookupIP: func(context.Context, string, string) ([]net.IP, error) {
		lookups++
		if lookups == 1 {
			return []net.IP{net.ParseIP("8.8.8.8")}, nil
		}
		return []net.IP{net.ParseIP("127.0.0.1")}, nil
	}, dialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		dials++
		if target != "8.8.8.8:80" {
			t.Fatalf("DNS was rebound at connect: %s", target)
		}
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "http://"))
	}}
	payload, e := f.Get(context.Background(), "http://rebind.fixture/")
	if e != nil || string(payload) != "pinned" || lookups != 1 || dials != 1 {
		t.Fatal("pinning failed", e, lookups, dials)
	}
}
func TestCompressedWireLimitIndependentOfDecodedLimit(t *testing.T) {
	data := make([]byte, 128<<10)
	for i := range data {
		data[i] = byte(rand.Uint32())
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		gz.Write(data)
		gz.Close()
	}))
	defer server.Close()
	f := Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(server.URL, "http://"): true}, MaxCompressed: 1024, MaxDecoded: 256 << 10}
	if _, e := f.Get(context.Background(), server.URL); e == nil {
		t.Fatal("compressed wire limit bypassed")
	}
}
func TestCredentialedRedirectDoesNotExportHeaders(t *testing.T) {
	leaked := false
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked = true }))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destination.URL, 302) }))
	defer origin.Close()
	f := Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(origin.URL, "http://"): true, strings.TrimPrefix(destination.URL, "http://"): true}}
	if _, e := f.GetWithHeaders(context.Background(), origin.URL, http.Header{"Key": []string{"synthetic"}}); e == nil || leaked {
		t.Fatal("credential redirect followed")
	}
}
