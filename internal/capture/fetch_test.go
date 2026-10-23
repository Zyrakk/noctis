package capture

import (
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchBoundaries(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "169.254.169.254", "100.100.100.200", "198.18.0.1", "2001:db8::1", "10.0.0.1"} {
		if publicIP(net.ParseIP(ip)) {
			t.Fatal(ip)
		}
	}
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	gz.Write([]byte(strings.Repeat("x", 2000)))
	gz.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "http://169.254.169.254/secret", 302)
		case "/gzip":
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(compressed.Bytes())
		case "/slow":
			time.Sleep(50 * time.Millisecond)
			w.Write([]byte("ok"))
		default:
			w.Write([]byte(strings.Repeat("x", 500)))
		}
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "http://")
	f := Fetcher{AllowLocal: map[string]bool{host: true}, MaxCompressed: 1000, MaxDecoded: 1000, Timeout: time.Second}
	if _, e := (Fetcher{}).Get(context.Background(), server.URL); e == nil {
		t.Fatal("private allowed")
	}
	if _, e := f.Get(context.Background(), server.URL); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/redirect", "/gzip"} {
		if _, e := f.Get(context.Background(), server.URL+path); e == nil {
			t.Fatal(path)
		}
	}
	f.Timeout = time.Millisecond
	if _, e := f.Get(context.Background(), server.URL+"/slow"); e == nil {
		t.Fatal("timeout")
	}
	for _, u := range []string{"file:///etc/passwd", "http://user:pass@example.com/", "http://hidden.onion/", "http://[fe80::1%25eth0]/"} {
		if _, e := f.Get(context.Background(), u); e == nil {
			t.Fatal(u)
		}
	}
}
