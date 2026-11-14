package runtimev2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/jackc/pgx/v5"
)

func TestCanonicalOrigin(t *testing.T) {
	valid := []string{
		"https://noctis.example", "http://localhost", "https://xn--bcher-kva.example",
		"https://example.com.", "https://127.0.0.1", "http://192.0.2.1:8080",
		"https://[::1]", "https://[2001:db8::1]:8443", "https://[::ffff:c000:201]",
		"https://example.com:65535", "http://example.com:0", "https://123.example",
	}
	invalid := []string{
		"", "null", "noctis.example", "ftp://example.com", "https:example.com", "https://",
		"HTTPS://example.com", "https://EXAMPLE.com", "https://example.com:443", "http://example.com:80",
		"https://example.com:08443", "https://example.com:", "https://example.com:65536", "https://example.com:-1",
		"https://example.com/", "https://example.com/path", "https://example.com?", "https://example.com#",
		"https://example.com?query", "https://example.com#fragment", "https://user@example.com", "https://user:pass@example.com",
		" https://example.com", "https://example.com ", "https://example.com\n", "https://exam ple.com", "https://bücher.example",
		"https://a..example", "https://-a.example", "https://a-.example", "https://a_b.example", "https://xn--a.example",
		"https://%65xample.com", "https://[::1", "https://::1", "https://[fe80::1%25eth0]", "https://[2001:DB8::1]",
		"https://[2001:db8:0:0:0:0:0:1]", "https://[::ffff:192.0.2.1]", "https://127.1", "https://127.0.0.01",
		"https://2130706433", "https://0x7f000001", "https://example.123", "https://example.0x1", "https://256.0.0.1",
	}
	for _, origin := range valid {
		t.Run(origin, func(t *testing.T) {
			if err := validateOrigin(origin); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, origin := range invalid {
		t.Run("reject/"+origin, func(t *testing.T) {
			if err := validateOrigin(origin); err == nil {
				t.Fatal("noncanonical origin accepted")
			}
			_, err := NewHandler(configv2.Config{Origin: origin, AdminFile: "missing-admin"})
			if err == nil || !strings.HasPrefix(err.Error(), "canonical origin required:") {
				t.Fatalf("handler did not validate origin before reading admin: %v", err)
			}
		})
	}
}

func httpConfigAdmin(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.json")
	if err := os.WriteFile(path, []byte(`{"username":"operator","password":"synthetic-http-password"}`), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func httpConfigCertificate(t *testing.T) (string, string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "synthetic internal TLS"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err = os.WriteFile(certPath, certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("synthetic certificate could not be trusted")
	}
	return certPath, keyPath, pool
}

func TestAPITLSConfigurationBeforeDatabase(t *testing.T) {
	cert, key, _ := httpConfigCertificate(t)
	_, otherKey, _ := httpConfigCertificate(t)
	invalid := filepath.Join(t.TempDir(), "invalid.pem")
	if err := os.WriteFile(invalid, []byte("not PEM"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, cert, key string }{
		{"certificate-only", cert, ""}, {"key-only", "", key},
		{"missing-certificate", "missing-cert", key}, {"missing-key", cert, "missing-key"},
		{"unreadable-certificate", t.TempDir(), key}, {"unreadable-key", cert, t.TempDir()},
		{"invalid-certificate", invalid, key}, {"invalid-key", cert, invalid}, {"mismatch", cert, otherKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The deliberately invalid DSN/listen would return other errors if
			// startup attempted either dependency before checking TLS.
			err := Run(context.Background(), configv2.Config{Mode: "api", Origin: "https://public.example", TLSCert: tc.cert, TLSKey: tc.key, DatabaseURL: ":invalid", Listen: ":invalid"})
			if err == nil || !strings.HasPrefix(err.Error(), "API TLS") {
				t.Fatalf("TLS was not rejected before DB/listen: %v", err)
			}
		})
	}
	for _, tc := range []struct{ name, cert, key string }{{"internal-http", "", ""}, {"tls", cert, key}} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := configv2.Config{Mode: "api", Origin: "https://public.example", TLSCert: tc.cert, TLSKey: tc.key, AdminFile: httpConfigAdmin(t), DatabaseURL: ":invalid", Listen: ":invalid"}
			loaded, err := loadAPITLS(cfg)
			if err != nil || (loaded != nil) != (tc.cert != "") {
				t.Fatalf("unexpected TLS configuration: %v %v", loaded, err)
			}
			if err = Run(context.Background(), cfg); err == nil || err.Error() != "v2 database unavailable" {
				t.Fatalf("valid HTTP configuration did not reach DB check: %v", err)
			}
		})
	}
	if err := Run(context.Background(), configv2.Config{Mode: "api", Origin: "https://public.example/", DatabaseURL: ":invalid", Listen: ":invalid"}); err == nil || !strings.HasPrefix(err.Error(), "canonical origin required:") {
		t.Fatalf("origin was not rejected before DB/listen: %v", err)
	}
	for _, mode := range []string{"worker", "collector"} {
		if err := Run(context.Background(), configv2.Config{Mode: mode, DatabaseURL: ":invalid", TLSCert: "unused"}); err == nil || err.Error() != "v2 database unavailable" {
			t.Fatalf("%s acquired HTTP requirements: %v", mode, err)
		}
	}
	// Handler construction has no dependency on TLS files.
	if _, err := NewHandler(configv2.Config{Origin: "https://public.example", AdminFile: httpConfigAdmin(t), TLSCert: "unused"}); err != nil {
		t.Fatal(err)
	}
}

func launchHTTPConfigAPI(t *testing.T, cfg configv2.Config) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Listen = ln.Addr().String()
	if err = ln.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, cfg) }()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("API did not shut down cleanly: %v", err)
				}
			case <-time.After(7 * time.Second):
				t.Error("API did not stop")
			}
		})
	}
	t.Cleanup(stop)
	return cfg.Listen, stop
}

func waitHTTPConfigAPI(t *testing.T, client *http.Client, base string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, err := client.Get(base + "/livez")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("API did not become live")
}

func TestRunAPITLSPostgres(t *testing.T) {
	dsn := productDB(t)
	cert, key, pool := httpConfigCertificate(t)
	ctx := context.Background()
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `LOCK TABLE noctis_v2.ai_configs IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	address, stop := launchHTTPConfigAPI(t, configv2.Config{Mode: "api", DatabaseURL: dsn, Origin: "https://public.example", AdminFile: httpConfigAdmin(t), TLSCert: cert, TLSKey: key})
	// Hold startup in its DB check, then delete the files. Serving must use
	// the already loaded pair, including when the public origin differs.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err = tx.Exec(ctx, `SELECT pg_stat_clear_snapshot()`); err != nil {
			t.Fatal(err)
		}
		var waiting bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND wait_event_type='Lock' AND query LIKE '%noctis_v2.ai_configs%')`).Scan(&waiting)
		if err != nil {
			t.Fatal(err)
		}
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("startup did not reach DB after TLS validation")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, path := range []string{cert, key} {
		if err = os.Remove(path); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: time.Second}
	defer client.CloseIdleConnections()
	waitHTTPConfigAPI(t, client, "https://"+address)
	plain := &http.Client{Timeout: time.Second}
	defer plain.CloseIdleConnections()
	for _, path := range []string{"/livez", "/", "/api/v2/auth/session"} {
		res, err := plain.Get("http://" + address + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != http.StatusBadRequest || strings.Contains(string(body), `"data"`) {
			t.Fatalf("HTTP reached application: %d %s", res.StatusCode, body)
		}
	}
	stop()
	if res, err := client.Get("https://" + address + "/livez"); err == nil {
		res.Body.Close()
		t.Fatal("listener remained usable after shutdown")
	}
}

func TestRunAPIBehindTLSProxyPostgres(t *testing.T) {
	dsn := productDB(t)
	proxy := httptest.NewUnstartedServer(nil)
	defer proxy.Close()
	origin := "https://" + proxy.Listener.Addr().String()
	address, stop := launchHTTPConfigAPI(t, configv2.Config{Mode: "api", DatabaseURL: dsn, Origin: origin, AdminFile: httpConfigAdmin(t)})
	backend, _ := url.Parse("http://" + address)
	waitHTTPConfigAPI(t, &http.Client{Timeout: time.Second}, backend.String())
	proxy.Config.Handler = httputil.NewSingleHostReverseProxy(backend)
	proxy.StartTLS()
	client := proxy.Client()
	client.Jar, _ = cookiejar.New(nil)
	request := func(method, path, requestOrigin, csrf, body string, status int) map[string]any {
		t.Helper()
		req, err := http.NewRequest(method, proxy.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Origin", requestOrigin)
		req.Header.Set("X-CSRF-Token", csrf)
		// Misleading forwarding headers cannot change origin admission.
		req.Header.Set("Forwarded", "proto=http;host=untrusted.example")
		req.Header.Set("X-Forwarded-Proto", "http")
		req.Header.Set("X-Forwarded-Host", "untrusted.example")
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		if res.StatusCode != status {
			raw, _ := io.ReadAll(res.Body)
			t.Fatalf("%s: got %d want %d: %s", path, res.StatusCode, status, raw)
		}
		if path == "/api/v2/auth/login" && status == 200 {
			cookies := res.Cookies()
			if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
				t.Fatal("proxy changed session cookie protections")
			}
		}
		var result map[string]any
		if err = json.NewDecoder(res.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	login := request("POST", "/api/v2/auth/login", origin, "", `{"username":"operator","password":"synthetic-http-password"}`, 200)
	csrf := login["data"].(map[string]any)["csrf"].(string)
	request("GET", "/api/v2/auth/session", origin, "", "", 200)
	request("POST", "/api/v2/auth/logout", "https://untrusted.example", csrf, "{}", 403)
	request("POST", "/api/v2/auth/logout", origin, "wrong", "{}", 403)
	request("POST", "/api/v2/auth/logout", origin, csrf, "{}", 200)
	request("GET", "/api/v2/auth/session", origin, "", "", 401)
	stop()
}
