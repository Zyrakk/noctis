package runtimev2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	db "github.com/Zyrakk/noctis/internal/database/v2"
	"github.com/Zyrakk/noctis/internal/intelligence"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func productDB(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("NOCTIS_V2_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	ctx := context.Background()
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	name := "noctis_v2_product_" + uuid.NewString()[:8]
	if _, e = c.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(dsn)
	u.Path = "/" + name
	t.Cleanup(func() { c.Exec(ctx, "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)"); c.Close(ctx) })
	ms, _ := db.Load(migrations.Files)
	if e = db.Migrate(ctx, u.String(), ms); e != nil {
		t.Fatal(e)
	}
	return u.String()
}
func TestProductFeedToPrivateAPIAndUncertainDeliveryPostgres(t *testing.T) {
	dsn := productDB(t)
	ctx := context.Background()
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	id, epoch := uuid.NewString(), uuid.NewString()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies VALUES('p1','[{"type":"cve","value":"CVE-2026-12345"}]',clock_timestamp());`)
	if e != nil {
		t.Fatal(e)
	}
	text := strings.Repeat("文 á ", 2000) + "CVE-2026-12345"
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `<rss><channel><item><guid>entry-one</guid><title>Fuente sintética</title><description>`+text+`</description><pubDate>`+time.Now().UTC().Format(time.RFC1123Z)+`</pubDate></item></channel></rss>`)
	}))
	defer feed.Close()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,name,policy_version,enabled,epoch,activated_at) VALUES($1,'rss',$2,'Synthetic fixture','p1',true,$3,clock_timestamp()-interval '1 hour')`, id, feed.URL, epoch)
	if e != nil {
		t.Fatal(e)
	}
	// A genuine restricted login role exercises capture, worker and readiness, not SET ROLE on an admin connection.
	role := "product_" + uuid.NewString()[:8]
	ident := pgx.Identifier{role}.Sanitize()
	for _, q := range []string{"CREATE ROLE " + ident + " LOGIN", "GRANT CONNECT ON DATABASE " + pgx.Identifier{strings.TrimPrefix(func() string { u, _ := url.Parse(dsn); return u.Path }(), "/")}.Sanitize() + " TO " + ident, "GRANT USAGE ON SCHEMA noctis_v2 TO " + ident, "GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA noctis_v2 TO " + ident, "GRANT SELECT ON public.noctis_v2_migrations TO " + ident, "REVOKE CREATE ON SCHEMA public FROM PUBLIC"} {
		if _, e = c.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	defer func() { c.Exec(ctx, "DROP OWNED BY "+ident); c.Exec(ctx, "DROP ROLE "+ident) }()
	u, _ := url.Parse(dsn)
	u.User = url.User(role)
	runtimeDSN := u.String()
	if _, e = Check(ctx, runtimeDSN, "worker"); e != nil {
		t.Fatal(e)
	}
	restricted, e := pgx.Connect(ctx, runtimeDSN)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = restricted.Exec(ctx, `CREATE TABLE noctis_v2.forbidden(id int)`); e == nil {
		t.Fatal("runtime DDL allowed")
	}
	restricted.Close(ctx)
	f := capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feed.URL, "http://"): true}}
	if e = (capture.Store{DSN: runtimeDSN}).Poll(ctx, id, f); e != nil {
		t.Fatal(e)
	}
	worker := intelligence.Worker{DSN: runtimeDSN, Owner: "product-test"}
	if e = worker.Once(ctx); e != nil {
		t.Fatal(e)
	}
	if e = worker.Brief(ctx, time.Now().UTC().Format("2006-01-02"), "p1"); e != nil {
		t.Fatal(e)
	}
	if e = worker.Brief(ctx, time.Now().UTC().Format("2006-01-02"), "p1"); e != nil {
		t.Fatal(e)
	}
	var obsID, revision string
	var observablesRaw []byte
	e = c.QueryRow(ctx, `SELECT o.id::text,o.revision,a.observables FROM noctis_v2.observations o JOIN noctis_v2.analyses a ON a.observation_id=o.id LIMIT 1`).Scan(&obsID, &revision, &observablesRaw)
	if e != nil {
		t.Fatal(e)
	}
	var observables []intelligence.Observable
	if e = json.Unmarshal(observablesRaw, &observables); e != nil {
		t.Fatal(e)
	}
	if len(observables) == 0 || observables[0].Evidence.Start < 10000 {
		t.Fatal("tail observable missing")
	}
	adminFile := filepath.Join(t.TempDir(), "admin.json")
	if e = os.WriteFile(adminFile, []byte(`{"username":"operator","password":"synthetic-test-password-only"}`), 0600); e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	handler, e := NewHandler(configv2.Config{DatabaseURL: runtimeDSN, AdminFile: adminFile, Origin: origin, Mode: "api"})
	if e != nil {
		t.Fatal(e)
	}
	server.Config.Handler = handler
	server.StartTLS()
	defer server.Close()
	client := server.Client()
	client.Jar, _ = cookiejar.New(nil)
	request := func(method, path, body, csrf string, want int) map[string]any {
		t.Helper()
		req, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		if path == "/api/v2/auth/login" && want == 200 {
			cookie := res.Header.Get("Set-Cookie")
			for _, flag := range []string{"HttpOnly", "Secure", "SameSite=Strict"} {
				if !strings.Contains(cookie, flag) {
					t.Fatalf("cookie flag missing %s", flag)
				}
			}
		}
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			t.Fatalf("%s %s status %d want %d: %s", method, path, res.StatusCode, want, raw)
		}
		v := map[string]any{}
		if len(raw) > 0 && res.Header.Get("Content-Type") == "application/json" {
			if e = json.Unmarshal(raw, &v); e != nil {
				t.Fatal(e)
			}
		}
		return v
	}
	request("GET", "/api/v2/cases", "", "", 401)
	request("POST", "/api/v2/auth/login", `{"username":"operator","password":"wrong"}`, "", 401)
	login := request("POST", "/api/v2/auth/login", `{"username":"operator","password":"synthetic-test-password-only"}`, "", 200)
	csrf := login["data"].(map[string]any)["csrf"].(string)
	var sessionHash string
	if e = c.QueryRow(ctx, `SELECT token_hash FROM noctis_v2.sessions WHERE NOT revoked LIMIT 1`).Scan(&sessionHash); e != nil {
		t.Fatal(e)
	}
	cookies := client.Jar.Cookies(func() *url.URL { u, _ := url.Parse(server.URL); return u }())
	if len(cookies) != 1 || cookies[0].Value == sessionHash {
		t.Fatal("session token not stored as hash")
	}
	for _, path := range []string{"today", "cases", "sources", "system", "auth/session"} {
		request("GET", "/api/v2/"+path, "", "", 200)
	}
	ev := request("GET", "/api/v2/evidence/"+obsID+"?revision="+url.QueryEscape(revision), "", "", 200)["data"].(map[string]any)
	if e = observables[0].Evidence.Validate([]byte(ev["text"].(string))); e != nil {
		t.Fatal(e)
	}
	cases := request("GET", "/api/v2/cases", "", "", 200)["data"].([]any)
	if len(cases) != 1 {
		t.Fatalf("cases=%d", len(cases))
	}
	caseID := cases[0].(map[string]any)["id"].(string)
	detail := request("GET", "/api/v2/cases/"+caseID, "", "", 200)["data"].(map[string]any)
	if len(detail["timeline"].([]any)) != 1 {
		t.Fatal("missing timeline")
	}
	request("GET", "/api/v2/evidence/"+obsID+"?revision=wrong", "", "", 404)
	request("POST", "/api/v2/auth/logout", "{}", "bad", 403)
	req, _ := http.NewRequest("POST", server.URL+"/api/v2/auth/logout", bytes.NewReader([]byte("{}")))
	req.Header.Set("Origin", "https://attacker.invalid")
	req.Header.Set("X-CSRF-Token", csrf)
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatal("cross Origin accepted")
	}
	request("POST", "/api/v2/auth/logout", "{}", csrf, 200)
	request("GET", "/api/v2/cases", "", "", 401)
	client.Jar.SetCookies(func() *url.URL { u, _ := url.Parse(server.URL); return u }(), cookies)
	request("GET", "/api/v2/auth/session", "", "", 401)
	request("POST", "/api/v2/auth/login", `{"username":"operator","password":"synthetic-test-password-only"}`, "", 200)
	if _, e = c.Exec(ctx, `UPDATE noctis_v2.sessions SET expires_at=clock_timestamp()-interval '1 second'`); e != nil {
		t.Fatal(e)
	}
	request("GET", "/api/v2/auth/session", "", "", 401)
	// A response lost after receiver acceptance preserves uncertain and is never automatically retried.
	var deliveries atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deliveries.Add(1)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer receiver.Close()
	if e = worker.DispatchOnce(ctx, receiver.URL, nil); e == nil {
		t.Fatal("lost acknowledgement accepted")
	}
	if e = worker.DispatchOnce(ctx, receiver.URL, nil); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatalf("uncertain retried %v", e)
	}
	if deliveries.Load() != 1 {
		t.Fatalf("delivered %d", deliveries.Load())
	}
	var state string
	if e = c.QueryRow(ctx, `SELECT state FROM noctis_v2.outbox`).Scan(&state); e != nil || state != "uncertain" {
		t.Fatalf("state %s %v", state, e)
	}
}
