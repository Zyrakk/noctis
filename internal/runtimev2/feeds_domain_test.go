package runtimev2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/enrichmentv2"
	"github.com/Zyrakk/noctis/internal/vulnv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestStructuredFeedsPermissionQuotaTTLAndPrivateDomainAPIPostgres(t *testing.T) {
	ctx := context.Background()
	dsn := productDB(t)
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close(ctx)
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var requests atomic.Int32
	now := time.Now().UTC()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/nvd":
			offset := 0
			if r.URL.Query().Get("startIndex") == "1" {
				offset = 1
			}
			fmt.Fprintf(w, `{"totalResults":2,"startIndex":%d,"resultsPerPage":1,"timestamp":%q,"vulnerabilities":[{"cve":{"id":"CVE-2026-1000%d","configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}}]}`, offset, now.Format(time.RFC3339), offset)
		case "/kev":
			fmt.Fprintf(w, `{"dateReleased":%q,"count":1,"vulnerabilities":[{"cveID":"CVE-2026-10000","dateAdded":%q,"dueDate":%q,"knownRansomwareCampaignUse":"Unknown"}]}`, now.Format(time.RFC3339), now.Format("2006-01-02"), now.Add(7*24*time.Hour).Format("2006-01-02"))
		case "/epss":
			fmt.Fprintf(w, `{"status":"OK","total":1,"offset":0,"data":[{"cve":"CVE-2026-10000","epss":"0.42","percentile":"0.97","date":%q}]}`, now.Format("2006-01-02"))
		case "/vt/ip_addresses/8.8.8.8", "/vt/ip_addresses/1.1.1.1", "/vt/ip_addresses/9.9.9.9":
			requests.Add(1)
			if r.Header.Get("x-apikey") != "synthetic-key" {
				t.Error("adapter credential missing")
			}
			io.WriteString(w, `{"data":{"attributes":{"last_analysis_stats":{"malicious":2,"suspicious":1,"harmless":10,"undetected":50},"reputation":0}}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	authority := strings.TrimPrefix(server.URL, "http://")
	fetcher := capture.Fetcher{AllowLocal: map[string]bool{authority: true}}
	feed := vulnv2.Store{DSN: dsn, Fetcher: fetcher}
	p1, e := feed.PollPage(ctx, "nvd", server.URL+"/nvd", 24*time.Hour)
	must(e)
	if p1.Complete || p1.Cursor.Offset != 1 {
		t.Fatal("NVD pagination", p1)
	}
	if p1.CalculationState != "pending" {
		t.Fatal("NVD receipt did not expose asynchronous applicability", p1)
	}
	p2, e := feed.PollPage(ctx, "nvd", server.URL+"/nvd", 24*time.Hour)
	must(e)
	if !p2.Complete || p2.Cursor.Offset != 0 {
		t.Fatal("NVD completion", p2)
	}
	_, e = feed.PollPage(ctx, "kev", server.URL+"/kev", 24*time.Hour)
	must(e)
	_, e = feed.PollPage(ctx, "epss", server.URL+"/epss", 24*time.Hour)
	must(e)
	var n int
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.vulnerability_facts WHERE applicability='unknown'`).Scan(&n))
	if n != 4 {
		t.Fatal("facts lost", n)
	}
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.local_applicability`).Scan(&n))
	if n != 0 {
		t.Fatal("feed capture performed synchronous applicability")
	}
	drainApplicability(t, dsn)
	replayed, err := feed.PollPage(ctx, "nvd", server.URL+"/nvd", 24*time.Hour)
	must(err)
	if replayed.CalculationState != "complete" {
		t.Fatal("idempotent snapshot replay lost completed calculation state", replayed)
	}
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.enrichment_policies VALUES('virustotal','p1',true,'["public"]',2,60)`)
	must(e)
	enrich := enrichmentv2.Store{DSN: dsn, Fetcher: fetcher, Endpoint: server.URL + "/vt", Secret: "synthetic-key"}
	if _, e = enrich.Lookup(ctx, enrichmentv2.Request{Provider: "virustotal", Type: "ip", Value: "8.8.8.8", DataClass: "restricted", Permission: true}); e == nil {
		t.Fatal("private data exported")
	}
	if _, e = enrich.Lookup(ctx, enrichmentv2.Request{Provider: "virustotal", Type: "ip", Value: "8.8.8.8", DataClass: "public"}); e == nil {
		t.Fatal("missing export permission accepted")
	}
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "9.9.9.9"} {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			_, e := enrich.Lookup(ctx, enrichmentv2.Request{Provider: "virustotal", Type: "ip", Value: ip, DataClass: "public", Permission: true})
			errs <- e
		}(ip)
	}
	wg.Wait()
	close(errs)
	failures := 0
	for e := range errs {
		if e != nil {
			failures++
		}
	}
	if failures != 1 || requests.Load() != 2 {
		t.Fatal("quota race", failures, requests.Load())
	}
	var cachedIP string
	must(c.QueryRow(ctx, `SELECT value FROM noctis_v2.enrichment_cache LIMIT 1`).Scan(&cachedIP))
	cached, e := enrich.Lookup(ctx, enrichmentv2.Request{Provider: "virustotal", Type: "ip", Value: cachedIP, DataClass: "public", Permission: true})
	must(e)
	if !cached.Cached || requests.Load() != 2 {
		t.Fatal("TTL cache not used")
	}
	_, e = c.Exec(ctx, `UPDATE noctis_v2.enrichment_cache SET expires_at=clock_timestamp()-interval '1 second'`)
	must(e)
	if _, e = enrich.Lookup(ctx, enrichmentv2.Request{Provider: "virustotal", Type: "ip", Value: cachedIP, DataClass: "public", Permission: true}); e == nil {
		t.Fatal("expired TTL bypassed quota")
	}
	// Private APIs expose provider provenance and unknown applicability, never a local compromise claim.
	dir := t.TempDir()
	admin := filepath.Join(dir, "admin.json")
	must(os.WriteFile(admin, []byte(`{"Username":"operator","Password":"synthetic-secret-password"}`), 0600))
	handler, e := NewHandler(configv2.Config{DatabaseURL: dsn, AdminFile: admin, Origin: "https://fixture.invalid"})
	must(e)
	token, csrf := uuid.NewString(), uuid.NewString()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sessions VALUES($1,'operator',$2,clock_timestamp()+interval '1 hour',false)`, tokenHash(token), csrf)
	must(e)
	get := func(path string) map[string]json.RawMessage {
		t.Helper()
		req := httptest.NewRequest("GET", "https://fixture.invalid/api/v2/"+path, nil)
		req.AddCookie(&http.Cookie{Name: "noctis_v2_session", Value: token})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		var body map[string]json.RawMessage
		must(json.Unmarshal(rec.Body.Bytes(), &body))
		return body
	}
	body := get("feeds?limit=1")
	var meta struct {
		Cursor string `json:"next_cursor"`
	}
	must(json.Unmarshal(body["meta"], &meta))
	if meta.Cursor == "" {
		t.Fatal("pagination cursor missing")
	}
	seen := map[string]bool{}
	for {
		var rows []struct {
			ID string `json:"id"`
		}
		must(json.Unmarshal(body["data"], &rows))
		for _, v := range rows {
			if seen[v.ID] {
				t.Fatal("duplicate page item")
			}
			seen[v.ID] = true
		}
		meta.Cursor = ""
		must(json.Unmarshal(body["meta"], &meta))
		if meta.Cursor == "" {
			break
		}
		body = get("feeds?limit=1&cursor=" + url.QueryEscape(meta.Cursor))
	}
	if len(seen) != 4 {
		t.Fatal("page coverage", len(seen))
	}
	body = get("vulnerabilities/CVE-2026-10000")
	if !strings.Contains(string(body["data"]), `"local_exposure":"unknown"`) {
		t.Fatal("exposure inferred", string(body["data"]))
	}
	for _, path := range []string{"claims", "entities", "indicators", "source-imports", "source-dispositions", "history", "changes", "applicability-work"} {
		get(path)
	}
	req := httptest.NewRequest("POST", "https://fixture.invalid/api/v2/indicators", strings.NewReader(`{}`))
	req.AddCookie(&http.Cookie{Name: "noctis_v2_session", Value: token})
	req.Header.Set("Origin", "https://fixture.invalid")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatal("new mutation missing CSRF", rec.Code)
	}
}
