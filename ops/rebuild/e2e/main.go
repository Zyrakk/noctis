// Local synthetic integration harness. Real inference requires explicit opt-in.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() (runErr error) {
	binary := flag.String("binary", "./noctis", "Compiled noctis executable")
	browser := flag.Bool("browser", false, "Run real Playwright fixture spec")
	product := flag.Bool("product", false, "Seed synthetic product A/B/C and run real product UI spec")
	ai := flag.Bool("ai", false, "Run compiled private AI panel with fake HTTPS gateways and API restart")
	realConfig := flag.String("real-ai-config", "", "Opt-in synthetic real-AI panel configuration JSON (no wire calls by default)")
	realCampaign := flag.String("real-ai-campaign", "", "Absolute durable USD 5 campaign state path; retain across every run")
	realInit := flag.Bool("real-ai-init", false, "Explicitly initialize a NEW campaign; never use to reset an existing authorization")
	realWire := flag.Bool("real-ai-enable-wire", false, "Explicitly enable sequential paid Store.Once; requires reviewed provider contract")
	realFake := flag.Bool("real-ai-fake-responses", false, "Offline synthetic Responses gateway; requires synthetic credential")
	realResume := flag.String("real-ai-resume-artifacts", "", "Existing private artifacts and encrypted master key; resume same database without seeding or changing configuration")
	realAudit := flag.String("real-ai-audit", "", "Private audited quarantine JSON; exact uncertain attempt, fingerprint, prior state SHA and corrected binary SHA")
	realPublicationAudit := flag.String("real-ai-publication-audit", "", "Private exact settled-publication-rejection disposition; preserves accounting and failed jobs")
	realPromptV2 := flag.Bool("real-ai-upgrade-prompt-v2", false, "Explicitly save a new prompt-v2 config revision with credential unchanged; existing campaign only")
	keep := flag.Bool("keep", false, "Keep synthetic DB and temporary secrets after stopping processes")
	flag.Parse()
	if *realInit && (*realAudit != "" || *realPublicationAudit != "" || *realPromptV2) {
		return errors.New("audited dispositions require existing campaign resume")
	}
	var realInputs *realAIInputs
	if *realConfig != "" {
		if *ai || *product || *browser || !*keep || *realCampaign == "" {
			return errors.New("real AI requires --keep and campaign path; use separately from other browser modes")
		}
		var err error
		realInputs, err = loadRealAIInputs(*realConfig, *realWire)
		if err != nil {
			return err
		}
	} else if *realWire || *realFake || *realInit || *realCampaign != "" || *realAudit != "" || *realPublicationAudit != "" || *realPromptV2 {
		return errors.New("real AI flags require --real-ai-config")
	}
	var externalReceipt map[string]any
	// Registered before resource cleanup, so the exported receipt is written only
	// after child processes and temporary database cleanup have completed.
	defer func() {
		if runErr != nil || externalReceipt == nil {
			return
		}
		path := os.Getenv("NOCTIS_V2_E2E_RECEIPT")
		if path == "" {
			return
		}
		raw, e := json.MarshalIndent(externalReceipt, "", "  ")
		if e == nil {
			e = os.WriteFile(path, append(raw, '\n'), 0600)
		}
		if e != nil {
			runErr = errors.New("cannot persist sanitized external e2e receipt")
		}
	}()
	binaryPath, e := filepath.Abs(*binary)
	if e != nil {
		return e
	}
	if realInputs != nil && !*realInit {
		if *realResume == "" || *realFake {
			return errors.New("existing campaign requires --real-ai-resume-artifacts; no new database or fixture is permitted")
		}
		return resumeRealAI(binaryPath, *realResume, *realCampaign, *realAudit, *realInputs, *realWire, *realPublicationAudit, *realPromptV2)
	}
	dsn := os.Getenv("NOCTIS_V2_TEST_DATABASE_URL")
	u, e := url.Parse(dsn)
	if e != nil || u.Hostname() != "127.0.0.1" || !strings.Contains(u.Path, "v2_test") {
		return errors.New("explicit local synthetic NOCTIS_V2_TEST_DATABASE_URL required")
	}
	runTimeout := 3 * time.Minute
	if realInputs != nil {
		runTimeout = 12 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), runTimeout)
	defer cancel()
	admin, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return e
	}
	defer admin.Close(context.Background())
	name := "noctis_v2_e2e_" + uuid.NewString()[:8]
	if _, e = admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize()); e != nil {
		return e
	}
	u.Path = "/" + name
	taskDSN := u.String()
	dir, e := os.MkdirTemp("", "noctis-v2-e2e-")
	if e != nil {
		return e
	}
	fmt.Println("Artifacts:", dir)
	defer func() {
		if !*keep {
			admin.Exec(context.Background(), "DROP DATABASE "+pgx.Identifier{name}.Sanitize()+" WITH (FORCE)")
			os.RemoveAll(dir)
		}
	}()
	secret := filepath.Join(dir, "database.secret")
	if e = os.WriteFile(secret, []byte(taskDSN), 0600); e != nil {
		return e
	}
	adminSecret := filepath.Join(dir, "admin.secret")
	password := "synthetic-e2e-password-only"
	if e = os.WriteFile(adminSecret, []byte(`{"username":"operator","password":"`+password+`"}`), 0600); e != nil {
		return e
	}
	command := func(args ...string) (string, error) {
		all := append([]string{"v2", "--database-secret-file", secret}, args...)
		cmd := exec.CommandContext(ctx, binaryPath, all...)
		raw, e := cmd.CombinedOutput()
		if e != nil {
			return "", fmt.Errorf("v2 %s failed: %w: %s", args[0], e, raw)
		}
		return strings.TrimSpace(string(raw)), nil
	}
	if _, e = command("migrate"); e != nil {
		return e
	}
	policy := filepath.Join(dir, "terms.json")
	os.WriteFile(policy, []byte(`[{"type":"cve","value":"CVE-2026-12345"}]`), 0600)
	if _, e = command("policy", "p1", policy); e != nil {
		return e
	}
	fixtureText := strings.Repeat("á証拠 ", 1500) + "CVE-2026-12345"
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<rss><channel><item><guid>synthetic-entry-1</guid><title>Aviso sintético de prueba</title><description>`+fixtureText+`</description><pubDate>`+time.Now().UTC().Add(time.Second).Format(time.RFC1123Z)+`</pubDate></item></channel></rss>`)
	}))
	defer feed.Close()
	source, e := command("source", "rss", feed.URL, "Fuente sintética local", "p1")
	if e != nil {
		return e
	}
	if _, e = command("poll", source, "--fixture-authority", strings.TrimPrefix(feed.URL, "http://")); e != nil {
		return e
	}
	if _, e = command("run-once"); e != nil {
		return e
	}
	if _, e = command("brief", time.Now().UTC().Format("2006-01-02"), "p1"); e != nil {
		return e
	}
	aiCaseID := ""
	if *ai {
		conn, ce := pgx.Connect(ctx, taskDSN)
		if ce != nil {
			return ce
		}
		// Product tests intentionally revoke other sources. Keep AI tied to the
		// original fixture instead of the mutable ordering of the case list.
		var ids []string
		e = conn.QueryRow(ctx, `SELECT ARRAY(SELECT DISTINCT m.case_id::text FROM noctis_v2.case_memberships m JOIN noctis_v2.observations o ON o.id=m.observation_id WHERE o.source_id=$1)`, source).Scan(&ids)
		conn.Close(ctx)
		if e != nil {
			return fmt.Errorf("resolve baseline AI fixture case: %w", e)
		}
		if len(ids) != 1 {
			return fmt.Errorf("baseline AI fixture must have exactly one case, got %d", len(ids))
		}
		aiCaseID = ids[0]
	}
	productIDs := map[string]string{}
	if *product || realInputs != nil {
		conn, ce := pgx.Connect(ctx, taskDSN)
		if ce != nil {
			return ce
		}
		productIDs, e = seedProductFixture(ctx, conn)
		conn.Close(ctx)
		if e != nil {
			return e
		}
	}
	var received atomic.Int64
	receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.Header.Get("Idempotency-Key") == "" {
			http.Error(w, "missing key", 400)
			return
		}
		w.WriteHeader(204)
	}))
	defer receiver.Close()
	if realInputs == nil {
		if _, e = command("dispatch-once", receiver.URL); e != nil {
			return e
		}
		if received.Load() != 1 {
			return errors.New("delivery count mismatch")
		}
	}
	// API and inference worker run under a real login without schema/DDL powers.
	role := "e2e_" + uuid.NewString()[:8]
	roleSQL := pgx.Identifier{role}.Sanitize()
	runtimeConn, e := pgx.Connect(ctx, taskDSN)
	if e != nil {
		return e
	}
	if _, e = runtimeConn.Exec(ctx, "CREATE ROLE "+roleSQL+" LOGIN;GRANT USAGE ON SCHEMA noctis_v2 TO "+roleSQL+";GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA noctis_v2 TO "+roleSQL+";GRANT DELETE ON noctis_v2.question_sources TO "+roleSQL+";GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA noctis_v2 TO "+roleSQL+";GRANT SELECT ON public.noctis_v2_migrations TO "+roleSQL); e != nil {
		runtimeConn.Close(ctx)
		return e
	}
	defer func() {
		runtimeConn.Exec(context.Background(), "DROP OWNED BY "+roleSQL)
		runtimeConn.Close(context.Background())
		admin.Exec(context.Background(), "DROP ROLE "+roleSQL)
	}()
	runtimeURL, _ := url.Parse(taskDSN)
	runtimeURL.User = url.User(role)
	if e = os.WriteFile(secret, []byte(runtimeURL.String()), 0600); e != nil {
		return e
	}
	cert, key, e := certificate(dir)
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	address := listener.Addr().String()
	listener.Close()
	origin := "https://" + address
	log, e := os.Create(filepath.Join(dir, "api.log"))
	if e != nil {
		return e
	}
	defer log.Close()
	apiArgs := []string{"v2", "--database-secret-file", secret, "serve", "--mode", "api", "--listen", address, "--admin-secret-file", adminSecret, "--origin", origin, "--tls-cert-file", cert, "--tls-key-file", key}
	var server *exec.Cmd
	var done chan error
	stopServer := func() {
		if server == nil {
			return
		}
		server.Process.Signal(syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(6 * time.Second):
			server.Process.Kill()
			<-done
		}
		server = nil
	}
	startServer := func() error {
		server = exec.Command(binaryPath, apiArgs...)
		server.Stdout = log
		server.Stderr = log
		if e := server.Start(); e != nil {
			return e
		}
		done = make(chan error, 1)
		cmd := server
		ch := done
		go func() { ch <- cmd.Wait() }()
		return nil
	}
	aiEnv := []string{}
	if realInputs != nil {
		extra, env, cleanup, re := setupRealAIFixture(ctx, dir, secret, origin, productIDs, *realConfig, *realCampaign, *realInit, *realWire, *realInputs, cert, key, *realFake)
		if re != nil {
			return re
		}
		defer cleanup()
		apiArgs = append(apiArgs, extra...)
		aiEnv = env
	}
	if *ai {
		extra, env, cleanup, ae := setupAIFixture(ctx, dir, binaryPath, secret, cert, key, origin, func() error { stopServer(); return startServer() })
		if ae != nil {
			return ae
		}
		defer cleanup()
		apiArgs = append(apiArgs, extra...)
		aiEnv = env
	}
	if e = startServer(); e != nil {
		return e
	}
	defer stopServer()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	client.Jar, _ = cookiejar.New(nil)
	ready := false
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
		res, e := client.Get(origin + "/healthz")
		if e == nil {
			res.Body.Close()
			if res.StatusCode == 200 {
				ready = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		return errors.New("API failed readiness; see artifact api.log")
	}
	post := func(path, body, csrf string) (map[string]any, error) {
		req, _ := http.NewRequest("POST", origin+path, bytes.NewBufferString(body))
		req.Header.Set("Origin", origin)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", csrf)
		res, e := client.Do(req)
		if e != nil {
			return nil, e
		}
		defer res.Body.Close()
		if res.StatusCode != 200 {
			return nil, fmt.Errorf("POST %s returned %d", path, res.StatusCode)
		}
		var result map[string]any
		e = json.NewDecoder(res.Body).Decode(&result)
		return result, e
	}
	session, e := post("/api/v2/auth/login", `{"username":"operator","password":"`+password+`"}`, "")
	if e != nil {
		return e
	}
	csrf := session["data"].(map[string]any)["csrf"].(string)
	for _, path := range []string{"/api/v2/cases", "/api/v2/today", "/api/v2/sources", "/api/v2/system", "/v2/cases"} {
		res, e := client.Get(origin + path)
		if e != nil {
			return e
		}
		raw, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode != 200 {
			return fmt.Errorf("GET %s returned %d", path, res.StatusCode)
		}
		if path == "/api/v2/cases" && !bytes.Contains(raw, []byte("Aviso sintético")) {
			return errors.New("case missing from real API")
		}
	}
	if *browser {
		cmd := exec.CommandContext(ctx, "npx", "playwright", "test", "tests/v2-real.spec.js", "--config=playwright.build.config.js")
		cmd.Dir = "web"
		cmd.Env = append(os.Environ(), "NOCTIS_V2_E2E_URL="+origin, "NOCTIS_V2_E2E_USERNAME=operator", "NOCTIS_V2_E2E_PASSWORD="+password)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			return e
		}
	}
	if *product {
		raw, _ := json.Marshal(productIDs)
		cmd := exec.CommandContext(ctx, "npx", "playwright", "test", "tests/v2-p7-real.spec.js", "tests/v2-operations-real.spec.js", "--config=playwright.p7.config.js", "--workers=1")
		cmd.Dir = "web"
		cmd.Env = append(os.Environ(), "NOCTIS_V2_E2E_URL="+origin, "NOCTIS_V2_E2E_USERNAME=operator", "NOCTIS_V2_E2E_PASSWORD="+password, "NOCTIS_V2_E2E_PRODUCT_IDS="+string(raw))
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			return e
		}
	}
	if *ai {
		cmd := exec.CommandContext(ctx, "npx", "playwright", "test", "tests/v2-ai-real.spec.js", "--config=playwright.ai.config.js")
		cmd.Dir = "web"
		cmd.Env = append(os.Environ(), "NOCTIS_V2_E2E_URL="+origin, "NOCTIS_V2_E2E_USERNAME=operator", "NOCTIS_V2_E2E_PASSWORD="+password, "NOCTIS_V2_AI_CASE_ID="+aiCaseID)
		cmd.Env = append(cmd.Env, aiEnv...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			return e
		}
	}
	if realInputs != nil {
		cmd := exec.CommandContext(ctx, "npx", "playwright", "test", "--config=../ops/rebuild/e2e/real_ai.playwright.cjs")
		cmd.Dir = "web"
		cmd.Env = append(os.Environ(), "NOCTIS_V2_E2E_URL="+origin, "NOCTIS_V2_E2E_USERNAME=operator", "NOCTIS_V2_E2E_PASSWORD="+password)
		cmd.Env = append(cmd.Env, aiEnv...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if e = cmd.Run(); e != nil {
			return errors.New("real AI opt-in browser failed; inspect private artifacts (no automatic retry)")
		}
	}
	if _, e = post("/api/v2/auth/logout", "{}", csrf); e != nil {
		return e
	}
	receipt := map[string]any{"result": "pass", "binary": binaryPath, "database": name, "source_id": source, "delivered": received.Load(), "browser": *browser, "ai": *ai, "product": *product, "product_ids": productIDs, "url": origin, "processes_stopped_on_exit": true}
	externalReceipt = map[string]any{"result": "pass", "binary": filepath.Base(binaryPath), "database": name, "delivered": received.Load(), "browser": *browser, "ai": *ai, "product": *product, "dataset": "SYNTHETIC", "restricted_runtime_login": true, "processes_stopped_on_exit": true, "temporary_database_removed": !*keep}
	if realInputs != nil {
		externalReceipt["real_ai_panel"] = true
		externalReceipt["real_ai_wire_enabled"] = *realWire
		externalReceipt["real_ai_receipt"] = filepath.Join(dir, "real-ai-receipt.json")
	}
	raw, _ := json.MarshalIndent(receipt, "", "  ")
	os.WriteFile(filepath.Join(dir, "receipt.json"), raw, 0600)
	fmt.Println(string(raw))
	return nil
}
func certificate(dir string) (string, string, error) {
	private, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		return "", "", e
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Local synthetic fixture"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &private.PublicKey, private)
	if e != nil {
		return "", "", e
	}
	cert, key := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if e = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		return "", "", e
	}
	if e = os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}), 0600); e != nil {
		return "", "", e
	}
	return cert, key, nil
}
