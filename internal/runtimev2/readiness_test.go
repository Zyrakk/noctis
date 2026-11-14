package runtimev2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	db "github.com/Zyrakk/noctis/internal/database/v2"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/vulnv2"
	migrations "github.com/Zyrakk/noctis/migrations/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// The only manifest writer: creates a fresh isolated database using the exact
// embedded migrations, then reads catalogs. Never introspects an operator DSN
// directly, copies business data, or attempts to parse migration SQL.
func TestReadinessContractPostgres(t *testing.T) {
	dsn := productDB(t)
	c := readinessConnection(t, dsn)
	ctx := context.Background()
	tx, err := c.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL search_path = pg_catalog`); err != nil {
		t.Fatal(err)
	}
	actual, err := readSchemaContract(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range contractRelations() {
		if _, ok := actual["relation:"+table]; !ok {
			t.Fatalf("declared operational table missing from migrations: %s", table)
		}
	}
	for _, signature := range contractFunctions() {
		if _, ok := actual["function:"+signature]; !ok {
			t.Fatalf("declared operational function missing from migrations: %s", signature)
		}
	}
	if os.Getenv("NOCTIS_V2_UPDATE_READINESS_CONTRACT") == "1" {
		raw, err := json.MarshalIndent(actual, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile("schema_contract.json", append(raw, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
		t.Logf("generated %d operational catalog entries from all embedded migrations", len(actual))
		return
	}
	var expected schemaContract
	if err = json.Unmarshal(readinessContractJSON, &expected); err != nil {
		t.Fatal(err)
	}
	// Unlike the live probe, CI compares both ways so new required columns and
	// constraints cannot silently leave the checked-in manifest behind.
	want, _ := json.Marshal(expected)
	got, _ := json.Marshal(actual)
	if string(want) != string(got) {
		t.Fatal("readiness contract differs from embedded migrations; review operations and regenerate schema_contract.json")
	}
	t.Logf("verified %d operational catalog entries against all embedded migrations", len(actual))
}

func readinessConnection(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func readinessExec(t *testing.T, c *pgx.Conn, sql string, args ...any) {
	t.Helper()
	if _, err := c.Exec(context.Background(), sql, args...); err != nil {
		t.Fatal(err)
	}
}

// Establishes an actual LOGIN connection. Readiness receives only the access
// declared for this mode, and no DDL, ownership or broad table/function grants.
func readinessRole(t *testing.T, admin *pgx.Conn, dsn, mode string, inherited bool) (string, string) {
	t.Helper()
	role := "readiness_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	login := pgx.Identifier{role}.Sanitize()
	readinessExec(t, admin, "CREATE ROLE "+login+" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION INHERIT")
	grantRole := login
	if inherited {
		grantRole = pgx.Identifier{role + "_grants"}.Sanitize()
		readinessExec(t, admin, "CREATE ROLE "+grantRole+" NOLOGIN NOSUPERUSER")
		readinessExec(t, admin, "GRANT "+grantRole+" TO "+login)
	}
	t.Cleanup(func() {
		readinessExec(t, admin, "DROP OWNED BY "+login)
		readinessExec(t, admin, "DROP ROLE "+login)
		if inherited {
			readinessExec(t, admin, "DROP OWNED BY "+grantRole)
			readinessExec(t, admin, "DROP ROLE "+grantRole)
		}
	})
	readinessExec(t, admin, "GRANT USAGE ON SCHEMA public,noctis_v2 TO "+grantRole)
	readinessExec(t, admin, "GRANT SELECT ON public.noctis_v2_migrations TO "+grantRole)
	tables, privileges := privilegesForMode(mode)
	for i, table := range tables {
		readinessExec(t, admin, "GRANT "+privileges[i]+" ON noctis_v2."+pgx.Identifier{table}.Sanitize()+" TO "+grantRole)
	}
	for _, signature := range readinessFunctions[mode] {
		readinessExec(t, admin, "GRANT EXECUTE ON FUNCTION "+signature+" TO "+grantRole)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.User(role)
	return u.String(), grantRole
}

func assertReady(t *testing.T, dsn, mode string) {
	t.Helper()
	h, err := Check(context.Background(), dsn, mode)
	want := map[string][]string{
		"api":       {"capture", "jobs", "cases", "evidence", "auth", "brief", "inference_jobs", "typed_query"},
		"worker":    {"jobs", "cases", "evidence", "brief", "inference_jobs"},
		"collector": {"capture"},
	}
	if err != nil || !h.Database || !h.Schema || !h.Functional || h.AIEnabled || !reflect.DeepEqual(h.Capabilities, want[mode]) {
		t.Fatalf("expected ready empty migrated DB for %s: %+v %v", mode, h, err)
	}
}

func assertUnready(t *testing.T, dsn, mode string, schema bool) Health {
	t.Helper()
	h, err := Check(context.Background(), dsn, mode)
	if err == nil || !h.Database || h.Schema != schema || h.Functional || h.AIEnabled || !reflect.DeepEqual(h.Capabilities, []string{"health_only"}) {
		t.Fatalf("incoherent unavailable state for %s: %+v %v", mode, h, err)
	}
	return h
}

func TestReadinessRestrictedModesPostgres(t *testing.T) {
	dsn := productDB(t)
	admin := readinessConnection(t, dsn)
	readinessExec(t, admin, `REVOKE CREATE ON SCHEMA public FROM PUBLIC`)
	readinessExec(t, admin, `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA noctis_v2 FROM PUBLIC`)
	for _, mode := range []string{"api", "worker", "collector"} {
		for _, inherited := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/direct", true: "/inherited"}[inherited], func(t *testing.T) {
				runtimeDSN, grantRole := readinessRole(t, admin, dsn, mode, inherited)
				login := readinessConnection(t, runtimeDSN)
				var restricted bool
				if err := login.QueryRow(context.Background(), `SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT rolreplication AND rolcanlogin FROM pg_roles WHERE rolname=current_user`).Scan(&restricted); err != nil || !restricted {
					t.Fatal("runtime connection is not a restricted LOGIN", err)
				}
				assertReady(t, runtimeDSN, mode)
				for _, sql := range []string{`CREATE TABLE noctis_v2.forbidden(id int)`, `DELETE FROM noctis_v2.sessions`, `INSERT INTO public.noctis_v2_migrations(name,checksum) VALUES('forbidden','bad')`} {
					if _, err := login.Exec(context.Background(), sql); err == nil {
						t.Fatalf("restricted connection unexpectedly allowed %s", sql)
					}
				}
				readinessExec(t, admin, "REVOKE INSERT ON noctis_v2.sessions FROM "+grantRole)
				if mode == "api" {
					assertUnready(t, runtimeDSN, mode, true)
					readinessExec(t, admin, "GRANT INSERT ON noctis_v2.sessions TO "+grantRole)
					assertReady(t, runtimeDSN, mode)
				} else {
					assertReady(t, runtimeDSN, mode)
				}
				for _, requirement := range []struct {
					table, privilege string
					required         bool
				}{
					{"question_sources", "UPDATE", mode == "api"},
					{"question_sources", "DELETE", mode == "api"},
					{"telegram_generation_transitions", "SELECT", mode == "api"},
					{"applicability_requests", "INSERT", true},
					{"applicability_requests", "UPDATE", mode == "worker"},
					{"applicability_effective", "SELECT", mode != "collector"},
					{"asset_versions", "UPDATE", mode == "worker"},
				} {
					readinessExec(t, admin, "REVOKE "+requirement.privilege+" ON noctis_v2."+requirement.table+" FROM "+grantRole)
					if requirement.required {
						assertUnready(t, runtimeDSN, mode, true)
						readinessExec(t, admin, "GRANT "+requirement.privilege+" ON noctis_v2."+requirement.table+" TO "+grantRole)
					}
					assertReady(t, runtimeDSN, mode)
				}
				for _, signature := range []string{
					"noctis_v2.select_current_nvd(text)",
					"noctis_v2.change_effective_body(uuid,jsonb)",
					"noctis_v2.enqueue_applicability(text,text,integer,text,timestamp with time zone,uuid)",
				} {
					readinessExec(t, admin, "REVOKE EXECUTE ON FUNCTION "+signature+" FROM "+grantRole)
					for _, required := range readinessFunctions[mode] {
						if required == signature {
							assertUnready(t, runtimeDSN, mode, true)
							readinessExec(t, admin, "GRANT EXECUTE ON FUNCTION "+signature+" TO "+grantRole)
						}
					}
					assertReady(t, runtimeDSN, mode)
				}
				readinessExec(t, admin, "REVOKE USAGE ON SCHEMA noctis_v2 FROM "+grantRole)
				assertUnready(t, runtimeDSN, mode, true)
				readinessExec(t, admin, "GRANT USAGE ON SCHEMA noctis_v2 TO "+grantRole)
				readinessExec(t, admin, "REVOKE SELECT ON public.noctis_v2_migrations FROM "+grantRole)
				assertUnready(t, runtimeDSN, mode, false)
				readinessExec(t, admin, "GRANT SELECT ON public.noctis_v2_migrations TO "+grantRole)
				assertReady(t, runtimeDSN, mode)
			})
		}
	}
	var unchanged bool
	if err := admin.QueryRow(context.Background(), `SELECT
 (SELECT count(*) FROM noctis_v2.sessions)=0 AND
 (SELECT count(*) FROM noctis_v2.ai_configs)=0 AND
 (SELECT count(*) FROM noctis_v2.observations)=0 AND
 (SELECT count(*) FROM noctis_v2.runtime_control)=1`).Scan(&unchanged); err != nil || !unchanged {
		t.Fatal("readiness changed the empty migrated database", err)
	}
}

func TestReadinessDriftAndHTTPPostgres(t *testing.T) {
	dsn := productDB(t)
	admin := readinessConnection(t, dsn)
	runtimeDSN, grantRole := readinessRole(t, admin, dsn, "api", true)
	secret := filepath.Join(t.TempDir(), "admin.json")
	if err := os.WriteFile(secret, []byte(`{"username":"fixture","password":"synthetic-password-only"}`), 0600); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(configv2.Config{Mode: "api", DatabaseURL: runtimeDSN, AdminFile: secret, Origin: "https://fixture.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	checkHTTP := func(t *testing.T, status int, schema bool) {
		t.Helper()
		for _, path := range []string{"/readyz", "/healthz"} {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			var h Health
			if err := json.Unmarshal(w.Body.Bytes(), &h); err != nil || w.Code != status || h.Functional != (status == 200) || h.Schema != schema {
				t.Fatalf("%s: %d %+v %v", path, w.Code, h, err)
			}
			if status != 200 && !reflect.DeepEqual(h.Capabilities, []string{"health_only"}) {
				t.Fatalf("failed readiness published capabilities: %+v", h)
			}
			if strings.Contains(w.Body.String(), "fixture") || strings.Contains(w.Body.String(), "SQLSTATE") {
				t.Fatal("readiness exposed private diagnostics")
			}
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/livez", nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"live":true`) {
			t.Fatalf("liveness depends on readiness: %d %s", w.Code, w.Body)
		}
	}
	ms, err := db.Load(migrations.Files)
	if err != nil {
		t.Fatal(err)
	}
	var immutableDefinition string
	if err = admin.QueryRow(context.Background(), `SELECT pg_get_functiondef('noctis_v2.ai_immutable_revision()'::regprocedure)`).Scan(&immutableDefinition); err != nil {
		t.Fatal(err)
	}
	var nvdDefinition, nvdView string
	if err = admin.QueryRow(context.Background(), `SELECT pg_get_functiondef('noctis_v2.nvd_revision(text)'::regprocedure),pg_get_viewdef('noctis_v2.nvd_current_selection'::regclass,true)`).Scan(&nvdDefinition, &nvdView); err != nil {
		t.Fatal(err)
	}
	nvdView = strings.TrimSuffix(strings.TrimSpace(nvdView), ";")
	cases := []struct {
		name, change, restore string
		schema                bool
	}{
		{"missing_table", `ALTER TABLE noctis_v2.sessions RENAME TO missing_sessions`, `ALTER TABLE noctis_v2.missing_sessions RENAME TO sessions`, false},
		{"missing_column", `ALTER TABLE noctis_v2.sources RENAME COLUMN adapter_config TO missing_adapter_config`, `ALTER TABLE noctis_v2.sources RENAME COLUMN missing_adapter_config TO adapter_config`, false},
		{"column_type", `ALTER TABLE noctis_v2.sources ALTER COLUMN name TYPE varchar(100)`, `ALTER TABLE noctis_v2.sources ALTER COLUMN name TYPE text`, false},
		{"critical_check", `ALTER TABLE noctis_v2.checkpoints DROP CONSTRAINT checkpoints_version_check; ALTER TABLE noctis_v2.checkpoints ADD CONSTRAINT checkpoints_version_check CHECK(version>=-1)`, `ALTER TABLE noctis_v2.checkpoints DROP CONSTRAINT checkpoints_version_check; ALTER TABLE noctis_v2.checkpoints ADD CONSTRAINT checkpoints_version_check CHECK(version>=0)`, false},
		{"critical_key", `ALTER TABLE noctis_v2.sources DROP CONSTRAINT sources_kind_native_id_key`, `ALTER TABLE noctis_v2.sources ADD CONSTRAINT sources_kind_native_id_key UNIQUE(kind,native_id)`, false},
		{"trigger_disabled", `ALTER TABLE noctis_v2.ai_configs DISABLE TRIGGER ai_configs_immutable`, `ALTER TABLE noctis_v2.ai_configs ENABLE TRIGGER ai_configs_immutable`, false},
		{"trigger_function_altered", `CREATE OR REPLACE FUNCTION noctis_v2.ai_immutable_revision() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$`, immutableDefinition, false},
		{"foreign_key_disabled", `ALTER TABLE noctis_v2.ai_secrets DISABLE TRIGGER ALL`, `ALTER TABLE noctis_v2.ai_secrets ENABLE TRIGGER ALL`, false},
		{"row_security", `ALTER TABLE noctis_v2.sessions ENABLE ROW LEVEL SECURITY`, `ALTER TABLE noctis_v2.sessions DISABLE ROW LEVEL SECURITY`, false},
		{"generation_trigger_disabled", `ALTER TABLE noctis_v2.telegram_generation_transitions DISABLE TRIGGER generation_transition_immutable`, `ALTER TABLE noctis_v2.telegram_generation_transitions ENABLE TRIGGER generation_transition_immutable`, false},
		{"applicability_queue_missing", `ALTER TABLE noctis_v2.applicability_requests RENAME TO missing_applicability_requests`, `ALTER TABLE noctis_v2.missing_applicability_requests RENAME TO applicability_requests`, false},
		{"applicability_trigger_disabled", `ALTER TABLE noctis_v2.observations DISABLE TRIGGER applicability_evidence`, `ALTER TABLE noctis_v2.observations ENABLE TRIGGER applicability_evidence`, false},
		{"nvd_function_altered", `CREATE OR REPLACE FUNCTION noctis_v2.nvd_revision(value text) RETURNS timestamptz LANGUAGE plpgsql IMMUTABLE AS $$BEGIN RETURN NULL; END$$`, nvdDefinition, false},
		{"nvd_selector_altered", `ALTER FUNCTION noctis_v2.select_current_nvd(text) VOLATILE`, `ALTER FUNCTION noctis_v2.select_current_nvd(text) STABLE`, false},
		{"nvd_view_altered", `CREATE OR REPLACE VIEW noctis_v2.nvd_current_selection AS SELECT * FROM (` + nvdView + `) selected WHERE false`, `CREATE OR REPLACE VIEW noctis_v2.nvd_current_selection AS ` + nvdView, false},
		{"governance_constraint_missing", `ALTER TABLE noctis_v2.question_sources DROP CONSTRAINT question_sources_one_governor`, `ALTER TABLE noctis_v2.question_sources ADD CONSTRAINT question_sources_one_governor UNIQUE(source_id)`, false},
		{"ledger_pending", `DELETE FROM public.noctis_v2_migrations WHERE name='` + ms[len(ms)-1].Name + `'`, `INSERT INTO public.noctis_v2_migrations(name,checksum) VALUES('` + ms[len(ms)-1].Name + `','` + ms[len(ms)-1].Checksum + `')`, false},
		{"ledger_additional", `INSERT INTO public.noctis_v2_migrations(name,checksum) VALUES('999_future.sql','bad')`, `DELETE FROM public.noctis_v2_migrations WHERE name='999_future.sql'`, false},
		{"ledger_checksum", `UPDATE public.noctis_v2_migrations SET checksum='bad' WHERE name='` + ms[0].Name + `'`, `UPDATE public.noctis_v2_migrations SET checksum='` + ms[0].Checksum + `' WHERE name='` + ms[0].Name + `'`, false},
		{"sessions_insert_denied", `REVOKE INSERT ON noctis_v2.sessions FROM ` + grantRole, `GRANT INSERT ON noctis_v2.sessions TO ` + grantRole, true},
		{"ai_select_denied", `REVOKE SELECT ON noctis_v2.ai_configs FROM ` + grantRole, `GRANT SELECT ON noctis_v2.ai_configs TO ` + grantRole, true},
		{"ai_query_failure", `INSERT INTO noctis_v2.ai_configs(revision,body,actor) VALUES(1,'{"bindings":"invalid"}','fixture')`, `TRUNCATE noctis_v2.ai_configs CASCADE`, true},
	}
	checkHTTP(t, 200, true)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			readinessExec(t, admin, tc.change)
			t.Cleanup(func() { readinessExec(t, admin, tc.restore) })
			assertUnready(t, runtimeDSN, "api", tc.schema)
			checkHTTP(t, 503, tc.schema)
		})
		assertReady(t, runtimeDSN, "api")
	}
	// Extra objects and absent performance indexes are outside the contract.
	readinessExec(t, admin, `CREATE TABLE noctis_v2.unrelated_readiness_fixture(id int); DROP INDEX noctis_v2.jobs_ready`)
	checkHTTP(t, 200, true)
	// A locked business table cannot make a probe exceed its caller's deadline.
	tx, err := admin.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(context.Background(), `LOCK TABLE noctis_v2.ai_configs IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	h, err := Check(ctx, runtimeDSN, "api")
	if err == nil || h.Functional || time.Since(start) > 2*time.Second {
		t.Fatalf("readiness ignored deadline: %+v %v", h, err)
	}
	// This handler has an unreachable DSN; liveness still does not connect.
	live, err := NewHandler(configv2.Config{Mode: "api", DatabaseURL: "postgres://127.0.0.1:1/noctis_v2?connect_timeout=1", AdminFile: secret, Origin: "https://fixture.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	live.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if w.Code != 200 {
		t.Fatal("liveness queried PostgreSQL")
	}
}

func TestReadinessRestrictedOperationsPostgres(t *testing.T) {
	dsn := productDB(t)
	admin := readinessConnection(t, dsn)
	readinessExec(t, admin, `REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA noctis_v2 FROM PUBLIC`)
	collectorDSN, _ := readinessRole(t, admin, dsn, "collector", true)
	workerDSN, _ := readinessRole(t, admin, dsn, "worker", true)
	apiDSN, _ := readinessRole(t, admin, dsn, "api", true)
	assertReady(t, collectorDSN, "collector")
	assertReady(t, workerDSN, "worker")
	assertReady(t, apiDSN, "api")
	var revision atomic.Int64
	feed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<rss><channel><item><guid>readiness-item</guid><title>CVE-2026-12345 revision %d</title><pubDate>%s</pubDate></item></channel></rss>`, revision.Load(), time.Now().UTC().Format(time.RFC1123Z))
	}))
	defer feed.Close()
	source := uuid.NewString()
	readinessExec(t, admin, `INSERT INTO noctis_v2.policies(version,terms) VALUES('readiness','[{"type":"cve","value":"CVE-2026-12345"}]')`)
	readinessExec(t, admin, `INSERT INTO noctis_v2.sources(id,kind,native_id,policy_version,enabled,epoch,activated_at) VALUES($1,'rss',$2,'readiness',true,$3,clock_timestamp()-interval '1 hour')`, source, feed.URL, uuid.NewString())
	worker := intelligence.Worker{DSN: workerDSN, Owner: "readiness-fixture"}
	for i := int64(1); i <= 2; i++ {
		revision.Store(i)
		readinessExec(t, admin, `UPDATE noctis_v2.sources SET poll_after=clock_timestamp()-interval '1 second' WHERE id=$1`, source)
		if err := (capture.Store{DSN: collectorDSN}).Poll(context.Background(), source, capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feed.URL, "http://"): true}}); err != nil {
			t.Fatal("collector operational grant contract", err)
		}
		if err := worker.Once(context.Background()); err != nil {
			t.Fatal("worker operational grant contract", err)
		}
		drainApplicability(t, workerDSN)
		if err := worker.Brief(context.Background(), time.Now().UTC().Format("2006-01-02"), "readiness"); err != nil {
			t.Fatal("worker brief grant contract", err)
		}
	}
	// Exercise new input -> durable queue -> pair/case projection using only
	// each mode's declared grants, including nested SQL function execution.
	asset := uuid.NewString()
	saveAsset := inventorySaveFixture(t, context.Background(), apiDSN, admin)
	saveAsset(asset, 0)
	nvd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"startIndex":0,"totalResults":1,"resultsPerPage":1,"timestamp":%q,"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","lastModified":"2026-01-01T00:00:00Z","configurations":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}}]}`, time.Now().UTC().Format(time.RFC3339Nano))
	}))
	defer nvd.Close()
	if _, err := (vulnv2.Store{DSN: collectorDSN, Fetcher: capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(nvd.URL, "http://"): true}}}).PollPage(context.Background(), "nvd", nvd.URL, time.Hour); err != nil {
		t.Fatal("collector applicability enqueue grant contract", err)
	}
	drainApplicability(t, workerDSN)
	var projected bool
	if err := admin.QueryRow(context.Background(), `SELECT
 EXISTS(SELECT FROM noctis_v2.applicability_current WHERE asset_id=$1 AND status='affected_version')
 AND EXISTS(SELECT FROM noctis_v2.applicability_transitions WHERE asset_id=$1)
 AND EXISTS(SELECT FROM noctis_v2.case_applicability_projection WHERE body->>'local_applicability'='affected_version')`, asset).Scan(&projected); err != nil || !projected {
		t.Fatal("restricted pipeline did not publish applicability projections", err)
	}
	apiLogin := readinessConnection(t, apiDSN)
	first, second := uuid.NewString(), uuid.NewString()
	readinessExec(t, admin, `INSERT INTO noctis_v2.questions(id,title) VALUES($1,'first'),($2,'second')`, first, second)
	tx, err := apiLogin.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(context.Background())
	for _, question := range []string{first, second, ""} {
		if err = replaceSourceGovernanceTx(context.Background(), tx, source, question); err != nil {
			t.Fatal("API governance replacement/removal grant contract", err)
		}
		var actual string
		if err = tx.QueryRow(context.Background(), `SELECT COALESCE((SELECT question_id::text FROM noctis_v2.question_sources WHERE source_id=$1),'')`, source).Scan(&actual); err != nil || actual != question {
			t.Fatal("API governance replacement/removal result", actual, err)
		}
	}
	if err = tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "admin.json")
	if err := os.WriteFile(secret, []byte(`{"username":"fixture","password":"synthetic-password-only"}`), 0600); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(configv2.Config{Mode: "api", DatabaseURL: apiDSN, AdminFile: secret, Origin: "https://fixture.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v2/auth/login", strings.NewReader(`{"username":"fixture","password":"synthetic-password-only"}`))
	r.Header.Set("Origin", "https://fixture.invalid")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != 200 || len(w.Result().Cookies()) != 1 {
		t.Fatalf("API login operational grant contract: %d %s", w.Code, w.Body)
	}
	sessionCookie := w.Result().Cookies()[0]
	read := httptest.NewRequest(http.MethodGet, "/api/v2/cases", nil)
	read.AddCookie(sessionCookie)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, read)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "CVE-2026-12345") {
		t.Fatalf("authenticated case read: %d %s", w.Code, w.Body)
	}
	for _, path := range []string{"assets", "applicability", "applicability-work", "changes", "today"} {
		read := httptest.NewRequest(http.MethodGet, "/api/v2/"+path, nil)
		read.AddCookie(sessionCookie)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, read)
		if w.Code != http.StatusOK {
			t.Fatalf("restricted %s read: %d %s", path, w.Code, w.Body)
		}
	}
	assertReady(t, collectorDSN, "collector")
	assertReady(t, workerDSN, "worker")
	assertReady(t, apiDSN, "api")
}
