package runtimev2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/Zyrakk/noctis/internal/vulnv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func drainApplicability(t *testing.T, dsn string) {
	t.Helper()
	w := vulnv2.ApplicabilityWorker{DSN: dsn, Owner: "applicability-test"}
	for n := 0; n < 20000; n++ {
		err := w.Once(context.Background())
		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	t.Fatal("applicability queue did not converge")
}

func queueFixture(t *testing.T) (context.Context, string, *pgx.Conn, string) {
	t.Helper()
	ctx, dsn := context.Background(), productDB(t)
	c, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(ctx) })
	snapshot := uuid.NewString()
	if _, err = c.Exec(ctx, `INSERT INTO noctis_v2.feed_snapshots(id,kind,url,hash,as_of,expires_at,payload) VALUES($1::uuid,'nvd','https://fixture.invalid/nvd',$1::text,clock_timestamp(),clock_timestamp()+interval '1 day','{}')`, snapshot); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Exec(ctx, `CREATE TABLE noctis_v2.page_audit(request_id uuid,pairs bigint,cases bigint,seconds double precision); CREATE FUNCTION noctis_v2.audit_applicability_page() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO noctis_v2.page_audit VALUES(NEW.id,NEW.pairs_processed-OLD.pairs_processed,NEW.cases_processed-OLD.cases_processed,extract(epoch FROM clock_timestamp()-transaction_timestamp())); RETURN NULL; END $$; CREATE TRIGGER audit_page AFTER UPDATE ON noctis_v2.applicability_requests FOR EACH ROW EXECUTE FUNCTION noctis_v2.audit_applicability_page()`); err != nil {
		t.Fatal(err)
	}
	return ctx, dsn, c, snapshot
}

func inventorySaveFixture(t *testing.T, ctx context.Context, dsn string, c *pgx.Conn) func(string, int) string {
	t.Helper()
	source, observation := uuid.NewString(), uuid.NewString()
	for _, q := range []string{
		`INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version) VALUES('` + source + `','rss','inventory-fixture',true,'p1')`,
		`INSERT INTO noctis_v2.content_blobs(hash,representation,payload) VALUES('inventory-fixture','text',convert_to('inventory fixture','UTF8'))`,
		`INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) VALUES('` + observation + `','` + source + `','inventory','1','inventory-fixture','text',gen_random_uuid(),'live',clock_timestamp())`,
	} {
		if _, err := c.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	admin := filepath.Join(t.TempDir(), "admin.json")
	if err := os.WriteFile(admin, []byte(`{"Username":"operator","Password":"synthetic-fixture-password"}`), 0600); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(configv2.Config{DatabaseURL: dsn, AdminFile: admin, Origin: "https://fixture.invalid"})
	if err != nil {
		t.Fatal(err)
	}
	token, csrf := uuid.NewString(), uuid.NewString()
	if _, err = c.Exec(ctx, `INSERT INTO noctis_v2.sessions VALUES($1,'operator',$2,clock_timestamp()+interval '1 hour',false)`, tokenHash(token), csrf); err != nil {
		t.Fatal(err)
	}
	return func(asset string, revision int) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"id": asset, "expected_revision": revision, "cpe": "cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*", "version": "1.0", "refs": []evidence.Ref{{ObservationID: observation, Revision: "1", Hash: "inventory-fixture", Representation: "text", Start: 0, End: 17}}})
		req := httptest.NewRequest("POST", "https://fixture.invalid/api/v2/assets", bytes.NewReader(body))
		req.Header.Set("Origin", "https://fixture.invalid")
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(&http.Cookie{Name: "noctis_v2_session", Value: token})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("inventory save: %d %s", rec.Code, rec.Body.String())
		}
		var result struct {
			Data struct {
				ID            string `json:"id"`
				Revision      int    `json:"revision"`
				CalculationID string `json:"calculation_id"`
				State         string `json:"calculation_state"`
			} `json:"data"`
		}
		if err = json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Data.ID != asset || result.Data.Revision != revision+1 || result.Data.State != "pending" {
			t.Fatal("inventory response contract", rec.Body.String())
		}
		return result.Data.CalculationID
	}
}

func TestApplicabilityQueueThresholdsPostgres(t *testing.T) {
	for _, axis := range []string{"cves", "assets"} {
		t.Run(axis, func(t *testing.T) {
			ctx, dsn, c, snapshot := queueFixture(t)
			asset := uuid.NewString()
			save := inventorySaveFixture(t, ctx, dsn, c)
			feedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprintf(w, `{"startIndex":0,"totalResults":1,"resultsPerPage":1,"timestamp":%q,"vulnerabilities":[{"cve":{"id":"CVE-2026-12345"}}]}`, time.Now().UTC().Format(time.RFC3339Nano))
			}))
			defer feedServer.Close()
			feed := vulnv2.Store{DSN: dsn, Fetcher: capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feedServer.URL, "http://"): true}}}
			revision := 0
			for _, n := range []int{999, 1000, 1001} {
				if axis == "cves" {
					_, err := c.Exec(ctx, `INSERT INTO noctis_v2.vulnerability_facts(snapshot_id,cve,body) SELECT $1,'CVE-2026-'||n::text,'{}' FROM generate_series(10000,10000+$2::int-1) n ON CONFLICT DO NOTHING`, snapshot, n)
					if err != nil {
						t.Fatal(err)
					}
				} else {
					_, err := c.Exec(ctx, `INSERT INTO noctis_v2.vulnerability_facts VALUES($1,'CVE-2026-12345','{}','unknown') ON CONFLICT DO NOTHING`, snapshot)
					if err != nil {
						t.Fatal(err)
					}
					_, err = c.Exec(ctx, `INSERT INTO noctis_v2.asset_versions(id,revision,cpe,version,evidence,producer) SELECT md5(n::text)::uuid,1,'cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*','1.0','[]','fixture' FROM generate_series(1,$1::int)n ON CONFLICT DO NOTHING`, n)
					if err != nil {
						t.Fatal(err)
					}
				}
				var err error
				var request string
				started := time.Now()
				if axis == "cves" {
					request = save(asset, revision)
					revision++
				} else {
					receipt, pollErr := feed.PollPage(ctx, "nvd", feedServer.URL, 24*time.Hour)
					if pollErr != nil {
						t.Fatal(pollErr)
					}
					if receipt.CalculationState != "pending" {
						t.Fatal("capture calculation state", receipt)
					}
					err = c.QueryRow(ctx, `SELECT id::text FROM noctis_v2.applicability_requests WHERE idempotency_key=$1`, "snapshot:"+receipt.SnapshotID+":CVE-2026-12345").Scan(&request)
				}
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("%s=%d enqueue+commit=%s", axis, n, time.Since(started))
				var before int
				if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.local_applicability`).Scan(&before); err != nil {
					t.Fatal(err)
				}
				if n == 999 && before != 0 {
					t.Fatal("enqueue calculated matrix")
				}
				started = time.Now()
				drainApplicability(t, dsn)
				var count, pages, maxAttempts int
				var state string
				if err = c.QueryRow(ctx, `SELECT pairs_processed,calculation_state FROM noctis_v2.applicability_work_status WHERE id=$1`, request).Scan(&count, &state); err != nil {
					t.Fatal(err)
				}
				if count != n || state != "complete" {
					t.Fatalf("coverage=%d state=%s expected=%d", count, state, n)
				}
				if err = c.QueryRow(ctx, `SELECT count(*),max(attempts) FROM noctis_v2.jobs WHERE input_id=$1`, request).Scan(&pages, &maxAttempts); err != nil {
					t.Fatal(err)
				}
				if pages <= 5 || maxAttempts != 1 {
					t.Fatalf("pages=%d attempts=%d", pages, maxAttempts)
				}
				if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.applicability_current`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != n {
					t.Fatalf("current coverage=%d expected=%d", count, n)
				}
				t.Logf("%s=%d pages=%d process=%s", axis, n, pages, time.Since(started))
				var maxRows int
				var maxSeconds float64
				if err = c.QueryRow(ctx, `SELECT max(pairs+cases),max(seconds) FROM noctis_v2.page_audit WHERE request_id=$1`, request).Scan(&maxRows, &maxSeconds); err != nil {
					t.Fatal(err)
				}
				if maxRows > vulnv2.ApplicabilityPageSize {
					t.Fatal("unbounded page", maxRows)
				}
				t.Logf("%s=%d max page rows=%d transaction=%.3fs", axis, n, maxRows, maxSeconds)
			}
		})
	}
}

func TestApplicabilityQueueFencingRollbackReplayAndPausePostgres(t *testing.T) {
	ctx, dsn, c, snapshot := queueFixture(t)
	asset := uuid.NewString()
	for _, q := range []string{
		`INSERT INTO noctis_v2.vulnerability_facts(snapshot_id,cve,body) SELECT '` + snapshot + `','CVE-2026-'||n::text,'{}' FROM generate_series(10000,10060)n`,
		`INSERT INTO noctis_v2.asset_versions VALUES('` + asset + `',1,'cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*','1','[]','fixture',clock_timestamp())`,
	} {
		if _, err := c.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request, err := vulnv2.EnqueueAssetApplicabilityTx(ctx, tx, asset, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	store := jobs.Store{DSN: dsn}
	w := vulnv2.ApplicabilityWorker{DSN: dsn, Owner: "first"}
	j, err := store.Claim(ctx, "first", time.Minute, "applicability")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Exec(ctx, `CREATE FUNCTION noctis_v2.reject_applicability_page() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic failure before page commit'; END $$; CREATE TRIGGER reject_page BEFORE UPDATE ON noctis_v2.applicability_requests FOR EACH ROW EXECUTE FUNCTION noctis_v2.reject_applicability_page()`)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Process(ctx, j); err == nil {
		t.Fatal("failed transaction committed")
	}
	var count int
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.local_applicability`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial page results", count, err)
	}
	_, err = c.Exec(ctx, `DROP TRIGGER reject_page ON noctis_v2.applicability_requests`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Exec(ctx, `CREATE FUNCTION noctis_v2.expire_applicability_lease() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN UPDATE noctis_v2.jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE stage='applicability' AND input_id=NEW.id AND state='leased'; RETURN NULL; END $$; CREATE TRIGGER expire_page_lease AFTER UPDATE ON noctis_v2.applicability_requests FOR EACH ROW EXECUTE FUNCTION noctis_v2.expire_applicability_lease()`)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Process(ctx, j); !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatal("lease expired during writes committed", err)
	}
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.local_applicability`).Scan(&count); err != nil || count != 0 {
		t.Fatal("expired page partial results", count, err)
	}
	_, err = c.Exec(ctx, `DROP TRIGGER expire_page_lease ON noctis_v2.applicability_requests`)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Process(ctx, j); err != nil {
		t.Fatal(err)
	}
	if err = w.Process(ctx, j); !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatal("committed job replay", err)
	}
	j, err = store.Claim(ctx, "expired", time.Minute, "applicability")
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Exec(ctx, `UPDATE noctis_v2.jobs SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, j.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Process(ctx, j); !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatal("expired lease published", err)
	}
	j, err = store.Claim(ctx, "reclaimed", time.Minute, "applicability")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Fail(ctx, j, "synthetic_quarantine", true); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = c.QueryRow(ctx, `SELECT calculation_state FROM noctis_v2.applicability_work_status WHERE id=$1`, request).Scan(&state); err != nil || state != "failed" {
		t.Fatal(state, err)
	}
	if err = store.Replay(ctx, j.ID); err != nil {
		t.Fatal(err)
	}
	_, err = c.Exec(ctx, `UPDATE noctis_v2.runtime_control SET paused=true`)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Once(ctx); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("global pause ignored", err)
	}
	_, err = c.Exec(ctx, `UPDATE noctis_v2.runtime_control SET paused=false`)
	if err != nil {
		t.Fatal(err)
	}
	drainApplicability(t, dsn)
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.applicability_current`).Scan(&count); err != nil || count != 61 {
		t.Fatal("recovery coverage", count, err)
	}
}

func TestApplicabilityQueueConcurrentBehindCursorAndExpiryPostgres(t *testing.T) {
	ctx, dsn, c, snapshot := queueFixture(t)
	asset := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	_, err := c.Exec(ctx, `INSERT INTO noctis_v2.asset_versions VALUES($1,1,'cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*','1','[]','fixture',clock_timestamp())`, asset)
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Exec(ctx, `INSERT INTO noctis_v2.vulnerability_facts(snapshot_id,cve,body) SELECT $1,'CVE-2026-'||n::text,'{}' FROM generate_series(10000,10060)n`, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vulnv2.EnqueueAssetApplicabilityTx(ctx, tx, asset, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	w := vulnv2.ApplicabilityWorker{DSN: dsn, Owner: "initial"}
	if err = w.Once(ctx); err != nil {
		t.Fatal(err)
	}
	// Both additions sort behind a running traversal's cursor. Their own durable
	// requests cover the opposite committed side, closing the bidirectional race.
	_, err = c.Exec(ctx, `INSERT INTO noctis_v2.asset_versions VALUES('00000000-0000-0000-0000-000000000001',1,'cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*','1','[]','fixture',clock_timestamp()),('ffffffff-ffff-ffff-ffff-ffffffffffff',2,'cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*','2','[]','fixture',clock_timestamp()); INSERT INTO noctis_v2.vulnerability_facts(snapshot_id,cve,body) VALUES('`+snapshot+`','CVE-2026-0001','{}')`)
	if err != nil {
		t.Fatal(err)
	}
	tx, err = c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vulnv2.EnqueueAssetApplicabilityTx(ctx, tx, "00000000-0000-0000-0000-000000000001", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vulnv2.EnqueueAssetApplicabilityTx(ctx, tx, asset, 2)
	if err != nil {
		t.Fatal(err)
	}
	_, err = vulnv2.EnqueueCVEApplicabilityTx(ctx, tx, "CVE-2026-0001", snapshot, time.Now().Add(7*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var scheduledJobs int
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.applicability_requests r JOIN noctis_v2.jobs j ON j.input_id=r.id WHERE r.idempotency_key LIKE 'expiry:%'`).Scan(&scheduledJobs); err != nil || scheduledJobs != 0 {
		t.Fatal("future expiry consumed retry horizon", scheduledJobs, err)
	}
	// Simulate restart after a week: only the due request ages, never its future job.
	if _, err = c.Exec(ctx, `UPDATE noctis_v2.applicability_requests SET due_at=clock_timestamp()-interval '1 second',created_at=clock_timestamp()-interval '7 days' WHERE idempotency_key LIKE 'expiry:%'`); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, owner := range []string{"parallel-a", "parallel-b"} {
		wg.Add(1)
		go func(owner string) {
			defer wg.Done()
			worker := vulnv2.ApplicabilityWorker{DSN: dsn, Owner: owner}
			for n := 0; n < 100; n++ {
				err := worker.Once(ctx)
				if errors.Is(err, pgx.ErrNoRows) {
					errs <- nil
					return
				}
				if err != nil {
					errs <- err
					return
				}
			}
			errs <- errors.New("queue failed to drain")
		}(owner)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	drainApplicability(t, dsn)
	var count int
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.applicability_current`).Scan(&count); err != nil || count != 124 {
		t.Fatal("behind-cursor coverage", count, err)
	}
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.applicability_current WHERE asset_id=$1 AND asset_revision=2`, asset).Scan(&count); err != nil || count != 62 {
		t.Fatal("obsolete asset revision restored", count, err)
	}
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.applicability_requests WHERE idempotency_key LIKE 'expiry:%' AND state='complete'`).Scan(&count); err != nil || count != 1 {
		t.Fatal("expiry request lost", count, err)
	}
	var progress []byte
	if err = c.QueryRow(ctx, `SELECT jsonb_agg(to_jsonb(w)) FROM noctis_v2.applicability_work_status w`).Scan(&progress); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err = json.Unmarshal(progress, &rows); err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row["calculation_state"] != "complete" {
			t.Fatal("incomplete progress", row)
		}
	}
}

func TestApplicabilityQueueBoundedCasesAndEvidenceChildrenPostgres(t *testing.T) {
	ctx, dsn, c, snapshot := queueFixture(t)
	source, observation, asset := uuid.NewString(), uuid.NewString(), uuid.NewString()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version) VALUES($1,'rss','queue-fixture',true,'p1')`, source)
	exec(`INSERT INTO noctis_v2.content_blobs(hash,representation,payload) VALUES('fixture','text',convert_to('CVE-2026-12345','UTF8'))`)
	exec(`INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) VALUES($1,$2,'queue','1','fixture','text',gen_random_uuid(),'live',clock_timestamp())`, observation, source)
	ref := evidence.Ref{ObservationID: observation, Revision: "1", Hash: "fixture", Representation: "text", Start: 0, End: 14}
	raw, _ := json.Marshal(ref)
	refs, _ := json.Marshal([]evidence.Ref{ref})
	exec(`INSERT INTO noctis_v2.observable_sightings VALUES('cve','CVE-2026-12345',$1,'1',0,14,$2)`, observation, string(raw))
	exec(`INSERT INTO noctis_v2.asset_versions VALUES($1,1,'cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*','1.0',$2,'fixture',clock_timestamp())`, asset, string(refs))
	exec(`INSERT INTO noctis_v2.vulnerability_facts VALUES($1,'CVE-2026-12345','{"configurations":[{"nodes":[{"cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*","versionEndExcluding":"2.0"}]}]}]}','unknown')`, snapshot)
	exec(`INSERT INTO noctis_v2.vulnerability_facts(snapshot_id,cve,body) SELECT $1,'CVE-2026-'||n::text,'{}' FROM generate_series(10000,10024)n`, snapshot)
	exec(`INSERT INTO noctis_v2.intelligence_cases(id,group_key,title,revision) SELECT md5('case:'||n)::uuid,'case:'||n,'Fixture',1 FROM generate_series(1,76)n`)
	exec(`INSERT INTO noctis_v2.case_revisions(case_id,revision,body) SELECT id,1,jsonb_build_object('id',id,'revision','1') FROM noctis_v2.intelligence_cases`)
	exec(`INSERT INTO noctis_v2.case_memberships(case_id,observation_id) SELECT id,$1 FROM noctis_v2.intelligence_cases`, observation)
	exec(`CREATE TABLE noctis_v2.publication_audit(tx bigint,case_id uuid,generation text); CREATE FUNCTION noctis_v2.audit_publication() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN INSERT INTO noctis_v2.publication_audit VALUES(txid_current(),NEW.case_id,NEW.body->>'applicability_generation'); RETURN NULL; END $$; CREATE TRIGGER audit_publication AFTER INSERT ON noctis_v2.case_changes FOR EACH ROW WHEN (NEW.body->>'kind'='local_applicability') EXECUTE FUNCTION noctis_v2.audit_publication()`)
	tx, err := c.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	request, err := vulnv2.EnqueueAssetApplicabilityTx(ctx, tx, asset, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	processRequest := func(requestID string) {
		t.Helper()
		var j jobs.Job
		err := c.QueryRow(ctx, `UPDATE noctis_v2.jobs j SET state='leased',lease_owner='ordered-fixture',lease_expires_at=clock_timestamp()+interval '1 minute',fence=fence+1,attempts=attempts+1 FROM noctis_v2.applicability_requests r WHERE j.input_id=r.id AND r.id=$1 AND j.input_revision=r.page::text AND j.stage='applicability' AND j.state='queued' RETURNING j.id::text,j.stage,j.input_id::text,j.input_revision,j.policy_version,j.schema_version,j.lease_owner,j.lease_expires_at,j.fence,j.attempts`, requestID).Scan(&j.ID, &j.Stage, &j.InputID, &j.InputRevision, &j.PolicyVersion, &j.SchemaVersion, &j.Owner, &j.ExpiresAt, &j.Fence, &j.Attempts)
		if err != nil {
			t.Fatal(err)
		}
		if err = (vulnv2.ApplicabilityWorker{DSN: dsn, Owner: "ordered-fixture"}).Process(ctx, j); err != nil {
			t.Fatal(err)
		}
	}
	processRequest(request)
	// The new case appears above the original maximum after the first pair
	// page. Its own early publication is pending; the parent's case traversal
	// must capture its bound after pairs finish and publish the final result.
	lateCase := "ffffffff-ffff-ffff-ffff-ffffffffffff"
	exec(`INSERT INTO noctis_v2.intelligence_cases(id,group_key,title,revision) VALUES($1,'late-case','Late fixture',1)`, lateCase)
	exec(`INSERT INTO noctis_v2.case_revisions VALUES($1,1,'{}',clock_timestamp())`, lateCase)
	exec(`INSERT INTO noctis_v2.case_memberships(case_id,observation_id) VALUES($1,$2)`, lateCase, observation)
	var lateRequest string
	if err = c.QueryRow(ctx, `SELECT id::text FROM noctis_v2.applicability_requests WHERE scope='case' AND input_id=$1`, lateCase).Scan(&lateRequest); err != nil {
		t.Fatal(err)
	}
	processRequest(lateRequest)
	drainApplicability(t, dsn)
	var count int
	var state string
	if err = c.QueryRow(ctx, `SELECT cases_processed,calculation_state FROM noctis_v2.applicability_work_status WHERE id=$1`, request).Scan(&count, &state); err != nil || count != 77 || state != "complete" {
		t.Fatal("publication continuation", count, state, err)
	}
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_applicability_projection WHERE body->>'local_applicability'='affected_version'`).Scan(&count); err != nil || count != 77 {
		t.Fatal("case coverage", count, err)
	}
	if err = c.QueryRow(ctx, `SELECT COALESCE(max(n),0) FROM (SELECT count(*) n FROM noctis_v2.publication_audit GROUP BY tx)a`).Scan(&count); err != nil || count > vulnv2.ApplicabilityPageSize {
		t.Fatal("unbounded dossier publication", count, err)
	}
	if err = c.QueryRow(ctx, `SELECT count(*) FROM (SELECT case_id,generation FROM noctis_v2.publication_audit GROUP BY case_id,generation HAVING count(*)>1)a`).Scan(&count); err != nil || count != 0 {
		t.Fatal("duplicate publication", count, err)
	}
	// Evidence invalidation creates bounded child asset requests, and the parent
	// work view cannot report complete until every child's publication has finished.
	exec(`UPDATE noctis_v2.observations SET source_deleted=true WHERE id=$1`, observation)
	var evidenceRequest string
	if err = c.QueryRow(ctx, `SELECT id::text FROM noctis_v2.applicability_requests WHERE scope='evidence' AND input_id=$1 ORDER BY created_at DESC LIMIT 1`, observation).Scan(&evidenceRequest); err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 10; n++ {
		if err = c.QueryRow(ctx, `SELECT state FROM noctis_v2.applicability_requests WHERE id=$1`, evidenceRequest).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state == "complete" {
			break
		}
		processRequest(evidenceRequest)
	}
	if err = c.QueryRow(ctx, `SELECT calculation_state FROM noctis_v2.applicability_work_status WHERE id=$1`, evidenceRequest).Scan(&state); err != nil || state != "pending" {
		t.Fatal("parent completed before child publication", state, err)
	}
	drainApplicability(t, dsn)
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_applicability_projection WHERE body->>'local_applicability'='unknown'`).Scan(&count); err != nil || count != 77 {
		t.Fatal("evidence retract coverage", count, err)
	}
	if err = c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.applicability_work_status WHERE calculation_state<>'complete'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("unfinished evidence children", count, err)
	}
}
