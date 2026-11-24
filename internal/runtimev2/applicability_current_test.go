package runtimev2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/inference"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/vulnv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type applicabilityFixture struct {
	t                              *testing.T
	ctx                            context.Context
	c                              *pgx.Conn
	dsn, caseID, observation, refs string
	now                            time.Time
}

func newApplicabilityFixture(t *testing.T) *applicabilityFixture {
	f := &applicabilityFixture{t: t, ctx: context.Background(), dsn: productDB(t), caseID: uuid.NewString(), observation: uuid.NewString(), now: time.Now().UTC()}
	var err error
	f.c, err = pgx.Connect(f.ctx, f.dsn)
	f.must(err)
	t.Cleanup(func() { f.c.Close(f.ctx) })
	source := uuid.NewString()
	f.exec(`INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version,epoch) VALUES($1,'rss','applicability',true,'p1',gen_random_uuid())`, source)
	f.exec(`INSERT INTO noctis_v2.content_blobs(hash,representation,payload) VALUES('fixture','text/plain;utf8;v1','CVE-2026-12345')`)
	f.exec(`INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) SELECT $1,id,'post','1','fixture','text/plain;utf8;v1',epoch,'live',clock_timestamp() FROM noctis_v2.sources WHERE id=$2`, f.observation, source)
	f.refs = fmt.Sprintf(`[{"observation_id":%q,"revision":"1","hash":"fixture","representation":"text/plain;utf8;v1","start":0,"end":14}]`, f.observation)
	f.exec(`INSERT INTO noctis_v2.intelligence_cases(id,group_key,title,revision) VALUES($1,'applicability','Synthetic CVE',1)`, f.caseID)
	f.exec(`INSERT INTO noctis_v2.case_revisions(case_id,revision,body) VALUES($1::uuid,1,jsonb_build_object('id',$1::uuid::text,'revision','1'))`, f.caseID)
	f.exec(`INSERT INTO noctis_v2.case_memberships(case_id,observation_id) VALUES($1,$2)`, f.caseID, f.observation)
	f.exec(`INSERT INTO noctis_v2.observable_sightings(observable_type,value,observation_id,revision,start_byte,end_byte,evidence) VALUES('cve','CVE-2026-12345',$1,'1',0,14,$2::jsonb->0)`, f.observation, f.refs)
	return f
}
func (f *applicabilityFixture) must(err error) {
	f.t.Helper()
	if err != nil {
		f.t.Fatal(err)
	}
}
func (f *applicabilityFixture) exec(sql string, args ...any) {
	f.t.Helper()
	_, err := f.c.Exec(f.ctx, sql, args...)
	f.must(err)
}
func (f *applicabilityFixture) asset(id string, revision int, version string) {
	f.t.Helper()
	f.exec(`INSERT INTO noctis_v2.asset_versions(id,revision,cpe,version,evidence,producer) VALUES($1,$2,'cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*',$3,$4,'fixture')`, id, revision, version, f.refs)
}
func (f *applicabilityFixture) feed(revision string, asOf, expires time.Time, end string) string {
	f.t.Helper()
	id := uuid.NewString()
	body := map[string]any{"configurations": []any{map[string]any{"cpeMatch": []any{map[string]any{"vulnerable": true, "criteria": "cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*", "versionEndExcluding": end}}}}}
	if revision != "" {
		body["lastModified"] = revision
	}
	raw, _ := json.Marshal(body)
	f.exec(`INSERT INTO noctis_v2.feed_snapshots(id,kind,url,hash,as_of,expires_at,payload) VALUES($1::uuid,'nvd','https://fixture.invalid',$1::uuid::text,$2,$3,'{}')`, id, asOf, expires)
	f.exec(`INSERT INTO noctis_v2.vulnerability_facts(snapshot_id,cve,body) VALUES($1,'CVE-2026-12345',$2)`, id, string(raw))
	return id
}
func (f *applicabilityFixture) refresh() {
	f.t.Helper()
	tx, err := f.c.Begin(f.ctx)
	f.must(err)
	defer tx.Rollback(f.ctx)
	f.must(vulnv2.RefreshApplicabilityTx(f.ctx, tx, "CVE-2026-12345"))
	f.must(tx.Commit(f.ctx))
}
func (f *applicabilityFixture) status(want string) {
	f.t.Helper()
	var got string
	f.must(f.c.QueryRow(f.ctx, `SELECT noctis_v2.case_applicability($1)->>'local_applicability'`, f.caseID).Scan(&got))
	if got != want {
		f.t.Fatalf("current case status %q, want %q", got, want)
	}
}
func (f *applicabilityFixture) generation() string {
	f.t.Helper()
	var got string
	f.must(f.c.QueryRow(f.ctx, `SELECT generation FROM noctis_v2.nvd_current_selection WHERE cve='CVE-2026-12345'`).Scan(&got))
	return got
}
func (f *applicabilityFixture) api() func(string) string {
	f.t.Helper()
	admin := filepath.Join(f.t.TempDir(), "admin.json")
	f.must(os.WriteFile(admin, []byte(`{"Username":"operator","Password":"synthetic-secret-password"}`), 0600))
	h, err := NewHandler(configv2.Config{DatabaseURL: f.dsn, AdminFile: admin, Origin: "https://fixture.invalid"})
	f.must(err)
	token := random()
	f.exec(`INSERT INTO noctis_v2.sessions VALUES($1,'operator','csrf',clock_timestamp()+interval '1 hour',false)`, tokenHash(token))
	return func(path string) string {
		f.t.Helper()
		r := httptest.NewRequest("GET", "https://fixture.invalid/api/v2/"+path, nil)
		r.AddCookie(&http.Cookie{Name: "noctis_v2_session", Value: token})
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			f.t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
}

func TestApplicabilityCurrentSelectionPostgres(t *testing.T) {
	f := newApplicabilityFixture(t)
	asset := uuid.NewString()
	f.asset(asset, 1, "1.5")
	old := f.feed("2026-01-01T00:00:00Z", f.now, f.now.Add(time.Hour), "2.0")
	f.refresh()
	f.status("affected_version")
	current := f.feed("2026-01-02T00:00:00.000", f.now.Add(time.Minute), f.now.Add(time.Hour), "1.0")
	f.status("unknown")
	f.refresh()
	f.status("not_affected_version")
	want := f.generation()
	f.feed("2026-01-01T00:00:00Z", f.now.Add(2*time.Minute), f.now.Add(2*time.Hour), "2.0")
	f.refresh()
	f.status("not_affected_version")
	if f.generation() != want {
		t.Fatal("older revision replay replaced current")
	}
	// An incremental page without this CVE cannot retire it.
	f.exec(`INSERT INTO noctis_v2.feed_snapshots(id,kind,url,hash,as_of,expires_at,payload) VALUES(gen_random_uuid(),'nvd','https://fixture.invalid','empty',clock_timestamp(),clock_timestamp()+interval '1 day','{}')`)
	if f.generation() != want {
		t.Fatal("missing CVE in page retired current")
	}
	f.exec(`UPDATE noctis_v2.feed_snapshots SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, current)
	f.status("unknown")
	f.refresh()
	f.status("unknown")
	var selected string
	f.must(f.c.QueryRow(f.ctx, `SELECT snapshot_id::text FROM noctis_v2.nvd_current_selection WHERE cve='CVE-2026-12345'`).Scan(&selected))
	if selected != current || selected == old {
		t.Fatal("TTL resurrected old snapshot", selected)
	}
	// Equal revisions with contradictory bodies remain unknown in either order.
	f.feed("2026-01-02T00:00:00Z", f.now.Add(3*time.Minute), f.now.Add(time.Hour), "3.0")
	f.refresh()
	f.status("unknown")
	var reason string
	f.must(f.c.QueryRow(f.ctx, `SELECT selection_reason FROM noctis_v2.nvd_current_selection`).Scan(&reason))
	if reason != "conflicting_nvd_revision" {
		t.Fatal(reason)
	}
}

func TestApplicabilityUnversionedAndEquivalentSelectionPostgres(t *testing.T) {
	f := newApplicabilityFixture(t)
	f.asset(uuid.NewString(), 1, "1.5")
	f.feed("", f.now.Add(-time.Hour), f.now.Add(time.Hour), "2.0")
	f.refresh()
	f.status("affected_version")
	f.feed("2026-01-02T00:00:00.000", f.now, f.now.Add(time.Hour), "1.0")
	f.refresh()
	f.status("not_affected_version")
	f.feed("2026-01-02T00:00:00Z", f.now, f.now.Add(time.Hour), "1.0")
	want := f.generation()
	f.refresh()
	f.status("not_affected_version")
	if f.generation() != want {
		t.Fatal("equivalent tie unstable")
	}
	f.feed("not-a-date", f.now.Add(time.Minute), f.now.Add(time.Hour), "2.0")
	f.refresh()
	f.status("unknown")
	var reason string
	f.must(f.c.QueryRow(f.ctx, `SELECT selection_reason FROM noctis_v2.nvd_current_selection`).Scan(&reason))
	if reason != "unversioned_nvd_record" {
		t.Fatal(reason)
	}
}

func TestApplicabilityRetractionsTTLBriefAndContextPostgres(t *testing.T) {
	f := newApplicabilityFixture(t)
	a, b := uuid.NewString(), uuid.NewString()
	f.asset(a, 1, "1.5")
	f.asset(b, 1, "1.5")
	snapshot := f.feed("2026-01-02T00:00:00Z", f.now, f.now.Add(time.Hour), "2.0")
	f.refresh()
	f.status("affected_version")
	api := f.api()
	worker := intelligence.Worker{DSN: f.dsn}
	period := f.now.Format("2006-01-02")
	f.must(worker.Brief(f.ctx, period, "p1"))
	f.asset(a, 2, "3.0")
	f.status("affected_version")
	f.refresh()
	f.status("affected_version")
	f.asset(b, 2, "3.0")
	f.status("unknown")
	f.refresh()
	f.status("not_affected_version")
	if body := api("cases/" + f.caseID); !strings.Contains(body, `"local_applicability":"not_affected_version"`) {
		t.Fatal(body)
	}
	if body := api("today"); !strings.Contains(body, `"invalidated":true`) {
		t.Fatal("brief remained current", body)
	}
	f.must(worker.Brief(f.ctx, period, "p1"))
	var brief string
	f.must(f.c.QueryRow(f.ctx, `SELECT body->>'text' FROM noctis_v2.briefs`).Scan(&brief))
	if strings.Contains(brief, "Current inventory applicability: affected_version") || !strings.Contains(brief, "not_affected_version") {
		t.Fatal("historical affected assertion regenerated", brief)
	}
	var before, after int
	f.must(f.c.QueryRow(f.ctx, `SELECT count(*) FROM noctis_v2.case_changes WHERE body->>'kind'='local_applicability'`).Scan(&before))
	f.refresh()
	f.must(f.c.QueryRow(f.ctx, `SELECT count(*) FROM noctis_v2.case_changes WHERE body->>'kind'='local_applicability'`).Scan(&after))
	if before != after {
		t.Fatal("duplicate transition", before, after)
	}
	var revision string
	f.must(f.c.QueryRow(f.ctx, `SELECT revision::text FROM noctis_v2.intelligence_cases WHERE id=$1`, f.caseID).Scan(&revision))
	store := inference.Store{DSN: f.dsn}
	prior, err := store.Submit(f.ctx, inference.Submit{Function: "case.summarize", RequestID: "current-context", Input: inference.Input{Kind: "case", ID: f.caseID, Revision: revision}}, "fixture")
	f.must(err)
	// Synthetic previously validated output: reads must revalidate its snapshot,
	// even before the expiry worker has published a new case revision.
	f.exec(`UPDATE noctis_v2.ai_jobs SET state='succeeded',result='{"summary":"Synthetic prior summary"}',error_code=NULL WHERE id=$1`, prior.ID)
	// Expiry is effective even while the worker is stopped; old history remains.
	f.exec(`UPDATE noctis_v2.feed_snapshots SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1`, snapshot)
	f.status("unknown")
	if body := api("applicability"); !strings.Contains(body, `"effective_status":"unknown"`) || !strings.Contains(body, "feed_snapshot_stale") {
		t.Fatal(body)
	}
	if body := api("today"); !strings.Contains(body, `"invalidated":true`) {
		t.Fatal(body)
	}
	historical, err := store.Job(f.ctx, prior.ID, "fixture")
	f.must(err)
	if historical.State != "dependency_blocked" || historical.Result != nil {
		t.Fatal("derived result survived support expiry", historical)
	}
	f.must(f.c.QueryRow(f.ctx, `SELECT revision::text FROM noctis_v2.intelligence_cases WHERE id=$1`, f.caseID).Scan(&revision))
	job, err := (inference.Store{DSN: f.dsn}).Submit(f.ctx, inference.Submit{Function: "case.summarize", RequestID: "stale-context", Input: inference.Input{Kind: "case", ID: f.caseID, Revision: revision}}, "fixture")
	f.must(err)
	var contextStatus string
	f.must(f.c.QueryRow(f.ctx, `SELECT snapshot->'context'->>'local_applicability' FROM noctis_v2.ai_jobs WHERE id=$1`, job.ID).Scan(&contextStatus))
	if contextStatus != "unknown" {
		t.Fatal("stale derived context", contextStatus)
	}
	_, err = (inference.Store{DSN: f.dsn}).Submit(f.ctx, inference.Submit{Function: "brief.compose", RequestID: "stale-brief", Input: inference.Input{Kind: "brief", Period: period}}, "fixture")
	if err == nil {
		t.Fatal("stale brief accepted as context")
	}
	f.must(worker.Brief(f.ctx, period, "p1"))
	f.must(f.c.QueryRow(f.ctx, `SELECT body->>'text' FROM noctis_v2.briefs`).Scan(&brief))
	if !strings.Contains(brief, "Current inventory applicability: unknown") || strings.Contains(brief, "Current inventory applicability: affected_version") {
		t.Fatal("expired brief restored historical applicability", brief)
	}
	f.refresh()
	f.refresh()
	f.must(f.c.QueryRow(f.ctx, `SELECT count(*) FROM noctis_v2.case_changes WHERE body->>'kind'='local_applicability'`).Scan(&after))
	if after != before+1 {
		t.Fatal("TTL duplicate/missing transition", before, after)
	}
	var history int
	f.must(f.c.QueryRow(f.ctx, `SELECT count(*) FROM noctis_v2.local_applicability WHERE status='affected_version'`).Scan(&history))
	if history != 2 {
		t.Fatal("history overwritten", history)
	}
}

func TestApplicabilitySurvivesObservationRevisionPostgres(t *testing.T) {
	f := newApplicabilityFixture(t)
	f.feed("2026-01-02T00:00:00Z", f.now, f.now.Add(time.Hour), "2.0")
	f.refresh()
	f.status("unknown") // Empty inventory cannot prove exclusion.
	f.asset(uuid.NewString(), 1, "1.5")
	f.refresh()
	f.status("affected_version")
	f.exec(`INSERT INTO noctis_v2.policies(version,terms) VALUES('p1','[{"type":"cve","value":"CVE-2026-12345"}]')`)
	f.exec(`INSERT INTO noctis_v2.content_blobs(hash,representation,payload) VALUES('updated-fixture','text/plain;utf8;v1','CVE-2026-12345 updated advisory')`)
	observation := uuid.NewString()
	f.exec(`INSERT INTO noctis_v2.observations(id,source_id,native_id,revision,hash,representation,epoch,mode,collected_at) SELECT $1,source_id,native_id,'2','updated-fixture',representation,epoch,'live',clock_timestamp() FROM noctis_v2.observations WHERE id=$2`, observation, f.observation)
	f.exec(`INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES(gen_random_uuid(),'parse',$1,'2','p1','1')`, observation)
	f.must((intelligence.Worker{DSN: f.dsn, Owner: "applicability-revision"}).Once(f.ctx))
	var status string
	f.must(f.c.QueryRow(f.ctx, `SELECT cr.body->>'local_applicability' FROM noctis_v2.intelligence_cases ic JOIN noctis_v2.case_revisions cr ON cr.case_id=ic.id AND cr.revision=ic.revision WHERE ic.id=$1`, f.caseID).Scan(&status))
	if status != "affected_version" {
		t.Fatal("new observation erased applicability", status)
	}
}

func TestApplicabilityEvidenceMembershipAndConcurrentPublicationPostgres(t *testing.T) {
	f := newApplicabilityFixture(t)
	a := uuid.NewString()
	f.asset(a, 1, "1.5")
	f.feed("2026-01-02T00:00:00Z", f.now, f.now.Add(time.Hour), "2.0")
	f.refresh()
	f.status("affected_version")
	oldGeneration := f.generation()
	f.feed("2026-01-03T00:00:00Z", f.now.Add(time.Minute), f.now.Add(time.Hour), "1.0")
	tx, err := f.c.Begin(f.ctx)
	f.must(err)
	applied, err := vulnv2.EvaluateCurrentPairTx(f.ctx, tx, "CVE-2026-12345", a, oldGeneration, 1)
	f.must(err)
	f.must(tx.Commit(f.ctx))
	if applied {
		t.Fatal("old generation published")
	}
	f.refresh()
	f.status("not_affected_version")
	f.exec(`UPDATE noctis_v2.observations SET source_deleted=true WHERE id=$1`, f.observation)
	f.status("unknown")
	f.refresh()
	f.exec(`UPDATE noctis_v2.observations SET source_deleted=false WHERE id=$1`, f.observation)
	f.refresh()
	f.status("not_affected_version")
	// An uncalculated new asset prevents an exclusion assertion.
	f.asset(uuid.NewString(), 1, "3.0")
	f.status("unknown")
	f.refresh()
	f.status("not_affected_version")
	var before, after int
	f.must(f.c.QueryRow(f.ctx, `SELECT count(*) FROM noctis_v2.case_changes`).Scan(&before))
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := pgx.Connect(f.ctx, f.dsn)
			if e != nil {
				errs <- e
				return
			}
			defer c.Close(f.ctx)
			tx, e := c.Begin(f.ctx)
			if e != nil {
				errs <- e
				return
			}
			defer tx.Rollback(f.ctx)
			if e = vulnv2.PublishApplicabilityCaseTx(f.ctx, tx, f.caseID); e == nil {
				e = tx.Commit(f.ctx)
			}
			errs <- e
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		f.must(err)
	}
	f.must(f.c.QueryRow(f.ctx, `SELECT count(*) FROM noctis_v2.case_changes`).Scan(&after))
	if after != before {
		t.Fatal("two workers duplicated publication")
	}
	f.exec(`DELETE FROM noctis_v2.case_memberships WHERE case_id=$1`, f.caseID)
	f.status("unknown")
	tx, err = f.c.Begin(f.ctx)
	f.must(err)
	f.must(vulnv2.PublishApplicabilityCaseTx(f.ctx, tx, f.caseID))
	f.must(tx.Commit(f.ctx))
	var stored string
	f.must(f.c.QueryRow(f.ctx, `SELECT cr.body->>'local_applicability' FROM noctis_v2.intelligence_cases ic JOIN noctis_v2.case_revisions cr ON cr.case_id=ic.id AND cr.revision=ic.revision WHERE ic.id=$1`, f.caseID).Scan(&stored))
	if stored != "unknown" {
		t.Fatal("membership removal not retracted", stored)
	}
}
