package runtimev2

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/configv2"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/Zyrakk/noctis/internal/vulnv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Semantic labels below are explicit synthetic adjudications supplied to the
// publication boundary. This exercises product semantics, not model quality.
func TestAcceptanceStoriesABCSyntheticPostgresAndPrivateAPI(t *testing.T) {
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
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES('p1','[{"type":"keyword","value":"ACME"},{"type":"cve","value":"CVE-2026-12345"}]')`)
	must(e)
	w := intelligence.Worker{DSN: dsn, Owner: "stories"}
	captureText := func(text string) (string, string, evidence.Ref) {
		t.Helper()
		source, epoch := uuid.NewString(), uuid.NewString()
		_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,enabled,policy_version,epoch,activated_at) VALUES($1,'rss',$3,true,'p1',$2,clock_timestamp()-interval '1 hour')`, source, epoch, source)
		must(e)
		now := time.Now().UTC()
		hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(text)))
		_, e = (capture.Store{DSN: dsn}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: source, Epoch: epoch, Mode: capture.Live, Items: []capture.Item{{NativeID: "post", Revision: "1", Hash: hash, Payload: []byte(text), Representation: "text/plain;utf8;v1", CollectedAt: now, PublishedAt: &now}}, Expected: capture.Checkpoint{Value: json.RawMessage(`null`)}, Next: capture.Checkpoint{Version: 1, Value: json.RawMessage(`1`)}})
		must(e)
		must(w.Once(ctx))
		var obs, caseID string
		must(c.QueryRow(ctx, `SELECT o.id::text,m.case_id::text FROM noctis_v2.observations o JOIN noctis_v2.case_memberships m ON m.observation_id=o.id WHERE o.source_id=$1`, source).Scan(&obs, &caseID))
		return obs, caseID, evidence.Ref{ObservationID: obs, Revision: "1", Hash: hash, Representation: "text/plain;utf8;v1", End: len(text)}
	}
	publish := func(obs string, ref evidence.Ref, claims []intelligence.AnalysisClaim, proposals []intelligence.EntityProposal) {
		t.Helper()
		_, e = c.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES($1,'semantic',$2,'1','p1','1')`, uuid.NewString(), obs)
		must(e)
		store := jobs.Store{DSN: dsn}
		job, e := store.Claim(ctx, "synthetic-semantic-fixture", time.Minute, "semantic")
		must(e)
		must(store.Finish(ctx, job, func(tx pgx.Tx) error {
			return intelligence.ApplyAnalysisTx(ctx, tx, intelligence.ValidatedAnalysis{JobKey: job.Key, Producer: "fixture:adjudicated-v1", Refs: []evidence.Ref{ref}, Claims: claims, Proposals: proposals, Limitations: []string{"Synthetic adjudicated fixture; no model quality result"}})
		}))
	}
	// B: one original and four copies create one material publication.
	sellerText := "ACME: una fuente afirma vender acceso; no hay confirmación de brecha. Shared hosting 8.8.8.8. Handle ghost."
	sellerObs, sellerCase, sellerRef := captureText(sellerText)
	for i := 0; i < 4; i++ {
		captureText(sellerText)
	}
	var n int
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_memberships WHERE case_id=$1`, sellerCase).Scan(&n))
	if n != 5 {
		t.Fatal("five appearances not preserved", n)
	}
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.case_changes WHERE case_id=$1`, sellerCase).Scan(&n))
	if n != 1 {
		t.Fatal("copies counted as news", n)
	}
	sellerClaim := uuid.NewString()
	publish(sellerObs, sellerRef, []intelligence.AnalysisClaim{{ID: sellerClaim, CaseID: sellerCase, Subject: "synthetic-source", Predicate: "claims_to_offer_access", Object: "ACME", Refs: []evidence.Ref{sellerRef}}}, []intelligence.EntityProposal{{Kind: "handle", Alias: "ghost", Scope: "synthetic:channel-A", Language: "und", Refs: []evidence.Ref{sellerRef}}, {Kind: "handle", Alias: "ghost", Scope: "synthetic:channel-B", Language: "und", Refs: []evidence.Ref{sellerRef}}})
	must(w.Brief(ctx, time.Now().UTC().Format("2006-01-02"), "p1"))
	denialObs, _, denialRef := captureText("ACME niega la oferta de acceso publicada por la fuente; esta negativa es otra afirmación atribuida.")
	publish(denialObs, denialRef, []intelligence.AnalysisClaim{{ID: uuid.NewString(), CaseID: sellerCase, Subject: "ACME", Predicate: "denies_access_offer", Object: "synthetic-source", Refs: []evidence.Ref{denialRef}, Dependencies: []intelligence.ClaimDependency{{ClaimVersion: intelligence.ClaimVersion{ID: sellerClaim, Revision: 1}, Relation: "contradicts"}}}}, nil)
	var invalid bool
	must(c.QueryRow(ctx, `SELECT invalidated FROM noctis_v2.briefs WHERE policy_version='p1'`).Scan(&invalid))
	if !invalid {
		t.Fatal("contradiction left brief current")
	}
	must(w.Brief(ctx, time.Now().UTC().Format("2006-01-02"), "p1"))
	must(c.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.claim_versions WHERE case_id=$1 AND status='source_claim'`, sellerCase).Scan(&n))
	if n != 2 {
		t.Fatal("contradictory source statements not retained", n)
	}
	// C: same handle in two scopes remains two entities; hosting is not identity.
	var entities []string
	rows, e := c.Query(ctx, `SELECT entity_id::text FROM noctis_v2.entity_aliases WHERE alias='ghost' ORDER BY scope`)
	must(e)
	for rows.Next() {
		var id string
		must(rows.Scan(&id))
		entities = append(entities, id)
	}
	rows.Close()
	must(rows.Err())
	if len(entities) != 2 || entities[0] == entities[1] {
		t.Fatal("name merged identities")
	}
	tx, e := c.Begin(ctx)
	must(e)
	hypothesis, e := intelligence.ProposeIdentityTx(ctx, tx, entities[0], entities[1], "possible_same_handle; shared_hosting_low_specificity", []evidence.Ref{sellerRef})
	must(e)
	must(tx.Commit(ctx))
	// A: feed ranges plus known inventory version affect applicability, not exposure.
	vulnObs, vulnCase, vulnRef := captureText("ACME inventario sintético producto synthetic:product, versión desconocida. Aviso CVE-2026-12345.")
	_ = vulnObs
	feedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"startIndex":0,"totalResults":1,"resultsPerPage":1,"timestamp":%q,"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0","versionEndExcluding":"2.0"}]}]}]}}]}`, time.Now().UTC().Format(time.RFC3339))
	}))
	defer feedServer.Close()
	_, e = (vulnv2.Store{DSN: dsn, Fetcher: capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(feedServer.URL, "http://"): true}}}).PollPage(ctx, "nvd", feedServer.URL, 24*time.Hour)
	must(e)
	dir := t.TempDir()
	admin := filepath.Join(dir, "admin.json")
	must(os.WriteFile(admin, []byte(`{"Username":"operator","Password":"synthetic-administrator"}`), 0600))
	handler, e := NewHandler(configv2.Config{DatabaseURL: dsn, AdminFile: admin, Origin: "https://fixture.invalid"})
	must(e)
	token, csrf := random(), random()
	_, e = c.Exec(ctx, `INSERT INTO noctis_v2.sessions VALUES($1,'operator',$2,clock_timestamp()+interval '1 hour',false)`, tokenHash(token), csrf)
	must(e)
	request := func(method, path string, input any) string {
		t.Helper()
		var body io.Reader
		if input != nil {
			raw, e := json.Marshal(input)
			must(e)
			body = bytes.NewReader(raw)
		}
		req := httptest.NewRequest(method, "https://fixture.invalid/api/v2/"+path, body)
		req.AddCookie(&http.Cookie{Name: "noctis_v2_session", Value: token})
		req.Header.Set("Origin", "https://fixture.invalid")
		req.Header.Set("X-CSRF-Token", csrf)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body.String())
		}
		return rec.Body.String()
	}
	asset := uuid.NewString()
	assetInput := map[string]any{"id": asset, "expected_revision": 0, "cpe": "cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*", "version": nil, "refs": []evidence.Ref{vulnRef}}
	request("POST", "assets", assetInput)
	var status string
	must(c.QueryRow(ctx, `SELECT status FROM noctis_v2.local_applicability WHERE asset_id=$1 AND asset_revision=1`, asset).Scan(&status))
	if status != "unknown" {
		t.Fatal("unknown version inferred affected", status)
	}
	assetInput["expected_revision"] = 1
	assetInput["version"] = "1.5"
	request("POST", "assets", assetInput)
	must(c.QueryRow(ctx, `SELECT status FROM noctis_v2.local_applicability WHERE asset_id=$1 AND asset_revision=2`, asset).Scan(&status))
	if status != "affected_version" {
		t.Fatal("range not matched", status)
	}
	detail := request("GET", "cases/"+vulnCase, nil)
	if !strings.Contains(detail, "inventory_version_matches_published_range") || !strings.Contains(detail, `"local_exposure":"unknown"`) {
		t.Fatal("priority reason or uncertainty absent", detail)
	}
	if graph := request("GET", "graph?root="+entities[0]+"&hops=2", nil); !strings.Contains(graph, hypothesis) || !strings.Contains(graph, "hypotheses_only") {
		t.Fatal("hypothesis path missing", graph)
	}
	request("POST", "entities/hypotheses/retract", map[string]string{"id": hypothesis})
	dossier := request("GET", "entities/"+entities[0]+"/dossier", nil)
	if !strings.Contains(dossier, "retracted") || !strings.Contains(dossier, "ghost") {
		t.Fatal("reversible dossier history lost")
	}
	request("GET", "claims?case_id="+sellerCase, nil)
	request("GET", "cases/"+sellerCase+"/timeline", nil)
	// Explicit indicator judgment expires and revokes without replay rejuvenation.
	indicator := intelligence.Indicator{ID: uuid.NewString(), Type: "ip", Value: "8.8.8.8", Scope: "synthetic-fixture-only", ValidFrom: time.Now().UTC().Add(-2 * time.Hour), ValidUntil: time.Now().UTC().Add(-time.Hour), PolicyVersion: "p1", Reason: "Synthetic operator judgment for lifecycle testing", Refs: []evidence.Ref{sellerRef}}
	request("POST", "indicators", indicator)
	if got := request("GET", "indicators", nil); !strings.Contains(got, `"effective_status":"expired"`) {
		t.Fatal("expired indicator presented active", got)
	}
	request("POST", "indicators/revoke", map[string]any{"id": indicator.ID, "revision": 1, "reason": "Synthetic withdrawal"})
	if got := request("GET", "indicators", nil); !strings.Contains(got, `"effective_status":"revoked"`) {
		t.Fatal("revocation absent", got)
	}
}
