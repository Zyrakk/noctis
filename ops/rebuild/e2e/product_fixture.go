package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/Zyrakk/noctis/internal/vulnv2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// seedProductFixture is opt-in synthetic adjudication, not a model evaluation.
// It passes through capture, deterministic case projection and fenced publication.
// SQL below only prepares the isolated harness policy/inventory, never production.
func seedProductFixture(ctx context.Context, c *pgx.Conn) (map[string]string, error) {
	const policy = "p7-synthetic-v1"
	dsn := c.Config().ConnString()
	if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES($1,'[{"type":"keyword","value":"ACME"},{"type":"cve","value":"CVE-2026-12345"}]')`, policy); e != nil {
		return nil, e
	}
	worker := intelligence.Worker{DSN: dsn, Owner: "p7-product-fixture"}
	ids := map[string]string{"dataset": "noctis-stories-v1"}
	captureText := func(title, text string) (string, string, evidence.Ref, error) {
		source, epoch := uuid.NewString(), uuid.NewString()
		if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,name,enabled,policy_version,epoch,activated_at) VALUES($1::uuid,'rss',$1::text,$2,true,$3,$4,clock_timestamp()-interval '1 hour')`, source, "Fuente sintética P7 · "+title, policy, epoch); e != nil {
			return "", "", evidence.Ref{}, e
		}
		now := time.Now().UTC()
		payload := title + "\n" + text
		hash := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(payload)))
		if _, e := (capture.Store{DSN: dsn}).CommitBatch(ctx, capture.Batch{BatchID: uuid.NewString(), Version: "1", SourceID: source, Epoch: epoch, Mode: capture.Live, Items: []capture.Item{{NativeID: "synthetic-post", Revision: "1", Hash: hash, Payload: []byte(payload), Representation: "text/plain;utf8;v1", CollectedAt: now, PublishedAt: &now}}, Expected: capture.Checkpoint{Value: json.RawMessage(`null`)}, Next: capture.Checkpoint{Version: 1, Value: json.RawMessage(`1`)}}); e != nil {
			return "", "", evidence.Ref{}, e
		}
		if e := worker.Once(ctx); e != nil {
			return "", "", evidence.Ref{}, e
		}
		var observation, caseID string
		if e := c.QueryRow(ctx, `SELECT o.id::text,m.case_id::text FROM noctis_v2.observations o JOIN noctis_v2.case_memberships m ON m.observation_id=o.id WHERE o.source_id=$1`, source).Scan(&observation, &caseID); e != nil {
			return "", "", evidence.Ref{}, e
		}
		return observation, caseID, evidence.Ref{ObservationID: observation, Revision: "1", Hash: hash, Representation: "text/plain;utf8;v1", End: len(payload)}, nil
	}
	publish := func(obs string, ref evidence.Ref, claims []intelligence.AnalysisClaim, proposals []intelligence.EntityProposal) error {
		if _, e := c.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) VALUES($1,'p7-synthetic-semantic',$2,'1',$3,'1')`, uuid.NewString(), obs, policy); e != nil {
			return e
		}
		store := jobs.Store{DSN: dsn}
		job, e := store.Claim(ctx, "p7-synthetic-adjudicator", time.Minute, "p7-synthetic-semantic")
		if e != nil {
			return e
		}
		return store.Finish(ctx, job, func(tx pgx.Tx) error {
			return intelligence.ApplyAnalysisTx(ctx, tx, intelligence.ValidatedAnalysis{JobKey: job.Key, Producer: "fixture:adjudicated-p7-v1", Refs: []evidence.Ref{ref}, Claims: claims, Proposals: proposals, Limitations: []string{"Synthetic explicit adjudication; no inference or model quality claim"}})
		})
	}
	// B preserves five observations for one original content, followed by a denial.
	const offerTitle = "P7 B · Oferta reportada ACME"
	const offerText = "ACME: una fuente afirma vender acceso. Cuatro copias no confirman una brecha. Evidencia café 🙂. Shared hosting 8.8.8.8."
	seller, sellerCase, sellerRef, e := captureText(offerTitle, offerText)
	if e != nil {
		return nil, e
	}
	ids["case_b"], ids["observation_b"] = sellerCase, seller
	for i := 0; i < 4; i++ {
		if _, _, _, e = captureText(offerTitle, offerText); e != nil {
			return nil, e
		}
	}
	claim := uuid.NewString()
	if e = publish(seller, sellerRef, []intelligence.AnalysisClaim{{ID: claim, CaseID: sellerCase, Subject: "Fuente sintética", Predicate: "oferta reportada", Object: "ACME", Refs: []evidence.Ref{sellerRef}}}, nil); e != nil {
		return nil, e
	}
	denial, _, denialRef, e := captureText("P7 B · Negativa ACME", "ACME niega la oferta de acceso. La negativa contradice la oferta; conservar ambas afirmaciones atribuidas.")
	if e != nil {
		return nil, e
	}
	if e = publish(denial, denialRef, []intelligence.AnalysisClaim{{ID: uuid.NewString(), CaseID: sellerCase, Subject: "ACME", Predicate: "niega oferta", Object: "Fuente sintética", Refs: []evidence.Ref{denialRef}, Dependencies: []intelligence.ClaimDependency{{ClaimVersion: intelligence.ClaimVersion{ID: claim, Revision: 1}, Relation: "contradicts"}}}}, nil); e != nil {
		return nil, e
	}
	// C keeps equal aliases in different scopes separate and proposes a reversible edge.
	obsC, caseC, refC, e := captureText("P7 C · Handle e infraestructura ACME", "ACME observa noctua-lab junto a node.example. Hosting compartido reduce especificidad; no se fusionan identidades.")
	if e != nil {
		return nil, e
	}
	ids["case_c"] = caseC
	if e = publish(obsC, refC, nil, []intelligence.EntityProposal{{Kind: "handle", Alias: "noctua-lab", Scope: "synthetic:channel-a", Language: "und", Refs: []evidence.Ref{refC}}, {Kind: "handle", Alias: "noctua-lab", Scope: "synthetic:channel-b", Language: "und", Refs: []evidence.Ref{refC}}}); e != nil {
		return nil, e
	}
	rows, e := c.Query(ctx, `SELECT entity_id::text FROM noctis_v2.entity_aliases WHERE alias='noctua-lab' ORDER BY scope`)
	if e != nil {
		return nil, e
	}
	var entities []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return nil, e
		}
		entities = append(entities, id)
	}
	rows.Close()
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if len(entities) != 2 {
		return nil, fmt.Errorf("synthetic scopes: expected two entities")
	}
	tx, e := c.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(context.Background())
	hypothesis, e := intelligence.ProposeIdentityTx(ctx, tx, entities[0], entities[1], "possible_same_handle; shared_hosting_low_specificity", []evidence.Ref{refC})
	if e != nil {
		return nil, e
	}
	if e = tx.Commit(ctx); e != nil {
		return nil, e
	}
	ids["entity_c"], ids["hypothesis_c"] = entities[0], hypothesis
	// A uses a fake local NVD snapshot, then preserves unknown and known versions.
	_, caseA, refA, e := captureText("P7 A · Vulnerabilidad vigilada ACME", "ACME inventario sintético producto synthetic:product, versión desconocida. Aviso CVE-2026-12345.")
	if e != nil {
		return nil, e
	}
	ids["case_a"] = caseA
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"startIndex":0,"totalResults":1,"resultsPerPage":1,"timestamp":%q,"vulnerabilities":[{"cve":{"id":"CVE-2026-12345","configurations":[{"nodes":[{"operator":"OR","cpeMatch":[{"vulnerable":true,"criteria":"cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*","versionStartIncluding":"1.0","versionEndExcluding":"2.0"}]}]}]}}]}`, time.Now().UTC().Format(time.RFC3339))
	}))
	defer server.Close()
	if _, e = (vulnv2.Store{DSN: dsn, Fetcher: capture.Fetcher{AllowLocal: map[string]bool{strings.TrimPrefix(server.URL, "http://"): true}}}).PollPage(ctx, "nvd", server.URL, 24*time.Hour); e != nil {
		return nil, e
	}
	refs, _ := json.Marshal([]evidence.Ref{refA})
	for _, version := range []any{nil, "1.5"} {
		asset := uuid.NewString()
		if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.asset_versions(id,revision,cpe,version,evidence,producer) VALUES($1,1,'cpe:2.3:a:synthetic:product:*:*:*:*:*:*:*:*',$2,$3,'operator:synthetic-fixture')`, asset, version, string(refs)); e != nil {
			return nil, e
		}
	}
	txA, e := c.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer txA.Rollback(context.Background())
	if e = vulnv2.RefreshApplicabilityTx(ctx, txA, "CVE-2026-12345"); e != nil {
		return nil, e
	}
	if e = txA.Commit(ctx); e != nil {
		return nil, e
	}
	indicator := intelligence.Indicator{ID: uuid.NewString(), Type: "ip", Value: "8.8.8.8", Scope: "synthetic-fixture-only", ValidFrom: time.Now().Add(-2 * time.Hour), ValidUntil: time.Now().Add(-time.Hour), PolicyVersion: policy, Producer: "operator:synthetic-fixture", Reason: "Synthetic expired lifecycle fixture", Refs: []evidence.Ref{sellerRef}}
	txI, e := c.Begin(ctx)
	if e != nil {
		return nil, e
	}
	defer txI.Rollback(context.Background())
	if e = intelligence.CreateIndicatorTx(ctx, txI, indicator); e != nil {
		return nil, e
	}
	if e = txI.Commit(ctx); e != nil {
		return nil, e
	}
	ids["indicator_expired"] = indicator.ID
	// Additional operations data stays separate from the adjudicated A/B/C stories.
	_, opsCase, opsRef, e := captureText("P8 · Operaciones sintéticas", "ACME operaciones sintéticas café original conservado; retención y atención fixture")
	if e != nil {
		return nil, e
	}
	var opsSource string
	if e = c.QueryRow(ctx, `SELECT source_id::text FROM noctis_v2.observations WHERE id=$1`, opsRef.ObservationID).Scan(&opsSource); e != nil {
		return nil, e
	}
	ids["case_ops"], ids["source_ops"], ids["observation_ops"] = opsCase, opsSource, opsRef.ObservationID
	refsOps, _ := json.Marshal([]evidence.Ref{opsRef})
	for i := 0; i < 51; i++ {
		if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.claim_versions(id,revision,case_id,subject,predicate,object,status,producer,policy_version,evidence) VALUES($1,1,$2,'Fuente operativa','reports',$3,'source_claim','fixture:operations',$4,$5)`, uuid.NewString(), opsCase, fmt.Sprintf("Afirmación paginada %02d", i), policy, string(refsOps)); e != nil {
			return nil, e
		}
	}
	expiredExport := uuid.NewString()
	ids["export_expired"] = expiredExport
	if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.private_exports(id,actor,case_id,revision,expires_at,body) SELECT $1,'operator',id,revision,clock_timestamp()-interval '1 minute','{}' FROM noctis_v2.intelligence_cases WHERE id=$2`, expiredExport, opsCase); e != nil {
		return nil, e
	}
	question := uuid.NewString()
	if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.questions(id,title) VALUES($1,'Operations synthetic PIR')`, question); e != nil {
		return nil, e
	}
	ids["question_ops"] = question
	for _, state := range []string{"expired", "revoked"} {
		id := uuid.NewString()
		ids["proposal_"+state] = id
		expiry := time.Now().Add(time.Hour)
		permission := "authorized"
		if state == "expired" {
			expiry = time.Now().Add(-time.Hour)
		} else {
			permission = "revoked"
		}
		if _, e = c.Exec(ctx, `INSERT INTO noctis_v2.discovery_proposals(id,question_id,kind,endpoint,provenance,reason,score,expires_at,permission_status) VALUES($1,$2,'html','http://127.0.0.1:1','{"origin":"fixture"}','synthetic fail-closed boundary','{"basis":"question_match","independence":"unknown"}',$3,$4)`, id, question, expiry, permission); e != nil {
			return nil, e
		}
	}
	if e = worker.Brief(ctx, time.Now().UTC().Format("2006-01-02"), policy); e != nil {
		return nil, e
	}
	return ids, nil
}
