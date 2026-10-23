package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ValidatedAnalysis is the P6 publication boundary. Validation is repeated here;
// the name does not confer authority on provider output. Finish must own the tx.
type ValidatedAnalysis struct {
	JobKey      jobs.Key         `json:"job_key"`
	Producer    string           `json:"producer"`
	Refs        []evidence.Ref   `json:"refs"`
	Claims      []AnalysisClaim  `json:"claims"`
	Roles       []ObservableRole `json:"roles"`
	Proposals   []EntityProposal `json:"proposals"`
	Limitations []string         `json:"limitations"`
}
type ClaimVersion struct {
	ID       string `json:"id"`
	Revision int    `json:"revision"`
}
type ClaimDependency struct {
	ClaimVersion
	Relation string `json:"relation"`
}
type AnalysisClaim struct {
	ID           string            `json:"id"`
	CaseID       string            `json:"case_id"`
	Subject      string            `json:"subject"`
	Predicate    string            `json:"predicate"`
	Object       string            `json:"object"`
	Refs         []evidence.Ref    `json:"refs"`
	Dependencies []ClaimDependency `json:"dependencies"`
}
type ObservableRole struct {
	Type  string         `json:"type"`
	Value string         `json:"value"`
	Role  string         `json:"role"`
	Refs  []evidence.Ref `json:"refs"`
}
type EntityProposal struct {
	Kind     string         `json:"kind"`
	Alias    string         `json:"alias"`
	Scope    string         `json:"scope"`
	Language string         `json:"language"`
	Refs     []evidence.Ref `json:"refs"`
}

// JudgeClaimTx records an attributed operator judgment as an immutable version.
// It is a separate boundary from untrusted semantic analysis publication.
func JudgeClaimTx(ctx context.Context, tx pgx.Tx, c ClaimVersion, status, producer, reason string, refs []evidence.Ref) error {
	if e := LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	if status == "retracted" {
		return RetractClaimTx(ctx, tx, c, producer, reason, refs)
	}
	if (status != "supported" && status != "contradicted" && status != "unresolved") || !strings.HasPrefix(producer, "operator:") || !bounded(reason, 4096) {
		return errors.New("explicit operator claim judgment required")
	}
	if e := validateRefsTx(ctx, tx, refs); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,8))`, c.ID); e != nil {
		return e
	}
	raw, _ := json.Marshal(refs)
	tag, e := tx.Exec(ctx, `INSERT INTO noctis_v2.claim_versions(id,revision,case_id,subject,predicate,object,status,producer,policy_version,evidence,reason) SELECT id,revision+1,case_id,subject,predicate,object,$3,$4,policy_version,$5,$6 FROM noctis_v2.claim_versions WHERE id=$1 AND revision=$2 AND revision=(SELECT max(revision) FROM noctis_v2.claim_versions WHERE id=$1) AND status<>'retracted'`, c.ID, c.Revision, status, producer, string(raw), reason)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("stale claim revision")
	}
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.claim_dependencies VALUES($1,$2,$1,$3,$4)`, c.ID, c.Revision+1, c.Revision, map[string]string{"supported": "supports", "contradicted": "contradicts", "unresolved": "depends_on"}[status])
	if e != nil {
		return e
	}
	if status == "contradicted" || status == "unresolved" {
		e = InvalidateProjectionTx(ctx, tx, []ClaimVersion{c}, nil, "operator_claim_"+status)
		if e != nil {
			return e
		}
	}
	changeID := uuid.NewString()
	change, _ := json.Marshal(map[string]any{"id": changeID, "kind": "operator_claim_judgment", "title": "Juicio de afirmación: " + status, "description": reason, "citations": refs, "claim_id": c.ID, "claim_revision": c.Revision + 1, "producer": producer})
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.case_changes(id,case_id,observation_id,body,material_key) SELECT $1,case_id,$2,$3,$4 FROM noctis_v2.claim_versions WHERE id=$5 AND revision=$6`, changeID, refs[0].ObservationID, string(change), fmt.Sprintf("judgment:%s:%d", c.ID, c.Revision+1), c.ID, c.Revision)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `WITH updated AS(UPDATE noctis_v2.intelligence_cases SET revision=revision+1,updated_at=clock_timestamp() WHERE id=(SELECT case_id FROM noctis_v2.claim_versions WHERE id=$1 AND revision=$2) RETURNING id,revision) INSERT INTO noctis_v2.case_revisions(case_id,revision,body) SELECT u.id,u.revision,old.body||jsonb_build_object('revision',u.revision::text,'supersedes',(u.revision-1)::text,'claims_status',$3::text,'judgment_producer',$4::text) FROM updated u JOIN noctis_v2.case_revisions old ON old.case_id=u.id AND old.revision=u.revision-1`, c.ID, c.Revision, status, producer)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.briefs b SET invalidated=true WHERE EXISTS(SELECT FROM noctis_v2.claim_versions c JOIN noctis_v2.case_memberships m ON m.case_id=c.case_id WHERE c.id=$1 AND b.body::text LIKE '%'||m.observation_id::text||'%')`, c.ID)
	return e
}

func RevokeEntityAliasTx(ctx context.Context, tx pgx.Tx, id string) error {
	tag, e := tx.Exec(ctx, `UPDATE noctis_v2.entity_aliases SET revoked=true WHERE id=$1 AND NOT revoked`, id)
	if e == nil && tag.RowsAffected() != 1 {
		return errors.New("alias unavailable")
	}
	return e
}
func ProposeIdentityTx(ctx context.Context, tx pgx.Tx, left, right, relation string, refs []evidence.Ref) (string, error) {
	if left == right || !bounded(relation, 128) {
		return "", errors.New("invalid identity hypothesis")
	}
	if e := validateRefsTx(ctx, tx, refs); e != nil {
		return "", e
	}
	id := uuid.NewString()
	raw, _ := json.Marshal(refs)
	_, e := tx.Exec(ctx, `INSERT INTO noctis_v2.entity_hypotheses(id,left_id,right_id,relation,evidence,status) VALUES($1,$2,$3,$4,$5,'unresolved')`, id, left, right, relation, string(raw))
	return id, e
}

func validateRefsTx(ctx context.Context, tx pgx.Tx, refs []evidence.Ref) error {
	if len(refs) == 0 || len(refs) > 256 {
		return errors.New("evidence refs required within limit")
	}
	for _, r := range refs {
		if _, e := uuid.Parse(r.ObservationID); e != nil {
			return errors.New("invalid evidence UUID")
		}
		var payload []byte
		e := tx.QueryRow(ctx, `SELECT b.payload FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE o.id=$1 AND o.revision=$2 AND o.hash=$3 AND o.representation=$4 AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL FOR SHARE OF o`, r.ObservationID, r.Revision, r.Hash, r.Representation).Scan(&payload)
		if e != nil {
			return fmt.Errorf("evidence unavailable: %w", e)
		}
		if e = r.Validate(payload); e != nil {
			return e
		}
	}
	return nil
}
func ValidateEvidenceTx(ctx context.Context, tx pgx.Tx, refs []evidence.Ref) error {
	return validateRefsTx(ctx, tx, refs)
}

// LockProjectionTx serializes short publication/invalidation transactions and
// brief snapshots. Parsing, RPC and inference happen outside this guard.
func LockProjectionTx(ctx context.Context, tx pgx.Tx) error {
	_, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(76238451003)`)
	return e
}
func containedRefs(refs, allowed []evidence.Ref) bool {
	if len(refs) == 0 {
		return false
	}
	for _, r := range refs {
		found := false
		for _, a := range allowed {
			if r.ObservationID == a.ObservationID && r.Revision == a.Revision && r.Hash == a.Hash && r.Representation == a.Representation && r.Start >= a.Start && r.End <= a.End && r.Start < r.End {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
func bounded(s string, n int) bool { return strings.TrimSpace(s) != "" && len(s) <= n }

// ApplyAnalysisTx publishes source claims and immutable case revisions atomically.
// It never promotes confidence, entity names or shared hosting into identity.
func ApplyAnalysisTx(ctx context.Context, tx pgx.Tx, a ValidatedAnalysis) error {
	if e := LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	if !bounded(a.Producer, 256) || len(a.Claims) > 128 || len(a.Roles) > 256 || len(a.Proposals) > 128 || len(a.Limitations) > 64 {
		return errors.New("analysis limits exceeded")
	}
	if e := validateRefsTx(ctx, tx, a.Refs); e != nil {
		return e
	}
	k := a.JobKey
	var jobID string
	if e := tx.QueryRow(ctx, `SELECT id::text FROM noctis_v2.jobs WHERE stage=$1 AND input_id=$2 AND input_revision=$3 AND policy_version=$4 AND schema_version=$5 AND state='leased' AND lease_expires_at>clock_timestamp() FOR UPDATE`, k.Stage, k.InputID, k.InputRevision, k.PolicyVersion, k.SchemaVersion).Scan(&jobID); e != nil {
		return e
	}
	for _, r := range a.Refs {
		if r.ObservationID != k.InputID || r.Revision != k.InputRevision {
			return errors.New("evidence outside job input")
		}
	}
	raw, e := json.Marshal(a)
	if e != nil {
		return e
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	var prior string
	e = tx.QueryRow(ctx, `SELECT digest FROM noctis_v2.analysis_results WHERE job_id=$1`, jobID).Scan(&prior)
	if e == nil {
		if prior != digest {
			return errors.New("analysis result conflict")
		}
		return nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	cases := map[string]bool{}
	contradictions := map[string]bool{}
	for _, c := range a.Claims {
		if _, e = uuid.Parse(c.ID); e != nil {
			return errors.New("invalid claim UUID")
		}
		if _, e = uuid.Parse(c.CaseID); e != nil {
			return errors.New("invalid case UUID")
		}
		if !bounded(c.Subject, 512) || !bounded(c.Predicate, 128) || !bounded(c.Object, 4096) || !containedRefs(c.Refs, a.Refs) || len(c.Dependencies) > 64 {
			return errors.New("invalid claim")
		}
		if e = validateRefsTx(ctx, tx, c.Refs); e != nil {
			return e
		}
		var member bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.case_memberships WHERE case_id=$1 AND observation_id=$2)`, c.CaseID, k.InputID).Scan(&member); e != nil {
			return e
		}
		if !member {
			// A cited contradiction may link an observation to the disputed case.
			// This adds support membership; it never merges the existing cases.
			linked := false
			for _, d := range c.Dependencies {
				if d.Relation != "contradicts" {
					continue
				}
				var target bool
				if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.claim_versions WHERE id=$1 AND revision=$2 AND case_id=$3 AND NOT invalidated AND status<>'retracted')`, d.ID, d.Revision, c.CaseID).Scan(&target); e != nil {
					return e
				}
				linked = linked || target
			}
			if !linked {
				return errors.New("claim outside input case without cited contradiction")
			}
			if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.case_memberships(case_id,observation_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, c.CaseID, k.InputID); e != nil {
				return e
			}
		}
		refs, _ := json.Marshal(c.Refs)
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.claim_versions(id,revision,case_id,subject,predicate,object,status,producer,policy_version,evidence) VALUES($1,1,$2,$3,$4,$5,'source_claim',$6,$7,$8)`, c.ID, c.CaseID, c.Subject, c.Predicate, c.Object, a.Producer, k.PolicyVersion, string(refs)); e != nil {
			return e
		}
		for _, d := range c.Dependencies {
			if d.ID == c.ID || (d.Relation != "supports" && d.Relation != "contradicts" && d.Relation != "depends_on") {
				return errors.New("invalid claim dependency")
			}
			var valid bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.claim_versions WHERE id=$1 AND revision=$2 AND NOT invalidated AND status<>'retracted')`, d.ID, d.Revision).Scan(&valid); e != nil {
				return e
			}
			if !valid {
				return errors.New("dependency unavailable")
			}
			// New immutable version can reference only versions already persisted. No forward edges.
			if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.claim_dependencies VALUES($1,1,$2,$3,$4)`, c.ID, d.ID, d.Revision, d.Relation); e != nil {
				return e
			}
			if d.Relation == "contradicts" {
				contradictions[c.CaseID] = true
			}
		}
		cases[c.CaseID] = true
	}
	for _, r := range a.Roles {
		if !bounded(r.Type, 64) || !bounded(r.Value, 2048) || !containedRefs(r.Refs, a.Refs) {
			return errors.New("invalid role")
		}
		switch r.Role {
		case "claimed_target", "reference", "benign", "unknown", "claimed_infrastructure":
		default:
			return errors.New("unsupported observable role")
		}
		if e = validateRefsTx(ctx, tx, r.Refs); e != nil {
			return e
		}
	}
	for _, p := range a.Proposals {
		if !bounded(p.Kind, 64) || !bounded(p.Alias, 512) || !bounded(p.Scope, 256) || !bounded(p.Language, 32) || !containedRefs(p.Refs, a.Refs) {
			return errors.New("invalid entity proposal")
		}
		if e = validateRefsTx(ctx, tx, p.Refs); e != nil {
			return e
		}
		id := uuid.NewString()
		refs, _ := json.Marshal(p.Refs)
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.entities(id,kind) VALUES($1,$2)`, id, p.Kind); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.entity_aliases(id,entity_id,alias,scope,language,evidence) VALUES($1,$2,$3,$4,$5,$6)`, uuid.NewString(), id, p.Alias, p.Scope, p.Language, string(refs)); e != nil {
			return e
		}
	}
	for id := range cases {
		var body []byte
		var rev int64
		if e = tx.QueryRow(ctx, `SELECT cr.body,ic.revision FROM noctis_v2.intelligence_cases ic JOIN noctis_v2.case_revisions cr ON cr.case_id=ic.id AND cr.revision=ic.revision WHERE ic.id=$1 FOR UPDATE OF ic`, id).Scan(&body, &rev); e != nil {
			return e
		}
		var v map[string]any
		if e = json.Unmarshal(body, &v); e != nil {
			return e
		}
		v["revision"] = fmt.Sprint(rev + 1)
		v["supersedes"] = fmt.Sprint(rev)
		v["analysis_job_key"] = k
		v["claims_status"] = "source_claim"
		if contradictions[id] {
			v["claims_status"] = "contested_source_claims"
		}
		v["limitations"] = a.Limitations
		body, _ = json.Marshal(v)
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.case_revisions(case_id,revision,body) VALUES($1,$2,$3)`, id, rev+1, string(body)); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `UPDATE noctis_v2.intelligence_cases SET revision=$2,updated_at=clock_timestamp() WHERE id=$1`, id, rev+1); e != nil {
			return e
		}
		if contradictions[id] {
			changeID := uuid.NewString()
			change, _ := json.Marshal(map[string]any{"id": changeID, "case_id": id, "kind": "source_contradiction", "title": "Una fuente presenta una contradicción", "description": "Se conservan las afirmaciones en conflicto y sus citas. La contradicción no determina cuál es verdadera.", "citations": a.Refs, "status": "source_claim"})
			key := fmt.Sprintf("source_contradiction:%s:%s", id, a.Refs[0].Hash)
			tag, err := tx.Exec(ctx, `INSERT INTO noctis_v2.case_changes(id,case_id,observation_id,body,material_key) VALUES($1,$2,$3,$4,$5) ON CONFLICT(material_key) DO NOTHING`, changeID, id, k.InputID, string(change), key)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 1 {
				_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.outbox(id,delivery_key,body,state,policy_version) SELECT $1,$2,$3,'queued',$5 FROM noctis_v2.observations o JOIN noctis_v2.sources s ON s.id=o.source_id WHERE o.id=$4 AND o.mode='live' AND o.epoch=s.epoch AND `+SourceAuthorizedSQL+` AND s.policy_version=$5 AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.published_at>=s.activated_at AND o.published_at<=clock_timestamp()+interval '5 minutes' AND EXISTS(SELECT FROM noctis_v2.analyses a WHERE a.observation_id=o.id AND a.policy_version=$5 AND a.gate='relevant') ON CONFLICT DO NOTHING`, uuid.NewString(), key, string(change), k.InputID, k.PolicyVersion)
				if e != nil {
					return e
				}
			}
			if _, e = tx.Exec(ctx, `UPDATE noctis_v2.briefs b SET invalidated=true WHERE EXISTS(SELECT FROM noctis_v2.case_memberships m WHERE m.case_id=$1 AND b.body::text LIKE '%'||m.observation_id::text||'%')`, id); e != nil {
				return e
			}
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.analysis_results(job_id,digest,body) VALUES($1,$2,$3)`, jobID, digest, string(raw))
	return e
}

// RetractClaimTx is an explicit operator judgment. Dependents stay in history
// but are invalidated, and affected briefs cease to be presented as current.
func RetractClaimTx(ctx context.Context, tx pgx.Tx, c ClaimVersion, producer, reason string, refs []evidence.Ref) error {
	if e := LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	if !strings.HasPrefix(producer, "operator:") || !bounded(reason, 4096) {
		return errors.New("operator and retraction reason required")
	}
	if e := validateRefsTx(ctx, tx, refs); e != nil {
		return e
	}
	if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,8))`, c.ID); e != nil {
		return e
	}
	raw, _ := json.Marshal(refs)
	tag, e := tx.Exec(ctx, `INSERT INTO noctis_v2.claim_versions(id,revision,case_id,subject,predicate,object,status,producer,policy_version,evidence,reason) SELECT id,revision+1,case_id,subject,predicate,object,'retracted',$3,policy_version,$4,$5 FROM noctis_v2.claim_versions WHERE id=$1 AND revision=$2 AND revision=(SELECT max(revision) FROM noctis_v2.claim_versions WHERE id=$1) AND status<>'retracted'`, c.ID, c.Revision, producer, string(raw), reason)
	if e != nil {
		return e
	}
	if tag.RowsAffected() != 1 {
		return errors.New("stale claim revision")
	}
	e = InvalidateProjectionTx(ctx, tx, []ClaimVersion{c}, nil, "claim_retracted: "+reason)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.briefs b SET invalidated=true WHERE EXISTS(SELECT FROM noctis_v2.claim_versions c JOIN noctis_v2.case_memberships m ON m.case_id=c.case_id WHERE c.invalidated AND b.body::text LIKE '%'||m.observation_id::text||'%')`)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `WITH RECURSIVE affected(id,revision) AS (SELECT $1::uuid,$2::integer UNION SELECT d.claim_id,d.claim_revision FROM noctis_v2.claim_dependencies d JOIN affected a ON d.dependency_id=a.id AND d.dependency_revision=a.revision WHERE d.relation IN('supports','depends_on')), updated AS (UPDATE noctis_v2.intelligence_cases ic SET revision=revision+1,updated_at=clock_timestamp() WHERE EXISTS(SELECT FROM noctis_v2.claim_versions c JOIN affected a ON a.id=c.id AND a.revision=c.revision WHERE c.case_id=ic.id) RETURNING id,revision) INSERT INTO noctis_v2.case_revisions(case_id,revision,body) SELECT u.id,u.revision,old.body||jsonb_build_object('revision',u.revision::text,'supersedes',(u.revision-1)::text,'claims_status','needs_revalidation','summary','Una retractación invalida afirmaciones derivadas; revisar evidencia y contradicciones.') FROM updated u JOIN noctis_v2.case_revisions old ON old.case_id=u.id AND old.revision=u.revision-1`, c.ID, c.Revision)
	if e != nil {
		return e
	}
	ref := refs[0]
	changeID := uuid.NewString()
	change, _ := json.Marshal(map[string]any{"id": changeID, "kind": "claim_retraction", "title": "Retractación de una afirmación", "description": reason, "citations": refs, "claim_id": c.ID, "claim_revision": c.Revision + 1})
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.case_changes(id,case_id,observation_id,body,material_key) SELECT $1,case_id,$2,$3,$4 FROM noctis_v2.claim_versions WHERE id=$5 AND revision=$6 ON CONFLICT(material_key) DO NOTHING`, changeID, ref.ObservationID, string(change), fmt.Sprintf("retraction:%s:%d", c.ID, c.Revision+1), c.ID, c.Revision)
	return e
}
