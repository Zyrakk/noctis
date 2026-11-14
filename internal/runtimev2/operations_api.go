package runtimev2

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/capture"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"io"
	"net/http"
	"strings"
	"time"
)

type operationInput struct {
	ExpectedRevision int64               `json:"expected_revision"`
	RequestID        string              `json:"request_id"`
	Action           string              `json:"action"`
	Reason           string              `json:"reason"`
	Deadline         *time.Time          `json:"deadline"`
	Format           string              `json:"format"`
	TTL              int                 `json:"ttl_seconds"`
	Quota            int                 `json:"quota"`
	Policy           json.RawMessage     `json:"policy"`
	Permission       string              `json:"permission"`
	Granted          bool                `json:"granted"`
	QuestionID       string              `json:"question_id"`
	Kind             string              `json:"kind"`
	Endpoint         string              `json:"endpoint"`
	Provenance       json.RawMessage     `json:"provenance"`
	SourceID         string              `json:"source_id"`
	DataClass        string              `json:"data_class"`
	RetainSeconds    int64               `json:"retain_seconds"`
	DryRun           bool                `json:"dry_run"`
	RunID            string              `json:"run_id"`
	Limit            int                 `json:"limit"`
	Title            string              `json:"title"`
	Terms            []intelligence.Term `json:"terms"`
	PolicyVersion    string              `json:"policy_version"`
	AdapterConfig    json.RawMessage     `json:"adapter_config"`
	Enabled          bool                `json:"enabled"`
	SnapshotID       string              `json:"snapshot_id"`
	PeerID           int64               `json:"peer_id"`
}
type operationError struct {
	status   int
	code     string
	revision int64
}

func (e *operationError) Error() string    { return e.code }
func reject(status int, code string) error { return &operationError{status: status, code: code} }

func permissionTx(ctx context.Context, tx pgx.Tx, actor, permission string) error {
	var allowed bool
	if e := tx.QueryRow(ctx, `SELECT COALESCE((SELECT granted FROM noctis_v2.operator_permissions WHERE actor=$1 AND permission=$2),false)`, actor, permission).Scan(&allowed); e != nil {
		return e
	}
	if !allowed {
		return reject(403, "permission_"+permission+"_required")
	}
	return nil
}
func attentionTx(ctx context.Context, tx pgx.Tx, id string) (json.RawMessage, error) {
	if _, e := tx.Exec(ctx, `INSERT INTO noctis_v2.case_attention(case_id) SELECT id FROM noctis_v2.intelligence_cases WHERE id=$1 ON CONFLICT DO NOTHING`, id); e != nil {
		return nil, e
	}
	// The immutable case revision is the material-change watermark. Silence never
	// alters claims; expiration and any new case revision reopen attention.
	_, e := tx.Exec(ctx, `UPDATE noctis_v2.case_attention a SET mode='automatic',revision=a.revision+1,reason='material_change_or_deadline',silent_until=NULL,exception=NULL FROM noctis_v2.intelligence_cases c WHERE c.id=a.case_id AND a.case_id=$1 AND a.mode<>'automatic' AND (c.revision>a.seen_revision OR a.silent_until<=clock_timestamp() OR (a.exception->>'deadline')::timestamptz<=clock_timestamp())`, id)
	if e != nil {
		return nil, e
	}
	var raw []byte
	e = tx.QueryRow(ctx, `SELECT to_jsonb(a) FROM noctis_v2.case_attention a WHERE case_id=$1`, id).Scan(&raw)
	return raw, e
}
func (a *API) handleOperations(w http.ResponseWriter, r *http.Request, c *pgx.Conn, path, actor string) (handled bool, err error) {
	parts := strings.Split(path, "/")
	isCase := len(parts) == 3 && parts[0] == "cases" && (parts[2] == "attention" || parts[2] == "exports" || parts[2] == "lifecycle")
	isSource := len(parts) == 3 && parts[0] == "sources" && parts[2] == "policy"
	isQuestion := len(parts) == 3 && parts[0] == "questions" && parts[2] == "policy"
	isDiscovery := parts[0] == "discovery"
	isExport := len(parts) == 2 && parts[0] == "exports"
	isTelegram := path == "telegram/candidates" || path == "telegram/import"
	if !isCase && !isSource && !isQuestion && !isDiscovery && !isExport && !isTelegram && path != "coverage" && path != "questions" && path != "permissions" && path != "runtime-control" && path != "retention" {
		return false, nil
	}
	handled = true
	defer func() {
		var oe *operationError
		if errors.As(err, &oe) {
			if oe.status == 409 {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(409)
				json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": oe.code, "current_revision": oe.revision}})
			} else {
				failure(w, oe.status, oe.code)
			}
			err = nil
		} else if errors.Is(err, pgx.ErrNoRows) {
			failure(w, 404, "not_found")
			err = nil
		}
	}()
	ctx := r.Context()
	if isCase {
		if _, e := uuid.Parse(parts[1]); e != nil {
			return true, pgx.ErrNoRows
		}
	}
	if r.Method == "GET" {
		switch {
		case path == "retention":
			source, class := r.URL.Query().Get("source_id"), r.URL.Query().Get("data_class")
			sourceID, e := uuid.Parse(source)
			if e != nil {
				return true, reject(400, "source_required")
			}
			source = sourceID.String()
			if strings.TrimSpace(class) == "" || len(class) > 64 {
				return true, reject(400, "data_class_required")
			}
			tx, e := c.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			if e != nil {
				return true, e
			}
			defer tx.Rollback(ctx)
			if e = permissionTx(ctx, tx, actor, "retention"); e != nil {
				return true, e
			}
			var raw []byte
			e = tx.QueryRow(ctx, `SELECT jsonb_build_object('source_id',s.id,'data_class',$2::text,'present',p.source_id IS NOT NULL,'revision',COALESCE(p.revision,0),'retain_seconds',p.retain_seconds) FROM noctis_v2.sources s LEFT JOIN noctis_v2.retention_policies p ON p.source_id=s.id AND p.data_class=$2 WHERE s.id=$1`, source, class).Scan(&raw)
			if e != nil {
				return true, e
			}
			response(w, json.RawMessage(raw))
		case path == "telegram/candidates":
			return true, jsonPage(ctx, w, r, c, path, `SELECT i.snapshot_id::text||':'||i.peer_id::text,jsonb_build_object('snapshot_id',i.snapshot_id,'account_id',n.account_id,'peer_type',i.peer_type,'peer_id',i.peer_id::text,'name',i.name,'folder',i.folder,'source_id',COALESCE(i.source_id,(SELECT s.id FROM noctis_v2.sources s WHERE s.kind='telegram' AND s.native_id=n.account_id||':channel:'||i.peer_id::text)),'provenance','current Telegram dialogs','created_at',n.created_at) FROM noctis_v2.telegram_inventory_candidates i JOIN noctis_v2.telegram_inventory_snapshots n ON n.id=i.snapshot_id JOIN noctis_v2.telegram_accounts a ON a.id=n.account_id AND a.auth_generation=n.auth_generation WHERE n.id=(SELECT z.id FROM noctis_v2.telegram_inventory_snapshots z WHERE z.account_id=n.account_id ORDER BY z.created_at DESC,z.id DESC LIMIT 1) AND ($1='' OR i.snapshot_id::text||':'||i.peer_id::text>$1) ORDER BY i.snapshot_id::text||':'||i.peer_id::text LIMIT $2`)
		case isCase && parts[2] == "attention":
			tx, e := c.Begin(ctx)
			if e != nil {
				return true, e
			}
			defer tx.Rollback(ctx)
			if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
				return true, e
			}
			raw, e := attentionTx(ctx, tx, parts[1])
			if e != nil {
				return true, e
			}
			if e = tx.Commit(ctx); e != nil {
				return true, e
			}
			response(w, raw)
		case isExport:
			tx, e := c.Begin(ctx)
			if e != nil {
				return true, e
			}
			defer tx.Rollback(ctx)
			if e = permissionTx(ctx, tx, actor, "export"); e != nil {
				return true, e
			}
			if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
				return true, e
			}
			var raw []byte
			var caseID string
			var revision int64
			e = tx.QueryRow(ctx, `SELECT body,case_id::text,revision FROM noctis_v2.private_exports WHERE id::text=$1 AND actor=$2 AND expires_at>clock_timestamp()`, parts[1], actor).Scan(&raw, &caseID, &revision)
			if errors.Is(e, pgx.ErrNoRows) {
				return true, reject(410, "export_expired_or_unavailable")
			}
			if e != nil {
				return true, e
			}
			var valid bool
			e = tx.QueryRow(ctx, `SELECT revision=$2 AND NOT EXISTS(SELECT FROM noctis_v2.case_memberships m JOIN noctis_v2.observations o ON o.id=m.observation_id WHERE m.case_id=ic.id AND o.retention_expired_at IS NOT NULL) FROM noctis_v2.intelligence_cases ic WHERE id=$1`, caseID, revision).Scan(&valid)
			if e != nil {
				return true, e
			}
			if !valid {
				return true, reject(410, "export_requires_regeneration")
			}
			response(w, json.RawMessage(raw))
		case path == "permissions":
			return true, jsonPage(ctx, w, r, c, path, `SELECT permission,jsonb_build_object('permission',permission,'granted',granted) FROM noctis_v2.operator_permissions WHERE actor=$1 AND ($2='' OR permission>$2) ORDER BY permission LIMIT $3`, actor)
		case path == "questions":
			return true, jsonPage(ctx, w, r, c, path, `SELECT id::text,to_jsonb(q) FROM noctis_v2.questions q WHERE ($1='' OR id::text>$1) ORDER BY id LIMIT $2`)
		case path == "runtime-control":
			var raw []byte
			err = c.QueryRow(ctx, `SELECT to_jsonb(r) FROM noctis_v2.runtime_control r`).Scan(&raw)
			if err == nil {
				response(w, json.RawMessage(raw))
			}
		case path == "coverage":
			return true, jsonPage(ctx, w, r, c, path+":"+r.URL.Query().Get("question_id"), `SELECT q.id::text||':'||COALESCE(s.id::text,''),jsonb_build_object('question_id',q.id,'question',q.title,'enabled',q.enabled,'source_id',s.id,'permission',COALESCE(s.enabled,false),'paused',NOT COALESCE(`+intelligence.SourceAuthorizedSQL+`,false),'last_success_at',s.last_success_at,'error',s.last_error,'coverage',COALESCE(s.coverage,'unknown'),'poll_after',s.poll_after,'lag_seconds',EXTRACT(epoch FROM clock_timestamp()-s.last_success_at),'independence',COALESCE(qs.independence,'unknown'),'unknowns',jsonb_build_array('unobserved_sources','independence_unverified')) FROM noctis_v2.questions q LEFT JOIN noctis_v2.question_sources qs ON qs.question_id=q.id LEFT JOIN noctis_v2.sources s ON s.id=qs.source_id WHERE ($1='' OR q.id::text=$1) AND ($2='' OR q.id::text||':'||COALESCE(s.id::text,'')>$2) ORDER BY 1 LIMIT $3`, r.URL.Query().Get("question_id"))
		case path == "discovery":
			return true, jsonPage(ctx, w, r, c, path+":"+r.URL.Query().Get("question_id"), `SELECT p.id::text,to_jsonb(p)||jsonb_build_object('policy_version',(SELECT 'question:'||q.id::text||CASE WHEN q.revision>1 THEN ':r'||q.revision::text ELSE '' END FROM noctis_v2.questions q WHERE q.id=p.question_id),'independence','unknown','trial',(SELECT to_jsonb(t) FROM noctis_v2.discovery_trials t WHERE t.proposal_id=p.id ORDER BY created_at DESC LIMIT 1)) FROM noctis_v2.discovery_proposals p WHERE ($1='' OR question_id::text=$1) AND ($2='' OR id::text>$2) ORDER BY id LIMIT $3`, r.URL.Query().Get("question_id"))
		default:
			return true, reject(405, "method_not_allowed")
		}
		return true, err
	}
	if r.Method != "POST" {
		return true, reject(405, "method_not_allowed")
	}
	var in operationInput
	dec := json.NewDecoder(io.LimitReader(r.Body, 65537))
	dec.DisallowUnknownFields()
	if e := dec.Decode(&in); e != nil {
		return true, reject(400, "invalid_request")
	}
	if in.RequestID == "" || len(in.RequestID) > 128 {
		return true, reject(400, "request_id_required")
	}
	raw, _ := json.Marshal(in)
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	tx, e := c.Begin(ctx)
	if e != nil {
		return true, e
	}
	defer tx.Rollback(context.Background())
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return true, e
	}
	var priorDigest, priorAction string
	var prior []byte
	e = tx.QueryRow(ctx, `SELECT digest,action,result FROM noctis_v2.action_receipts WHERE actor=$1 AND request_id=$2`, actor, in.RequestID).Scan(&priorDigest, &priorAction, &prior)
	if e == nil {
		if priorDigest != digest || priorAction != path {
			return true, reject(409, "request_id_conflict")
		}
		response(w, json.RawMessage(prior))
		return true, nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return true, e
	}
	var result any
	switch {
	case path == "telegram/import":
		if actor != a.username {
			return true, reject(403, "admin_required")
		}
		if _, e = uuid.Parse(in.SnapshotID); e != nil || in.PeerID <= 0 {
			return true, reject(400, "invalid_candidate")
		}
		var account, generation, name string
		var hash int64
		e = tx.QueryRow(ctx, `SELECT n.account_id,n.auth_generation::text,i.name,i.access_hash FROM noctis_v2.telegram_inventory_candidates i JOIN noctis_v2.telegram_inventory_snapshots n ON n.id=i.snapshot_id JOIN noctis_v2.telegram_accounts a ON a.id=n.account_id AND a.auth_generation=n.auth_generation WHERE n.id=$1 AND i.peer_id=$2 AND a.closed AND n.id=(SELECT z.id FROM noctis_v2.telegram_inventory_snapshots z WHERE z.account_id=n.account_id ORDER BY z.created_at DESC,z.id DESC LIMIT 1) FOR UPDATE OF a,i`, in.SnapshotID, in.PeerID).Scan(&account, &generation, &name, &hash)
		if e != nil {
			return true, reject(409, "inventory_stale_or_capture_running")
		}
		native := fmt.Sprintf("%s:channel:%d", account, in.PeerID)
		var source string
		e = tx.QueryRow(ctx, `SELECT id::text FROM noctis_v2.sources WHERE kind='telegram' AND native_id=$1`, native).Scan(&source)
		if errors.Is(e, pgx.ErrNoRows) {
			source = uuid.NewString()
			if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,name,enabled,policy_version) VALUES($1,'telegram',$2,$3,false,'')`, source, native, name); e != nil {
				return true, e
			}
			if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_peers(account_id,peer_type,peer_id,source_id,auth_generation,access_hash,allowed,inventory_snapshot) VALUES($1,'channel',$2,$3,$4,$5,false,$6)`, account, in.PeerID, source, generation, hash, in.SnapshotID); e != nil {
				return true, e
			}
		} else if e != nil {
			return true, e
		}
		if _, e = tx.Exec(ctx, `UPDATE noctis_v2.telegram_peers SET inventory_snapshot=$4,access_hash=$5 WHERE account_id=$1 AND peer_type='channel' AND peer_id=$2 AND source_id=$3 AND auth_generation=$6`, account, in.PeerID, source, in.SnapshotID, hash, generation); e != nil {
			return true, e
		}
		_, err = tx.Exec(ctx, `UPDATE noctis_v2.telegram_inventory_candidates SET source_id=$3 WHERE snapshot_id=$1 AND peer_id=$2`, in.SnapshotID, in.PeerID, source)
		result = map[string]any{"source_id": source, "imported": true, "activation": "explicit source policy required"}
	case isQuestion:
		var rev int64
		var title string
		var terms []byte
		if e = tx.QueryRow(ctx, `SELECT revision,title,terms FROM noctis_v2.questions WHERE id::text=$1 FOR UPDATE`, parts[1]).Scan(&rev, &title, &terms); e != nil {
			return true, e
		}
		if rev != in.ExpectedRevision {
			return true, &operationError{409, "stale_revision", rev}
		}
		if in.Title != "" {
			title = in.Title
		}
		if len(title) > 512 {
			return true, reject(400, "invalid_question")
		}
		if len(in.Terms) > 0 {
			if len(in.Terms) > 128 {
				return true, reject(400, "watch_term_limit")
			}
			for _, term := range in.Terms {
				if term.Type == "" || term.Value == "" || len(term.Value) > 512 {
					return true, reject(400, "invalid_watch_term")
				}
			}
			terms, _ = json.Marshal(in.Terms)
		}
		version := fmt.Sprintf("question:%s:r%d", parts[1], rev+1)
		_, err = tx.Exec(ctx, `UPDATE noctis_v2.questions SET revision=revision+1,title=$2,terms=$3,enabled=$4 WHERE id::text=$1`, parts[1], title, string(terms), in.Enabled)
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES($1,$2)`, version, string(terms))
		}
		if err == nil {
			_, err = tx.Exec(ctx, `UPDATE noctis_v2.sources s SET policy_version=$2,policy_revision=policy_revision+1 WHERE EXISTS(SELECT FROM noctis_v2.question_sources qs WHERE qs.source_id=s.id AND qs.question_id::text=$1)`, parts[1], version)
		}
		if err == nil {
			// New immutable job identities use the new PIR policy. Older in-flight
			// jobs are rejected by the worker's publication fence.
			_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version) SELECT gen_random_uuid(),'parse',o.id,o.revision,$2,'1' FROM noctis_v2.observations o JOIN noctis_v2.sources s ON s.id=o.source_id JOIN noctis_v2.question_sources qs ON qs.source_id=s.id WHERE qs.question_id::text=$1 AND `+intelligence.SourceAuthorizedSQL+` AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL ON CONFLICT DO NOTHING`, parts[1], version)
		}
		result = map[string]any{"id": parts[1], "revision": rev + 1, "enabled": in.Enabled, "policy_version": version}
	case path == "questions":
		if in.Title == "" || len(in.Title) > 512 || len(in.Terms) == 0 || len(in.Terms) > 128 {
			return true, reject(400, "question_and_terms_required")
		}
		for _, term := range in.Terms {
			if term.Type == "" || term.Value == "" || len(term.Value) > 512 {
				return true, reject(400, "invalid_watch_term")
			}
		}
		id := uuid.NewString()
		terms, _ := json.Marshal(in.Terms)
		version := "question:" + id
		_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.questions(id,title,terms) VALUES($1,$2,$3)`, id, in.Title, string(terms))
		if err == nil {
			_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.policies(version,terms) VALUES($1,$2)`, version, string(terms))
		}
		result = map[string]any{"id": id, "title": in.Title, "policy_version": version}
	case isSource:
		var version string
		var rev int64
		if e = tx.QueryRow(ctx, `SELECT policy_version,policy_revision FROM noctis_v2.sources WHERE id::text=$1 FOR UPDATE`, parts[1]).Scan(&version, &rev); e != nil {
			return true, e
		}
		if in.PolicyVersion == "" {
			in.PolicyVersion = version
		}
		var exists bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.policies WHERE version=$1)`, in.PolicyVersion).Scan(&exists); e != nil {
			return true, e
		}
		if !exists {
			return true, reject(400, "policy_not_found")
		}
		if in.ExpectedRevision != rev {
			return true, &operationError{409, "stale_revision", rev}
		}
		if in.Enabled {
			var missingBaseline bool
			if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id LEFT JOIN noctis_v2.telegram_inventory_candidates i ON i.snapshot_id=p.inventory_snapshot AND i.peer_id=p.peer_id WHERE s.id::text=$1 AND p.inventory_snapshot IS NOT NULL AND s.activated_at IS NULL AND COALESCE(i.pts,0)<=0)`, parts[1]).Scan(&missingBaseline); e != nil {
				return true, e
			}
			if missingBaseline {
				return true, reject(409, "current_channel_baseline_required")
			}
			_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.telegram_channel_states(account_id,channel_id,pts) SELECT p.account_id,p.peer_id,i.pts FROM noctis_v2.telegram_peers p JOIN noctis_v2.sources s ON s.id=p.source_id JOIN noctis_v2.telegram_inventory_candidates i ON i.snapshot_id=p.inventory_snapshot AND i.peer_id=p.peer_id WHERE s.id::text=$1 AND s.activated_at IS NULL AND i.pts>0 ON CONFLICT DO NOTHING`, parts[1])
			if err != nil {
				return true, err
			}
			var valid bool
			e = tx.QueryRow(ctx, `SELECT NOT EXISTS(SELECT FROM noctis_v2.telegram_peers p JOIN noctis_v2.telegram_accounts a ON a.id=p.account_id LEFT JOIN noctis_v2.telegram_inventory_snapshots n ON n.id=p.inventory_snapshot WHERE p.source_id::text=$1 AND p.inventory_snapshot IS NOT NULL AND (p.auth_generation<>a.auth_generation OR n.auth_generation<>a.auth_generation OR n.id IS DISTINCT FROM (SELECT z.id FROM noctis_v2.telegram_inventory_snapshots z WHERE z.account_id=a.id ORDER BY z.created_at DESC,z.id DESC LIMIT 1)))`, parts[1]).Scan(&valid)
			if e != nil {
				return true, e
			}
			if !valid {
				return true, reject(409, "inventory_identity_changed")
			}
			_, err = tx.Exec(ctx, `UPDATE noctis_v2.sources SET epoch=COALESCE(epoch,gen_random_uuid()),activated_at=COALESCE(activated_at,clock_timestamp()) WHERE id::text=$1`, parts[1])
			if err != nil {
				return true, err
			}
			_, err = tx.Exec(ctx, `UPDATE noctis_v2.telegram_peers SET allowed=true WHERE source_id::text=$1`, parts[1])
			if err != nil {
				return true, err
			}
		}
		err = tx.QueryRow(ctx, `UPDATE noctis_v2.sources SET enabled=$2,policy_version=$3,policy_revision=policy_revision+1 WHERE id::text=$1 RETURNING policy_revision`, parts[1], in.Enabled, in.PolicyVersion).Scan(&rev)
		if in.QuestionID == "" && strings.HasPrefix(in.PolicyVersion, "question:") {
			pieces := strings.Split(in.PolicyVersion, ":")
			if len(pieces) > 1 {
				if _, parseErr := uuid.Parse(pieces[1]); parseErr == nil {
					in.QuestionID = pieces[1]
				}
			}
		}
		if err == nil && in.QuestionID != "" {
			_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.question_sources(question_id,source_id) VALUES($1,$2) ON CONFLICT DO NOTHING`, in.QuestionID, parts[1])
		}
		if err == nil && in.Enabled {
			err = resumeSourceParseTx(ctx, tx, parts[1])
		} else if err == nil {
			err = pauseSourceParseTx(ctx, tx, parts[1])
		}
		result = map[string]any{"source_id": parts[1], "enabled": in.Enabled, "policy_version": in.PolicyVersion, "policy_revision": rev}
	case isCase && parts[2] == "lifecycle":
		if in.Action != "following" && in.Action != "resolved" && in.Action != "archived" {
			return true, reject(400, "invalid_lifecycle")
		}
		var rev int64
		if e = tx.QueryRow(ctx, `SELECT revision FROM noctis_v2.intelligence_cases WHERE id=$1`, parts[1]).Scan(&rev); e != nil {
			return true, e
		}
		if rev != in.ExpectedRevision {
			return true, &operationError{409, "stale_revision", rev}
		}
		_, err = tx.Exec(ctx, `WITH u AS(UPDATE noctis_v2.intelligence_cases SET lifecycle=$2,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING id,revision) INSERT INTO noctis_v2.case_revisions(case_id,revision,body) SELECT u.id,u.revision,cr.body||jsonb_build_object('revision',u.revision::text,'lifecycle',$2::text) FROM u JOIN noctis_v2.case_revisions cr ON cr.case_id=u.id AND cr.revision=u.revision-1`, parts[1], in.Action)
		result = map[string]any{"case_id": parts[1], "revision": rev + 1, "lifecycle": in.Action, "claims_unchanged": true}
	case path == "permissions":
		if actor != a.username {
			return true, reject(403, "admin_required")
		}
		if in.Permission != "export" && in.Permission != "discovery_authorize" && in.Permission != "retention" {
			return true, reject(400, "invalid_permission")
		}
		_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.operator_permissions VALUES($1,$2,$3) ON CONFLICT(actor,permission) DO UPDATE SET granted=excluded.granted`, actor, in.Permission, in.Granted)
		result = map[string]any{"permission": in.Permission, "granted": in.Granted}
	case isCase && parts[2] == "attention":
		before, e := attentionTx(ctx, tx, parts[1])
		if e != nil {
			return true, e
		}
		var att struct {
			Revision int64 `json:"revision"`
		}
		json.Unmarshal(before, &att)
		if in.ExpectedRevision != att.Revision {
			return true, &operationError{409, "stale_revision", att.Revision}
		}
		var caseRev int64
		if e = tx.QueryRow(ctx, `SELECT revision FROM noctis_v2.intelligence_cases WHERE id=$1`, parts[1]).Scan(&caseRev); e != nil {
			return true, e
		}
		mode := "automatic"
		var exception any
		switch in.Action {
		case "seen", "resume":
		case "silence", "exception":
			if strings.TrimSpace(in.Reason) == "" || len(in.Reason) > 4096 || in.Deadline == nil || !in.Deadline.After(time.Now()) || in.Deadline.After(time.Now().Add(30*24*time.Hour)) {
				return true, reject(400, "bounded_reason_and_deadline_required")
			}
			mode = "silent_until_change"
			if in.Action == "exception" {
				mode = "exception"
				b, _ := json.Marshal(map[string]any{"action": in.Reason, "deadline": in.Deadline, "status": "pending"})
				exception = string(b)
			}
		default:
			return true, reject(400, "invalid_attention_action")
		}
		_, err = tx.Exec(ctx, `UPDATE noctis_v2.case_attention SET revision=revision+1,seen_revision=$2,mode=$3,reason=$4,silent_until=$5,exception=$6 WHERE case_id=$1`, parts[1], caseRev, mode, in.Reason, in.Deadline, exception)
		if err == nil {
			result, err = attentionTx(ctx, tx, parts[1])
		}
	case isCase && parts[2] == "exports":
		if e = permissionTx(ctx, tx, actor, "export"); e != nil {
			return true, e
		}
		if in.Format != "json" {
			return true, reject(400, "format_json_required")
		}
		var revision int64
		var body []byte
		e = tx.QueryRow(ctx, `SELECT ic.revision,cr.body FROM noctis_v2.intelligence_cases ic JOIN noctis_v2.case_revisions cr ON cr.case_id=ic.id AND cr.revision=ic.revision WHERE ic.id=$1`, parts[1]).Scan(&revision, &body)
		if e != nil {
			return true, e
		}
		if revision != in.ExpectedRevision {
			return true, &operationError{409, "stale_revision", revision}
		}
		// Export contains citations and availability, never reconstructs an original
		// from a summary or from a blob retained for a different observation.
		rows, e := tx.Query(ctx, `SELECT jsonb_build_object('observation_id',o.id,'revision',o.revision,'hash',o.hash,'representation',o.representation,'label','original','availability',CASE WHEN o.retention_expired_at IS NOT NULL THEN 'expired' WHEN b.hash IS NULL THEN 'unavailable' ELSE 'available' END) FROM noctis_v2.case_memberships m JOIN noctis_v2.observations o ON o.id=m.observation_id LEFT JOIN noctis_v2.content_blobs b USING(hash,representation) WHERE m.case_id=$1 ORDER BY o.id`, parts[1])
		if e != nil {
			return true, e
		}
		refs := []json.RawMessage{}
		for rows.Next() {
			var v []byte
			if e = rows.Scan(&v); e != nil {
				rows.Close()
				return true, e
			}
			refs = append(refs, v)
		}
		rows.Close()
		if e = rows.Err(); e != nil {
			return true, e
		}
		id := uuid.NewString()
		expiry := time.Now().UTC().Add(5 * time.Minute)
		var claims []byte
		if e = tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(c)),'[]') FROM (SELECT DISTINCT ON(id) * FROM noctis_v2.claim_versions WHERE case_id=$1 ORDER BY id,revision DESC)c`, parts[1]).Scan(&claims); e != nil {
			return true, e
		}
		data := map[string]any{"case_id": parts[1], "revision": revision, "case": json.RawMessage(body), "claims": json.RawMessage(claims), "citations": refs, "representations": []string{"original references; availability per citation", "generated translations are separate AI products and never originals"}, "generated_at": time.Now().UTC(), "limitations": []string{"Claims preserve attributed and unresolved status; independence unknown; no original text reconstructed."}}
		encoded, _ := json.Marshal(data)
		_, err = tx.Exec(ctx, `INSERT INTO noctis_v2.private_exports(id,actor,case_id,revision,expires_at,body) VALUES($1,$2,$3,$4,$5,$6)`, id, actor, parts[1], revision, expiry, string(encoded))
		result = map[string]any{"id": id, "download_url": "/api/v2/exports/" + id, "expires_at": expiry, "revision": revision}
	case path == "runtime-control":
		if actor != a.username {
			return true, reject(403, "admin_required")
		}
		if in.Action != "pause" && in.Action != "resume" {
			return true, reject(400, "invalid_control_action")
		}
		var rev int64
		if e = tx.QueryRow(ctx, `SELECT revision FROM noctis_v2.runtime_control`).Scan(&rev); e != nil {
			return true, e
		}
		if rev != in.ExpectedRevision {
			return true, &operationError{409, "stale_revision", rev}
		}
		_, err = tx.Exec(ctx, `UPDATE noctis_v2.runtime_control SET paused=$1,revision=revision+1,reason=$2`, in.Action == "pause", in.Reason)
		result = map[string]any{"paused": in.Action == "pause", "revision": rev + 1, "preserved": []string{"inbox", "checkpoints", "jobs", "outbox", "ledger"}}
	case isDiscovery:
		result, err = a.mutateDiscovery(ctx, tx, actor, parts, in)
	case path == "retention":
		if e = permissionTx(ctx, tx, actor, "retention"); e != nil {
			return true, e
		}
		result, err = retentionTx(ctx, tx, in)
	default:
		return true, reject(405, "method_not_allowed")
	}
	if err != nil {
		return true, err
	}
	encoded, _ := json.Marshal(result)
	if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.action_receipts VALUES($1,$2,$3,$4,$5)`, actor, in.RequestID, path, digest, string(encoded)); e != nil {
		return true, e
	}
	audit, _ := json.Marshal(map[string]any{"request_id": in.RequestID, "result": result})
	if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.domain_audit(id,actor,action,result) VALUES($1,$2,$3,$4)`, uuid.NewString(), actor, path, string(audit)); e != nil {
		return true, e
	}
	if e = tx.Commit(ctx); e != nil {
		return true, e
	}
	if isDiscovery && len(parts) == 3 && parts[2] == "trial" && in.Action == "run" {
		trialID := result.(map[string]any)["id"].(string)
		allow := map[string]bool{}
		for _, host := range a.cfg.FixtureAuthorities {
			allow[host] = true
		}
		callErr := RunDiscoveryTrial(ctx, a.cfg.DatabaseURL, trialID, capture.Fetcher{AllowLocal: allow})
		state, code := "succeeded", ""
		if callErr != nil {
			state, code = "failed", "trial_fetch_failed_or_authorization_changed"
		}
		result = map[string]any{"id": trialID, "state": state, "error": code, "coverage": "bounded_fetch; semantic_coverage_unknown"}
		encoded, _ := json.Marshal(result)
		if _, e = c.Exec(ctx, `UPDATE noctis_v2.action_receipts SET result=$3 WHERE actor=$1 AND request_id=$2`, actor, in.RequestID, string(encoded)); e != nil {
			return true, e
		}
	}
	response(w, result)
	return true, nil
}

func (a *API) mutateDiscovery(ctx context.Context, tx pgx.Tx, actor string, parts []string, in operationInput) (any, error) {
	if len(parts) == 1 {
		if in.Kind != "rss" && in.Kind != "atom" && in.Kind != "html" && in.Kind != "paste" && in.Kind != "forum" {
			return nil, reject(400, "unsupported_source_kind")
		}
		if in.Endpoint == "" || len(in.Endpoint) > 4096 || len(in.Provenance) == 0 || strings.TrimSpace(in.Reason) == "" {
			return nil, reject(400, "provenance_and_reason_required")
		}
		if _, e := uuid.Parse(in.QuestionID); e != nil {
			return nil, reject(400, "question_required")
		}
		id := uuid.NewString()
		score := `{"basis":"operator_question_match","observed_yield":null,"independence":"unknown","not_based_on_repeated_claim_count":true}`
		_, e := tx.Exec(ctx, `INSERT INTO noctis_v2.discovery_proposals(id,question_id,kind,endpoint,provenance,reason,score,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,clock_timestamp()+interval '7 days')`, id, in.QuestionID, in.Kind, in.Endpoint, string(in.Provenance), in.Reason, score)
		return map[string]any{"id": id, "revision": 1, "permission_status": "proposed"}, e
	}
	if len(parts) != 3 {
		return nil, reject(404, "not_found")
	}
	var revision int64
	var status string
	var current bool
	e := tx.QueryRow(ctx, `SELECT revision,permission_status,expires_at>clock_timestamp() FROM noctis_v2.discovery_proposals WHERE id::text=$1 FOR UPDATE`, parts[1]).Scan(&revision, &status, &current)
	if e != nil {
		return nil, e
	}
	if revision != in.ExpectedRevision {
		return nil, &operationError{409, "stale_revision", revision}
	}
	switch parts[2] {
	case "authorize":
		if e = permissionTx(ctx, tx, actor, "discovery_authorize"); e != nil {
			return nil, e
		}
		if !current {
			return nil, reject(410, "proposal_expired")
		}
		var policy struct {
			Allowed bool   `json:"allowed"`
			Purpose string `json:"purpose"`
		}
		if json.Unmarshal(in.Policy, &policy) != nil || !policy.Allowed || strings.TrimSpace(policy.Purpose) == "" {
			return nil, reject(400, "explicit_policy_required")
		}
		_, e = tx.Exec(ctx, `UPDATE noctis_v2.discovery_proposals SET revision=revision+1,permission_status='authorized',policy=$2 WHERE id::text=$1`, parts[1], string(in.Policy))
	case "revoke":
		if e = permissionTx(ctx, tx, actor, "discovery_authorize"); e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `UPDATE noctis_v2.discovery_proposals SET revision=revision+1,permission_status='revoked' WHERE id::text=$1`, parts[1])
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE noctis_v2.discovery_trials SET state='revoked' WHERE proposal_id::text=$1 AND state='active'`, parts[1])
		}
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE noctis_v2.sources s SET enabled=false,policy_revision=policy_revision+1 FROM noctis_v2.discovery_proposals p WHERE p.id::text=$1 AND p.source_id=s.id`, parts[1])
		}
		if e == nil {
			_, e = tx.Exec(ctx, `UPDATE noctis_v2.outbox b SET state='blocked',blocked_reason='discovery_revoked' WHERE state='queued' AND EXISTS(SELECT FROM noctis_v2.discovery_proposals p JOIN noctis_v2.observations o ON o.source_id=p.source_id WHERE p.id::text=$1 AND b.body::text LIKE '%'||o.id::text||'%')`, parts[1])
		}
	case "activate":
		if e = permissionTx(ctx, tx, actor, "discovery_authorize"); e != nil {
			return nil, e
		}
		if status != "authorized" || !current {
			return nil, reject(403, "source_authorization_required")
		}
		var alreadyActivated bool
		if e = tx.QueryRow(ctx, `SELECT source_id IS NOT NULL FROM noctis_v2.discovery_proposals WHERE id::text=$1`, parts[1]).Scan(&alreadyActivated); e != nil {
			return nil, e
		}
		if alreadyActivated {
			return nil, reject(409, "source_already_activated")
		}
		var kind, endpoint, question string
		if e = tx.QueryRow(ctx, `SELECT kind,endpoint,question_id::text FROM noctis_v2.discovery_proposals WHERE id::text=$1`, parts[1]).Scan(&kind, &endpoint, &question); e != nil {
			return nil, e
		}
		// Activation always binds the current PIR revision, including after edits.
		var questionRevision int64
		if e = tx.QueryRow(ctx, `SELECT revision FROM noctis_v2.questions WHERE id=$1`, question).Scan(&questionRevision); e != nil {
			return nil, e
		}
		in.PolicyVersion = "question:" + question
		if questionRevision > 1 {
			in.PolicyVersion = fmt.Sprintf("question:%s:r%d", question, questionRevision)
		}
		var valid bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT FROM noctis_v2.policies WHERE version=$1)`, in.PolicyVersion).Scan(&valid); e != nil {
			return nil, e
		}
		if !valid {
			return nil, reject(400, "policy_not_found")
		}
		config := in.AdapterConfig
		if kind == "html" || kind == "paste" || kind == "forum" {
			var wc capture.WebConfig
			if json.Unmarshal(config, &wc) != nil || wc.ParserVersion == "" || wc.MaxItems < 1 || wc.MaxItems > 1000 {
				return nil, reject(400, "bounded_adapter_config_required")
			}
		} else if len(config) == 0 {
			config = json.RawMessage(`{}`)
		}
		source := uuid.NewString()
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.sources(id,kind,native_id,name,policy_version,enabled,epoch,activated_at,adapter_config) VALUES($1,$2,$3,$3,$4,true,$5,clock_timestamp(),$6)`, source, kind, endpoint, in.PolicyVersion, uuid.NewString(), string(config))
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.question_sources(question_id,source_id) VALUES($1,$2)`, question, source)
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec(ctx, `UPDATE noctis_v2.discovery_proposals SET source_id=$2,revision=revision+1 WHERE id::text=$1`, parts[1], source)
		return map[string]any{"id": parts[1], "source_id": source, "revision": revision + 1, "enabled": true}, e
	case "trial":
		if status != "authorized" || !current {
			return nil, reject(403, "source_authorization_required")
		}
		if in.TTL < 1 || in.TTL > 3600 || in.Quota < 1 || in.Quota > 100 {
			return nil, reject(400, "trial_bounds_required")
		}
		id := uuid.NewString()
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.discovery_trials(id,proposal_id,proposal_revision,expires_at,quota) VALUES($1,$2,$3,clock_timestamp()+$4::interval,$5)`, id, parts[1], revision, fmt.Sprintf("%d seconds", in.TTL), in.Quota)
		return map[string]any{"id": id, "state": "active", "quota": in.Quota, "ttl_seconds": in.TTL, "revision": revision}, e
	default:
		return nil, reject(405, "method_not_allowed")
	}
	return map[string]any{"id": parts[1], "revision": revision + 1}, e
}

// RunDiscoveryTrial reserves quota under a row lock and revalidates immediately
// before the wire. Reads never invoke this method. Each explicit run is bounded.
func RunDiscoveryTrial(ctx context.Context, dsn, id string, f capture.Fetcher) error {
	c, e := pgx.Connect(ctx, dsn)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	var endpoint string
	e = c.QueryRow(ctx, `UPDATE noctis_v2.discovery_trials t SET used=used+1 FROM noctis_v2.discovery_proposals p JOIN noctis_v2.questions q ON q.id=p.question_id WHERE t.id=$1 AND p.id=t.proposal_id AND t.state='active' AND t.expires_at>clock_timestamp() AND t.used<t.quota AND p.permission_status='authorized' AND p.revision=t.proposal_revision AND p.expires_at>clock_timestamp() AND q.enabled AND (p.source_id IS NULL OR EXISTS(SELECT FROM noctis_v2.sources s WHERE s.id=p.source_id AND `+intelligence.SourceAuthorizedSQL+`)) RETURNING p.endpoint`, id).Scan(&endpoint)
	if e != nil {
		return reject(409, "trial_expired_revoked_or_quota")
	}
	var questionRevision int64
	f.BeforeRequest = func(ctx context.Context) error {
		e := c.QueryRow(ctx, `SELECT q.revision FROM noctis_v2.discovery_trials t JOIN noctis_v2.discovery_proposals p ON p.id=t.proposal_id JOIN noctis_v2.questions q ON q.id=p.question_id WHERE t.id=$1 AND t.state='active' AND t.expires_at>clock_timestamp() AND p.expires_at>clock_timestamp() AND p.permission_status='authorized' AND p.revision=t.proposal_revision AND q.enabled AND (p.source_id IS NULL OR EXISTS(SELECT FROM noctis_v2.sources s WHERE s.id=p.source_id AND `+intelligence.SourceAuthorizedSQL+`))`, id).Scan(&questionRevision)
		if e != nil {
			return e
		}
		return nil
	}
	var callErr error
	callErr = intelligence.GuardProjectionIO(ctx, c, func(ioCtx context.Context) error {
		_, e := f.Get(ioCtx, endpoint)
		return e
	})
	code := ""
	if callErr != nil {
		code = "trial_fetch_failed"
	}
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE noctis_v2.discovery_trials t SET last_error=NULLIF($2,''),last_success_at=CASE WHEN $2='' THEN clock_timestamp() ELSE last_success_at END,coverage=CASE WHEN $2='' THEN 'bounded_fetch; semantic_coverage_unknown' ELSE 'unknown' END FROM noctis_v2.discovery_proposals p JOIN noctis_v2.questions q ON q.id=p.question_id WHERE t.id=$1 AND p.id=t.proposal_id AND t.state='active' AND t.expires_at>clock_timestamp() AND p.expires_at>clock_timestamp() AND p.permission_status='authorized' AND p.revision=t.proposal_revision AND q.enabled AND q.revision=$3 AND (p.source_id IS NULL OR EXISTS(SELECT FROM noctis_v2.sources s WHERE s.id=p.source_id AND `+intelligence.SourceAuthorizedSQL+`))`, id, code, questionRevision)
	if e != nil {
		return e
	}
	return errors.Join(callErr, tx.Commit(ctx))
}
