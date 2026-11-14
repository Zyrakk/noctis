package inference

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/Zyrakk/noctis/internal/jobs"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"time"
)

func digest(v any) string          { b, _ := json.Marshal(v); return fmt.Sprintf("%x", sha256.Sum256(b)) }
func semantic(f Function) bool     { return strings.HasPrefix(string(f), "semantic.") }
func compatible(a, b Binding) bool { a.Function = ""; b.Function = ""; return digest(a) == digest(b) }
func compatibleFunctions(c Config, b Binding) []Function {
	fs := []Function{b.Function}
	if semantic(b.Function) {
		fs = []Function{}
		for _, x := range c.Bindings {
			if semantic(x.Function) && x.Enabled && compatible(b, x) {
				fs = append(fs, x.Function)
			}
		}
	}
	return fs
}
func (s Store) Submit(ctx context.Context, in Submit, actor string) (JobView, error) {
	spec, ok := Spec(in.Function)
	if !ok || spec.InputKind != in.Input.Kind || actor == "" || in.RequestID == "" || len(in.RequestID) > 128 {
		return JobView{}, ErrInvalid
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return JobView{}, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return JobView{}, e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(76238451004)`); e != nil {
		return JobView{}, e
	}
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return JobView{}, e
	}
	var priorID string
	var priorInput []byte
	var priorFunc Function
	e = tx.QueryRow(ctx, `SELECT id::text,input,function_id FROM noctis_v2.ai_jobs WHERE actor=$1 AND request_id=$2`, actor, in.RequestID).Scan(&priorID, &priorInput, &priorFunc)
	if e == nil {
		var prev Input
		json.Unmarshal(priorInput, &prev)
		if priorFunc != in.Function || digest(prev) != digest(in.Input) {
			return JobView{}, ErrConflict
		}
		tx.Rollback(ctx)
		return s.Job(ctx, priorID, actor)
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return JobView{}, e
	}
	cfg, e := readConfig(ctx, tx)
	if e != nil {
		return JobView{}, e
	}
	if cfg.Revision == 0 {
		cfg.Revision = 1
		raw, _ := json.Marshal(cfg)
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.ai_configs(revision,body,actor) VALUES(1,$1,'system:disabled-bootstrap')`, string(raw)); e != nil {
			return JobView{}, e
		}
	}
	snap, e := snapshot(ctx, tx, in.Input, actor)
	if e != nil {
		return JobView{}, e
	}
	state, code := "queued", ""
	if semantic(in.Function) {
		var gate struct {
			Gate string `json:"gate"`
		}
		if json.Unmarshal(snap.Context, &gate) != nil || (gate.Gate != "relevant" && gate.Gate != "unknown") {
			state = "dependency_blocked"
			code = "mechanical_gate_ineligible"
		}
	}
	b, conn, be := findBinding(cfg, in.Function)
	if be != nil {
		state = "dependency_blocked"
		code = "function_disabled"
	}
	if be == nil && !allowedClass(conn, snap.Input.DataClass) {
		state = "dependency_blocked"
		code = "data_class_denied"
	}
	cacheBinding := b
	if semantic(in.Function) {
		cacheBinding.Function = ""
	}
	key := jobCacheKey(cfg.Revision, cacheBinding, snap)
	id := uuid.NewString()
	raw, _ := json.Marshal(in.Input)
	sr, _ := json.Marshal(snap)
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.ai_jobs(id,actor,request_id,function_id,input,snapshot,config_revision,state,error_code,cache_key) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10)`, id, actor, in.RequestID, in.Function, string(raw), string(sr), cfg.Revision, state, code, key)
	if e != nil {
		return JobView{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return JobView{}, e
	}
	return s.Job(ctx, id, actor)
}
func jobCacheKey(revision int64, binding Binding, snapshot Snapshot) string {
	return digest(struct {
		Config   int64
		Binding  Binding
		Snapshot Snapshot
	}{revision, binding, snapshot})
}
func allowedClass(c Connection, class string) bool {
	for _, d := range c.DataClasses {
		if d == class {
			return true
		}
	}
	return false
}
func (s Store) Job(ctx context.Context, id, actor string) (JobView, error) {
	j := JobView{ID: id, StatusURL: "/api/v2/ai/jobs/" + id, Refs: []evidence.Ref{}, Limitations: []string{}}
	if _, e := uuid.Parse(id); e != nil {
		return j, pgx.ErrNoRows
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return j, e
	}
	defer c.Close(context.Background())
	var raw []byte
	var code *string
	var snapRaw []byte
	e = c.QueryRow(ctx, `SELECT function_id,state,result,error_code,snapshot FROM noctis_v2.ai_jobs WHERE id=$1 AND actor=$2`, id, actor).Scan(&j.Function, &j.State, &raw, &code, &snapRaw)
	if e != nil {
		return j, e
	}
	if code != nil {
		j.Error, j.ValidationReason = validationCode(*code)
	}
	j.Terminal = j.State == "succeeded" || j.State == "failed" || j.State == "cancelled" || j.State == "dependency_blocked" || j.State == "budget_blocked"
	if len(raw) > 0 {
		var result Result
		if json.Unmarshal(raw, &result) != nil {
			return j, ErrInvalid
		}
		var snap Snapshot
		if json.Unmarshal(snapRaw, &snap) != nil {
			return j, ErrInvalid
		}
		tx, e := c.Begin(ctx)
		if e != nil {
			return j, e
		}
		defer tx.Rollback(context.Background())
		if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
			return j, e
		}
		if e = validateSnapshot(ctx, tx, snap, actor); e != nil {
			j.State = "dependency_blocked"
			j.Error = "result_requires_revalidation"
			j.Terminal = true
			j.Limitations = []string{"The evidence or context changed; this historical result is no longer current."}
			return j, nil
		}
		j.Result = &result
		j.Refs = result.Refs
		j.Limitations = result.Limitations
	}
	return j, nil
}
func (s Store) Cancel(ctx context.Context, id, actor string) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tag, e := c.Exec(ctx, `UPDATE noctis_v2.ai_jobs SET state='cancelled',fence=fence+1,lease_until=NULL WHERE id=$1 AND actor=$2 AND state NOT IN ('succeeded','failed','cancelled')`, id, actor)
	if e == nil && tag.RowsAffected() == 0 {
		var exists bool
		e = c.QueryRow(ctx, `SELECT true FROM noctis_v2.ai_jobs WHERE id=$1 AND actor=$2`, id, actor).Scan(&exists)
	}
	return e
}

type execution struct {
	ID, Actor, Cache string
	Function         Function
	Fence            int64
	Revision         int64
	Attempts         int
	Snapshot         Snapshot
	Binding          Binding
	Connection       Connection
	Functions        []Function
	Group            []leasedJob
	Attempt          string
	Key              string
	Cached           *Result
}
type leasedJob struct {
	ID       string
	Function Function
	Fence    int64
}

// Once performs one bounded physical invocation. Running leases survive crashes;
// possible remote execution is quarantined as uncertainty, never blindly retried.
func (s Store) Once(ctx context.Context) error {
	x, e := s.claim(ctx)
	if e != nil {
		return e
	}
	if x.Cached != nil {
		return s.publish(ctx, x, *x.Cached)
	}
	g, e := s.authorizedWire(ctx, x)
	// Accounting is independent of publication fencing, including cancelled jobs.
	if re := s.reconcile(context.WithoutCancel(ctx), x, g, e); re != nil {
		return re
	}
	if e != nil {
		return s.fail(ctx, x, e)
	}
	if g.Model == "unknown" {
		g.Result.Limitations = append(g.Result.Limitations, "The provider does not report the actual model; upstream identity is unknown.")
	}
	if g.Usage == nil {
		g.Result.Limitations = append(g.Result.Limitations, "Usage not reported: the uncertain maximum exposure is retained.")
	}
	if e = validateResult(x, g.Result); e != nil {
		return s.fail(ctx, x, e)
	}
	return s.publish(ctx, x, g.Result)
}
func (s Store) claim(ctx context.Context) (execution, error) {
	var x execution
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return x, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return x, e
	}
	defer tx.Rollback(context.Background())
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(76238451004)`); e != nil {
		return x, e
	}
	// A killed attempt may have crossed the wire. Keep the maximum exposure.
	if _, e = tx.Exec(ctx, `UPDATE noctis_v2.ai_attempts a SET state='uncertain' FROM noctis_v2.ai_jobs j WHERE a.job_id=j.id AND a.state IN ('reserved','sent') AND (j.state<>'running' OR j.lease_until<=clock_timestamp());UPDATE noctis_v2.ai_jobs j SET state='dependency_blocked',error_code='execution_uncertain',lease_until=NULL WHERE j.state='running' AND j.lease_until<=clock_timestamp() AND EXISTS(SELECT FROM noctis_v2.ai_attempts a JOIN noctis_v2.ai_attempt_jobs aj ON aj.attempt_id=a.id WHERE aj.job_id=j.id AND a.state='uncertain')`); e != nil {
		return x, e
	}
	var sr []byte
	e = tx.QueryRow(ctx, `SELECT id::text,actor,function_id,config_revision,snapshot,cache_key,fence+1,attempts+1 FROM noctis_v2.ai_jobs WHERE state='queued' OR (state='retry_wait' AND retry_at<=clock_timestamp() AND attempts<5) OR (state='running' AND lease_until<=clock_timestamp()) ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1`).Scan(&x.ID, &x.Actor, &x.Function, &x.Revision, &sr, &x.Cache, &x.Fence, &x.Attempts)
	if errors.Is(e, pgx.ErrNoRows) {
		if ce := tx.Commit(ctx); ce != nil {
			return x, ce
		}
		return x, e
	}
	if e != nil {
		return x, e
	}
	if json.Unmarshal(sr, &x.Snapshot) != nil {
		return x, ErrInvalid
	}
	cfg, e := readConfig(ctx, tx)
	if e != nil {
		return x, e
	}
	block := func(code, state string) (execution, error) {
		_, e := tx.Exec(ctx, `UPDATE noctis_v2.ai_jobs SET state=$2,error_code=$3,lease_until=NULL WHERE id=$1`, x.ID, state, code)
		if e == nil {
			e = tx.Commit(ctx)
		}
		if e != nil {
			return x, e
		}
		return x, pgx.ErrNoRows
	}
	if cfg.Revision != x.Revision {
		return block("configuration_changed", "dependency_blocked")
	}
	b, conn, e := findBinding(cfg, x.Function)
	if e != nil {
		return block("function_disabled", "dependency_blocked")
	}
	if !allowedClass(conn, x.Snapshot.Input.DataClass) {
		return block("data_class_denied", "dependency_blocked")
	}
	x.Binding = b
	x.Connection = conn
	x.Functions = compatibleFunctions(cfg, b)
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return x, e
	}
	if e = validateSnapshot(ctx, tx, x.Snapshot, x.Actor); e != nil {
		return block("dependency_changed", "dependency_blocked")
	}
	x.Key, e = s.decrypt(ctx, tx, cfg.Revision, conn.ID)
	if e != nil {
		return block("credential_unavailable", "dependency_blocked")
	}
	if x.Key == "" {
		return block("credential_missing", "dependency_blocked")
	}
	x.Group = []leasedJob{{x.ID, x.Function, x.Fence}}
	if semantic(x.Function) {
		rows, e := tx.Query(ctx, `SELECT id::text,function_id,fence+1 FROM noctis_v2.ai_jobs WHERE cache_key=$1 AND actor=$2 AND id<>$3 AND state='queued' ORDER BY id FOR UPDATE`, x.Cache, x.Actor, x.ID)
		if e != nil {
			return x, e
		}
		for rows.Next() {
			var j leasedJob
			if e = rows.Scan(&j.ID, &j.Function, &j.Fence); e != nil {
				rows.Close()
				return x, e
			}
			x.Group = append(x.Group, j)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return x, e
		}
	}
	var cached []byte
	ce := tx.QueryRow(ctx, `SELECT result FROM noctis_v2.ai_jobs WHERE cache_key=$1 AND actor=$2 AND state='succeeded' AND result IS NOT NULL ORDER BY created_at DESC LIMIT 1`, x.Cache, x.Actor).Scan(&cached)
	if ce == nil {
		var r Result
		if json.Unmarshal(cached, &r) != nil {
			return x, ErrInvalid
		}
		if semantic(x.Function) {
			r.Kind = "semantic"
		}
		x.Cached = &r
		for _, j := range x.Group {
			if _, e = tx.Exec(ctx, `UPDATE noctis_v2.ai_jobs SET state='running',fence=$2,lease_until=clock_timestamp()+interval '3 minutes' WHERE id=$1`, j.ID, j.Fence); e != nil {
				return x, e
			}
		}
		return x, tx.Commit(ctx)
	}
	if !errors.Is(ce, pgx.ErrNoRows) {
		return x, ce
	}
	maximum := int64(b.Limits.MaxInputTokens)*b.Price.Input + int64(b.Limits.MaxOutputTokens)*b.Price.Output
	// All cap checks share a transaction lock across processes. Global exposure is
	// counted once per physical attempt; compound functions each retain attribution.
	for _, period := range []struct {
		SQL    string
		Global int64
		Daily  bool
	}{{"date_trunc('day',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'", cfg.DailyCap, true}, {"date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'", cfg.MonthlyCap, false}} {
		var used int64
		if e = tx.QueryRow(ctx, `SELECT COALESCE(sum(exposure_units),0) FROM noctis_v2.ai_attempts WHERE created_at>=`+period.SQL).Scan(&used); e != nil {
			return x, e
		}
		if used > period.Global-maximum {
			return block("global_budget_exhausted", "budget_blocked")
		}
		for _, f := range x.Functions {
			fb, _, fe := findBinding(cfg, f)
			if fe != nil {
				return x, fe
			}
			cap := fb.MonthlyCap
			if period.Daily {
				cap = fb.DailyCap
			}
			if e = tx.QueryRow(ctx, `SELECT COALESCE(sum(exposure_units),0) FROM noctis_v2.ai_attempts WHERE functions ? $1 AND created_at>=`+period.SQL, string(f)).Scan(&used); e != nil {
				return x, e
			}
			if used > cap-maximum {
				return block("function_budget_exhausted", "budget_blocked")
			}
		}
	}
	var active int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_attempts WHERE state IN ('reserved','sent')`).Scan(&active); e != nil {
		return x, e
	}
	if active >= cfg.MaxConcurrent {
		return block("global_concurrency_cap", "budget_blocked")
	}
	for _, f := range x.Functions {
		fb, _, _ := findBinding(cfg, f)
		if e = tx.QueryRow(ctx, `SELECT count(*) FROM noctis_v2.ai_attempts WHERE state IN ('reserved','sent') AND functions ? $1`, string(f)).Scan(&active); e != nil {
			return x, e
		}
		if active >= fb.MaxConcurrent {
			return block("function_concurrency_cap", "budget_blocked")
		}
	}
	x.Attempt = uuid.NewString()
	br, _ := json.Marshal(b)
	cr, _ := json.Marshal(conn)
	fr, _ := json.Marshal(x.Functions)
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.ai_attempts(id,job_id,fence,config_revision,function_id,functions,binding,connection,maximum_units,exposure_units,state,requested_model) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,'reserved',$10)`, x.Attempt, x.ID, x.Fence, x.Revision, x.Function, string(fr), string(br), string(cr), maximum, b.Model)
	if e != nil {
		return x, e
	}
	for _, j := range x.Group {
		if _, e = tx.Exec(ctx, `INSERT INTO noctis_v2.ai_attempt_jobs(attempt_id,job_id,fence) VALUES($1,$2,$3)`, x.Attempt, j.ID, j.Fence); e != nil {
			return x, e
		}
		_, e = tx.Exec(ctx, `UPDATE noctis_v2.ai_jobs SET state='running',fence=$2,lease_until=clock_timestamp()+interval '3 minutes',attempts=attempts+1,error_code=NULL WHERE id=$1`, j.ID, j.Fence)
		if e != nil {
			return x, e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return x, e
	}
	// Revalidate enablement/credentials/privacy immediately before network. This
	// transaction is short; no network runs while holding configuration locks.
	c2, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return x, e
	}
	defer c2.Close(context.Background())
	var current int64
	e = c2.QueryRow(ctx, `SELECT max(revision) FROM noctis_v2.ai_configs`).Scan(&current)
	if e != nil {
		return x, e
	}
	if current != x.Revision {
		g := &GatewayError{"configuration_changed", true, false, 0}
		s.reconcile(ctx, x, GatewayResult{}, g)
		s.fail(ctx, x, g)
		return x, pgx.ErrNoRows
	}
	_, e = c2.Exec(ctx, `UPDATE noctis_v2.ai_attempts SET state='sent' WHERE id=$1 AND state='reserved'`, x.Attempt)
	return x, e
}
func (s Store) reconcile(ctx context.Context, x execution, r GatewayResult, callErr error) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	state := "settled"
	if r.Model == "" {
		r.Model = "unknown"
	}
	var actual any
	var usage any
	if r.Usage != nil {
		actual = r.Usage.Input*x.Binding.Price.Input + r.Usage.Output*x.Binding.Price.Output
		raw, _ := json.Marshal(r.Usage)
		usage = string(raw)
	} else {
		var ge *GatewayError
		if callErr == nil || !errors.As(callErr, &ge) || ge.Uncertain {
			state = "uncertain"
		} else {
			state = "released"
			actual = int64(0)
		}
	}
	_, e = c.Exec(ctx, `UPDATE noctis_v2.ai_attempts SET state=$2,actual_units=$3,exposure_units=CASE WHEN $2='uncertain' THEN exposure_units ELSE $3::bigint END,declared_model=$4,usage=$5,accounting_exception=CASE WHEN $3::bigint>maximum_units THEN 'actual_exceeds_reservation' WHEN $4<>requested_model AND $4<>'unknown' THEN 'declared_model_changed' ELSE NULL END WHERE id=$1 AND state IN ('reserved','sent','uncertain')`, x.Attempt, state, actual, r.Model, usage)
	return e
}
func (s Store) fail(ctx context.Context, x execution, cause error) error {
	var ge *GatewayError
	if !errors.As(cause, &ge) {
		ge = &GatewayError{"publication_rejected", true, false, 0}
	}
	var validation *ResultValidationError
	if errors.As(cause, &validation) {
		ge = &GatewayError{validation.Error(), true, false, 0}
	}
	state := "failed"
	code := ge.Code
	var diagnostic *TransportDiagnostic
	if errors.As(cause, &diagnostic) {
		code = diagnostic.Error()
	}
	delay := ge.RetryAfter
	if delay < time.Second {
		delay = time.Second * time.Duration(1<<min(x.Attempts, 8))
	}
	if !ge.Permanent && !ge.Uncertain && x.Attempts < 5 {
		state = "retry_wait"
	}
	if ge.Uncertain {
		state = "dependency_blocked"
	}
	c, e := pgx.Connect(context.WithoutCancel(ctx), s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	for _, j := range x.Group {
		_, e = c.Exec(context.WithoutCancel(ctx), `UPDATE noctis_v2.ai_jobs SET state=$3,error_code=$4,retry_at=clock_timestamp()+$5::interval,lease_until=NULL WHERE id=$1 AND fence=$2 AND state='running'`, j.ID, j.Fence, state, code, delay.String())
		if e != nil {
			return e
		}
	}
	return nil
}
func validateResult(x execution, r Result) error {
	if r.Labels == nil || r.Claims == nil || r.Entities == nil || r.Roles == nil || r.Refs == nil || r.Limitations == nil {
		return invalidResult("null_collections")
	}
	if r.SchemaVersion != "1" || (r.Kind != string(x.Function) && !(semantic(x.Function) && r.Kind == "semantic")) {
		return invalidResult("version_kind")
	}
	if len(r.Text) > 131072 || len(r.Labels) > 32 || len(r.Claims) > 128 || len(r.Entities) > 128 || len(r.Roles) > 256 || len(r.Refs) > 256 || len(r.Limitations) > 64 {
		return invalidResult("limits")
	}
	for _, l := range r.Limitations {
		if len(l) > 4096 {
			return invalidResult("limits")
		}
	}
	for _, l := range r.Labels {
		switch l {
		case "access_offer", "news", "rumor", "denial", "research", "direct_evidence", "irrelevant", "relevant", "unknown":
		default:
			return invalidResult("labels_intent")
		}
	}
	switch r.Intent {
	case "", "seller_claim", "report", "negation", "research", "unknown":
	default:
		return invalidResult("labels_intent")
	}
	validRefs := func(refs []evidence.Ref, required bool) bool {
		if required && len(refs) == 0 {
			return false
		}
		for _, r := range refs {
			ok := false
			for _, d := range x.Snapshot.Documents {
				a := d.Ref
				if r.ObservationID == a.ObservationID && r.Revision == a.Revision && r.Hash == a.Hash && r.Representation == a.Representation && r.Start >= 0 && r.End <= a.End && r.Start < r.End {
					full := ""
					for _, c := range d.Segments {
						full += c.Text
					}
					if r.Validate([]byte(full)) == nil {
						ok = true
					}
				}
			}
			if !ok {
				return false
			}
		}
		return true
	}
	if !validRefs(r.Refs, len(x.Snapshot.Documents) > 0) {
		return invalidResult("root_refs")
	}
	for _, c := range r.Claims {
		if c.Subject == "" || len(c.Subject) > 512 || c.Predicate == "" || len(c.Predicate) > 128 || c.Object == "" || len(c.Object) > 4096 || !validRefs(c.Refs, true) {
			return invalidResult("claim_fields_refs")
		}
	}
	for _, v := range r.Entities {
		if v.Kind == "" || len(v.Kind) > 64 || v.Alias == "" || len(v.Alias) > 512 || v.Scope == "" || len(v.Scope) > 256 || v.Language == "" || len(v.Language) > 32 || !validRefs(v.Refs, true) {
			return invalidResult("entity_fields_refs")
		}
	}
	for _, v := range r.Roles {
		if v.Type == "" || len(v.Type) > 64 || v.Value == "" || len(v.Value) > 2048 || !validRefs(v.Refs, true) {
			return invalidResult("role_fields_refs")
		}
		switch v.Role {
		case "claimed_target", "reference", "benign", "unknown", "claimed_infrastructure":
		default:
			return invalidResult("role_fields_refs")
		}
		found := false
		for _, d := range x.Snapshot.Documents {
			full := ""
			for _, chunk := range d.Segments {
				full += chunk.Text
			}
			observables, e := intelligence.Extract([]byte(full), d.Ref)
			if e != nil {
				return invalidResult("observable_extraction")
			}
			for _, obs := range observables {
				if obs.Type == v.Type && obs.Value == v.Value {
					for _, ref := range v.Refs {
						if ref.ObservationID == obs.Evidence.ObservationID && ref.Start <= obs.Evidence.Start && ref.End >= obs.Evidence.End {
							found = true
						}
					}
				}
			}
		}
		if !found {
			return invalidResult("observable_extraction")
		}
	}
	if x.Function == "query.plan" {
		if r.Plan == nil || ValidatePlan(*r.Plan) != nil {
			return invalidResult("plan")
		}
	} else if r.Plan != nil {
		return invalidResult("plan")
	}
	if x.Function == "identity.disambiguate" {
		if r.Identity == nil || !validRefs(r.Identity.Refs, true) || len(r.Identity.Relation) > 128 || r.Identity.Relation == "" {
			return invalidResult("identity")
		}
	} else if r.Identity != nil {
		return invalidResult("identity")
	}
	return nil
}
func (s Store) publish(ctx context.Context, x execution, result Result) error {
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(context.Background())
	fail := func(code string) error {
		tx.Rollback(context.Background())
		return s.fail(ctx, x, &GatewayError{code, true, false, 0})
	}
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(76238451004)`); e != nil {
		return e
	}
	if e = intelligence.LockProjectionTx(ctx, tx); e != nil {
		return e
	}
	cfg, e := readConfig(ctx, tx)
	if e != nil {
		return e
	}
	if cfg.Revision != x.Revision {
		return fail("configuration_changed")
	}
	if e = validateSnapshot(ctx, tx, x.Snapshot, x.Actor); e != nil {
		return fail("dependency_changed")
	}
	for _, j := range x.Group {
		var valid bool
		e = tx.QueryRow(ctx, `SELECT true FROM noctis_v2.ai_jobs WHERE id=$1 AND state='running' AND fence=$2 AND lease_until>clock_timestamp() FOR UPDATE`, j.ID, j.Fence).Scan(&valid)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			return e
		}
		r := result
		r.Kind = string(j.Function)
		r.Limitations = append(r.Limitations, "AI output: source claims or proposals; it does not confirm facts or attribution.")
		tag, pe := tx.Exec(ctx, `INSERT INTO noctis_v2.ai_publications(cache_key,function_id,job_id) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, x.Cache, j.Function, j.ID)
		if pe != nil {
			return pe
		}
		// Only observation semantic jobs enter the domain analysis boundary.
		if semantic(j.Function) {
			if tag.RowsAffected() == 1 {
				if e = publishObservation(ctx, tx, x, j, r); e != nil {
					return fail("domain_publication_rejected")
				}
			}
		}
		if j.Function == "identity.disambiguate" && tag.RowsAffected() == 1 {
			if _, e = intelligence.ProposeIdentityTx(ctx, tx, x.Snapshot.Input.ID, x.Snapshot.Input.RightID, r.Identity.Relation, r.Identity.Refs); e != nil {
				return e
			}
		}
		if j.Function == "vulnerability.context" {
			r.Limitations = append(r.Limitations, "Local applicability and exposure: unknown; this text does not alter feed facts.")
		}
		if j.Function == "evidence.translate" {
			r.Limitations = append(r.Limitations, "Generated translation; consult the linked original representation.")
		}
		raw, _ := json.Marshal(r)
		deps, _ := json.Marshal(x.Snapshot)
		_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.ai_products(job_id,function_id,input_kind,input_id,input_revision,dependencies,result) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(job_id) DO NOTHING`, j.ID, j.Function, x.Snapshot.Input.Kind, x.Snapshot.Input.ID, x.Snapshot.Input.Revision, string(deps), string(raw))
		if e != nil {
			return e
		}
		tag, e = tx.Exec(ctx, `UPDATE noctis_v2.ai_jobs SET state='succeeded',result=$3,lease_until=NULL WHERE id=$1 AND fence=$2 AND state='running' AND lease_until>clock_timestamp()`, j.ID, j.Fence, string(raw))
		if e != nil {
			return e
		}
		if tag.RowsAffected() != 1 {
			return jobs.ErrLeaseLost
		}
	}
	return tx.Commit(ctx)
}
func publishObservation(ctx context.Context, tx pgx.Tx, x execution, j leasedJob, r Result) error {
	var policy, caseID string
	e := tx.QueryRow(ctx, `SELECT s.policy_version,m.case_id::text FROM noctis_v2.observations o JOIN noctis_v2.sources s ON s.id=o.source_id JOIN noctis_v2.case_memberships m ON m.observation_id=o.id WHERE o.id=$1 AND s.enabled ORDER BY m.case_id LIMIT 1`, x.Snapshot.Input.ID).Scan(&policy, &caseID)
	if e != nil {
		return e
	}
	key := jobs.Key{Stage: "ai:" + j.ID, InputID: x.Snapshot.Input.ID, InputRevision: x.Snapshot.Input.Revision, PolicyVersion: policy, SchemaVersion: "1"}
	domainJob := uuid.NewString()
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.jobs(id,stage,input_id,input_revision,policy_version,schema_version,state,lease_owner,lease_expires_at,fence) VALUES($1,$2,$3,$4,$5,$6,'leased',$7,clock_timestamp()+interval '1 minute',$8)`, domainJob, key.Stage, key.InputID, key.InputRevision, key.PolicyVersion, key.SchemaVersion, j.ID, j.Fence)
	if e != nil {
		return e
	}
	a := intelligence.ValidatedAnalysis{JobKey: key, Producer: "inference:" + j.ID, Refs: r.Refs, Limitations: r.Limitations}
	// Compound results are projected by function, so a coalesced semantic pass
	// cannot duplicate claims or entity proposals for every selected function.
	if j.Function == "semantic.claims" {
		for _, v := range r.Claims {
			a.Claims = append(a.Claims, intelligence.AnalysisClaim{ID: uuid.NewString(), CaseID: caseID, Subject: v.Subject, Predicate: v.Predicate, Object: v.Object, Refs: v.Refs})
		}
	}
	if j.Function == "semantic.entities_relations" {
		for _, v := range r.Entities {
			a.Proposals = append(a.Proposals, intelligence.EntityProposal{Kind: v.Kind, Alias: v.Alias, Scope: v.Scope, Language: v.Language, Refs: v.Refs})
		}
	}
	if j.Function == "semantic.observable_roles" {
		for _, v := range r.Roles {
			a.Roles = append(a.Roles, intelligence.ObservableRole{Type: v.Type, Value: v.Value, Role: v.Role, Refs: v.Refs})
		}
	}
	return jobs.FinishTx(ctx, tx, jobs.Job{ID: domainJob, Key: key, Lease: jobs.Lease{Owner: j.ID, Fence: j.Fence}}, func(tx pgx.Tx) error { return intelligence.ApplyAnalysisTx(ctx, tx, a) })
}
