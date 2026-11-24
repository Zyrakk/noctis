package inference

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)

func Chunks(text string, size int) ([]Segment, error) {
	if !utf8.ValidString(text) || size < 4 {
		return nil, ErrInvalid
	}
	out := []Segment{}
	for start := 0; start < len(text); {
		end := min(start+size, len(text))
		for end < len(text) && !utf8.RuneStart(text[end]) {
			end--
		}
		out = append(out, Segment{start, end, text[start:end]})
		start = end
	}
	return out, nil
}
func document(ctx context.Context, tx pgx.Tx, id, rev string) (Document, error) {
	var d Document
	var raw []byte
	e := tx.QueryRow(ctx, `SELECT o.id::text,o.revision,o.hash,o.representation,b.payload,s.id::text,s.policy_version,s.epoch::text FROM noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) JOIN noctis_v2.sources s ON s.id=o.source_id WHERE o.id=$1 AND ($2='' OR o.revision=$2) AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL AND `+intelligence.SourceAuthorizedSQL+` FOR SHARE OF o,s`, id, rev).Scan(&d.Ref.ObservationID, &d.Ref.Revision, &d.Ref.Hash, &d.Ref.Representation, &raw, &d.SourceID, &d.SourcePolicy, &d.Epoch)
	if e != nil {
		return d, e
	}
	if len(raw) == 0 {
		return d, errors.New("empty evidence")
	}
	d.Ref.End = len(raw)
	d.Segments, e = Chunks(string(raw), 8192)
	return d, e
}
func snapshot(ctx context.Context, tx pgx.Tx, in Input, actor string) (Snapshot, error) {
	s := Snapshot{Input: in, Documents: []Document{}, Dependencies: []Dependency{}, Context: json.RawMessage(`{}`)}
	// Data classification is server controlled. An operator cannot downgrade private captures.
	s.Input.DataClass = "private-approved"
	switch in.Kind {
	case "observation":
		if _, e := uuid.Parse(in.ID); e != nil || in.Revision == "" {
			return s, ErrInvalid
		}
		d, e := document(ctx, tx, in.ID, in.Revision)
		if e != nil {
			return s, e
		}
		s.Documents = append(s.Documents, d)
		var contextRaw []byte
		e = tx.QueryRow(ctx, `SELECT jsonb_build_object('observables',observables,'gate',gate,'policy_version',policy_version) FROM noctis_v2.analyses WHERE observation_id=$1 AND policy_version=$2 AND stage='parse' ORDER BY schema_version DESC LIMIT 1`, in.ID, d.SourcePolicy).Scan(&contextRaw)
		if e == nil {
			s.Context = contextRaw
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return s, e
		}
	case "case":
		var rev string
		var raw []byte
		e := tx.QueryRow(ctx, `SELECT c.revision::text,noctis_v2.case_effective_body(c.id,r.body) FROM noctis_v2.intelligence_cases c JOIN noctis_v2.case_revisions r ON r.case_id=c.id AND r.revision=c.revision WHERE c.id=$1 AND c.revision::text=$2 FOR SHARE OF c`, in.ID, in.Revision).Scan(&rev, &raw)
		if e != nil {
			return s, e
		}
		s.Context = raw
		s.Dependencies = append(s.Dependencies, Dependency{"case", in.ID, rev})
		rows, e := tx.Query(ctx, `SELECT m.observation_id::text FROM noctis_v2.case_memberships m JOIN noctis_v2.observations o ON o.id=m.observation_id WHERE m.case_id=$1 AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL ORDER BY m.observation_id LIMIT 201`, in.ID)
		if e != nil {
			return s, e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return s, e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil || len(ids) > 200 {
			return s, errors.New("case exceeds bounded context")
		}
		for _, id := range ids {
			d, e := document(ctx, tx, id, "")
			if e != nil {
				return s, e
			}
			s.Documents = append(s.Documents, d)
		}
	case "brief":
		if _, e := strconv.ParseInt(strings.ReplaceAll(in.Period, "-", ""), 10, 64); e != nil || len(in.Period) != 10 {
			return s, ErrInvalid
		}
		var raw []byte
		var version string
		e := tx.QueryRow(ctx, `SELECT body,policy_version FROM noctis_v2.briefs WHERE period=$1 AND NOT invalidated AND noctis_v2.brief_applicability_current(body) ORDER BY policy_version DESC LIMIT 1`, in.Period).Scan(&raw, &version)
		if e != nil {
			return s, e
		}
		s.Context = raw
		s.Dependencies = append(s.Dependencies, Dependency{"brief", in.Period, version})
		rows, e := tx.Query(ctx, `SELECT DISTINCT observation_id::text FROM noctis_v2.case_changes WHERE created_at>=$1::date AND created_at<$1::date+interval '1 day' ORDER BY observation_id::text LIMIT 201`, in.Period)
		if e != nil {
			return s, e
		}
		ids := []string{}
		for rows.Next() {
			var id string
			if e = rows.Scan(&id); e != nil {
				rows.Close()
				return s, e
			}
			ids = append(ids, id)
		}
		e = rows.Err()
		rows.Close()
		if e != nil || len(ids) > 200 {
			return s, ErrInvalid
		}
		for _, id := range ids {
			d, e := document(ctx, tx, id, "")
			if e != nil {
				return s, e
			}
			s.Documents = append(s.Documents, d)
		}
	case "identity":
		if in.ID == in.RightID {
			return s, ErrInvalid
		}
		var raw []byte
		e := tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(a)),'[]') FROM noctis_v2.entity_aliases a WHERE entity_id::text=ANY($1) AND NOT revoked`, []string{in.ID, in.RightID}).Scan(&raw)
		if e != nil {
			return s, e
		}
		var aliases []struct {
			Evidence []evidence.Ref `json:"evidence"`
		}
		if json.Unmarshal(raw, &aliases) != nil || len(aliases) == 0 {
			return s, ErrInvalid
		}
		s.Context = raw
		for _, a := range aliases {
			for _, r := range a.Evidence {
				d, e := document(ctx, tx, r.ObservationID, r.Revision)
				if e != nil {
					return s, e
				}
				s.Documents = append(s.Documents, d)
			}
		}
		s.Dependencies = append(s.Dependencies, Dependency{"identity", in.ID, string(raw)})
	case "vulnerability":
		if !cvePattern.MatchString(in.ID) {
			return s, ErrInvalid
		}
		var raw []byte
		var revision string
		e := tx.QueryRow(ctx, `SELECT body,generation FROM noctis_v2.nvd_current_selection WHERE cve=$1 AND expires_at>clock_timestamp() AND selection_reason=''`, in.ID).Scan(&raw, &revision)
		if e != nil {
			return s, e
		}
		s.Context = raw
		s.Dependencies = append(s.Dependencies, Dependency{"vulnerability", in.ID, revision})
	case "source":
		var raw []byte
		var policy string
		e := tx.QueryRow(ctx, `SELECT jsonb_build_object('id',id,'kind',kind,'name',name,'coverage',coverage,'last_success_at',last_success_at,'enabled',enabled),policy_version FROM noctis_v2.sources WHERE id=$1`, in.ID).Scan(&raw, &policy)
		if e != nil {
			return s, e
		}
		s.Context = raw
		s.Dependencies = append(s.Dependencies, Dependency{"source", in.ID, policy})
	case "query":
		if strings.TrimSpace(in.Text) == "" || len(in.Text) > 8192 {
			return s, ErrInvalid
		}
		s.Context, _ = json.Marshal(map[string]any{"question": in.Text, "allowed_entities": []string{"observations", "cases", "entities", "observables"}})
	case "query_result":
		var raw []byte
		var dependencies []byte
		e := tx.QueryRow(ctx, `SELECT jsonb_build_object('plan',plan,'rows',rows),dependencies FROM noctis_v2.ai_query_results WHERE id=$1 AND actor=$2`, in.ID, actor).Scan(&raw, &dependencies)
		if e != nil {
			return s, e
		}
		s.Context = raw
		if json.Unmarshal(dependencies, &s.Dependencies) != nil {
			return s, ErrInvalid
		}
		s.Dependencies = append(s.Dependencies, Dependency{"query_result", in.ID, actor})
	default:
		return s, ErrInvalid
	}
	return s, nil
}
func validateSnapshot(ctx context.Context, tx pgx.Tx, s Snapshot, actor string) error {
	for _, d := range s.Dependencies {
		switch d.Kind {
		case "evidence":
			var ref evidence.Ref
			if json.Unmarshal([]byte(d.Revision), &ref) != nil {
				return ErrInvalid
			}
			if e := intelligence.ValidateEvidenceTx(ctx, tx, []evidence.Ref{ref}); e != nil {
				return e
			}
		case "query_source":
			var stamp string
			if e := tx.QueryRow(ctx, `SELECT policy_version||':'||epoch::text FROM noctis_v2.sources WHERE id=$1 AND enabled FOR SHARE`, d.ID).Scan(&stamp); e != nil || stamp != d.Revision {
				return errors.New("query source changed")
			}
		case "query_case":
			var rev string
			if e := tx.QueryRow(ctx, `SELECT revision::text FROM noctis_v2.intelligence_cases WHERE id=$1 FOR SHARE`, d.ID).Scan(&rev); e != nil || rev != d.Revision {
				return errors.New("query case changed")
			}
		case "query_entity":
			var aliases []byte
			if e := tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM noctis_v2.entity_aliases a WHERE entity_id=$1 AND NOT revoked`, d.ID).Scan(&aliases); e != nil || string(aliases) != d.Revision {
				return errors.New("query entity changed")
			}
		}
	}
	for _, d := range s.Documents {
		if e := intelligence.ValidateEvidenceTx(ctx, tx, []evidence.Ref{d.Ref}); e != nil {
			return e
		}
		var enabled bool
		if e := tx.QueryRow(ctx, `SELECT `+intelligence.SourceAuthorizedSQL+` FROM noctis_v2.sources s JOIN noctis_v2.observations o ON o.source_id=s.id WHERE o.id=$1 FOR SHARE OF s`, d.Ref.ObservationID).Scan(&enabled); e != nil || !enabled {
			return errors.New("source authorization revoked")
		}
	}
	// Rebuild the typed input under the projection guard, catching revision, policy,
	// retraction and feed expiry changes without manufacturing observations.
	fresh, e := snapshot(ctx, tx, s.Input, actor)
	if e != nil {
		return e
	}
	a, _ := json.Marshal(fresh)
	b, _ := json.Marshal(s)
	var va, vb any
	if json.Unmarshal(a, &va) != nil || json.Unmarshal(b, &vb) != nil || !reflect.DeepEqual(va, vb) {
		return errors.New("dependency snapshot changed")
	}
	return nil
}
func ValidatePlan(p QueryPlan) error {
	if p.Version != "1" || p.Operation != "search" || (p.Mode != "exact" && p.Mode != "fulltext") || p.Limit < 1 || p.Limit > 100 || len(p.Text) > 4096 || len(p.Cursor) > 128 {
		return ErrInvalid
	}
	switch p.Entity {
	case "observations", "cases", "entities", "observables":
	default:
		return ErrInvalid
	}
	if p.Cursor != "" {
		if _, e := uuid.Parse(p.Cursor); e != nil {
			return ErrInvalid
		}
	}
	for _, id := range []string{p.Filters.SourceID, p.Filters.CaseID} {
		if id != "" {
			if _, e := uuid.Parse(id); e != nil {
				return ErrInvalid
			}
		}
	}
	if len(p.Filters.Kind) > 128 {
		return ErrInvalid
	}
	return nil
}
func (s Store) Query(ctx context.Context, p QueryPlan, actor string) (QueryResult, error) {
	r := QueryResult{ID: uuid.NewString(), Plan: p, Rows: []json.RawMessage{}}
	if e := ValidatePlan(p); e != nil {
		return r, e
	}
	c, e := pgx.Connect(ctx, s.DSN)
	if e != nil {
		return r, e
	}
	defer c.Close(context.Background())
	tx, e := c.Begin(ctx)
	if e != nil {
		return r, e
	}
	defer tx.Rollback(context.Background())
	// Only enum-selected SQL fragments are interpolated. All user values are parameters.
	var from, id, text, kind, extra string
	refSQL := "'{}'::jsonb"
	switch p.Entity {
	case "observations":
		from = "noctis_v2.observations o JOIN noctis_v2.content_blobs b USING(hash,representation) JOIN noctis_v2.sources src ON src.id=o.source_id"
		id = "o.id::text"
		text = "convert_from(b.payload,'UTF8')"
		kind = "o.representation"
		refSQL = "jsonb_build_object('ref',jsonb_build_object('observation_id',o.id,'revision',o.revision,'hash',o.hash,'representation',o.representation,'start',0,'end',octet_length(b.payload)))"
		extra = " AND NOT o.source_deleted AND o.superseded_by IS NULL AND o.retention_expired_at IS NULL AND ($4='' OR o.source_id::text=$4) AND ($5='' OR EXISTS(SELECT FROM noctis_v2.case_memberships m WHERE m.observation_id=o.id AND m.case_id::text=$5))"
	case "cases":
		from = "noctis_v2.intelligence_cases o"
		id = "o.id::text"
		text = "o.title"
		kind = "'case'::text"
		extra = " AND ($4='' OR EXISTS(SELECT FROM noctis_v2.case_memberships m JOIN noctis_v2.observations obs ON obs.id=m.observation_id WHERE m.case_id=o.id AND obs.source_id::text=$4)) AND ($5='' OR o.id::text=$5)"
	case "entities":
		from = "noctis_v2.entities o JOIN noctis_v2.entity_aliases a ON a.entity_id=o.id AND NOT a.revoked"
		id = "o.id::text"
		text = "a.alias"
		kind = "o.kind"
		extra = " AND $4='' AND $5=''"
	case "observables":
		from = "noctis_v2.observable_sightings o JOIN noctis_v2.observations obs ON obs.id=o.observation_id"
		id = "o.observation_id::text"
		text = "o.value"
		kind = "o.observable_type"
		refSQL = "jsonb_build_object('ref',jsonb_build_object('observation_id',obs.id,'revision',obs.revision,'hash',obs.hash,'representation',obs.representation,'start',o.start_byte,'end',o.end_byte))"
		extra = " AND NOT obs.source_deleted AND obs.superseded_by IS NULL AND obs.retention_expired_at IS NULL AND ($4='' OR obs.source_id::text=$4) AND ($5='' OR EXISTS(SELECT FROM noctis_v2.case_memberships m WHERE m.observation_id=obs.id AND m.case_id::text=$5))"
	}
	match := "(" + text + "=$1)"
	if p.Mode == "fulltext" {
		match = "to_tsvector('simple'," + text + ") @@ plainto_tsquery('simple',$1)"
	}
	query := fmt.Sprintf(`SELECT DISTINCT jsonb_build_object('id',%s,'text',left(%s,4096),'kind',%s)||%s,%s FROM %s WHERE ($1='' OR %s) AND ($2='' OR %s>$2) AND ($3='' OR %s=$3)%s ORDER BY %s LIMIT $6`, id, text, kind, refSQL, id, from, match, id, kind, extra, id)
	rows, e := tx.Query(ctx, query, p.Text, p.Cursor, p.Filters.Kind, p.Filters.SourceID, p.Filters.CaseID, p.Limit+1)
	if e != nil {
		return r, e
	}
	ids := []string{}
	for rows.Next() {
		var raw []byte
		var rowID string
		if e = rows.Scan(&raw, &rowID); e != nil {
			rows.Close()
			return r, e
		}
		r.Rows = append(r.Rows, json.RawMessage(raw))
		ids = append(ids, rowID)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return r, e
	}
	if len(r.Rows) > p.Limit {
		r.Rows = r.Rows[:p.Limit]
		r.NextCursor = ids[p.Limit-1]
	}
	plan, _ := json.Marshal(p)
	raw, _ := json.Marshal(r.Rows)
	dependencies := []Dependency{}
	for _, row := range r.Rows {
		var v struct {
			ID  string        `json:"id"`
			Ref *evidence.Ref `json:"ref"`
		}
		if json.Unmarshal(row, &v) != nil {
			return r, ErrInvalid
		}
		if v.Ref != nil {
			d, de := document(ctx, tx, v.Ref.ObservationID, v.Ref.Revision)
			if de != nil {
				return r, de
			}
			ref, _ := json.Marshal(v.Ref)
			dependencies = append(dependencies, Dependency{"evidence", v.Ref.ObservationID, string(ref)}, Dependency{"query_source", d.SourceID, d.SourcePolicy + ":" + d.Epoch})
		}
		if p.Entity == "cases" {
			var rev string
			if e = tx.QueryRow(ctx, `SELECT revision::text FROM noctis_v2.intelligence_cases WHERE id=$1 FOR SHARE`, v.ID).Scan(&rev); e != nil {
				return r, e
			}
			dependencies = append(dependencies, Dependency{"query_case", v.ID, rev})
		}
		if p.Entity == "entities" {
			var aliases []byte
			if e = tx.QueryRow(ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM noctis_v2.entity_aliases a WHERE entity_id=$1 AND NOT revoked`, v.ID).Scan(&aliases); e != nil {
				return r, e
			}
			dependencies = append(dependencies, Dependency{"query_entity", v.ID, string(aliases)})
		}
	}
	deps, _ := json.Marshal(dependencies)
	_, e = tx.Exec(ctx, `INSERT INTO noctis_v2.ai_query_results(id,actor,plan,rows,dependencies) VALUES($1,$2,$3,$4,$5)`, r.ID, actor, string(plan), string(raw), string(deps))
	if e != nil {
		return r, e
	}
	return r, tx.Commit(ctx)
}
