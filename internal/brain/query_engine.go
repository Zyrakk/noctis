package brain

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/modules"
	"github.com/Zyrakk/noctis/internal/processor"
)

const schemaContext = `
Database tables:

raw_content: All collected findings.
  Columns: id (UUID), source_type (telegram/paste/forum/web), source_name, category (credential_leak/malware_sample/vulnerability/threat_actor_comms/access_broker/data_dump/canary_hit/irrelevant), sub_category, severity (critical/high/medium/low/info), summary (text), author, collected_at (timestamp), provenance (first_party/third_party_reporting/unknown), sub_metadata (JSONB)

iocs: Extracted indicators of compromise.
  Columns: id (UUID), type (ip/domain/hash_md5/hash_sha256/email/crypto_wallet/url/cve), value (text), context (text), first_seen, last_seen, sighting_count, threat_score (0-1), active (bool)

entities: Knowledge graph nodes.
  Columns: id (text, format entity:type:name), type (threat_actor/malware/campaign/tool/ip/domain/hash/cve/url/email/channel), properties (JSONB with name, observed, aliases, needs_review)

edges: Graph relationships.
  Columns: source_id, target_id, relationship (uses/targets/deploys/exploits/referenced_in/mentioned_in/associated_with/found_in)

correlations: Confirmed pattern matches.
  Columns: cluster_id, entity_ids (text[]), finding_ids (text[]), correlation_type, confidence (0-1), method (rule/analyst), evidence (JSONB)

analytical_notes: Brain's analytical judgments.
  Columns: entity_id, finding_id, note_type (correlation_judgment/attribution/pattern/prediction/warning/context), title, content, confidence (0-1), created_by (analyst/correlator/human), created_at

vulnerabilities: CVE intelligence.
  Columns: cve_id, cvss_v31_score, epss_score, kev_listed (bool), dark_web_mentions, exploit_available (bool), priority_score, priority_label

sources: Source registry.
  Columns: identifier, name, type, status (active/discovered/paused/dead), value_score, unique_iocs
`

// QueryResult holds the result of a natural language query.
type QueryResult struct {
	Query    string   `json:"query"`
	SQL      string   `json:"sql"`
	Columns  []string `json:"columns"`
	Rows     [][]any  `json:"rows"`
	RowCount int      `json:"row_count"`
	Duration string   `json:"duration"`
}

// QueryEngine translates natural language questions into SQL queries.
type QueryEngine struct {
	analyzer *analyzer.Analyzer
	pool     *pgxpool.Pool
	sem      *processor.ConcurrencyLimiter
	status   *modules.StatusTracker
}

// NewQueryEngine creates a query engine.
func NewQueryEngine(
	a *analyzer.Analyzer,
	pool *pgxpool.Pool,
	concurrency int,
	provider, model string,
) *QueryEngine {
	qe := &QueryEngine{
		analyzer: a,
		pool:     pool,
		sem:      processor.NewConcurrencyLimiter(concurrency),
		status:   modules.NewStatusTracker(modules.ModQueryEngine, "Query Engine", "brain"),
	}
	qe.status.SetAIInfo(provider, model)
	qe.status.SetEnabled(true)
	return qe
}

// Status returns the module status tracker for registry registration.
func (qe *QueryEngine) Status() *modules.StatusTracker {
	return qe.status
}

// Query translates a natural language question into SQL, executes it, and returns results.
func (qe *QueryEngine) Query(ctx context.Context, question string) (*QueryResult, error) {
	if err := qe.sem.Acquire(ctx); err != nil {
		return nil, err
	}
	defer qe.sem.Release()

	// 1. Generate SQL from natural language.
	sql, err := qe.generateSQL(ctx, question)
	if err != nil {
		qe.status.RecordError(err)
		return nil, fmt.Errorf("sql generation: %w", err)
	}

	// 2. Validate SQL is safe (SELECT only).
	if err := validateSQL(sql); err != nil {
		qe.status.RecordError(err)
		return nil, fmt.Errorf("unsafe SQL: %w", err)
	}

	// 3. Execute with timeout.
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	start := time.Now()
	rows, err := qe.pool.Query(queryCtx, sql)
	if err != nil {
		qe.status.RecordError(err)
		return nil, fmt.Errorf("query execution: %w", err)
	}
	defer rows.Close()

	// 4. Read column names.
	fields := rows.FieldDescriptions()
	colNames := make([]string, len(fields))
	for i, f := range fields {
		colNames[i] = string(f.Name)
	}

	// 5. Read rows (cap at 100).
	var resultRows [][]any
	for rows.Next() {
		values, err := rows.Values()
		if err != nil {
			continue
		}
		resultRows = append(resultRows, values)
		if len(resultRows) >= 100 {
			break
		}
	}
	if err := rows.Err(); err != nil {
		qe.status.RecordError(err)
		return nil, fmt.Errorf("reading rows: %w", err)
	}

	qe.status.RecordSuccess()
	qe.status.SetExtra("last_query", question)
	qe.status.SetExtra("last_sql", sql)
	qe.status.SetExtra("last_row_count", len(resultRows))

	return &QueryResult{
		Query:    question,
		SQL:      sql,
		Columns:  colNames,
		Rows:     resultRows,
		RowCount: len(resultRows),
		Duration: time.Since(start).Round(time.Millisecond).String(),
	}, nil
}

func (qe *QueryEngine) generateSQL(ctx context.Context, question string) (string, error) {
	prompt := fmt.Sprintf(`You are a PostgreSQL expert. Convert this natural language question into a SQL query.

DATABASE SCHEMA:
%s

QUESTION: %s

RULES:
- Generate ONLY a SELECT query. Never INSERT, UPDATE, DELETE, DROP, ALTER, or any DDL.
- Always include LIMIT (default 50, max 100).
- Use ILIKE for text searches, not exact match.
- For entity lookups, search properties->>'name' ILIKE pattern.
- For time filters, use collected_at for findings and created_at for other tables.
- When asked about actors, search entities WHERE type = 'threat_actor'.
- When joining entities to findings, go through edges table.
- Return ONLY the SQL query. No explanation, no markdown, no code fences.`, schemaContext, question)

	resp, err := qe.analyzer.RawCompletion(ctx, prompt)
	if err != nil {
		return "", err
	}

	sql := strings.TrimSpace(resp)
	sql = strings.TrimPrefix(sql, "```sql")
	sql = strings.TrimPrefix(sql, "```")
	sql = strings.TrimSuffix(sql, "```")
	sql = strings.TrimSpace(sql)

	return sql, nil
}

// validateSQL checks that the query is a safe read-only SELECT.
func validateSQL(sql string) error {
	normalized := strings.ToUpper(strings.TrimSpace(sql))

	if !strings.HasPrefix(normalized, "SELECT") && !strings.HasPrefix(normalized, "WITH") {
		return fmt.Errorf("query must be a SELECT statement")
	}

	// Block multi-statement queries (SQL injection via semicolons).
	if strings.Contains(sql, ";") {
		return fmt.Errorf("query must not contain semicolons")
	}

	blocked := []string{
		"INSERT ", "UPDATE ", "DELETE ", "DROP ", "ALTER ",
		"TRUNCATE ", "CREATE ", "GRANT ", "REVOKE ", "EXECUTE ", "COPY ",
	}
	for _, kw := range blocked {
		if strings.Contains(normalized, kw) {
			return fmt.Errorf("query contains blocked keyword: %s", strings.TrimSpace(kw))
		}
	}

	if !strings.Contains(normalized, "LIMIT") {
		return fmt.Errorf("query must contain LIMIT clause")
	}

	return nil
}
