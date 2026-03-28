package discovery

import (
	"context"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/modules"
)

// maxTriageAttempts is the number of times a URL can appear in a triage batch
// without being classified before it is auto-trashed.
const maxTriageAttempts = 3

// TriageWorker periodically checks for pending_triage sources, sends them
// to the LLM for classification, and promotes or deletes them.
type TriageWorker struct {
	pool           *pgxpool.Pool
	analyzer       *analyzer.Analyzer
	engine         *Engine // optional; used to refresh auto-blacklist after learning
	batchSize      int
	modelName      string
	status         *modules.StatusTracker
	triageAttempts map[string]int // identifier -> failed attempt count
}

// NewTriageWorker creates a triage worker using the given analyzer (typically
// the fast/classify analyzer) for LLM calls. modelName is recorded in the
// audit log for traceability. The engine parameter is optional; when provided,
// the worker refreshes the engine's auto-blacklist after learning new domains.
func NewTriageWorker(pool *pgxpool.Pool, az *analyzer.Analyzer, batchSize int, modelName string, engine *Engine) *TriageWorker {
	if batchSize <= 0 {
		batchSize = 30
	}
	return &TriageWorker{
		pool:           pool,
		analyzer:       az,
		engine:         engine,
		batchSize:      batchSize,
		modelName:      modelName,
		status:         modules.NewStatusTracker(modules.ModSourceTriage, "Source Triage", "infra"),
		triageAttempts: make(map[string]int),
	}
}

// Status returns the worker's status tracker for the module registry.
func (tw *TriageWorker) Status() *modules.StatusTracker {
	return tw.status
}

// Run starts the triage loop. It checks every 5 minutes for pending URLs
// and processes a batch when the threshold is met. Stops on context cancel.
func (tw *TriageWorker) Run(ctx context.Context) {
	tw.status.MarkStarted()
	defer tw.status.MarkStopped()

	tw.status.SetExtra("batch_size", tw.batchSize)
	slog.Info("triage: worker started", "batch_size", tw.batchSize)

	// Try an immediate cycle, then tick.
	tw.runCycle(ctx)

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("triage: stopping")
			return
		case <-ticker.C:
			tw.runCycle(ctx)
		}
	}
}

// runCycle checks pending count and processes one batch if threshold is met.
func (tw *TriageWorker) runCycle(ctx context.Context) {
	var count int
	err := tw.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sources WHERE status = 'pending_triage'`,
	).Scan(&count)
	if err != nil {
		slog.Error("triage: count pending", "error", err)
		tw.status.RecordError(err)
		return
	}

	if count < tw.batchSize {
		slog.Debug("triage: below threshold", "pending", count, "threshold", tw.batchSize)
		return
	}

	tw.processBatch(ctx)
}

// triageRow is a pending source fetched for triage.
type triageRow struct {
	ID         string
	Identifier string
}

// processBatch fetches a batch of pending URLs, sends them to the LLM,
// and applies the classification decisions.
func (tw *TriageWorker) processBatch(ctx context.Context) {
	rows, err := tw.pool.Query(ctx, `
		SELECT id, identifier FROM sources
		WHERE status = 'pending_triage'
		ORDER BY created_at ASC
		LIMIT $1`, tw.batchSize)
	if err != nil {
		slog.Error("triage: fetch batch", "error", err)
		tw.status.RecordError(err)
		return
	}
	defer rows.Close()

	var batch []triageRow
	for rows.Next() {
		var r triageRow
		if err := rows.Scan(&r.ID, &r.Identifier); err != nil {
			slog.Error("triage: scan row", "error", err)
			tw.status.RecordError(err)
			return
		}
		batch = append(batch, r)
	}
	if err := rows.Err(); err != nil {
		slog.Error("triage: rows error", "error", err)
		tw.status.RecordError(err)
		return
	}

	if len(batch) == 0 {
		return
	}

	// Collect identifiers for the LLM prompt.
	urls := make([]string, len(batch))
	for i, r := range batch {
		urls[i] = r.Identifier
	}

	result, err := tw.analyzer.TriageURLs(ctx, urls)
	if err != nil {
		slog.Error("triage: LLM call failed, skipping batch", "error", err)
		tw.status.RecordError(err)
		return
	}

	// Build lookup sets with normalized keys for fuzzy matching.
	// The LLM may return URLs with minor differences (trailing slashes,
	// lowercased, URL-decoded) compared to the original identifiers.
	investigateSet := make(map[string]struct{}, len(result.Investigate))
	for _, u := range result.Investigate {
		investigateSet[normalizeURLForMatch(u)] = struct{}{}
	}
	trashSet := make(map[string]struct{}, len(result.Trash))
	for _, u := range result.Trash {
		norm := normalizeURLForMatch(u)
		if _, dup := investigateSet[norm]; !dup {
			trashSet[norm] = struct{}{}
		}
	}

	batchID := uuid.New().String()
	var nInvestigate, nTrash, nAutoTrashed int

	for _, r := range batch {
		norm := normalizeURLForMatch(r.Identifier)
		var decision string
		if _, ok := investigateSet[norm]; ok {
			decision = "investigate"
			nInvestigate++
			delete(tw.triageAttempts, r.Identifier)
			if _, err := tw.pool.Exec(ctx,
				`UPDATE sources SET status = 'discovered', updated_at = NOW() WHERE id = $1`,
				r.ID,
			); err != nil {
				slog.Error("triage: promote source", "id", r.ID, "error", err)
				continue
			}
		} else if _, ok := trashSet[norm]; ok {
			decision = "trash"
			nTrash++
			delete(tw.triageAttempts, r.Identifier)
			if _, err := tw.pool.Exec(ctx,
				`DELETE FROM sources WHERE id = $1`, r.ID,
			); err != nil {
				slog.Error("triage: delete source", "id", r.ID, "error", err)
				continue
			}
		} else {
			// URL not in LLM response — increment attempt counter.
			tw.triageAttempts[r.Identifier]++
			attempts := tw.triageAttempts[r.Identifier]
			if attempts >= maxTriageAttempts {
				slog.Warn("triage: auto-trashing URL after max attempts",
					"identifier", r.Identifier, "attempts", attempts)
				decision = "trash"
				nAutoTrashed++
				delete(tw.triageAttempts, r.Identifier)
				if _, err := tw.pool.Exec(ctx,
					`DELETE FROM sources WHERE id = $1`, r.ID,
				); err != nil {
					slog.Error("triage: delete stale source", "id", r.ID, "error", err)
					continue
				}
				// Count auto-trashed URLs for domain learning.
				result.Trash = append(result.Trash, r.Identifier)
			} else {
				slog.Warn("triage: URL not classified by LLM",
					"identifier", r.Identifier, "attempt", attempts)
				continue
			}
		}

		// Log decision to audit table.
		if _, err := tw.pool.Exec(ctx, `
			INSERT INTO source_triage_log (batch_id, identifier, decision, model_used)
			VALUES ($1, $2, $3, $4)`,
			batchID, r.Identifier, decision, tw.modelName,
		); err != nil {
			slog.Error("triage: log decision", "error", err)
		}
	}

	slog.Info("triage: batch complete",
		"batch_id", batchID,
		"investigate", nInvestigate,
		"trash", nTrash,
		"auto_trashed", nAutoTrashed,
	)
	tw.status.RecordSuccess()

	// Learn from trash decisions: increment domain counts and auto-blacklist
	// domains that cross the threshold.
	if nTrash > 0 {
		tw.learnFromTrash(ctx, result.Trash)
	}
}

// learnFromTrash extracts domains from trashed URLs, upserts their counts
// into discovered_blacklist, and auto-blacklists domains that reach the
// threshold. It also cleans up remaining pending_triage URLs from newly
// blacklisted domains.
func (tw *TriageWorker) learnFromTrash(ctx context.Context, trashedURLs []string) {
	// Deduplicate domains in this batch.
	domains := make(map[string]struct{})
	for _, rawURL := range trashedURLs {
		d := extractDomain(rawURL)
		if d != "" {
			domains[d] = struct{}{}
		}
	}

	for domain := range domains {
		// Skip domains protected by the engine's allowlist.
		if tw.engine != nil && tw.engine.isDomainAllowed(domain) {
			continue
		}

		var count int
		err := tw.pool.QueryRow(ctx, `
			INSERT INTO discovered_blacklist (domain, trash_count)
			VALUES ($1, 1)
			ON CONFLICT (domain) DO UPDATE SET trash_count = discovered_blacklist.trash_count + 1
			RETURNING trash_count`, domain,
		).Scan(&count)
		if err != nil {
			slog.Error("triage: upsert blacklist domain", "domain", domain, "error", err)
			continue
		}

		if count >= autoBlacklistThreshold {
			slog.Info("triage: auto-blacklisted domain",
				"domain", domain, "trash_count", count)

			// Purge remaining pending_triage URLs from this domain.
			tag, err := tw.pool.Exec(ctx, `
				DELETE FROM sources
				WHERE status = 'pending_triage'
				  AND identifier LIKE '%' || $1 || '%'`, domain)
			if err != nil {
				slog.Error("triage: purge pending for blacklisted domain",
					"domain", domain, "error", err)
			} else if tag.RowsAffected() > 0 {
				slog.Info("triage: purged pending URLs for blacklisted domain",
					"domain", domain, "deleted", tag.RowsAffected())
			}
		}
	}

	// Refresh the engine's in-memory auto-blacklist.
	if tw.engine != nil {
		tw.engine.RefreshAutoBlacklist(ctx)
	}
}

// normalizeURLForMatch normalizes a URL for fuzzy comparison between the
// original identifier and the LLM's response. Lowercases, trims trailing
// slashes, and URL-decodes the path.
func normalizeURLForMatch(rawURL string) string {
	rawURL = strings.ToLower(strings.TrimSpace(rawURL))
	rawURL = strings.TrimRight(rawURL, "/")
	if decoded, err := url.QueryUnescape(rawURL); err == nil {
		rawURL = decoded
	}
	return rawURL
}

// extractDomain returns the lowercase hostname from a URL, or "" if
// the URL cannot be parsed.
func extractDomain(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return ""
	}
	return strings.ToLower(parsed.Hostname())
}
