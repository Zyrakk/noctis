package discovery

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/modules"
)

// TriageWorker periodically checks for pending_triage sources, sends them
// to the LLM for classification, and promotes or deletes them.
type TriageWorker struct {
	pool      *pgxpool.Pool
	analyzer  *analyzer.Analyzer
	batchSize int
	status    *modules.StatusTracker
}

// NewTriageWorker creates a triage worker using the given analyzer (typically
// the fast/classify analyzer) for LLM calls.
func NewTriageWorker(pool *pgxpool.Pool, az *analyzer.Analyzer, batchSize int) *TriageWorker {
	if batchSize <= 0 {
		batchSize = 100
	}
	return &TriageWorker{
		pool:      pool,
		analyzer:  az,
		batchSize: batchSize,
		status:    modules.NewStatusTracker(modules.ModSourceTriage, "Source Triage", "infra"),
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

	// Build lookup sets. If a URL appears in both, treat as investigate.
	investigateSet := make(map[string]struct{}, len(result.Investigate))
	for _, u := range result.Investigate {
		investigateSet[u] = struct{}{}
	}
	trashSet := make(map[string]struct{}, len(result.Trash))
	for _, u := range result.Trash {
		if _, dup := investigateSet[u]; !dup {
			trashSet[u] = struct{}{}
		}
	}

	batchID := uuid.New().String()
	var nInvestigate, nTrash int

	for _, r := range batch {
		var decision string
		if _, ok := investigateSet[r.Identifier]; ok {
			decision = "investigate"
			nInvestigate++
			if _, err := tw.pool.Exec(ctx,
				`UPDATE sources SET status = 'discovered', updated_at = NOW() WHERE id = $1`,
				r.ID,
			); err != nil {
				slog.Error("triage: promote source", "id", r.ID, "error", err)
				continue
			}
		} else if _, ok := trashSet[r.Identifier]; ok {
			decision = "trash"
			nTrash++
			if _, err := tw.pool.Exec(ctx,
				`DELETE FROM sources WHERE id = $1`, r.ID,
			); err != nil {
				slog.Error("triage: delete source", "id", r.ID, "error", err)
				continue
			}
		} else {
			// URL not in LLM response — leave as pending_triage for next batch.
			slog.Warn("triage: URL not classified by LLM, leaving pending",
				"identifier", r.Identifier)
			continue
		}

		// Log decision to audit table.
		if _, err := tw.pool.Exec(ctx, `
			INSERT INTO source_triage_log (batch_id, identifier, decision, model_used)
			VALUES ($1, $2, $3, $4)`,
			batchID, r.Identifier, decision, "",
		); err != nil {
			slog.Error("triage: log decision", "error", err)
		}
	}

	slog.Info("triage: batch complete",
		"batch_id", batchID,
		"investigate", nInvestigate,
		"trash", nTrash,
	)
	tw.status.RecordSuccess()
}
