package brain

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/modules"
	"github.com/Zyrakk/noctis/internal/processor"
)

// Analyst evaluates pending correlation candidates using an LLM, promoting,
// rejecting, or deferring each one. Every decision is logged to
// correlation_decisions for auditability and future fine-tuning.
type Analyst struct {
	analyzer *analyzer.Analyzer
	archive  *archive.Store
	sem      *processor.ConcurrencyLimiter
	status   *modules.StatusTracker
	cfg      config.AnalystConfig
	model    string
}

// NewAnalyst creates an Analyst bound to the given analyzer and archive store.
func NewAnalyst(
	a *analyzer.Analyzer,
	archiveStore *archive.Store,
	cfg config.AnalystConfig,
	concurrency int,
	provider, model string,
) *Analyst {
	analyst := &Analyst{
		analyzer: a,
		archive:  archiveStore,
		sem:      processor.NewConcurrencyLimiter(concurrency),
		cfg:      cfg,
		model:    model,
		status:   modules.NewStatusTracker(modules.ModAnalyst, "Analyst", "brain"),
	}
	analyst.status.SetAIInfo(provider, model)
	analyst.status.SetEnabled(cfg.Enabled)
	return analyst
}

// Run starts the analyst on a periodic interval and blocks until ctx is cancelled.
func (a *Analyst) Run(ctx context.Context) {
	if !a.cfg.Enabled {
		return
	}
	a.status.MarkStarted()
	defer a.status.MarkStopped()

	interval := time.Duration(a.cfg.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 60 * time.Minute
	}
	a.status.SetExtra("interval", interval.String())

	log.Printf("brain: analyst started (interval=%s, batch=%d, threshold=%.2f)",
		interval, a.cfg.BatchSize, a.cfg.PromoteThreshold)

	// Run once on startup, then on interval.
	a.runCycle(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("brain: analyst stopping")
			return
		case <-ticker.C:
			a.runCycle(ctx)
		}
	}
}

func (a *Analyst) runCycle(ctx context.Context) {
	start := time.Now()
	batchSize := a.cfg.BatchSize
	if batchSize <= 0 {
		batchSize = 10
	}

	candidates, err := a.archive.FetchPendingCandidates(ctx, batchSize)
	if err != nil {
		a.status.RecordError(err)
		log.Printf("brain: analyst: fetch candidates error: %v", err)
		return
	}

	if len(candidates) == 0 {
		log.Printf("brain: analyst: no pending candidates, skipping LLM evaluation")
		a.status.SetExtra("last_cycle_candidates", 0)
		return
	}

	var promoted, rejected, deferred int

	for _, cand := range candidates {
		if ctx.Err() != nil {
			return
		}

		// Skip candidates below minimum signal count.
		minSignals := a.cfg.MinSignalCount
		if minSignals <= 0 {
			minSignals = 2
		}
		if cand.SignalCount < minSignals {
			continue
		}

		decision, err := a.evaluateCandidate(ctx, cand)
		if err != nil {
			a.status.RecordError(err)
			log.Printf("brain: analyst: evaluate error for %s: %v", cand.ClusterID, err)
			continue
		}

		switch decision.Decision {
		case "promote":
			promoted++
		case "reject":
			rejected++
		case "defer":
			deferred++
		}

		a.status.RecordSuccess()
	}

	a.status.SetExtra("last_cycle_duration", time.Since(start).String())
	a.status.SetExtra("last_cycle_promoted", promoted)
	a.status.SetExtra("last_cycle_rejected", rejected)
	a.status.SetExtra("last_cycle_deferred", deferred)
	a.status.SetExtra("last_cycle_total", len(candidates))

	log.Printf("brain: analyst cycle complete in %s — %d promoted, %d rejected, %d deferred",
		time.Since(start).Round(time.Millisecond), promoted, rejected, deferred)
}

// evaluateCandidate builds context, sends to LLM, acts on the decision, and logs it.
func (a *Analyst) evaluateCandidate(ctx context.Context, cand archive.CorrelationCandidate) (*archive.CorrelationDecision, error) {
	// 1. Build context for the LLM prompt.
	promptData := a.buildCandidateContext(ctx, cand)

	// 2. Send to LLM.
	if err := a.sem.Acquire(ctx); err != nil {
		return nil, err
	}
	result, err := a.analyzer.EvaluateCorrelation(ctx, promptData)
	a.sem.Release()
	if err != nil {
		return nil, err
	}

	// 3. Create decision record.
	contextSnapshot := promptDataToJSON(promptData)
	modelUsed := a.model
	decision := &archive.CorrelationDecision{
		CandidateID:     cand.ID,
		ClusterID:       cand.ClusterID,
		Decision:        result.Decision,
		Confidence:      result.Confidence,
		Reasoning:       result.Reasoning,
		ContextSnapshot: contextSnapshot,
		ModelUsed:       &modelUsed,
	}

	// 4. Act on decision.
	promoteThreshold := a.cfg.PromoteThreshold
	if promoteThreshold <= 0 {
		promoteThreshold = 0.7
	}

	switch result.Decision {
	case "promote":
		if result.Confidence >= promoteThreshold {
			corr := &archive.Correlation{
				ClusterID:       cand.ClusterID,
				EntityIDs:       cand.EntityIDs,
				FindingIDs:      cand.FindingIDs,
				CorrelationType: cand.CandidateType,
				Confidence:      result.Confidence,
				Method:          "analyst",
				Evidence:        cand.Signals,
			}
			if err := a.archive.UpsertCorrelation(ctx, corr); err != nil {
				return nil, fmt.Errorf("promote correlation: %w", err)
			}
			decision.PromotedCorrelationID = &corr.ID
			a.archive.UpdateCandidateStatus(ctx, cand.ID, "promoted")

			// Write a single analytical note for the correlation.
			var primaryEntity *string
			if len(cand.EntityIDs) > 0 {
				eidCopy := cand.EntityIDs[0]
				primaryEntity = &eidCopy
			}
			note := &archive.AnalyticalNote{
				CorrelationID: &corr.ID,
				EntityID:      primaryEntity,
				NoteType:      "correlation_judgment",
				Title:         fmt.Sprintf("Correlation confirmed: %s", cand.CandidateType),
				Content:       result.Reasoning,
				Confidence:    result.Confidence,
				CreatedBy:     "analyst",
				ModelUsed:     &modelUsed,
				Status:        "active",
			}
			a.archive.InsertAnalyticalNote(ctx, note)
		} else {
			// Confidence too low to promote — defer instead.
			decision.Decision = "defer"
		}

	case "reject":
		a.archive.UpdateCandidateStatus(ctx, cand.ID, "rejected")

		var primaryEntity *string
		if len(cand.EntityIDs) > 0 {
			eidCopy := cand.EntityIDs[0]
			primaryEntity = &eidCopy
		}
		note := &archive.AnalyticalNote{
			EntityID:   primaryEntity,
			NoteType:   "correlation_judgment",
			Title:      fmt.Sprintf("Correlation rejected: %s", cand.CandidateType),
			Content:    result.Reasoning,
			Confidence: result.Confidence,
			CreatedBy:  "analyst",
			ModelUsed:  &modelUsed,
			Status:     "active",
		}
		a.archive.InsertAnalyticalNote(ctx, note)

	case "defer":
		if result.Reasoning != "" {
			note := &archive.AnalyticalNote{
				NoteType:   "context",
				Title:      fmt.Sprintf("Deferred: need more data for %s", cand.CandidateType),
				Content:    result.Reasoning,
				Confidence: result.Confidence,
				CreatedBy:  "analyst",
				ModelUsed:  &modelUsed,
				Status:     "active",
			}
			a.archive.InsertAnalyticalNote(ctx, note)
		}
	}

	// 5. Log decision.
	if err := a.archive.InsertCorrelationDecision(ctx, decision); err != nil {
		log.Printf("brain: analyst: log decision error: %v", err)
	}

	return decision, nil
}

// buildCandidateContext gathers findings, entities, and notes to populate the
// LLM prompt. Errors in individual lookups are tolerated — we proceed with
// whatever context we can assemble.
func (a *Analyst) buildCandidateContext(ctx context.Context, cand archive.CorrelationCandidate) *analyzer.CorrelationPromptData {
	data := &analyzer.CorrelationPromptData{
		CandidateType: cand.CandidateType,
		SignalCount:   cand.SignalCount,
		Evidence:      signalsToString(cand.Signals),
	}

	// Fetch related findings.
	for _, fid := range cand.FindingIDs {
		rc, err := a.archive.FetchRawContentByID(ctx, fid)
		if err != nil {
			continue
		}
		data.Findings = append(data.Findings, analyzer.CorrelationFindingSummary{
			Category:    rc.Category,
			Severity:    rc.Severity,
			Summary:     rc.Summary,
			SourceName:  rc.SourceName,
			CollectedAt: rc.CollectedAt.Format(time.RFC3339),
		})
	}

	// Fetch related entities with their graph neighbors.
	for _, eid := range cand.EntityIDs {
		entity, err := a.archive.FetchEntityByID(ctx, eid)
		if err != nil {
			continue
		}
		neighbors, _ := a.archive.FetchEntityNeighbors(ctx, eid, 1)

		var neighborSummaries []analyzer.CorrelationNeighborSummary
		for _, n := range neighbors {
			neighborSummaries = append(neighborSummaries, analyzer.CorrelationNeighborSummary{
				ID:           n.ID,
				Relationship: n.Relationship,
			})
		}

		propsStr := "{}"
		if b, err := json.Marshal(entity.Properties); err == nil {
			propsStr = string(b)
		}

		data.Entities = append(data.Entities, analyzer.CorrelationEntitySummary{
			ID:         eid,
			Type:       entity.Type,
			Properties: propsStr,
			Neighbors:  neighborSummaries,
		})
	}

	// Fetch existing analytical notes for these entities.
	notes, _ := a.archive.FetchNotesForCorrelationContext(ctx, cand.EntityIDs)
	for _, n := range notes {
		data.Notes = append(data.Notes, analyzer.CorrelationNoteSummary{
			CreatedAt:  n.CreatedAt.Format(time.RFC3339),
			Title:      n.Title,
			Content:    n.Content,
			Confidence: n.Confidence,
		})
	}

	return data
}

// signalsToString converts the signals JSONB map to a readable string for the prompt.
func signalsToString(signals map[string]any) string {
	if len(signals) == 0 {
		return "(no signals)"
	}
	b, err := json.Marshal(signals)
	if err != nil {
		return "(error serializing signals)"
	}
	return string(b)
}

// promptDataToJSON converts prompt data to a JSON map for storing in context_snapshot.
func promptDataToJSON(data *analyzer.CorrelationPromptData) map[string]any {
	result := map[string]any{
		"candidate_type": data.CandidateType,
		"signal_count":   data.SignalCount,
		"finding_count":  len(data.Findings),
		"entity_count":   len(data.Entities),
		"note_count":     len(data.Notes),
	}
	return result
}
