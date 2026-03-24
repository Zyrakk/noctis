package brain

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/modules"
	"github.com/Zyrakk/noctis/internal/processor"
)

// BriefGenerator produces periodic intelligence briefs by gathering metrics
// and sending them to the LLM for synthesis.
type BriefGenerator struct {
	analyzer *analyzer.Analyzer
	archive  *archive.Store
	sem      *processor.ConcurrencyLimiter
	status   *modules.StatusTracker
	cfg      config.BriefConfig
	model    string
}

// NewBriefGenerator creates a brief generator.
func NewBriefGenerator(
	a *analyzer.Analyzer,
	archiveStore *archive.Store,
	cfg config.BriefConfig,
	concurrency int,
	provider, model string,
) *BriefGenerator {
	bg := &BriefGenerator{
		analyzer: a,
		archive:  archiveStore,
		sem:      processor.NewConcurrencyLimiter(concurrency),
		cfg:      cfg,
		model:    model,
		status:   modules.NewStatusTracker(modules.ModBriefGenerator, "Brief Generator", "brain"),
	}
	bg.status.SetAIInfo(provider, model)
	bg.status.SetEnabled(cfg.Enabled)
	return bg
}

// Run starts the daily brief schedule and blocks until ctx is cancelled.
func (bg *BriefGenerator) Run(ctx context.Context) {
	if !bg.cfg.Enabled {
		return
	}
	bg.status.MarkStarted()
	defer bg.status.MarkStopped()

	scheduleHour := bg.cfg.ScheduleHour
	if scheduleHour < 0 || scheduleHour > 23 {
		scheduleHour = 6
	}

	log.Printf("brain: brief generator started (schedule=%02d:00 UTC)", scheduleHour)
	bg.status.SetExtra("schedule_hour", fmt.Sprintf("%02d:00 UTC", scheduleHour))

	// On startup, check if today's brief exists. If not, generate one.
	latest, err := bg.archive.FetchLatestBrief(ctx, "daily")
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		bg.status.RecordError(err)
		log.Printf("brain: brief generator: startup check error: %v", err)
	} else if latest == nil || errors.Is(err, pgx.ErrNoRows) || latest.PeriodEnd.Before(startOfDay(time.Now().UTC())) {
		log.Printf("brain: brief generator: no brief for today, generating on startup")
		bg.generateBrief(ctx)
	}

	for {
		next := nextScheduleTime(scheduleHour)
		bg.status.SetExtra("next_run", next.Format(time.RFC3339))

		select {
		case <-ctx.Done():
			log.Printf("brain: brief generator stopping")
			return
		case <-time.After(time.Until(next)):
			bg.generateBrief(ctx)
		}
	}
}

func (bg *BriefGenerator) generateBrief(ctx context.Context) {
	start := time.Now()
	end := time.Now().UTC()
	periodStart := end.Add(-24 * time.Hour)

	log.Printf("brain: brief generator: gathering metrics for %s to %s",
		periodStart.Format(time.RFC3339), end.Format(time.RFC3339))

	// 1. Gather metrics.
	metrics, err := bg.archive.FetchBriefMetrics(ctx, periodStart, end)
	if err != nil {
		bg.status.RecordError(err)
		log.Printf("brain: brief generator: metrics error: %v", err)
		return
	}

	// Skip if no data.
	totalFindings := sumMap(metrics.FindingsBySeverity)
	if totalFindings == 0 {
		log.Printf("brain: brief generator: no findings in period, skipping")
		bg.status.SetExtra("last_skip_reason", "no findings")
		return
	}

	// 2. Gather top findings.
	topFindings, err := bg.archive.FetchTopFindings(ctx, periodStart, end, 10)
	if err != nil {
		log.Printf("brain: brief generator: top findings error: %v", err)
		// non-fatal, continue with empty
	}

	// 3. Gather trending entities.
	trendingEntities, err := bg.archive.FetchTrendingEntities(ctx, periodStart, end, 10)
	if err != nil {
		log.Printf("brain: brief generator: trending entities error: %v", err)
	}

	// 4. Build prompt data.
	totalIOCs := sumMap(metrics.NewIOCsByType)
	promptData := &analyzer.BriefPromptData{
		PeriodStart:      periodStart.Format("2006-01-02 15:04 UTC"),
		PeriodEnd:        end.Format("2006-01-02 15:04 UTC"),
		TotalFindings:    totalFindings,
		CriticalFindings: metrics.FindingsBySeverity["critical"],
		HighFindings:     metrics.FindingsBySeverity["high"],
		TotalIOCs:        totalIOCs,
		NewCorrelations:  metrics.NewCorrelations,
		AnalystConfirmed: metrics.AnalystConfirmed,
		NewNotes:         metrics.NewNotes,
		DeactivatedIOCs:  metrics.DeactivatedIOCs,
	}

	for _, f := range topFindings {
		promptData.TopFindings = append(promptData.TopFindings, analyzer.BriefFinding{
			Severity:    f.Severity,
			Category:    f.Category,
			SubCategory: f.SubCategory,
			Summary:     f.Summary,
			SourceName:  f.SourceName,
		})
	}
	for _, e := range trendingEntities {
		promptData.TrendingEntities = append(promptData.TrendingEntities, analyzer.BriefEntity{
			ID:           e.ID,
			Type:         e.Type,
			MentionCount: e.MentionCount,
			PrevCount:    e.PrevCount,
		})
	}
	for _, s := range metrics.SourceActivity {
		promptData.SourceActivity = append(promptData.SourceActivity, analyzer.BriefSource{
			Name:         s.Name,
			FindingCount: s.FindingCount,
			ValueScore:   s.ValueScore,
		})
	}

	// 5. Call LLM.
	if err := bg.sem.Acquire(ctx); err != nil {
		return
	}
	result, err := bg.analyzer.GenerateBrief(ctx, promptData)
	bg.sem.Release()
	if err != nil {
		bg.status.RecordError(err)
		log.Printf("brain: brief generator: LLM error: %v", err)
		return
	}

	// 6. Build full markdown content from sections.
	content := buildMarkdownContent(result)

	// 7. Store brief.
	modelUsed := bg.model
	metricsMap := map[string]any{
		"total_findings":    totalFindings,
		"critical_findings": metrics.FindingsBySeverity["critical"],
		"high_findings":     metrics.FindingsBySeverity["high"],
		"total_iocs":        totalIOCs,
		"new_correlations":  metrics.NewCorrelations,
		"analyst_confirmed": metrics.AnalystConfirmed,
		"new_notes":         metrics.NewNotes,
		"deactivated_iocs":  metrics.DeactivatedIOCs,
	}

	brief := &archive.IntelligenceBrief{
		PeriodStart:          periodStart,
		PeriodEnd:            end,
		BriefType:            "daily",
		Title:                result.Title,
		ExecutiveSummary:     result.ExecutiveSummary,
		Content:              content,
		Sections:             result.Sections,
		Metrics:              metricsMap,
		ModelUsed:            &modelUsed,
		GenerationDurationMs: int(time.Since(start).Milliseconds()),
	}

	if err := bg.archive.InsertBrief(ctx, brief); err != nil {
		bg.status.RecordError(err)
		log.Printf("brain: brief generator: store error: %v", err)
		return
	}

	bg.status.SetExtra("last_brief_id", brief.ID)
	bg.status.SetExtra("last_duration", time.Since(start).String())
	bg.status.SetExtra("last_findings", totalFindings)
	bg.status.RecordSuccess()

	log.Printf("brain: brief generated in %s — %q (%d findings, %d IOCs)",
		time.Since(start).Round(time.Millisecond), result.Title, totalFindings, totalIOCs)
}

// nextScheduleTime returns the next occurrence of the given hour (UTC).
func nextScheduleTime(hour int) time.Time {
	now := time.Now().UTC()
	next := time.Date(now.Year(), now.Month(), now.Day(), hour, 0, 0, 0, time.UTC)
	if next.Before(now) {
		next = next.Add(24 * time.Hour)
	}
	return next
}

// startOfDay returns midnight UTC for the given time.
func startOfDay(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// sumMap returns the sum of all values in a map.
func sumMap(m map[string]int64) int64 {
	var total int64
	for _, v := range m {
		total += v
	}
	return total
}

// buildMarkdownContent renders brief sections as markdown.
func buildMarkdownContent(result *analyzer.BriefResult) string {
	content := "# " + result.Title + "\n\n"
	content += "## Executive Summary\n\n" + result.ExecutiveSummary + "\n\n"

	sectionOrder := []struct{ key, title string }{
		{"key_threats", "Key Threats"},
		{"correlation_insights", "Correlation Insights"},
		{"emerging_trends", "Emerging Trends"},
		{"collection_gaps", "Collection Gaps"},
		{"recommended_actions", "Recommended Actions"},
	}

	for _, s := range sectionOrder {
		if val, ok := result.Sections[s.key]; ok {
			if str, ok := val.(string); ok {
				content += "## " + s.title + "\n\n" + str + "\n\n"
			} else {
				content += "## " + s.title + "\n\n" + fmt.Sprintf("%v", val) + "\n\n"
			}
		}
	}

	return content
}
