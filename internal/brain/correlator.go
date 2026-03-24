package brain

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/modules"
)

// CorrelationStore defines the archive operations used by the correlation engine.
// The real archive.Store satisfies this interface.
type CorrelationStore interface {
	FindSharedIOCs(ctx context.Context, minSources int) ([]archive.SharedIOCResult, error)
	FindHandleReuse(ctx context.Context, minSources int) ([]archive.HandleReuseResult, error)
	FindTemporalIOCOverlap(ctx context.Context, windowHours int, minSharedIOCs int) ([]archive.TemporalOverlapResult, error)
	FindEntityClusters(ctx context.Context, entityType string, minConnections int) ([]archive.EntityClusterResult, error)
	UpsertCorrelation(ctx context.Context, c *archive.Correlation) error
	UpsertCandidate(ctx context.Context, c *archive.CorrelationCandidate) error
	UpsertEntity(ctx context.Context, id, entityType string, properties map[string]any) error
}

// toolWhitelist contains entity names that are legitimate security/forensics
// tools and should not serve as the sole basis for campaign clustering.
// If ALL shared entities in a cluster are whitelisted, the correlation is skipped.
var toolWhitelist = map[string]bool{
	// Forensics & IR tools
	"volatility": true, "dumpit": true, "autopsy": true, "ftk": true,
	"process monitor": true, "procmon": true, "wireshark": true, "tcpdump": true,
	"velociraptor": true,
	// Offensive security / red team tools (commonly discussed in reporting)
	"mimikatz": true, "bloodhound": true, "sharphound": true, "rubeus": true,
	"impacket": true, "crackmapexec": true, "netexec": true, "responder": true,
	"hashcat": true, "john the ripper": true, "nmap": true, "burp suite": true,
	"metasploit": true, "nuclei": true,
	// Generic technique names that aren't campaigns
	"credential_theft": true, "credential_dumping": true, "memory_dump": true,
	"lateral_movement": true, "privilege_escalation": true, "dll_sideloading": true,
	"phishing": true,
}

// Correlator is the correlation sub-module with its own status tracking.
type Correlator struct {
	store  CorrelationStore
	cfg    config.CorrelationConfig
	status *modules.StatusTracker
}

// NewCorrelator creates a correlator bound to the given store and config.
func NewCorrelator(store CorrelationStore, cfg config.CorrelationConfig) *Correlator {
	c := &Correlator{
		store:  store,
		cfg:    cfg,
		status: modules.NewStatusTracker(modules.ModCorrelator, "Correlator", "brain"),
	}
	c.status.SetEnabled(cfg.Enabled)
	return c
}

// Run starts the correlation engine on a periodic interval and blocks until
// ctx is cancelled.
func (c *Correlator) Run(ctx context.Context) {
	if !c.cfg.Enabled {
		return
	}
	c.status.MarkStarted()
	defer c.status.MarkStopped()

	interval := time.Duration(c.cfg.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	c.status.SetExtra("interval", interval.String())

	log.Printf("brain: correlator started (interval=%s, threshold=%d)", interval, c.cfg.MinEvidenceThreshold)

	// Run once immediately on startup, then on interval.
	c.runCycle(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("brain: correlator stopping")
			return
		case <-ticker.C:
			c.runCycle(ctx)
		}
	}
}

// runCycle calls each rule function in sequence and logs totals.
func (c *Correlator) runCycle(ctx context.Context) {
	start := time.Now()

	var totalCorrelations, totalCandidates int

	co, ca := c.correlateSharedIOCs(ctx)
	totalCorrelations += co
	totalCandidates += ca

	co, ca = c.correlateHandleReuse(ctx)
	totalCorrelations += co
	totalCandidates += ca

	co, ca = c.correlateTemporalOverlap(ctx)
	totalCorrelations += co
	totalCandidates += ca

	co, ca = c.correlateEntityClusters(ctx)
	totalCorrelations += co
	totalCandidates += ca

	// Update status tracker.
	c.status.SetExtra("last_cycle_duration", time.Since(start).String())
	c.status.SetExtra("last_cycle_correlations", totalCorrelations)
	c.status.SetExtra("last_cycle_candidates", totalCandidates)
	c.status.RecordSuccess()

	log.Printf("brain: correlation cycle complete in %s — %d correlations, %d candidates",
		time.Since(start).Round(time.Millisecond), totalCorrelations, totalCandidates)
}

// corrClusterID generates a deterministic cluster ID for deduplication.
func corrClusterID(corrType, input string) string {
	h := sha256.Sum256([]byte(input))
	return fmt.Sprintf("corr:%s:%x", corrType, h)
}

// clampConfidence ensures confidence is in [0.0, 1.0].
func clampConfidence(v float64) float64 {
	if v > 1.0 {
		return 1.0
	}
	if v < 0.0 {
		return 0.0
	}
	return v
}

func (c *Correlator) correlateSharedIOCs(ctx context.Context) (correlations, candidates int) {
	results, err := c.store.FindSharedIOCs(ctx, 2)
	if err != nil {
		log.Printf("brain: correlate shared iocs: query error: %v", err)
		c.status.RecordError(err)
		return 0, 0
	}

	threshold := c.cfg.MinEvidenceThreshold
	if threshold <= 0 {
		threshold = 3
	}

	for _, r := range results {
		signalCount := r.SourceCount
		clusterID := corrClusterID("shared_ioc", r.IOCType+":"+r.IOCValue)

		entityIDs := []string{fmt.Sprintf("ioc:%s:%s", r.IOCType, r.IOCValue)}
		for _, src := range r.Sources {
			entityIDs = append(entityIDs, fmt.Sprintf("source:%s", src))
		}

		evidence := map[string]any{
			"ioc_type":    r.IOCType,
			"ioc_value":   r.IOCValue,
			"sources":     r.Sources,
			"finding_ids": r.FindingIDs,
		}

		if signalCount >= threshold {
			confidence := clampConfidence(float64(signalCount)*0.15 + 0.5)
			corr := &archive.Correlation{
				ClusterID:       clusterID,
				EntityIDs:       entityIDs,
				FindingIDs:      r.FindingIDs,
				CorrelationType: "shared_ioc",
				Confidence:      confidence,
				Method:          "rule",
				Evidence:        evidence,
			}
			if err := c.store.UpsertCorrelation(ctx, corr); err != nil {
				log.Printf("brain: correlate shared iocs: upsert error: %v", err)
				c.status.RecordError(err)
				continue
			}
			correlations++
		} else {
			cand := &archive.CorrelationCandidate{
				ClusterID:     clusterID,
				EntityIDs:     entityIDs,
				FindingIDs:    r.FindingIDs,
				CandidateType: "shared_ioc",
				SignalCount:   signalCount,
				Signals:       evidence,
				Status:        "pending",
			}
			if err := c.store.UpsertCandidate(ctx, cand); err != nil {
				log.Printf("brain: correlate shared iocs: candidate error: %v", err)
				c.status.RecordError(err)
				continue
			}
			candidates++
		}
	}
	return correlations, candidates
}

func (c *Correlator) correlateHandleReuse(ctx context.Context) (correlations, candidates int) {
	results, err := c.store.FindHandleReuse(ctx, 2)
	if err != nil {
		log.Printf("brain: correlate handle reuse: query error: %v", err)
		c.status.RecordError(err)
		return 0, 0
	}

	threshold := c.cfg.MinEvidenceThreshold
	if threshold <= 0 {
		threshold = 3
	}

	for _, r := range results {
		signalCount := r.SourceCount
		authorID := r.AuthorID
		if authorID == "" {
			authorID = "_"
		}
		clusterID := corrClusterID("handle_reuse", r.Author+":"+authorID)

		// Create/update actor entity with same normalization as graph bridge.
		normalized := strings.ToLower(strings.ReplaceAll(r.Author, " ", "_"))
		entityID := fmt.Sprintf("entity:threat_actor:%s", normalized)
		props := map[string]any{
			"name":    r.Author,
			"sources": r.Sources,
		}
		if r.AuthorID != "" {
			props["author_id"] = r.AuthorID
		}
		if err := c.store.UpsertEntity(ctx, entityID, "threat_actor", props); err != nil {
			log.Printf("brain: correlate handle reuse: upsert entity error: %v", err)
			c.status.RecordError(err)
		}

		entityIDs := []string{entityID}
		evidence := map[string]any{
			"author":      r.Author,
			"author_id":   r.AuthorID,
			"sources":     r.Sources,
			"finding_ids": r.FindingIDs,
		}

		if signalCount >= threshold {
			confidence := clampConfidence(float64(signalCount)*0.2 + 0.4)
			corr := &archive.Correlation{
				ClusterID:       clusterID,
				EntityIDs:       entityIDs,
				FindingIDs:      r.FindingIDs,
				CorrelationType: "handle_reuse",
				Confidence:      confidence,
				Method:          "rule",
				Evidence:        evidence,
			}
			if err := c.store.UpsertCorrelation(ctx, corr); err != nil {
				log.Printf("brain: correlate handle reuse: upsert error: %v", err)
				c.status.RecordError(err)
				continue
			}
			correlations++
		} else {
			cand := &archive.CorrelationCandidate{
				ClusterID:     clusterID,
				EntityIDs:     entityIDs,
				FindingIDs:    r.FindingIDs,
				CandidateType: "handle_reuse",
				SignalCount:   signalCount,
				Signals:       evidence,
				Status:        "pending",
			}
			if err := c.store.UpsertCandidate(ctx, cand); err != nil {
				log.Printf("brain: correlate handle reuse: candidate error: %v", err)
				c.status.RecordError(err)
				continue
			}
			candidates++
		}
	}
	return correlations, candidates
}

func (c *Correlator) correlateTemporalOverlap(ctx context.Context) (correlations, candidates int) {
	windowHours := c.cfg.TemporalWindowHours
	if windowHours <= 0 {
		windowHours = 48
	}

	results, err := c.store.FindTemporalIOCOverlap(ctx, windowHours, 2)
	if err != nil {
		log.Printf("brain: correlate temporal overlap: query error: %v", err)
		c.status.RecordError(err)
		return 0, 0
	}

	threshold := c.cfg.MinEvidenceThreshold
	if threshold <= 0 {
		threshold = 3
	}

	for _, r := range results {
		signalCount := r.SharedCount

		// Sort finding IDs for deterministic cluster ID.
		a, b := r.FindingA, r.FindingB
		if a > b {
			a, b = b, a
		}
		clusterID := corrClusterID("temporal", a+":"+b)

		// Build entity IDs from shared IOCs (format: "type:value").
		var entityIDs []string
		for _, iocPair := range r.SharedIOCs {
			parts := strings.SplitN(iocPair, ":", 2)
			if len(parts) == 2 {
				entityIDs = append(entityIDs, fmt.Sprintf("ioc:%s:%s", parts[0], parts[1]))
			}
		}

		findingIDs := []string{r.FindingA, r.FindingB}
		evidence := map[string]any{
			"finding_a":    r.FindingA,
			"finding_b":    r.FindingB,
			"source_a":     r.SourceA,
			"source_b":     r.SourceB,
			"shared_iocs":  r.SharedIOCs,
			"window_hours": windowHours,
		}

		if signalCount >= threshold {
			confidence := clampConfidence(float64(signalCount)*0.2 + 0.3)
			corr := &archive.Correlation{
				ClusterID:       clusterID,
				EntityIDs:       entityIDs,
				FindingIDs:      findingIDs,
				CorrelationType: "temporal_ioc_overlap",
				Confidence:      confidence,
				Method:          "rule",
				Evidence:        evidence,
			}
			if err := c.store.UpsertCorrelation(ctx, corr); err != nil {
				log.Printf("brain: correlate temporal overlap: upsert error: %v", err)
				c.status.RecordError(err)
				continue
			}
			correlations++
		} else {
			cand := &archive.CorrelationCandidate{
				ClusterID:     clusterID,
				EntityIDs:     entityIDs,
				FindingIDs:    findingIDs,
				CandidateType: "temporal_ioc_overlap",
				SignalCount:   signalCount,
				Signals:       evidence,
				Status:        "pending",
			}
			if err := c.store.UpsertCandidate(ctx, cand); err != nil {
				log.Printf("brain: correlate temporal overlap: candidate error: %v", err)
				c.status.RecordError(err)
				continue
			}
			candidates++
		}
	}
	return correlations, candidates
}

func (c *Correlator) correlateEntityClusters(ctx context.Context) (correlations, candidates int) {
	threshold := c.cfg.MinEvidenceThreshold
	if threshold <= 0 {
		threshold = 3
	}

	// Find actors sharing infrastructure/malware.
	actorResults, err := c.store.FindEntityClusters(ctx, "threat_actor", 2)
	if err != nil {
		log.Printf("brain: correlate entity clusters: actor query error: %v", err)
		c.status.RecordError(err)
	}

	// Find malware families sharing C2/infrastructure.
	malwareResults, err := c.store.FindEntityClusters(ctx, "malware", 2)
	if err != nil {
		log.Printf("brain: correlate entity clusters: malware query error: %v", err)
		c.status.RecordError(err)
	}

	allResults := make([]archive.EntityClusterResult, 0, len(actorResults)+len(malwareResults))
	allResults = append(allResults, actorResults...)
	allResults = append(allResults, malwareResults...)

	for _, r := range allResults {
		// Skip clusters where ALL shared entities are whitelisted tools.
		allWhitelisted := true
		for _, name := range r.SharedNames {
			if !toolWhitelist[strings.ToLower(strings.TrimSpace(name))] {
				allWhitelisted = false
				break
			}
		}
		if allWhitelisted && len(r.SharedNames) > 0 {
			continue
		}

		signalCount := r.SharedCount

		a, b := r.EntityA, r.EntityB
		if a > b {
			a, b = b, a
		}
		clusterID := corrClusterID("campaign", a+":"+b)

		entityIDs := append([]string{r.EntityA, r.EntityB}, r.SharedIDs...)
		evidence := map[string]any{
			"entity_a":        r.EntityA,
			"name_a":          r.NameA,
			"entity_b":        r.EntityB,
			"name_b":          r.NameB,
			"shared_entities": r.SharedIDs,
			"shared_names":    r.SharedNames,
		}

		if signalCount >= threshold {
			confidence := clampConfidence(float64(signalCount)*0.15 + 0.4)
			corr := &archive.Correlation{
				ClusterID:       clusterID,
				EntityIDs:       entityIDs,
				FindingIDs:      []string{},
				CorrelationType: "campaign_cluster",
				Confidence:      confidence,
				Method:          "rule",
				Evidence:        evidence,
			}
			if err := c.store.UpsertCorrelation(ctx, corr); err != nil {
				log.Printf("brain: correlate entity clusters: upsert error: %v", err)
				c.status.RecordError(err)
				continue
			}
			correlations++
		} else {
			cand := &archive.CorrelationCandidate{
				ClusterID:     clusterID,
				EntityIDs:     entityIDs,
				FindingIDs:    []string{},
				CandidateType: "campaign_cluster",
				SignalCount:   signalCount,
				Signals:       evidence,
				Status:        "pending",
			}
			if err := c.store.UpsertCandidate(ctx, cand); err != nil {
				log.Printf("brain: correlate entity clusters: candidate error: %v", err)
				c.status.RecordError(err)
				continue
			}
			candidates++
		}
	}
	return correlations, candidates
}
