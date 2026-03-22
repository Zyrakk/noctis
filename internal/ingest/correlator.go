package ingest

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
)

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

// correlationStore defines the archive operations used by the correlation engine.
// The real archive.Store satisfies this interface.
type correlationStore interface {
	FindSharedIOCs(ctx context.Context, minSources int) ([]archive.SharedIOCResult, error)
	FindHandleReuse(ctx context.Context, minSources int) ([]archive.HandleReuseResult, error)
	FindTemporalIOCOverlap(ctx context.Context, windowHours int, minSharedIOCs int) ([]archive.TemporalOverlapResult, error)
	FindEntityClusters(ctx context.Context, entityType string, minConnections int) ([]archive.EntityClusterResult, error)
	UpsertCorrelation(ctx context.Context, c *archive.Correlation) error
	UpsertCandidate(ctx context.Context, c *archive.CorrelationCandidate) error
	UpsertEntity(ctx context.Context, id, entityType string, properties map[string]interface{}) error
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

// correlationWorker runs the correlation engine on a periodic interval.
func (p *IngestPipeline) correlationWorker(ctx context.Context) {
	interval := time.Duration(p.corrCfg.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 15 * time.Minute
	}

	log.Printf("ingest: correlation worker started (interval=%s, threshold=%d)", interval, p.corrCfg.MinEvidenceThreshold)

	// Run once immediately on startup, then on interval.
	p.runCorrelationCycle(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("ingest: correlation worker stopping")
			return
		case <-ticker.C:
			p.runCorrelationCycle(ctx)
		}
	}
}

// runCorrelationCycle calls each rule function in sequence and logs totals.
func (p *IngestPipeline) runCorrelationCycle(ctx context.Context) {
	start := time.Now()
	log.Printf("ingest: correlation cycle starting")

	var totalCorrelations, totalCandidates int

	c, cand := p.correlateSharedIOCs(ctx)
	totalCorrelations += c
	totalCandidates += cand

	c, cand = p.correlateHandleReuse(ctx)
	totalCorrelations += c
	totalCandidates += cand

	c, cand = p.correlateTemporalOverlap(ctx)
	totalCorrelations += c
	totalCandidates += cand

	c, cand = p.correlateEntityClusters(ctx)
	totalCorrelations += c
	totalCandidates += cand

	log.Printf("ingest: correlation cycle complete in %s — %d correlations, %d candidates",
		time.Since(start).Round(time.Millisecond), totalCorrelations, totalCandidates)
}

func (p *IngestPipeline) correlateSharedIOCs(ctx context.Context) (correlations, candidates int) {
	results, err := p.corrStore.FindSharedIOCs(ctx, 2)
	if err != nil {
		log.Printf("ingest: correlate shared iocs: query error: %v", err)
		return 0, 0
	}

	threshold := p.corrCfg.MinEvidenceThreshold
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

		evidence := map[string]interface{}{
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
			if err := p.corrStore.UpsertCorrelation(ctx, corr); err != nil {
				log.Printf("ingest: correlate shared iocs: upsert error: %v", err)
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
			if err := p.corrStore.UpsertCandidate(ctx, cand); err != nil {
				log.Printf("ingest: correlate shared iocs: candidate error: %v", err)
				continue
			}
			candidates++
		}
	}
	return correlations, candidates
}

func (p *IngestPipeline) correlateHandleReuse(ctx context.Context) (correlations, candidates int) {
	results, err := p.corrStore.FindHandleReuse(ctx, 2)
	if err != nil {
		log.Printf("ingest: correlate handle reuse: query error: %v", err)
		return 0, 0
	}

	threshold := p.corrCfg.MinEvidenceThreshold
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

		// Create/update actor entity with same normalization as bridgeLLMEntitiesToGraph.
		normalized := strings.ToLower(strings.ReplaceAll(r.Author, " ", "_"))
		entityID := fmt.Sprintf("entity:threat_actor:%s", normalized)
		props := map[string]interface{}{
			"name":    r.Author,
			"sources": r.Sources,
		}
		if r.AuthorID != "" {
			props["author_id"] = r.AuthorID
		}
		if err := p.corrStore.UpsertEntity(ctx, entityID, "threat_actor", props); err != nil {
			log.Printf("ingest: correlate handle reuse: upsert entity error: %v", err)
		}

		entityIDs := []string{entityID}
		evidence := map[string]interface{}{
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
			if err := p.corrStore.UpsertCorrelation(ctx, corr); err != nil {
				log.Printf("ingest: correlate handle reuse: upsert error: %v", err)
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
			if err := p.corrStore.UpsertCandidate(ctx, cand); err != nil {
				log.Printf("ingest: correlate handle reuse: candidate error: %v", err)
				continue
			}
			candidates++
		}
	}
	return correlations, candidates
}

func (p *IngestPipeline) correlateTemporalOverlap(ctx context.Context) (correlations, candidates int) {
	windowHours := p.corrCfg.TemporalWindowHours
	if windowHours <= 0 {
		windowHours = 48
	}

	results, err := p.corrStore.FindTemporalIOCOverlap(ctx, windowHours, 2)
	if err != nil {
		log.Printf("ingest: correlate temporal overlap: query error: %v", err)
		return 0, 0
	}

	threshold := p.corrCfg.MinEvidenceThreshold
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
		evidence := map[string]interface{}{
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
			if err := p.corrStore.UpsertCorrelation(ctx, corr); err != nil {
				log.Printf("ingest: correlate temporal overlap: upsert error: %v", err)
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
			if err := p.corrStore.UpsertCandidate(ctx, cand); err != nil {
				log.Printf("ingest: correlate temporal overlap: candidate error: %v", err)
				continue
			}
			candidates++
		}
	}
	return correlations, candidates
}

func (p *IngestPipeline) correlateEntityClusters(ctx context.Context) (correlations, candidates int) {
	threshold := p.corrCfg.MinEvidenceThreshold
	if threshold <= 0 {
		threshold = 3
	}

	// Find actors sharing infrastructure/malware.
	actorResults, err := p.corrStore.FindEntityClusters(ctx, "threat_actor", 2)
	if err != nil {
		log.Printf("ingest: correlate entity clusters: actor query error: %v", err)
	}

	// Find malware families sharing C2/infrastructure.
	malwareResults, err := p.corrStore.FindEntityClusters(ctx, "malware", 2)
	if err != nil {
		log.Printf("ingest: correlate entity clusters: malware query error: %v", err)
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
		evidence := map[string]interface{}{
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
			if err := p.corrStore.UpsertCorrelation(ctx, corr); err != nil {
				log.Printf("ingest: correlate entity clusters: upsert error: %v", err)
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
			if err := p.corrStore.UpsertCandidate(ctx, cand); err != nil {
				log.Printf("ingest: correlate entity clusters: candidate error: %v", err)
				continue
			}
			candidates++
		}
	}
	return correlations, candidates
}
