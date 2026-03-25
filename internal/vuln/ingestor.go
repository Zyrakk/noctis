package vuln

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/modules"
)

// VulnIngestor orchestrates vulnerability intelligence ingestion from
// NVD, EPSS, and CISA KEV APIs, cross-references with Noctis data,
// and computes priority scores.
type VulnIngestor struct {
	archive    *archive.Store
	httpClient *http.Client
	status     *modules.StatusTracker
	cfg        config.VulnConfig

	lastNVDPoll  time.Time
	lastEPSSPoll time.Time
	lastKEVPoll  time.Time
}

// NewVulnIngestor creates a new vulnerability ingestor.
func NewVulnIngestor(archiveStore *archive.Store, cfg config.VulnConfig) *VulnIngestor {
	return &VulnIngestor{
		archive: archiveStore,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
		cfg:    cfg,
		status: modules.NewStatusTracker(modules.ModVulnIngestor, "Vuln Ingestor", "infra"),
	}
}

// Status returns the module status tracker for registry registration.
func (v *VulnIngestor) Status() *modules.StatusTracker {
	return v.status
}

// Run starts the periodic vulnerability ingestion loop.
func (v *VulnIngestor) Run(ctx context.Context) {
	if !v.cfg.Enabled {
		return
	}
	v.status.SetEnabled(true)
	v.status.MarkStarted()
	defer v.status.MarkStopped()

	interval := time.Duration(v.cfg.IntervalHours) * time.Hour
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	v.status.SetExtra("interval", interval.String())
	v.status.SetExtra("nvd_api_key", v.cfg.NVDAPIKey != "")

	log.Printf("vuln: ingestor started (interval=%s, nvd_key=%v)", interval, v.cfg.NVDAPIKey != "")

	// Run first cycle immediately.
	v.runCycle(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("vuln: ingestor stopping")
			return
		case <-ticker.C:
			v.runCycle(ctx)
		}
	}
}

func (v *VulnIngestor) runCycle(ctx context.Context) {
	start := time.Now()

	// 1. Fetch NVD updates.
	nvdCount, err := v.fetchNVDUpdates(ctx, v.lastNVDPoll)
	if err != nil {
		v.status.RecordError(err)
		log.Printf("vuln: nvd error: %v", err)
	} else {
		v.lastNVDPoll = start
		v.status.SetExtra("last_nvd_count", nvdCount)
	}

	// 2. EPSS — once per day.
	if v.shouldUpdateEPSS() {
		epssCount, err := v.updateEPSSScores(ctx)
		if err != nil {
			v.status.RecordError(err)
			log.Printf("vuln: epss error: %v", err)
		} else {
			v.lastEPSSPoll = start
			v.status.SetExtra("last_epss_count", epssCount)
			log.Printf("vuln: epss updated %d scores", epssCount)
		}
	}

	// 3. KEV — once per day.
	if v.shouldUpdateKEV() {
		kevCount, err := v.updateKEVData(ctx)
		if err != nil {
			v.status.RecordError(err)
			log.Printf("vuln: kev error: %v", err)
		} else {
			v.lastKEVPoll = start
			v.status.SetExtra("last_kev_count", kevCount)
			log.Printf("vuln: kev updated %d entries", kevCount)
		}
	}

	// 4. Cross-reference with Noctis data.
	enriched, err := v.crossReferenceNoctisData(ctx)
	if err != nil {
		log.Printf("vuln: enrichment error: %v", err)
	} else {
		v.status.SetExtra("last_enriched", enriched)
	}

	// 5. Recompute priorities.
	prioritized, err := v.recomputePriorities(ctx)
	if err != nil {
		log.Printf("vuln: priority error: %v", err)
	} else {
		v.status.SetExtra("last_prioritized", prioritized)
	}

	v.status.SetExtra("last_cycle_duration", time.Since(start).String())
	v.status.RecordSuccess()

	log.Printf("vuln: cycle complete in %s — nvd=%d, enriched=%d, prioritized=%d",
		time.Since(start).Round(time.Millisecond), nvdCount, enriched, prioritized)
}

// shouldUpdateEPSS returns true if EPSS hasn't been updated today.
func (v *VulnIngestor) shouldUpdateEPSS() bool {
	if v.lastEPSSPoll.IsZero() {
		return true
	}
	return time.Since(v.lastEPSSPoll) > 24*time.Hour
}

// shouldUpdateKEV returns true if KEV hasn't been updated today.
func (v *VulnIngestor) shouldUpdateKEV() bool {
	if v.lastKEVPoll.IsZero() {
		return true
	}
	return time.Since(v.lastKEVPoll) > 24*time.Hour
}
