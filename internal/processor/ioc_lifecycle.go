package processor

import (
	"context"
	"log"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/modules"
)

// IOCLifecycleManager runs periodically to apply confidence decay to active IOCs
// and deactivate those that fall below the threshold.
type IOCLifecycleManager struct {
	archive *archive.Store
	status  *modules.StatusTracker
	cfg     config.IOCLifecycleConfig
}

// NewIOCLifecycleManager creates a new lifecycle manager.
func NewIOCLifecycleManager(archiveStore *archive.Store, cfg config.IOCLifecycleConfig) *IOCLifecycleManager {
	m := &IOCLifecycleManager{
		archive: archiveStore,
		cfg:     cfg,
		status:  modules.NewStatusTracker(modules.ModIOCLifecycle, "IOC Lifecycle", "processor"),
	}
	m.status.SetEnabled(cfg.Enabled)
	return m
}

// Run starts the periodic lifecycle loop. Blocks until ctx is cancelled.
func (m *IOCLifecycleManager) Run(ctx context.Context) {
	if !m.cfg.Enabled {
		return
	}
	m.status.MarkStarted()
	defer m.status.MarkStopped()

	interval := time.Duration(m.cfg.IntervalMinutes) * time.Minute
	if interval <= 0 {
		interval = 60 * time.Minute
	}

	threshold := m.cfg.DeactivateThreshold
	if threshold <= 0 {
		threshold = 0.1
	}

	m.status.SetExtra("interval", interval.String())
	m.status.SetExtra("deactivate_threshold", threshold)

	log.Printf("processor: ioc lifecycle started (interval=%s, threshold=%.2f)", interval, threshold)

	// Backfill lifetime defaults on startup.
	if err := m.archive.SetIOCLifetimeDefaults(ctx); err != nil {
		log.Printf("processor: ioc lifecycle: backfill lifetime defaults error: %v", err)
	} else {
		log.Printf("processor: ioc lifecycle: lifetime defaults backfilled")
	}

	// Run first cycle immediately.
	m.runCycle(ctx, threshold)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("processor: ioc lifecycle stopping")
			return
		case <-ticker.C:
			m.runCycle(ctx, threshold)
		}
	}
}

func (m *IOCLifecycleManager) runCycle(ctx context.Context, threshold float64) {
	start := time.Now()

	updated, deactivated, err := m.archive.UpdateIOCScores(ctx, threshold)
	if err != nil {
		m.status.RecordError(err)
		log.Printf("processor: ioc lifecycle cycle error: %v", err)
		return
	}

	m.status.SetExtra("last_cycle_duration", time.Since(start).String())
	m.status.SetExtra("last_updated", updated)
	m.status.SetExtra("last_deactivated", deactivated)
	m.status.RecordSuccess()

	log.Printf("processor: ioc lifecycle cycle complete in %s — updated %d scores, deactivated %d IOCs",
		time.Since(start).Round(time.Millisecond), updated, deactivated)
}
