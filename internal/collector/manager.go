package collector

import (
	"context"
	"log"
	"strings"
	"sync"

	"github.com/Zyrakk/noctis/internal/models"
	"github.com/Zyrakk/noctis/internal/modules"
)

// CollectorManager wraps all collectors and registers each one as a tracked
// module in the status registry. It owns the goroutine lifecycle and
// finding fan-in.
type CollectorManager struct {
	collectors  []Collector
	trackers    map[string]*modules.StatusTracker
	ingestFn    func(ctx context.Context, f models.Finding) error
	discoveryFn func(ctx context.Context, content string, findingID string) error
	registry    *modules.Registry
}

// NewCollectorManager creates a manager that tracks each collector as an
// independent module. ingestFn is called for every finding; discoveryFn
// (may be nil) is called after ingest.
func NewCollectorManager(
	collectors []Collector,
	registry *modules.Registry,
	ingestFn func(ctx context.Context, f models.Finding) error,
	discoveryFn func(ctx context.Context, content string, findingID string) error,
) *CollectorManager {
	mgr := &CollectorManager{
		collectors:  collectors,
		trackers:    make(map[string]*modules.StatusTracker, len(collectors)),
		ingestFn:    ingestFn,
		discoveryFn: discoveryFn,
		registry:    registry,
	}

	for _, coll := range collectors {
		name := coll.Name()
		id := collectorModuleID(name)
		tracker := modules.NewStatusTracker(id, name, "collector")
		tracker.SetEnabled(true)
		mgr.trackers[name] = tracker
		registry.Register(tracker)
	}

	return mgr
}

// Run starts all collectors and blocks until ctx is cancelled and all
// goroutines have drained.
func (m *CollectorManager) Run(ctx context.Context) {
	var wg sync.WaitGroup

	for _, coll := range m.collectors {
		c := coll
		name := c.Name()
		tracker := m.trackers[name]
		ch := make(chan models.Finding, 50)

		tracker.MarkStarted()

		// Goroutine A: collector producer.
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer tracker.MarkStopped()
			if err := c.Start(ctx, ch); err != nil && ctx.Err() == nil {
				log.Printf("collector: %s error: %v", name, err)
				tracker.RecordError(err)
			}
		}()

		// Goroutine B: finding consumer → ingest + discovery.
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range ch {
				if err := m.ingestFn(ctx, f); err != nil {
					log.Printf("collector: %s ingest error: %v", name, err)
					tracker.RecordError(err)
				}
				if m.discoveryFn != nil {
					if err := m.discoveryFn(ctx, f.Content, f.ID); err != nil {
						log.Printf("collector: %s discovery error: %v", name, err)
					}
				}
				tracker.RecordSuccess()
			}
		}()
	}

	wg.Wait()
}

// collectorModuleID maps a collector name to its modules.ModuleID.
func collectorModuleID(name string) modules.ModuleID {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "telegram"):
		return modules.ModCollectorTelegram
	case strings.Contains(lower, "paste"):
		return modules.ModCollectorPaste
	case strings.Contains(lower, "forum"):
		return modules.ModCollectorForum
	case strings.Contains(lower, "rss") || strings.Contains(lower, "web"):
		return modules.ModCollectorRSS
	default:
		return modules.ModuleID("collector." + lower)
	}
}
