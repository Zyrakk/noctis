// Package brain contains the intelligence processing sub-modules:
// correlation, analyst, and (future) attributor.
package brain

import (
	"context"
	"sync"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/modules"
)

// Brain orchestrates all intelligence processes.
type Brain struct {
	correlator     *Correlator
	analyst        *Analyst
	briefGenerator *BriefGenerator
	registry       *modules.Registry
}

// NewBrain creates the brain with all sub-modules and registers their
// StatusTrackers with the registry.
func NewBrain(
	store CorrelationStore,
	corrCfg config.CorrelationConfig,
	analystCfg config.AnalystConfig,
	analystAnalyzer *analyzer.Analyzer,
	archiveStore *archive.Store,
	registry *modules.Registry,
	analystProvider, analystModel string,
	analystConcurrency int,
	briefCfg config.BriefConfig,
) *Brain {
	b := &Brain{
		registry: registry,
	}

	b.correlator = NewCorrelator(store, corrCfg)
	registry.Register(b.correlator.status)

	b.analyst = NewAnalyst(analystAnalyzer, archiveStore, analystCfg, analystConcurrency, analystProvider, analystModel)
	registry.Register(b.analyst.status)

	b.briefGenerator = NewBriefGenerator(analystAnalyzer, archiveStore, briefCfg, analystConcurrency, analystProvider, analystModel)
	registry.Register(b.briefGenerator.status)

	return b
}

// Run starts all intelligence sub-modules and blocks until ctx is cancelled.
func (b *Brain) Run(ctx context.Context) {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		b.correlator.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		b.analyst.Run(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		b.briefGenerator.Run(ctx)
	}()

	wg.Wait()
}
