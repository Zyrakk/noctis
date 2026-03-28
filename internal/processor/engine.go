package processor

import (
	"context"
	"log"
	"sync"
	"sync/atomic"

	"github.com/Zyrakk/noctis/internal/analyzer"
	"github.com/Zyrakk/noctis/internal/archive"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/modules"
)

// ProcessingEngine orchestrates the classification and extraction pipelines.
// Each sub-module has its own StatusTracker registered with the module registry.
type ProcessingEngine struct {
	classifier  *Classifier
	summarizer  *Summarizer
	iocExtract  *IOCExtractor
	entExtract  *EntityExtractor
	graphBridge *GraphBridge
	librarian    *Librarian
	iocLifecycle *IOCLifecycleManager

	archive          *archive.Store
	workerCfg        config.CollectionConfig
	maxContentLength int
	registry         *modules.Registry

	// Poison item tracking — shared across workers of the same type.
	classifyFailCounts  map[string]int
	classifyFailMu      sync.Mutex
	extractFailCounts   map[string]int
	extractFailMu       sync.Mutex
	librarianFailCounts map[string]int
	librarianFailMu     sync.Mutex

	// Budget circuit breaker — when any worker hits ErrBudgetExhausted,
	// all classification workers pause for budgetPauseDuration.
	budgetExhausted atomic.Bool
}

// NewProcessingEngine creates the engine with all sub-modules and registers
// their StatusTrackers with the registry.
func NewProcessingEngine(
	archiveStore *archive.Store,
	classifyAnalyzer *analyzer.Analyzer,
	fullAnalyzer *analyzer.Analyzer,
	workerCfg config.CollectionConfig,
	registry *modules.Registry,
	classifyProvider string,
	classifyModel string,
	fullProvider string,
	fullModel string,
	classifyConcurrency int,
	extractConcurrency int,
	iocLifecycleCfg config.IOCLifecycleConfig,
) *ProcessingEngine {
	// Apply defaults for zero-value config fields.
	if workerCfg.ClassificationWorkers <= 0 {
		workerCfg.ClassificationWorkers = 8
	}
	if workerCfg.EntityExtractionWorkers <= 0 {
		workerCfg.EntityExtractionWorkers = 2
	}
	if workerCfg.LibrarianWorkers <= 0 {
		workerCfg.LibrarianWorkers = 1
	}
	if workerCfg.ClassificationBatchSize <= 0 {
		workerCfg.ClassificationBatchSize = 10
	}

	classifier := NewClassifier(classifyAnalyzer, classifyConcurrency, classifyProvider, classifyModel)
	summarizer := NewSummarizer(classifyAnalyzer, classifyConcurrency, classifyProvider, classifyModel)
	iocExtract := NewIOCExtractor(classifyAnalyzer, classifyConcurrency, classifyProvider, classifyModel)
	entExtract := NewEntityExtractor(fullAnalyzer, extractConcurrency, fullProvider, fullModel)
	graphBridge := NewGraphBridge(archiveStore)
	librarian := NewLibrarian(fullAnalyzer, extractConcurrency, fullProvider, fullModel)
	iocLifecycle := NewIOCLifecycleManager(archiveStore, iocLifecycleCfg)

	// Register all sub-modules with the registry.
	registry.Register(classifier.status)
	registry.Register(summarizer.status)
	registry.Register(iocExtract.status)
	registry.Register(entExtract.status)
	registry.Register(graphBridge.status)
	registry.Register(librarian.status)
	registry.Register(iocLifecycle.status)

	return &ProcessingEngine{
		classifier:  classifier,
		summarizer:  summarizer,
		iocExtract:  iocExtract,
		entExtract:  entExtract,
		graphBridge: graphBridge,
		librarian:    librarian,
		iocLifecycle: iocLifecycle,
		archive:          archiveStore,
		workerCfg:        workerCfg,
		maxContentLength: workerCfg.MaxContentLength,
		registry:         registry,

		classifyFailCounts:  make(map[string]int),
		extractFailCounts:   make(map[string]int),
		librarianFailCounts: make(map[string]int),
	}
}

// Run starts the classification and extraction pipelines and blocks until
// ctx is cancelled.
func (e *ProcessingEngine) Run(ctx context.Context) {
	// Startup backfill tasks.
	if count, err := e.archive.ResetOldClassifications(ctx, CurrentClassificationVersion); err != nil {
		log.Printf("processor: reclassification reset error: %v", err)
	} else if count > 0 {
		log.Printf("processor: reset %d entries for reclassification (version < %d)", count, CurrentClassificationVersion)
	}

	if count, err := e.archive.BackfillEntitiesFromIOCs(ctx); err != nil {
		log.Printf("processor: entity backfill error: %v", err)
	} else if count > 0 {
		log.Printf("processor: backfilled %d entities from existing IOCs", count)
	}

	if count, err := e.archive.CleanupAssociatedWithEdges(ctx); err != nil {
		log.Printf("processor: edge cleanup error: %v", err)
	} else if count > 0 {
		log.Printf("processor: cleaned up %d associated_with edges → referenced_in", count)
	}

	if count, err := e.archive.BackfillIOCSightings(ctx); err != nil {
		log.Printf("processor: ioc sightings backfill error: %v", err)
	} else if count > 0 {
		log.Printf("processor: backfilled %d ioc sightings", count)
	}

	// Mark all sub-modules as started.
	e.classifier.status.MarkStarted()
	e.summarizer.status.MarkStarted()
	e.iocExtract.status.MarkStarted()
	e.entExtract.status.MarkStarted()
	e.graphBridge.status.MarkStarted()
	e.librarian.status.MarkStarted()

	e.classifier.status.SetWorkerCount(e.workerCfg.ClassificationWorkers)
	e.summarizer.status.SetWorkerCount(e.workerCfg.ClassificationWorkers)
	e.iocExtract.status.SetWorkerCount(e.workerCfg.EntityExtractionWorkers)
	e.entExtract.status.SetWorkerCount(e.workerCfg.EntityExtractionWorkers)
	e.graphBridge.status.SetWorkerCount(e.workerCfg.EntityExtractionWorkers)
	e.librarian.status.SetWorkerCount(e.workerCfg.LibrarianWorkers)

	var wg sync.WaitGroup

	// Start classification pipeline workers.
	for i := range e.workerCfg.ClassificationWorkers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e.classifyPipelineWorker(ctx, id)
		}(i)
	}

	// Start extraction pipeline workers.
	for i := range e.workerCfg.EntityExtractionWorkers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e.extractPipelineWorker(ctx, id)
		}(i)
	}

	// Start librarian pipeline workers.
	for i := range e.workerCfg.LibrarianWorkers {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			e.librarianPipelineWorker(ctx, id)
		}(i)
	}

	// Start IOC lifecycle manager (self-contained periodic loop).
	wg.Add(1)
	go func() {
		defer wg.Done()
		e.iocLifecycle.Run(ctx)
	}()

	wg.Wait()

	// Mark all sub-modules as stopped.
	e.classifier.status.MarkStopped()
	e.summarizer.status.MarkStopped()
	e.iocExtract.status.MarkStopped()
	e.entExtract.status.MarkStopped()
	e.graphBridge.status.MarkStopped()
	e.librarian.status.MarkStopped()
}
