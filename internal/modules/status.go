package modules

import (
	"maps"
	"sync"
	"sync/atomic"
	"time"
)

// ModuleID uniquely identifies a module or sub-module in the system.
type ModuleID string

// Pre-defined module IDs. Every module and sub-module gets one.
const (
	// Collector modules
	ModCollectorTelegram ModuleID = "collector.telegram"
	ModCollectorRSS      ModuleID = "collector.rss"
	ModCollectorPaste    ModuleID = "collector.paste"
	ModCollectorForum    ModuleID = "collector.forum"
	ModCollectorLeakSite ModuleID = "collector.leaksite" // future
	ModCollectorSpecter  ModuleID = "collector.specter"  // future

	// Processor sub-modules
	ModClassifier      ModuleID = "processor.classifier"
	ModSummarizer      ModuleID = "processor.summarizer"
	ModLibrarian       ModuleID = "processor.librarian" // future: sub-classification
	ModIOCExtractor    ModuleID = "processor.ioc_extractor"
	ModEntityExtractor ModuleID = "processor.entity_extractor"
	ModGraphBridge     ModuleID = "processor.graph_bridge"
	ModIOCLifecycle    ModuleID = "processor.ioc_lifecycle"

	// Brain sub-modules
	ModCorrelator ModuleID = "brain.correlator"
	ModAnalyst        ModuleID = "brain.analyst"    // future: LLM correlation confirmation
	ModBriefGenerator ModuleID = "brain.brief_generator"
	ModAttributor     ModuleID = "brain.attributor" // future: actor attribution

	// Infrastructure
	ModDashboard       ModuleID = "infra.dashboard"
	ModDiscovery       ModuleID = "infra.discovery"
	ModSourceAnalyzer  ModuleID = "infra.source_analyzer"
)

// ModuleStatus is the universal health report for any module or sub-module.
// Every component in the system implements this same structure.
type ModuleStatus struct {
	ID       ModuleID `json:"id"`
	Name     string   `json:"name"`     // Human-readable name
	Category string   `json:"category"` // "collector", "processor", "brain", "infra"
	Running  bool     `json:"running"`
	Enabled  bool     `json:"enabled"` // Configured to run (might not be running yet)
	StartedAt time.Time `json:"started_at,omitzero"`
	StoppedAt time.Time `json:"stopped_at,omitzero"`

	// AI provider info (nil for non-AI modules)
	AIProvider string `json:"ai_provider,omitempty"` // "groq", "glm", "anthropic", ""
	AIModel    string `json:"ai_model,omitempty"`    // "llama-4-scout", "GLM-5", ""

	// Throughput
	TotalProcessed int64     `json:"total_processed"`
	TotalErrors    int64     `json:"total_errors"`
	LastActivityAt time.Time `json:"last_activity_at,omitzero"`
	LastErrorAt    time.Time `json:"last_error_at,omitzero"`
	LastError      string    `json:"last_error,omitempty"`

	// Queue depth (for workers that poll a queue)
	QueueDepth int64 `json:"queue_depth,omitempty"`

	// Worker count (for modules with multiple goroutines)
	WorkerCount int `json:"worker_count,omitempty"`

	// Extra metadata specific to this module type
	Extra map[string]any `json:"extra,omitempty"`
}

// StatusTracker provides thread-safe counters and timestamps for a module.
// Embed this in your module struct and call its methods from workers.
type StatusTracker struct {
	id          ModuleID
	name        string
	category    string
	aiProvider  string
	aiModel     string
	enabled     bool
	workerCount int

	running      atomic.Bool
	startedAt    atomic.Value // time.Time
	stoppedAt    atomic.Value // time.Time
	processed    atomic.Int64
	errors       atomic.Int64
	queueDepth   atomic.Int64
	lastActivity atomic.Value // time.Time
	lastErrorAt  atomic.Value // time.Time

	lastErrorMu sync.RWMutex
	lastError   string

	extraMu sync.RWMutex
	extra   map[string]any
}

// NewStatusTracker creates a tracker for a specific module.
func NewStatusTracker(id ModuleID, name, category string) *StatusTracker {
	return &StatusTracker{
		id:       id,
		name:     name,
		category: category,
		extra:    make(map[string]any),
	}
}

func (s *StatusTracker) SetAIInfo(provider, model string) {
	s.aiProvider = provider
	s.aiModel = model
}

func (s *StatusTracker) SetEnabled(v bool)    { s.enabled = v }
func (s *StatusTracker) SetWorkerCount(n int) { s.workerCount = n }

func (s *StatusTracker) MarkStarted() {
	s.running.Store(true)
	s.startedAt.Store(time.Now())
}

func (s *StatusTracker) MarkStopped() {
	s.running.Store(false)
	s.stoppedAt.Store(time.Now())
}

func (s *StatusTracker) RecordSuccess() {
	s.processed.Add(1)
	s.lastActivity.Store(time.Now())
}

func (s *StatusTracker) RecordError(err error) {
	s.errors.Add(1)
	s.lastErrorAt.Store(time.Now())
	s.lastErrorMu.Lock()
	if err != nil {
		s.lastError = err.Error()
	}
	s.lastErrorMu.Unlock()
}

func (s *StatusTracker) SetQueueDepth(n int64) {
	s.queueDepth.Store(n)
}

func (s *StatusTracker) SetExtra(key string, value any) {
	s.extraMu.Lock()
	s.extra[key] = value
	s.extraMu.Unlock()
}

func (s *StatusTracker) Status() ModuleStatus {
	ms := ModuleStatus{
		ID:             s.id,
		Name:           s.name,
		Category:       s.category,
		Running:        s.running.Load(),
		Enabled:        s.enabled,
		AIProvider:     s.aiProvider,
		AIModel:        s.aiModel,
		TotalProcessed: s.processed.Load(),
		TotalErrors:    s.errors.Load(),
		QueueDepth:     s.queueDepth.Load(),
		WorkerCount:    s.workerCount,
	}

	if v := s.startedAt.Load(); v != nil {
		ms.StartedAt = v.(time.Time)
	}
	if v := s.stoppedAt.Load(); v != nil {
		ms.StoppedAt = v.(time.Time)
	}
	if v := s.lastActivity.Load(); v != nil {
		ms.LastActivityAt = v.(time.Time)
	}
	if v := s.lastErrorAt.Load(); v != nil {
		ms.LastErrorAt = v.(time.Time)
	}
	s.lastErrorMu.RLock()
	ms.LastError = s.lastError
	s.lastErrorMu.RUnlock()

	s.extraMu.RLock()
	if len(s.extra) > 0 {
		ms.Extra = make(map[string]any, len(s.extra))
		maps.Copy(ms.Extra, s.extra)
	}
	s.extraMu.RUnlock()

	return ms
}
