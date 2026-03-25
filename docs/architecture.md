# Noctis Architecture

Noctis is a Kubernetes-native threat intelligence daemon. It collects content from multiple dark web and open source sources, archives every item unconditionally, and runs intelligence analysis across five architectural layers.

---

## 1. System Overview

### Five-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 1 — Collectors                                               │
│  Telegram (MTProto)   Paste (HTTP/Tor)   Forum (HTTP/Tor)          │
│  Web/RSS (HTTP/Tor)                                                 │
└────────────────────────────┬────────────────────────────────────────┘
                             │ models.Finding (chan, buffered 50)
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 2 — Ingest Pipeline                                          │
│  archive.Insert (content_hash dedup)                                │
│  matcher.Match (keyword + regex rules)                              │
│  Alert path: Classify → ExtractIOCs → Summarize → alertFn          │
└────────────────────────────┬────────────────────────────────────────┘
                             │ raw_content (PostgreSQL)
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 3 — Processing Engine (background workers)                   │
│  Classifier     Summarizer      IOC Extractor   Entity Extractor   │
│  Graph Bridge   Librarian       IOC Lifecycle                       │
└────────────────────────────┬────────────────────────────────────────┘
                             │ classified raw_content, iocs, entities
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 4 — Intelligence Brain                                       │
│  Correlator (rule engine)   Analyst (LLM confirm/reject)           │
│  Brief Generator            Query Engine (NL→SQL)                  │
└────────────────────────────┬────────────────────────────────────────┘
                             │ correlations, analytical_notes, briefs
                             ▼
┌─────────────────────────────────────────────────────────────────────┐
│  Layer 5 — Infrastructure + Dashboard                               │
│  VulnIngestor (NVD/EPSS/KEV)                                       │
│  SourceValueAnalyzer        Enrichment Pipeline (3 providers)       │
│  Dashboard HTTP server      Health HTTP server                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Module Registry Pattern

Every subsystem that runs as a goroutine or processes data embeds a `*modules.StatusTracker` and registers it with a central `*modules.Registry` at startup.

**StatusTracker** is a thread-safe counters-and-timestamps struct backed by `atomic.Bool`, `atomic.Int64`, and `atomic.Value`. The operations it exposes:

```go
// Configuration (called once at construction)
tracker.SetEnabled(true)
tracker.SetWorkerCount(n)
tracker.SetAIInfo(provider, model)      // e.g., "groq", "llama-4-scout"

// Lifecycle (called from the running goroutine)
tracker.MarkStarted()
tracker.MarkStopped()

// Per-item accounting
tracker.RecordSuccess()
tracker.RecordError(err)

// Queue telemetry
tracker.SetQueueDepth(n)

// Arbitrary module-specific metadata
tracker.SetExtra("interval", "15m")
tracker.SetExtra("last_cycle_correlations", 4)
```

`tracker.Status()` returns a value-type `ModuleStatus` snapshot safe for concurrent read by the dashboard.

**Registry** is a `sync.RWMutex`-protected map from `ModuleID` to `*StatusTracker`. Three read methods are available:

```go
registry.Register(tracker)                     // called once at startup per module
registry.AllStatuses() map[string]ModuleStatus // flat map, used by /api/status
registry.StatusesByCategory() map[string][]ModuleStatus // grouped: "collector", "processor", "brain", "infra"
```

### Data Flow (collector → brain → enrich)

```
Collector.Start() emits models.Finding
  │
  └─► CollectorManager consumer goroutine
        ├── ingestFn(finding) → IngestPipeline.Process()
        │     ├── archive.Insert()               // persists to raw_content
        │     ├── matcher.Match()
        │     │    ├── [no match] → return       // stays classified=false
        │     │    └── [match] → alert path
        │     │          ├── Classify (fast LLM)
        │     │          ├── ExtractIOCs (full LLM)
        │     │          ├── Summarize (full LLM)
        │     │          └── alertFn(EnrichedFinding) → Prometheus metrics
        │     └── archive.MarkClassified()
        │
        └── discoveryFn(content, findingID) → discovery.Engine.ProcessContent()
              └── ExtractURLs → classify by heuristic → INSERT INTO sources ON CONFLICT DO NOTHING

[background] ProcessingEngine.classifyPipelineWorker (N workers)
  FetchUnclassified() → Classify (fast LLM) → Summarize (full LLM) → MarkClassified()

[background] ProcessingEngine.extractPipelineWorker (M workers)
  FetchClassifiedUnextracted() → IOCExtractor → GraphBridge.BridgeIOCs()
                               → EntityExtractor → GraphBridge.BridgeEntities()
                               → MarkEntitiesExtracted()

[background] ProcessingEngine.librarianPipelineWorker (L workers)
  FetchUnsubclassified() → Librarian.SubClassify() → MarkSubClassified()

[background] IOCLifecycleManager (ticker)
  UpdateIOCScores() → exponential decay → deactivate below threshold

[background] Brain.Correlator (ticker)
  4 rules → correlations table or correlation_candidates table

[background] Brain.Analyst (ticker)
  FetchPendingCandidates() → EvaluateCorrelation (brain LLM) → promote/reject/defer
  → analytical_notes + correlation_decisions

[background] Brain.BriefGenerator (daily scheduler)
  FetchBriefMetrics() → GenerateBrief (brain LLM) → intelligence_briefs

[on-demand] Brain.QueryEngine
  NL question → generateSQL (brain LLM) → validateSQL → execute with 10s timeout

[background] VulnIngestor (ticker)
  NVD (paginated) + EPSS CSV (250K batch) + CISA KEV JSON → cross-reference → priority score

[background] SourceValueAnalyzer (ticker, 6h)
  Per-source metrics → value_score → UPDATE sources

[background] Enrichment Pipeline (ticker)
  FetchUnenrichedIOCs() → AbuseIPDB / VirusTotal / crt.sh → MarkIOCEnriched()
```

---

## 2. Package Layout

```
cmd/
  noctis/
    main.go            Entry point: registers cobra commands
    serve.go           Full startup sequence and graceful shutdown
    version.go         Version constant

internal/
  analyzer/            LLM abstraction layer — prompt rendering + JSON parsing
    analyzer.go        Analyzer struct, all prompt methods, stripCodeFences helper
  archive/             PostgreSQL persistence (raw_content, iocs, entities, edges, ...)
    store.go           archive.Store — all DB operations (Insert, MarkClassified, UpsertIOC, ...)
  brain/               Intelligence sub-system
    brain.go           Brain orchestrator — starts Correlator, Analyst, BriefGenerator
    correlator.go      Rule-based correlation engine (4 rules)
    analyst.go         LLM analyst — promote/reject/defer correlation candidates
    brief_generator.go Daily intelligence brief via LLM
    query_engine.go    NL→SQL query engine with safety validation
    correlator_test.go Unit tests for correlator rules
  collector/           Data source collectors
    collector.go       Collector interface definition
    manager.go         CollectorManager — goroutine lifecycle, status tracking
    telegram.go        MTProto collector via gotd/td
    paste.go           Pastebin API + generic scraper collector
    forum.go           Forum scraper with CSS selectors, circuit breaker
    web.go             RSS/scrape/search feed collector
    tor.go             SOCKS5 proxy transport for Tor-routed requests
    value.go           SourceValueAnalyzer — per-source quality metrics
    *_test.go          Collector unit tests
  config/              YAML config structs and loader
    config.go          All config types, Load(), substituteEnvVars()
  dashboard/           Web dashboard server
    server.go          dashboard.Server — HTTP mux, auth middleware
    handlers.go        REST API handlers (/api/findings, /api/iocs, /api/graph, ...)
    queries.go         Complex SQL queries backing dashboard API endpoints
    static/            Embedded React SPA (app.js, index.html, icons/, manifest.json)
  database/            PostgreSQL connection pool
    database.go        Connect(), LoadMigrations(), RunMigrations()
  discovery/           URL extraction and source registry
    engine.go          discovery.Engine — regex URL extraction, source classification
  dispatcher/          Prometheus metrics
    prometheus.go      PrometheusMetrics — RecordFinding, RecordMatcherMatch, ...
  enrichment/          IOC external enrichment pipeline
    enricher.go        Enricher — periodic loop, EnrichmentProvider interface
    abuseipdb.go       AbuseIPDB provider (IP, 2s rate limit)
    virustotal.go      VirusTotal provider (IP/domain/hash, 15s rate limit)
    crtsh.go           crt.sh certificate transparency provider (domain, 5s rate limit)
  health/              HTTP health and readiness endpoints
    health.go          /healthz, /readyz, QRAuthState
  ingest/              Real-time ingest pipeline
    pipeline.go        IngestPipeline.Process() — archive + match + alert path
    pipeline_test.go   Unit tests
  llm/                 OpenAI-compatible LLM client
    client.go          LLMClient interface and OpenAICompatClient implementation
  matcher/             Keyword and regex rule evaluation
    matcher.go         Matcher.Match() — evaluates all rules, returns MatchResult
  models/              Shared domain types
    finding.go         Finding, EnrichedFinding, IOC, Category, Severity
  modules/             Module status registry
    status.go          ModuleID constants, StatusTracker, ModuleStatus
    registry.go        Registry — Register, AllStatuses, StatusesByCategory
  pipeline/            Legacy fan-in pipeline (pre-archive pivot, still present)
    pipeline.go        Pipeline.Run() — collector fan-in (not used in main path)
  processor/           Background processing sub-modules
    engine.go          ProcessingEngine — starts all worker goroutines
    workers.go         classifyPipelineWorker, extractPipelineWorker, librarianPipelineWorker
    classifier.go      Classifier sub-module with ConcurrencyLimiter
    summarizer.go      Summarizer sub-module
    ioc_extractor.go   IOCExtractor sub-module
    entity_extractor.go EntityExtractor sub-module
    graph_bridge.go    GraphBridge — IOC and entity → graph node/edge creation
    librarian.go       Librarian sub-module for sub-classification
    ioc_lifecycle.go   IOCLifecycleManager — decay scoring and deactivation
    helpers.go         ConcurrencyLimiter, FindingFromRawContent, SleepOrCancel, TagsFromCategory
    helpers_test.go    Unit tests
  vuln/                Vulnerability intelligence ingestion
    ingestor.go        VulnIngestor — orchestrates NVD, EPSS, KEV, cross-reference
    nvd.go             NVD API polling (paginated, rate-limited)
    epss.go            EPSS CSV download and batch upsert (~250K rows)
    kev.go             CISA KEV JSON download
    enrichment.go      Noctis cross-reference (IOC → CVE matching)
    priority.go        ComputePriority() — weighted scoring formula

migrations/
  001_init.sql         findings, canary_tokens, actor_profiles
  002_graph.sql        entities, edges
  003_pivot.sql        raw_content, iocs, artifacts, sources
  004_cleanup_discovered.sql  Source status cleanup
  005_provenance.sql   Provenance and classification versioning columns
  006_correlations.sql ioc_sightings, correlations, correlation_candidates
  007_phase2.sql       sub_classification columns, analytical_notes, correlation_decisions, source value columns
  008_phase3.sql       IOC lifecycle columns, intelligence_briefs, vulnerabilities
  009_enrichment.sql   IOC enrichment columns (enrichment JSONB, enriched_at, enrichment_sources)

prompts/
  classify.tmpl            Category + confidence + severity + provenance + reasoning
  classify_detail.tmpl     Sub-category + structured sub_metadata (Librarian)
  evaluate_correlation.tmpl Promote/reject/defer decision for correlation candidates
  extract_entities.tmpl    Named entity + relationship extraction
  extract_iocs.tmpl        IOC extraction with malicious flag
  severity.tmpl            Severity assessment (standalone, used in alert path)
  summarize.tmpl           Analyst-readable one-paragraph summary
  daily_brief.tmpl         Full intelligence brief synthesis
  stylometry.tmpl          Actor stylometric fingerprinting (reserved)

web/                   React SPA source (built output embedded in dashboard/static/)
  src/
    App.jsx            Router, layout
    pages/             Findings, IOCs, Graph, Correlations, AnalyticalNotes, SystemStatus
    components/        Layout, nav, shared UI
```

---

## 3. Startup Sequence (from `serve.go`)

The startup order is strict. Steps that are numbered here match the logical dependencies.

**1. Config load and validation**
```go
cfg, err := config.Load(configPath)  // reads YAML, substitutes ${VAR} env tokens
config.Validate(cfg)
```

**2. Structured logger**

`slog.NewJSONHandler(os.Stdout, ...)` at the level set by `cfg.LogLevel`.

**3. Health server** (goroutine)

HTTP server at `cfg.HealthPort` (default 8080) serving `/healthz` and `/readyz`. Starts immediately; readiness is set to `false` until step 18.

**4. Database pool + migrations**
```go
pool, _ := database.Connect(ctx, cfg.Database.DSN)
migrations, _ := database.LoadMigrations("migrations")
database.RunMigrations(ctx, pool, migrations)
```
Migrations are idempotent (`IF NOT EXISTS`, `ADD COLUMN IF NOT EXISTS`). All 9 migrations run sequentially.

**5. Module Registry**
```go
registry := modules.NewRegistry()
```
The registry is constructed before any modules so it can be passed to every constructor that follows.

**6. Dashboard server** (goroutine, if `cfg.Dashboard.Enabled`)
```go
dashServer = dashboard.NewServer(fmt.Sprintf(":%d", dashPort), pool, cfg.Dashboard.APIKey, registry)
go dashServer.ListenAndServe()
```
Starts before processing engines so the dashboard is visible during warmup.

**7. LLM clients**

Three clients are constructed in single-mode or dual-mode depending on config:

| Client | Config key | Default use |
|---|---|---|
| `fullClient` | `llm` | Summarization, IOC extraction, entity extraction, Librarian |
| `classifyClient` (fast) | `llmFast` | Classification — falls back to `fullClient` if `llmFast.model` is empty |
| `brainClient` | `llmBrain` | Correlator evaluation, Brief Generator, Query Engine — falls back to `fullClient` |

All three use `llm.NewOpenAICompatClient(baseURL, apiKey, model)`, an OpenAI-compatible HTTP client.

**8. Analyzers from prompt templates**
```go
fullAnalyzer = analyzer.New(fullClient, promptsDir)
classifyAnalyzer = analyzer.New(fastClient, promptsDir)
brainAnalyzer = analyzer.New(brainClient, promptsDir)
```
`analyzer.New` reads all `*.tmpl` files from `promptsDir` (default `/prompts`, override via `NOCTIS_PROMPTS_DIR`). Template parse failures produce a warning log but are non-fatal.

**9. Discovery engine**
```go
discoveryEngine = discovery.NewEngine(pool, cfg.Discovery)
discoveryEngine.SetMonitoredChannels(telegramUsernames)
```
Registered Telegram channel usernames are pre-loaded so the discovery engine skips already-monitored sources.

**10. ProcessingEngine** (goroutine)

Registers 7 sub-modules with the registry, runs startup backfill tasks, then starts worker goroutines:

```go
processingEngine = processor.NewProcessingEngine(
    archiveStore, classifyAnalyzer, fullAnalyzer, cfg.Collection, registry,
    classifyProvider, classifyModel, fullProvider, fullModel,
    classifyConcurrency, extractConcurrency, cfg.IOCLifecycle,
)
go processingEngine.Run(pipelineCtx)
```

Defaults when config values are zero:
- `ClassificationWorkers`: 8
- `EntityExtractionWorkers`: 2
- `LibrarianWorkers`: 1
- `ClassificationBatchSize`: 10

**11. Brain** (goroutine)
```go
intelligenceBrain = brain.NewBrain(
    archiveStore, cfg.Correlation, cfg.Analyst, brainAnalyzer,
    archiveStore, registry, brainProvider, brainModel, brainConcurrency, cfg.BriefGenerator,
)
go intelligenceBrain.Run(pipelineCtx)
```

**12. QueryEngine** (on-demand, not a goroutine)
```go
queryEngine = brain.NewQueryEngine(brainAnalyzer, pool, brainConcurrency, brainProvider, brainModel)
registry.Register(queryEngine.Status())
dashServer.SetQueryEngine(&queryEngineAdapter{engine: queryEngine})
```
No background goroutine. Invoked only when the dashboard calls `/api/query`.

**13. IngestPipeline** (Process method only, no goroutine)
```go
ingestPipeline, _ = ingest.NewIngestPipeline(
    archiveStore, cfg.Matching.Rules, classifyAnalyzer, fullAnalyzer, metrics, alertFn,
)
```
`Process()` is called synchronously from CollectorManager's consumer goroutine.

**14. VulnIngestor** (goroutine)
```go
vulnIngestor = vuln.NewVulnIngestor(archiveStore, cfg.Vuln)
registry.Register(vulnIngestor.Status())
go vulnIngestor.Run(pipelineCtx)
```

**15. SourceValueAnalyzer** (goroutine)
```go
sourceAnalyzer = collector.NewSourceValueAnalyzer(pool)
registry.Register(sourceAnalyzer.Status())
go sourceAnalyzer.Run(pipelineCtx)
```

**16. Enrichment Pipeline** (goroutine)
```go
var enrichProviders []enrichment.EnrichmentProvider
if cfg.Enrichment.AbuseIPDBKey != ""  { enrichProviders = append(enrichProviders, enrichment.NewAbuseIPDBProvider(...)) }
if cfg.Enrichment.VirusTotalKey != "" { enrichProviders = append(enrichProviders, enrichment.NewVirusTotalProvider(...)) }
enrichProviders = append(enrichProviders, enrichment.NewCRTShProvider())  // always added

enricher = enrichment.NewEnricher(archiveStore, cfg.Enrichment, enrichProviders)
registry.Register(enricher.Status())
go enricher.Run(pipelineCtx)
```
`crt.sh` is always included because it requires no API key.

**17. CollectorManager** (goroutine)

Collectors are built conditionally:
```go
if cfg.Sources.Paste.Enabled    { collectors = append(collectors, collector.NewPasteCollector(...)) }
if cfg.Sources.Telegram.Enabled { collectors = append(collectors, collector.NewTelegramCollector(...)) }
if cfg.Sources.Forums.Enabled   { collectors = append(collectors, collector.NewForumCollector(...)) }
if cfg.Sources.Web.Enabled      { collectors = append(collectors, collector.NewWebCollector(...)) }
```

`CollectorManager` is constructed with injected `ingestFn` and `discoveryFn` callbacks:
```go
collectorMgr = collector.NewCollectorManager(collectors, registry, ingestFn, discoveryFn)
go collectorMgr.Run(pipelineCtx)
```

**18. Readiness**
```go
hs.SetReady(true)
```
The `/readyz` endpoint now returns 200.

**19. Graceful shutdown**

On `SIGINT`/`SIGTERM`:
1. `dashServer.Shutdown(5s context)` — drains HTTP connections
2. `pipelineCancel()` — cancels `pipelineCtx`, signalling all goroutines to stop
3. `<-collectorDone` — waits for CollectorManager (and by extension all collectors) to drain
4. `pool.Close()` — deferred, releases DB connections

---

## 4. Module Status System

### ModuleID Constants

All 22 module IDs defined in `internal/modules/status.go`:

| ModuleID | Category | Description |
|---|---|---|
| `collector.telegram` | collector | MTProto Telegram channel monitor |
| `collector.rss` | collector | Web/RSS feed collector |
| `collector.paste` | collector | Pastebin + scraper collector |
| `collector.forum` | collector | Forum thread scraper |
| `collector.leaksite` | collector | Dedicated leak site collector (future) |
| `collector.specter` | collector | Specter intelligence feed (future) |
| `processor.classifier` | processor | LLM category + severity + provenance assignment |
| `processor.summarizer` | processor | LLM text summarization |
| `processor.librarian` | processor | LLM sub-classification with fine-grained metadata |
| `processor.ioc_extractor` | processor | LLM malicious indicator extraction |
| `processor.entity_extractor` | processor | LLM named entity extraction |
| `processor.graph_bridge` | processor | Entity/edge creation in knowledge graph (no AI) |
| `processor.ioc_lifecycle` | processor | IOC confidence decay and deactivation (no AI) |
| `processor.enrichment` | processor | IOC external API enrichment |
| `brain.correlator` | brain | Rule-based cross-source correlation |
| `brain.analyst` | brain | LLM correlation candidate evaluation |
| `brain.brief_generator` | brain | Daily LLM intelligence brief synthesis |
| `brain.query_engine` | brain | Natural language to SQL (on-demand) |
| `brain.attributor` | brain | Actor attribution engine (future) |
| `infra.dashboard` | infra | Web dashboard HTTP server |
| `infra.discovery` | infra | URL extraction and source discovery |
| `infra.source_analyzer` | infra | Per-source quality metrics computation |
| `infra.vuln_ingestor` | infra | NVD/EPSS/KEV vulnerability intelligence |

### ModuleStatus struct

```go
type ModuleStatus struct {
    ID             ModuleID       `json:"id"`
    Name           string         `json:"name"`
    Category       string         `json:"category"`
    Running        bool           `json:"running"`
    Enabled        bool           `json:"enabled"`
    StartedAt      time.Time      `json:"started_at,omitzero"`
    StoppedAt      time.Time      `json:"stopped_at,omitzero"`
    AIProvider     string         `json:"ai_provider,omitempty"`
    AIModel        string         `json:"ai_model,omitempty"`
    TotalProcessed int64          `json:"total_processed"`
    TotalErrors    int64          `json:"total_errors"`
    LastActivityAt time.Time      `json:"last_activity_at,omitzero"`
    LastErrorAt    time.Time      `json:"last_error_at,omitzero"`
    LastError      string         `json:"last_error,omitempty"`
    QueueDepth     int64          `json:"queue_depth,omitempty"`
    WorkerCount    int            `json:"worker_count,omitempty"`
    Extra          map[string]any `json:"extra,omitempty"`
}
```

`Extra` is module-specific. Examples: `interval`, `last_cycle_duration`, `last_cycle_correlations`, `next_run`, `schedule_hour`, `last_nvd_count`.

---

## 5. Collector Layer

### CollectorManager Pattern

`CollectorManager` owns the goroutine lifecycle for all collectors. It is constructed with two injected function types:

```go
type CollectorManager struct {
    ingestFn    func(ctx context.Context, f models.Finding) error
    discoveryFn func(ctx context.Context, content string, findingID string) error
    trackers    map[string]*modules.StatusTracker
}
```

For each collector, two goroutines are launched:

**Goroutine A — producer:** calls `collector.Start(ctx, ch)` which blocks until `ctx` is cancelled, writing `models.Finding` values to `ch` (buffered, size 50).

**Goroutine B — consumer:** reads from `ch`, calls `ingestFn`, then `discoveryFn`, records success/error on the tracker.

```go
// Goroutine A
go func() {
    defer tracker.MarkStopped()
    if err := c.Start(ctx, ch); err != nil && ctx.Err() == nil {
        tracker.RecordError(err)
    }
}()

// Goroutine B
go func() {
    for f := range ch {
        ingestFn(ctx, f)
        discoveryFn(ctx, f.Content, f.ID)
        tracker.RecordSuccess()
    }
}()
```

The `WaitGroup` in `CollectorManager.Run` waits for all goroutines before returning, enabling clean shutdown.

### Collector Implementations

**TelegramCollector** (`collector.telegram`)
- Transport: MTProto via `gotd/td` library
- Login: QR code auth with optional 2FA password; session persisted to `cfg.SessionFile`
- On start: optionally fetches the last N messages via `MessagesGetHistory` for catch-up
- Message handler: `OnNewChannelMessage` — SHA-256 dedup in-memory, converts to `models.Finding`
- Channel discovery: telegram-specific messages are passed through `discoveryEngine` for new channel extraction

**PasteCollector** (`collector.paste`)
- Two sub-goroutines per `Start` call: one polls the Pastebin `scrape.pastebin.com` API (limit 50), one polls each custom scraper URL
- Supports SOCKS5 Tor proxy via `cfg.Sources.Tor`
- User-Agent rotation on each request
- In-memory SHA-256 dedup keyed on paste content hash

**ForumCollector** (`collector.forum`)
- One goroutine per site in `cfg.Sources.Forums.Sites`
- Thread list pagination via CSS selector (`goquery`)
- Optional form-based login: POST to `auth.loginURL` with configurable field names
- Per-site circuit breaker: threshold 5 errors, initial backoff 30s, max 1h, exponential doubling
- Supports SOCKS5 Tor proxy

**WebCollector / RSS** (`collector.rss`)
- One goroutine per feed in `cfg.Sources.Web.Feeds`
- Three feed types:
  - `rss`: parsed via `gofeed`, each item becomes a finding
  - `scrape`: fetches URL, extracts content via CSS selector
  - `search`: URL template with `{query}` placeholder, fetches up to 20 result links
- Response body capped at 10 MB
- Supports SOCKS5 Tor proxy

---

## 6. Processing Engine

`ProcessingEngine` contains 7 sub-modules, each with its own `StatusTracker`. It starts N+M+L+1 goroutines on `Run`:

| Sub-module | LLM | Worker count |
|---|---|---|
| Classifier | fast (Groq/llama-4-scout) | `cfg.Collection.ClassificationWorkers` (default 8) |
| Summarizer | full (GLM-5) | shares classify worker count |
| IOC Extractor | full (GLM-5) | `cfg.Collection.EntityExtractionWorkers` (default 2) |
| Entity Extractor | full (GLM-5) | shares extract worker count |
| Graph Bridge | none | shares extract worker count |
| Librarian | full (GLM-5) | `cfg.Collection.LibrarianWorkers` (default 1) |
| IOC Lifecycle Manager | none | 1 (periodic ticker) |

### Startup Backfill

Before starting workers, `ProcessingEngine.Run` executes four backfill queries:
1. `ResetOldClassifications(ctx, CurrentClassificationVersion=3)` — resets entries classified by older pipeline versions for reprocessing
2. `BackfillEntitiesFromIOCs(ctx)` — creates entity nodes for IOCs that predate the graph bridge
3. `CleanupAssociatedWithEdges(ctx)` — migrates stale `associated_with` edges to `referenced_in`
4. `BackfillIOCSightings(ctx)` — populates the `ioc_sightings` table from existing `iocs` rows

### classifyPipelineWorker

Runs N times concurrently. Each iteration:

```
FetchUnclassified(ctx, batchSize)   [ORDER BY collected_at ASC, WHERE classified=false]
  for each entry:
    Classifier.Classify(ctx, finding)
      → category, confidence, severity, provenance
    if confidence < 0.80 → tags += "needs_review"
    Summarizer.Summarize(ctx, finding, category, severity)
      → summary text
    archive.MarkClassified(ctx, id, category, tags, severity, summary, provenance, version=3)
```

Each LLM call is guarded by a `ConcurrencyLimiter` (buffered channel semaphore). Workers sleep `WorkerIdleInterval` (30s) when the queue is empty.

### extractPipelineWorker

Runs M times concurrently. Each iteration:

```
FetchClassifiedUnextracted(ctx, batchSize)  [WHERE classified=true AND entities_extracted=false]
  for each entry:
    IOCExtractor.Extract(ctx, finding)
      → []models.IOC (only entries with malicious=true)
    for each IOC: archive.UpsertIOC(...)
    if IOCs > 0: GraphBridge.BridgeIOCs(entry, iocs)

    if category != "irrelevant":
      EntityExtractor.Extract(ctx, finding, category, sourceName, sourceType, provenance)
        → EntityExtractionResult{Entities, Relationships}
      GraphBridge.BridgeEntities(entry, result)

    archive.MarkEntitiesExtracted(entry.ID)
```

### librarianPipelineWorker

Runs L times concurrently. Each iteration:

```
FetchUnsubclassified(ctx, batchSize)  [WHERE classified=true AND entities_extracted=true AND sub_classified=false]
  for each entry:
    if category == "canary_hit": MarkSubClassified(id, "", nil); continue

    entityNames = FetchEntityNamesForFinding(id)
    iocValues   = FetchIOCValuesForFinding(id)

    Librarian.SubClassify(ctx, finding, category, provenance, entityNames, iocValues)
      → sub_category, sub_metadata{}, confidence, reasoning
    archive.MarkSubClassified(id, sub_category, sub_metadata)
```

Valid sub-categories per top-level category:

| Category | Valid sub-categories |
|---|---|
| `malware_sample` | `malware_analysis`, `malware_delivery`, `c2_infrastructure`, `malware_source_code`, `malware_config` |
| `credential_leak` | `database_dump`, `combo_list`, `api_key_leak`, `session_token`, `stealer_log` |
| `vulnerability` | `vulnerability_disclosure`, `exploit_poc`, `exploit_weaponized`, `patch_advisory`, `vulnerability_discussion` |
| `threat_actor_comms` | `campaign_planning`, `tool_discussion`, `recruitment`, `bragging` |
| `access_broker` | `rdp_access`, `vpn_access`, `shell_access`, `database_access`, `cloud_access` |
| `data_dump` | `corporate_data`, `government_data`, `personal_data`, `healthcare_data` |

### IOC Lifecycle Manager

Runs once per `cfg.IOCLifecycle.IntervalMinutes` (default 60 minutes). On startup, calls `SetIOCLifetimeDefaults` to backfill `lifetime_days` for existing IOCs. Each cycle calls `archive.UpdateIOCScores(ctx, threshold)` which applies exponential decay to `threat_score` and deactivates IOCs that fall below `cfg.IOCLifecycle.DeactivateThreshold` (default 0.1).

### ConcurrencyLimiter

A buffered channel used as a counting semaphore to limit concurrent LLM calls per sub-module:

```go
type ConcurrencyLimiter struct { sem chan struct{} }

func (c *ConcurrencyLimiter) Acquire(ctx context.Context) error {
    select {
    case c.sem <- struct{}{}: return nil
    case <-ctx.Done():        return ctx.Err()
    }
}

func (c *ConcurrencyLimiter) Release() { <-c.sem }
```

Each sub-module (Classifier, Summarizer, IOCExtractor, EntityExtractor, Librarian) has its own independent `ConcurrencyLimiter` sized from `classifyConcurrency` or `extractConcurrency` config.

### Graph Bridge Entity ID Format

Entity IDs use structured string keys to enable deterministic upserts:

| Entity type | ID format | Example |
|---|---|---|
| Source/channel | `source:<name>` | `source:BreachedForums` |
| IOC | `ioc:<type>:<value>` | `ioc:ip:185.220.101.5` |
| Named entity | `entity:<type>:<normalized_name>` | `entity:threat_actor:apt28` |

Edges use: `edge:<source_id>:<target_id>:<relationship>`.

Relationship types: `uses`, `targets`, `deploys`, `exploits`, `referenced_in`, `mentioned_in`, `associated_with`, `found_in`.

Low-confidence entities (from LLM extraction) are dropped entirely. Medium-confidence entities are written with `needs_review: true` in their properties. Unobserved entity pairs have their relationship type downgraded to `referenced_in`.

---

## 7. Intelligence Brain

### Correlator

Runs once immediately on startup, then every `cfg.Correlation.IntervalMinutes` (default 15 minutes). Each cycle runs 4 rule functions in sequence:

**Rule 1 — Shared IOC cross-source** (`correlateSharedIOCs`)

Finds IOCs that appear in findings from at least 2 different sources (via `ioc_sightings` table). Confidence formula: `min(1.0, source_count * 0.15 + 0.5)`

**Rule 2 — Handle reuse** (`correlateHandleReuse`)

Finds authors (handles) appearing in findings from at least 2 different sources. Confidence formula: `min(1.0, source_count * 0.2 + 0.4)`. Also upserts a `threat_actor` entity for the handle into the graph.

**Rule 3 — Temporal IOC overlap** (`correlateTemporalOverlap`)

Finds pairs of findings from different sources within `cfg.Correlation.TemporalWindowHours` (default 48) that share at least 2 IOCs. Confidence formula: `min(1.0, shared_count * 0.2 + 0.3)`

**Rule 4 — Entity cluster detection** (`correlateEntityClusters`)

Runs twice — once for `threat_actor` entity type, once for `malware` entity type. Finds pairs of entities sharing at least 2 common graph neighbors. Confidence formula: `min(1.0, shared_count * 0.15 + 0.4)`

A **toolWhitelist** prevents common security tools (mimikatz, bloodhound, impacket, nmap, metasploit, and others) from forming spurious campaign clusters. If all shared entities in a cluster are whitelisted, the correlation is skipped entirely.

**Threshold logic:** If `signal_count >= cfg.Correlation.MinEvidenceThreshold` (default 3), the result is written to `correlations` as a confirmed correlation. Otherwise it is written to `correlation_candidates` with `status=pending` for analyst review.

Cluster IDs are deterministic SHA-256 hashes of the rule type + evidence key, enabling idempotent upserts (`ON CONFLICT (cluster_id) DO UPDATE`).

### Analyst

Runs every `cfg.Analyst.IntervalMinutes` (default 60 minutes). Each cycle:

```
FetchPendingCandidates(ctx, batchSize=10)
  for each candidate where signal_count >= cfg.Analyst.MinSignalCount (default 2):
    buildCandidateContext(candidate)
      → fetch related findings (summary, category, severity, source, timestamp)
      → fetch related entities with 1-hop graph neighbors
      → fetch existing analytical notes for those entities
    analyzer.EvaluateCorrelation(ctx, promptData)
      → evaluate_correlation.tmpl → LLM → {decision, confidence, reasoning, missing_evidence}
```

Decision handling:

| Decision | Action |
|---|---|
| `promote` (confidence >= `promoteThreshold`, default 0.7) | Insert into `correlations`, write `analytical_notes` for each entity, `UpdateCandidateStatus(promoted)` |
| `promote` (confidence < `promoteThreshold`) | Downgraded to `defer` |
| `reject` | Write rejection note, `UpdateCandidateStatus(rejected)` |
| `defer` | Write context note if reasoning is non-empty |

Every decision — regardless of outcome — is logged to `correlation_decisions` with the full context snapshot (candidate type, signal count, finding/entity/note counts, model used). This builds an audit trail and future fine-tuning dataset.

### Brief Generator

On startup: checks if today's brief exists (`FetchLatestBrief("daily")`). If not, generates one immediately.

Daily schedule: waits until `cfg.BriefGenerator.ScheduleHour:00 UTC` (default 06:00), then generates.

Generation process:
1. `FetchBriefMetrics(periodStart, periodEnd)` — findings by severity, new IOCs by type, new correlations, analyst-confirmed count, new notes, deactivated IOCs, source activity
2. `FetchTopFindings(periodStart, periodEnd, 10)` — top 10 findings by severity
3. `FetchTrendingEntities(periodStart, periodEnd, 10)` — entities with highest mention growth
4. Build `BriefPromptData`, render `daily_brief.tmpl`, call LLM
5. Parse JSON response: `{title, executive_summary, sections:{key_threats, correlation_insights, emerging_trends, collection_gaps, recommended_actions}}`
6. Build full markdown from sections, store in `intelligence_briefs`

Skips generation if `total_findings == 0` for the period.

### Query Engine

On-demand only — no background goroutine. Called from the dashboard `/api/query` endpoint.

```go
func (qe *QueryEngine) Query(ctx context.Context, question string) (*QueryResult, error) {
    // 1. Acquire concurrency slot
    qe.sem.Acquire(ctx)
    defer qe.sem.Release()

    // 2. Generate SQL from NL question using embedded schema context
    sql, _ := qe.generateSQL(ctx, question)

    // 3. Safety validation:
    //    - must start with SELECT or WITH
    //    - no semicolons (blocks multi-statement injection)
    //    - no INSERT/UPDATE/DELETE/DROP/ALTER/TRUNCATE/CREATE/GRANT/REVOKE/EXECUTE/COPY
    //    - must contain LIMIT
    validateSQL(sql)

    // 4. Execute with 10-second timeout
    queryCtx, _ := context.WithTimeout(ctx, 10*time.Second)
    rows, _ := qe.pool.Query(queryCtx, sql)

    // 5. Read up to 100 rows
}
```

The schema context embedded in `query_engine.go` describes all queryable tables with column names and types: `raw_content`, `iocs`, `entities`, `edges`, `correlations`, `analytical_notes`, `vulnerabilities`, `sources`.

---

## 8. Ingest Pipeline

`IngestPipeline` now has a single public method: `Process(ctx, finding)`. Background classification was moved entirely to `ProcessingEngine`.

```go
func (p *IngestPipeline) Process(ctx context.Context, f models.Finding) error {
    // 1. Archive unconditionally (CTE-based dedup on content_hash)
    rc := archive.FromFinding(f)
    p.archive.Insert(ctx, rc)

    // 2. Rule matching
    result, matched := p.matcher.Match(f)
    if !matched {
        p.metrics.RecordMatcherDrop()
        return nil  // background worker will handle it
    }

    // 3. Alert path (synchronous, blocks caller goroutine)
    // 3a. Classify (fast LLM) — returns category, confidence, severity, provenance
    classResult, _ := p.classifyAnalyzer.Classify(ctx, &f, result.MatchedRules)

    // 3b. Extract IOCs (full LLM)
    iocs, _ := p.fullAnalyzer.ExtractIOCs(ctx, &f)

    // 3c. Merge severity (LLM severity used if higher than rule-based)
    if llmSev > enriched.Severity { enriched.Severity = llmSev }

    // 3d. Summarize (full LLM)
    summary, _ := p.fullAnalyzer.Summarize(ctx, &f, category, severity)

    // 4. Alert dispatch
    p.alertFn(enriched)  // → PrometheusMetrics.RecordFinding

    // 5. Mark classified in archive (so background worker skips it)
    p.archive.MarkClassified(ctx, rc.ID, category, tags, severity, summary, provenance, version=3)

    return nil  // errors are logged and swallowed — pipeline must not crash
}
```

The matcher evaluates ALL configured rules regardless of early match. A finding is considered matched if at least one rule fires. Rules are compiled at startup; invalid regex patterns are fatal.

**Rule types:**
- `keyword`: `strings.Contains(strings.ToLower(content), pattern)` — case-insensitive
- `regex`: `regexp.MatchString(pattern, content)` — on original content

---

## 9. Infrastructure Services

### Vulnerability Ingestor

Runs every `cfg.Vuln.IntervalHours` (default 6 hours). Each cycle:

1. **NVD API** (`fetchNVDUpdates`) — paginates through `https://services.nvd.nist.gov/rest/json/cves/2.0` with `lastModStartDate` filter on subsequent runs. Rate-limited per NVD policy. Upserts into `vulnerabilities` table.

2. **EPSS** (`updateEPSSScores`, once per 24h) — downloads the daily EPSS CSV from `https://epss.cyentia.com/epss_scores-current.csv.gz`. Processes in 250K-row batches, updates `epss_score` and `epss_percentile` for all known CVEs.

3. **CISA KEV** (`updateKEVData`, once per 24h) — downloads `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. Sets `kev_listed=true`, `kev_date_added`, `kev_due_date`, `kev_ransomware_use`.

4. **Noctis cross-reference** (`crossReferenceNoctisData`) — finds CVE IOCs in `iocs` table and links them to `vulnerabilities`, updating `dark_web_mentions`, `first_seen_noctis`, `last_seen_noctis`.

5. **Priority scoring** (`recomputePriorities`) — calls `ComputePriority()` for all vulnerabilities.

**Priority formula:**

```go
// KEV-listed = automatic critical (confirmed active exploitation)
if vuln.KEVListed { return 1.0, "critical" }

score = epss_score * 0.4                                     // probability of exploitation
      + (cvss_v31_score / 10.0) * 0.3                       // technical severity
      + min(float64(dark_web_mentions)/10.0, 1.0) * 0.2     // threat actor interest
      + 0.1 (if exploit_available)                           // public exploit exists

// Label thresholds: >= 0.8 critical, >= 0.6 high, >= 0.3 medium, >= 0.1 low, else info
```

### Source Value Analyzer

Runs every 6 hours (hardcoded). For each source with status `active`, `approved`, or `discovered`:

| Metric | Computation |
|---|---|
| `unique_iocs` | IOCs first seen in this source not seen in any other source within the prior 7 days |
| `correlation_contributions` | Count of correlations where a finding from this source appears in `finding_ids` |
| `avg_severity` | Average of `CASE severity WHEN 'critical' THEN 4 ... END` across classified non-irrelevant findings |
| `signal_to_noise` | `non_irrelevant_findings / total_classified_findings` |
| `freshness_score` | `exp(-hours_since_last_collected / 24.0)` — 1.0 at 0h, ~0.37 at 24h, ~0.14 at 48h |
| `value_score` | `0.3 * ioc_ratio + 0.2 * corr_ratio + 0.2 * (avg_severity/4) + 0.15 * signal_to_noise + 0.15 * freshness` |

### Enrichment Pipeline

Runs every `cfg.Enrichment.IntervalMinutes` (default 30 minutes). Fetches up to `batchSize` (default 20) unenriched IOCs from `iocs WHERE active=true AND enriched_at IS NULL`, runs each through all applicable providers in order, merges results, and calls `MarkIOCEnriched`.

`EnrichmentProvider` interface:

```go
type EnrichmentProvider interface {
    Name() string
    SupportedTypes() []string
    Enrich(ctx context.Context, iocType, value string) (*EnrichmentResult, error)
    RateLimit() time.Duration
}
```

| Provider | Supported types | Rate limit | API key required |
|---|---|---|---|
| `abuseipdb` | `ip` | 2 seconds | Yes — `cfg.Enrichment.AbuseIPDBKey` |
| `virustotal` | `ip`, `domain`, `hash_md5`, `hash_sha256` | 15 seconds | Yes — `cfg.Enrichment.VirusTotalKey` |
| `crtsh` | `domain` | 5 seconds | No |

Rate limiting is applied per-provider via `time.Sleep(provider.RateLimit())` before each call. Enrichment boosts `base_score` but never lowers it: `newBaseScore = max(base_score, maxScore * 0.8)`.

Results are merged into a JSONB map keyed by provider name and stored in `iocs.enrichment`. `enrichment_sources` tracks which providers ran. IOCs with no applicable provider are still marked as enriched with empty results to prevent repeated reprocessing.

---

## 10. Data Flow Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│  COLLECTORS                                                              │
│                                                                          │
│  TelegramCollector  PasteCollector  ForumCollector  WebCollector        │
│  (MTProto, gotd/td)  (HTTP/Tor)      (HTTP/Tor,       (HTTP/Tor,        │
│                                       goquery)          gofeed)          │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │ chan models.Finding (buffered 50)
                             │ drained by CollectorManager consumer goroutine
                             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  INGEST PIPELINE (Process called synchronously per finding)              │
│                                                                          │
│  archive.Insert()                                                        │
│  ├── CTE: INSERT INTO raw_content ON CONFLICT(content_hash) DO NOTHING  │
│  │         UNION ALL SELECT id WHERE content_hash=$N  LIMIT 1           │
│  │                                                                       │
│  └── matcher.Match(finding)                                              │
│       ├── [no match] → metrics.RecordMatcherDrop() → return             │
│       └── [match]                                                        │
│            ├── Classify    (fast LLM, classify.tmpl)                    │
│            ├── ExtractIOCs (full LLM, extract_iocs.tmpl)                │
│            ├── Summarize   (full LLM, summarize.tmpl)                   │
│            ├── alertFn(EnrichedFinding) → PrometheusMetrics             │
│            └── archive.MarkClassified(classified=true, version=3)       │
│                                                                          │
│  [parallel] discoveryFn → ExtractURLs → classify → INSERT INTO sources  │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │ PostgreSQL: raw_content (classified=false)
                             │ polled by background workers
                             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  PROCESSING ENGINE (background workers, 30s idle sleep)                  │
│                                                                          │
│  classifyPipelineWorker (N=8 goroutines)                                │
│  ├── FetchUnclassified(batch=10) [ORDER BY collected_at ASC]            │
│  ├── Classifier → category, confidence, severity, provenance            │
│  │   (fast LLM, classify.tmpl)                                          │
│  └── Summarizer → summary text (full LLM, summarize.tmpl)              │
│       └── MarkClassified(classified=true, version=3)                    │
│                                                                          │
│  extractPipelineWorker (M=2 goroutines)                                 │
│  ├── FetchClassifiedUnextracted(batch=10)                               │
│  ├── IOCExtractor → []IOC (full LLM, extract_iocs.tmpl)               │
│  │   └── UpsertIOC + GraphBridge.BridgeIOCs                            │
│  ├── EntityExtractor → {entities, relationships} (full LLM)            │
│  │   └── GraphBridge.BridgeEntities                                     │
│  └── MarkEntitiesExtracted                                              │
│                                                                          │
│  librarianPipelineWorker (L=1 goroutines)                               │
│  ├── FetchUnsubclassified(batch=10)                                     │
│  ├── Librarian → sub_category + sub_metadata (full LLM)                │
│  └── MarkSubClassified                                                  │
│                                                                          │
│  IOCLifecycleManager (ticker, default 60m)                              │
│  └── UpdateIOCScores → decay threat_score, deactivate below threshold   │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │ PostgreSQL: entities, edges, iocs, ioc_sightings
                             ▼
┌──────────────────────────────────────────────────────────────────────────┐
│  INTELLIGENCE BRAIN                                                      │
│                                                                          │
│  Correlator (ticker, default 15m)                                       │
│  ├── Rule 1: shared_ioc          → ioc_sightings cross-source           │
│  ├── Rule 2: handle_reuse        → author cross-source                  │
│  ├── Rule 3: temporal_ioc_overlap → findings within window sharing IOCs │
│  └── Rule 4: campaign_cluster    → entity pairs sharing graph neighbors │
│       → correlations (confirmed) or correlation_candidates (pending)    │
│                                                                          │
│  Analyst (ticker, default 60m)                                          │
│  ├── FetchPendingCandidates                                             │
│  ├── build context: findings + entities + existing notes                │
│  ├── EvaluateCorrelation (brain LLM, evaluate_correlation.tmpl)        │
│  └── promote → correlations + analytical_notes                         │
│      reject  → analytical_notes                                         │
│      defer   → analytical_notes (if reasoning non-empty)               │
│      all     → correlation_decisions (audit trail)                      │
│                                                                          │
│  BriefGenerator (daily at cfg.scheduleHour:00 UTC, default 06:00)      │
│  ├── FetchBriefMetrics + FetchTopFindings + FetchTrendingEntities       │
│  ├── GenerateBrief (brain LLM, daily_brief.tmpl)                       │
│  └── InsertBrief → intelligence_briefs                                  │
│                                                                          │
│  QueryEngine (on-demand, from dashboard /api/query)                     │
│  ├── NL question → generateSQL (brain LLM)                             │
│  ├── validateSQL (SELECT-only, LIMIT required, no DDL/DML)             │
│  └── execute with 10s timeout, cap 100 rows                            │
└────────────────────────────┬─────────────────────────────────────────────┘
                             │
         ┌───────────────────┼────────────────────┐
         ▼                   ▼                    ▼
┌──────────────┐   ┌───────────────────┐   ┌──────────────────────┐
│ VulnIngestor │   │ SourceValueAnalyz.│   │ Enrichment Pipeline  │
│ (ticker 6h)  │   │ (ticker 6h)       │   │ (ticker 30m)         │
│ NVD + EPSS   │   │ per-source value  │   │ AbuseIPDB (IP, 2s)   │
│ + KEV        │   │ metric compute    │   │ VirusTotal (15s)     │
│ + priority   │   │ → sources table   │   │ crt.sh (domain, 5s)  │
└──────────────┘   └───────────────────┘   └──────────────────────┘
```

---

## 11. Concurrency Model

All long-running goroutines share a single `pipelineCtx` derived from `context.Background()`. Cancellation of `pipelineCtx` (via `pipelineCancel()`) signals all goroutines to stop. Each goroutine polls `ctx.Err()` or selects on `ctx.Done()`.

```
main goroutine
  │
  ├── health.Server goroutine (:8080)
  │
  ├── dashboard.Server goroutine (:3000, if enabled)
  │
  ├── processingEngine.Run goroutine
  │     ├── classifyPipelineWorker goroutine × 8 (default)
  │     ├── extractPipelineWorker goroutine × 2 (default)
  │     ├── librarianPipelineWorker goroutine × 1 (default)
  │     └── iocLifecycle.Run goroutine × 1 (ticker)
  │
  ├── intelligenceBrain.Run goroutine
  │     ├── correlator.Run goroutine (ticker, default 15m)
  │     ├── analyst.Run goroutine (ticker, default 60m)
  │     └── briefGenerator.Run goroutine (daily scheduler)
  │
  ├── sourceAnalyzer.Run goroutine (ticker, 6h)
  │
  ├── vulnIngestor.Run goroutine (ticker, default 6h)
  │
  ├── enricher.Run goroutine (ticker, default 30m)
  │
  └── collectorMgr.Run goroutine
        ├── [per collector] producer goroutine (blocks in collector.Start)
        │     TelegramCollector.Start
        │     PasteCollector.Start
        │       ├── pollPastebin goroutine
        │       └── pollScraper goroutine × per scraper config
        │     ForumCollector.Start
        │       └── pollForum goroutine × per site
        │     WebCollector.Start
        │       └── feed goroutine × per feed
        │
        └── [per collector] consumer goroutine (reads ch, calls ingestFn + discoveryFn)
```

**LLM concurrency is controlled per sub-module** via `ConcurrencyLimiter` (buffered channel semaphore). This prevents LLM API rate limit violations regardless of how many workers are running.

| Sub-module | Concurrency config |
|---|---|
| Classifier | `cfg.LLMFast.MaxConcurrency` → fallback `cfg.LLM.MaxConcurrent` → default 2 |
| Summarizer, IOCExtractor, EntityExtractor, Librarian | `cfg.LLM.MaxConcurrent` → default 2 |
| Analyst, BriefGenerator, QueryEngine | `cfg.LLMBrain.MaxConcurrent` → default 1 |

**No shared rate limiter exists between worker goroutines.** Concurrency is bounded by the semaphore; workers proceed as fast as the LLM allows within the slot budget. Workers sleep `WorkerIdleInterval` (30 seconds) when their fetch query returns an empty batch, then immediately re-poll.

**Goroutine count at steady state** (default config, all collectors enabled):
- 1 health server
- 1 dashboard server
- 8 classification workers
- 2 extraction workers
- 1 librarian worker
- 1 IOC lifecycle ticker
- 1 correlator ticker
- 1 analyst ticker
- 1 brief generator scheduler
- 1 source value analyzer ticker
- 1 vuln ingestor ticker
- 1 enrichment ticker
- 4 collector producers (1 per collector type)
- 4 collector consumers (1 per collector type)
- N sub-goroutines inside PasteCollector (1 + scrapers), ForumCollector (1 per site), WebCollector (1 per feed)

Minimum at steady state with all default workers and 1 of each collector type: approximately 28 goroutines before accounting for sub-collector goroutines driven by site/feed configuration.
