# Development Guide

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.25+ | Build and test (module uses go 1.25.6) |
| PostgreSQL | 15+ | Development and testing database |
| Docker | any recent | Container builds and local images |
| golangci-lint | latest | Static analysis and linting |

## Building from Source

### Binary

```bash
go build -o noctis ./cmd/noctis/
```

### Using the Makefile

```bash
make build           # outputs to bin/noctis
make clean           # removes bin/
```

The Makefile injects version information at link time:

```
LDFLAGS := -ldflags "-X main.version=$(VERSION)"
```

The module path is `github.com/Zyrakk/noctis`. Pass `VERSION` to override the default (`dev`):

```bash
make build VERSION=v0.3.1
```

## Running Tests

```bash
make test            # go test -race -count=1 ./...
make lint            # golangci-lint run ./...
```

Tests run with the race detector enabled (`-race`) and cache disabled (`-count=1`).

Test files follow Go convention (`*_test.go` alongside source). Key test files:

- `internal/discovery/triage_test.go` — triage worker unit tests
- `internal/discovery/engine_test.go` — discovery engine, allow-patterns, invite hash extraction
- `internal/collector/telegram_test.go` — invite hash resolution, identifier normalization
- `internal/llm/openai_compat_test.go` — LLM client tests
- `internal/llm/errors_test.go` — budget error sentinel tests
- `internal/processor/helpers_test.go` — processor helper functions
- `internal/analyzer/truncate_test.go` — content truncation logic

## Docker Build

### Using the Makefile

```bash
make docker-build TAG=latest
```

This builds `ghcr.io/zyrakk/noctis:latest`. Override the image name with the `IMAGE` variable:

```bash
make docker-build IMAGE=myrepo/noctis TAG=v0.3.1
```

### Directly with Docker

```bash
docker build --build-arg VERSION=dev -t ghcr.io/zyrakk/noctis:dev .
```

### Build stages

The Dockerfile uses a two-stage build:

1. **Builder** — `golang:1.25-alpine`: installs git and CA certificates, downloads modules, compiles with `CGO_ENABLED=0`.
2. **Runtime** — `gcr.io/distroless/static-debian12:nonroot`: copies only the compiled binary, migration files, and prompt templates.

Artifacts copied into the runtime image:

- `/noctis` — compiled binary
- `/migrations/` — PostgreSQL DDL files
- `/prompts/` — LLM prompt templates

The container runs as the `nonroot` user. Default entrypoint:

```
/noctis serve --config /etc/noctis/config.yaml
```

---

## Project Structure

```
cmd/noctis/                 — CLI entry point and commands
  main.go                   — root command, version flag
  serve.go                  — noctis serve (main daemon; wires all components)
  search.go                 — noctis search + noctis stats
  source.go                 — noctis source (list/approve/pause/remove)
  config_cmd.go             — noctis config validate
  telegram_auth.go          — noctis telegram-auth (--qr / --sms)

internal/
  analyzer/                 — LLM prompt execution: Classify, SubClassify,
                              Summarize, ExtractIOCs, ExtractEntities,
                              AssessSeverity, EvaluateCorrelation, GenerateBrief
  archive/                  — PostgreSQL persistence layer (raw_content, iocs,
                              entities, edges, correlations, briefs, vulns)
  brain/                    — Intelligence sub-modules: Correlator, Analyst,
                              BriefGenerator, QueryEngine
  collector/                — Telegram, Paste, Forum, Web collectors + Tor
                              transport + CollectorManager + SourceValueAnalyzer
  config/                   — YAML parsing, ${VAR} env substitution, validation
  database/                 — PostgreSQL connection pool and migration runner
  discovery/                — Source discovery engine (URL extraction, three-tier
                              filtering, AI triage worker, auto-blacklist learning)
    engine.go               — URL extraction, filtering, allow-patterns/domains
    triage.go               — TriageWorker: AI-powered URL classification,
                              auto-blacklist learning, audit logging
  dispatcher/               — Prometheus metrics recording
  enrichment/               — IOC enrichment pipeline: AbuseIPDB, VirusTotal,
                              crt.sh providers
  health/                   — HTTP health checks (/healthz, /readyz) + QR auth
  ingest/                   — Real-time ingest pipeline (matching + alert path)
  llm/                      — OpenAI-compatible LLM client, token-bucket rate
                              limiter (ratelimit.go), Gemini spending tracker
                              (spending.go), budget error sentinel (errors.go)
  matcher/                  — Keyword/regex pattern matching engine
  models/                   — Finding, IOC, Severity, Category, ActorProfile, Canary
  modules/                  — StatusTracker, ModuleStatus, Registry (system-wide
                              health and observability)
  processor/                — Processing engine: Classifier, Summarizer,
                              IOCExtractor, EntityExtractor, GraphBridge,
                              Librarian, IOCLifecycleManager + ConcurrencyLimiter
  vuln/                     — Vulnerability intelligence: NVD, EPSS, KEV ingestors

migrations/                 — PostgreSQL DDL (numbered, applied in order)
  001_init.sql .. 009_enrichment.sql
  010_triage.sql            — source_triage_log + discovered_blacklist tables
  011_normalize_telegram_identifiers.sql — URL-to-bare-username migration
  012_purge_legacy_embedly_urls.sql — cleanup broken pending_triage URLs
prompts/                    — LLM prompt templates (*.tmpl, Go text/template)
  triage.tmpl               — batch URL classification for source triage
deploy/                     — Kubernetes manifests
testdata/                   — Config test fixtures
```

---

## modules.Registry

`internal/modules` provides system-wide status tracking and observability for
every component.

### StatusTracker

`StatusTracker` is a thread-safe struct that holds counters and timestamps for a
single module or sub-module. All mutating operations use atomics or mutexes and
are safe to call from multiple goroutines.

```go
tracker := modules.NewStatusTracker(modules.ModClassifier, "Classifier", "processor")
tracker.SetAIInfo("groq", "llama-4-scout-17b-16e-instruct")
tracker.SetEnabled(true)
tracker.SetWorkerCount(8)

tracker.MarkStarted()
tracker.RecordSuccess()       // increments TotalProcessed, updates LastActivityAt
tracker.RecordError(err)      // increments TotalErrors, stores LastError
tracker.SetQueueDepth(42)     // optional; for poll-loop workers
tracker.SetExtra("interval", "15m")  // arbitrary key-value metadata
tracker.MarkStopped()

status := tracker.Status()   // returns a ModuleStatus snapshot
```

`ModuleStatus` fields: `ID`, `Name`, `Category`, `Running`, `Enabled`,
`StartedAt`, `StoppedAt`, `AIProvider`, `AIModel`, `TotalProcessed`,
`TotalErrors`, `LastActivityAt`, `LastErrorAt`, `LastError`, `QueueDepth`,
`WorkerCount`, `Extra`.

### Registry

`Registry` holds all registered trackers and is passed down from `serve.go`
to every component that needs it.

```go
registry := modules.NewRegistry()
registry.Register(tracker)                    // idempotent by ModuleID

all := registry.AllStatuses()                 // map[string]ModuleStatus
byCategory := registry.StatusesByCategory()  // map[string][]ModuleStatus
```

`StatusesByCategory` groups by the `category` string used at tracker
construction time. Current categories in use: `"collector"`, `"processor"`,
`"brain"`, `"infra"`.

Pre-defined `ModuleID` constants live in `internal/modules/status.go` and cover
all current and planned modules. Always use a constant — never a raw string.

---

## Adding a New Collector

1. **Create** `internal/collector/mytype.go` implementing the `Collector`
   interface:

   ```go
   type Collector interface {
       Name() string
       Start(ctx context.Context, out chan<- models.Finding) error
   }
   ```

   `Start` must block until `ctx` is cancelled and send all findings to `out`.
   It must not close `out`; the `CollectorManager` owns the channel lifecycle.

2. **Add** a config struct to `internal/config/config.go` and nest it under
   `SourcesConfig`. Add the YAML tag.

3. **Register** in `cmd/noctis/serve.go`: check `cfg.Sources.MyType.Enabled`,
   instantiate `collector.NewMyCollector(...)`, and append to `collectors`.
   The `CollectorManager` created later will automatically create a
   `StatusTracker` for it using the collector's `Name()` return value and
   register it in the registry.

4. **Add** the corresponding config section to `deploy/configmap.yaml`.

5. **Write** tests in `internal/collector/mytype_test.go`.

Note: `CollectorManager` maps collector names to module IDs via
`collectorModuleID(name)`. If a `ModuleID` constant for the new collector does
not yet exist in `internal/modules/status.go`, add one before registering.

---

## Adding a New Processor Sub-module

1. **Create** `internal/processor/mymodule.go`. Embed a `*modules.StatusTracker`
   and a `*ConcurrencyLimiter`:

   ```go
   type MyModule struct {
       analyzer *analyzer.Analyzer
       sem      *ConcurrencyLimiter
       status   *modules.StatusTracker
   }

   func NewMyModule(a *analyzer.Analyzer, concurrency int, provider, model string) *MyModule {
       m := &MyModule{
           analyzer: a,
           sem:      NewConcurrencyLimiter(concurrency),
           status:   modules.NewStatusTracker(modules.ModMyModule, "My Module", "processor"),
       }
       m.status.SetAIInfo(provider, model)
       m.status.SetEnabled(true)
       return m
   }

   func (m *MyModule) Process(ctx context.Context, ...) (..., error) {
       if err := m.sem.Acquire(ctx); err != nil {
           return ..., err
       }
       defer m.sem.Release()
       // call m.analyzer method
       m.status.RecordSuccess()
       return ...
   }
   ```

2. **Add** a `ModuleID` constant to `internal/modules/status.go`.

3. **Wire** into `ProcessingEngine`:
   - Add the field to the `ProcessingEngine` struct.
   - Instantiate in `NewProcessingEngine`.
   - Call `registry.Register(m.status)` in `NewProcessingEngine`.
   - Call `m.status.MarkStarted()` / `m.status.MarkStopped()` in `Run`.
   - Start the worker goroutine from `Run`.

4. **Implement** the poll-loop worker in `internal/processor/workers.go`
   (or a dedicated file), following the `classifyPipelineWorker` or
   `extractPipelineWorker` pattern.

---

## Adding a New Brain Sub-module

1. **Create** `internal/brain/mymodule.go`. Embed a `*modules.StatusTracker`
   and a `*processor.ConcurrencyLimiter`:

   ```go
   type MyBrainModule struct {
       analyzer *analyzer.Analyzer
       archive  *archive.Store
       sem      *processor.ConcurrencyLimiter
       status   *modules.StatusTracker
       cfg      config.MyModuleConfig
   }

   func NewMyBrainModule(a *analyzer.Analyzer, store *archive.Store, cfg config.MyModuleConfig,
       concurrency int, provider, model string) *MyBrainModule {
       m := &MyBrainModule{...}
       m.status = modules.NewStatusTracker(modules.ModMyBrainModule, "My Brain Module", "brain")
       m.status.SetAIInfo(provider, model)
       m.status.SetEnabled(cfg.Enabled)
       return m
   }

   func (m *MyBrainModule) Run(ctx context.Context) {
       if !m.cfg.Enabled {
           return
       }
       m.status.MarkStarted()
       defer m.status.MarkStopped()
       // periodic ticker loop
   }
   ```

2. **Add** a `ModuleID` constant to `internal/modules/status.go`.

3. **Add** the sub-module to `Brain` in `internal/brain/brain.go`:
   - Add the field to the `Brain` struct.
   - Instantiate in `NewBrain`.
   - Call `registry.Register(m.status)`.
   - Start via `wg.Add(1)` + goroutine in `Brain.Run`.

4. **Add** a config struct and wire it through `cmd/noctis/serve.go` into
   `NewBrain`.

5. **Add** a prompt template to `prompts/` if the module uses LLM inference,
   and add the corresponding `Analyzer` method in `internal/analyzer/analyzer.go`.

---

## Adding a New Enrichment Provider

Implement the `EnrichmentProvider` interface defined in
`internal/enrichment/enricher.go`:

```go
type EnrichmentProvider interface {
    Name() string                                                           // e.g. "abuseipdb"
    SupportedTypes() []string                                               // e.g. ["ip"]
    Enrich(ctx context.Context, iocType, value string) (*EnrichmentResult, error)
    RateLimit() time.Duration                                               // minimum gap between calls
}
```

`EnrichmentResult` fields: `Provider` (string), `Malicious` (*bool, nil =
unknown), `Score` (*float64, nil = unknown), `Data` (map[string]any for
provider-specific metadata).

Steps:

1. **Create** `internal/enrichment/myprovider.go` implementing the interface.
2. **Instantiate** in `cmd/noctis/serve.go` when the relevant API key is
   configured, and append to `enrichProviders` before `enrichment.NewEnricher`.
3. **Add** the API key field to `EnrichmentConfig` in `config.go` if needed,
   along with a corresponding env var.

The `Enricher` automatically respects each provider's `RateLimit()` between
calls and only passes IOCs of supported types to each provider.

---

## Adding a New Collector Source in `serve.go`

The wiring pattern in `cmd/noctis/serve.go` is consistent for all collectors:

```go
if cfg.Sources.MyType.Enabled {
    mc := collector.NewMyCollector(&cfg.Sources.MyType, &cfg.Sources.Tor)
    collectors = append(collectors, mc)
    slog.Info("mytype collector enabled")
}
```

`CollectorManager` then wraps all collectors, creates per-collector
`StatusTracker` instances, registers them with the registry, and fans all
findings into the ingest pipeline.

---

## CI/CD Pipeline

The workflow lives in `.github/workflows/build.yaml`.

| Property | Value |
|----------|-------|
| Trigger | Push to `main`, or semver tags (`v*`) |
| Architectures | `linux/amd64`, `linux/arm64` (QEMU + buildx) |
| Registry | `ghcr.io/zyrakk/noctis` |
| Auth | `GITHUB_TOKEN` (built-in) |
| Layer cache | GitHub Actions cache (`type=gha`) |

### Image tags produced

| Event | Tag(s) |
|-------|--------|
| Push to `main` | `latest` |
| Semver tag (e.g. `v1.2.3`) | `1.2.3`, `1.2` |

The `VERSION` build argument is set from `${{ github.ref_name }}` so the binary
embeds the tag name at compile time.
