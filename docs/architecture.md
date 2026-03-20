# Noctis Architecture

Noctis is a Kubernetes-native threat intelligence daemon that collects content from multiple sources, archives everything unconditionally, and runs two parallel analysis paths: a synchronous real-time alert path for rule-matched content and an asynchronous background path for everything else.

---

## Package Layout

```
internal/
  collector/       Telegram, Paste, Forum, Web collectors
  ingest/          IngestPipeline (Process method + background workers)
  archive/         raw_content persistence layer (Store)
  matcher/         keyword and regex rule evaluation
  analyzer/        LLM-backed classify/extract/assess/summarize
  discovery/       URL extraction and source registry management
  dispatcher/      Prometheus metrics and alertFn callback
  models/          Finding, EnrichedFinding, IOC, Severity, Category
  pipeline/        Legacy fan-in pipeline (pre-archive, still present)
  config/          YAML config structs and loader
  llm/             OpenAI-compatible LLM client
  database/        pgx connection pool setup
  health/          HTTP health/readiness endpoints, QR auth state
  dashboard/       Web dashboard server, API handlers, embedded React SPA
migrations/
  001_init.sql     findings, canary_tokens, actor_profiles
  002_graph.sql    entities, edges
  003_pivot.sql    raw_content, iocs, artifacts, sources
```

---

## Pipeline Overview

```
  ┌──────────────────────────────────────────────────────┐
  │                     Collectors                        │
  │  TelegramCollector  PasteCollector  ForumCollector   │
  │      WebCollector  (each a goroutine)                │
  └────────────────────┬─────────────────────────────────┘
                       │  chan models.Finding (buffered, size 50 per collector)
                       ▼
  ┌──────────────────────────────────────────────────────┐
  │              IngestPipeline.Process()                 │
  │                                                       │
  │  1. archive.Insert (CTE-based dedup by content_hash) │
  │  2. matcher.Match (keyword + regex rules)            │
  │                                                       │
  │   [match]                    [no match]              │
  │      │                           │                   │
  │      ▼                           ▼                   │
  │  ALERT PATH               ARCHIVE PATH               │
  │  (synchronous)            (stays unclassified)       │
  │  Classify                 Background workers         │
  │  ExtractIOCs              pick up later              │
  │  AssessSeverity                                      │
  │  Summarize                                           │
  │  alertFn (Prometheus)                                │
  │  archive.MarkClassified                              │
  └──────────────────────────────────────────────────────┘
                       │ async (background)
                       ▼
  ┌──────────────────────────────────────────────────────┐
  │              Background Workers                       │
  │                                                       │
  │  classificationWorker(s)      entityExtractionWorker │
  │  FetchUnclassified (FIFO)     FetchClassifiedUnextracted
  │  Classify → AssessSeverity    ExtractIOCs            │
  │  → Summarize                  UpsertIOC              │
  │  MarkClassified               MarkEntitiesExtracted  │
  │                                                       │
  │  Shared rate limiter: 2s minimum between LLM calls  │
  │  Idle sleep: 30s when queue is empty                 │
  └──────────────────────────────────────────────────────┘
```

---

## Stage Details

### 1. Collectors (`internal/collector/`)

Each collector implements the `Collector` interface:

```go
type Collector interface {
    Name() string
    Start(ctx context.Context, out chan<- models.Finding) error
}
```

`Start` blocks until `ctx` is cancelled and closes `out` on return. Each collector runs as a dedicated goroutine.

| Collector | Transport | Method |
|---|---|---|
| `TelegramCollector` | MTProto via `gotd/td` | Registers `OnNewChannelMessage` handler; optionally catches up recent messages via `MessagesGetHistory`. QR-code login with optional 2FA. In-memory SHA-256 dedup. |
| `PasteCollector` | HTTP / SOCKS5 (Tor) | Polls `scrape.pastebin.com` API (limit 50) and arbitrary scraper URLs. Extracts paste links via regex. User-Agent rotation. |
| `ForumCollector` | HTTP / SOCKS5 (Tor) | Paginates thread-list pages using CSS selectors (`goquery`). Supports form-based login. Per-site circuit breaker (threshold 5 errors, initial backoff 30s, max 1h, exponential doubling). |
| `WebCollector` | HTTP / SOCKS5 (Tor) | Three feed types: `rss` (parsed via `gofeed`), `scrape` (CSS selector), `search` (URL template with `{query}` placeholder, fetches top 20 result links). Response body capped at 10 MB. |

**Content hash**: SHA-256 of the raw content string (hex-encoded). Used for in-memory dedup within each collector and for database-level dedup in the archive.

**Finding struct** (from `internal/models/finding.go`):
- `ID` — UUID v4
- `Source` — `"telegram"`, `"paste"`, `"forum"`, `"web"`
- `SourceID` — channel ID / thread URL / paste key
- `SourceName` — human-readable name
- `Content` — full raw text
- `ContentHash` — SHA-256 hex
- `Author`, `Timestamp`, `CollectedAt`, `Metadata`

---

### 2. Ingest Pipeline (`internal/ingest/pipeline.go`)

`IngestPipeline.Process(ctx, finding)` is the per-finding entry point called by collectors. It never returns an error that crashes the pipeline — all errors are logged and swallowed.

```
Process(finding):
  1. archive.FromFinding(f) → RawContent
  2. archive.Store.Insert(ctx, rc)
       CTE: INSERT INTO raw_content ... ON CONFLICT (content_hash) DO NOTHING RETURNING id
            UNION ALL SELECT id FROM raw_content WHERE content_hash = $5
            LIMIT 1
       → rc.ID populated (new or existing row)
  3. matcher.Match(f)
       → if no match: metrics.RecordMatcherDrop(), return
  4. [ALERT PATH]
     4a. analyzer.Classify(ctx, &f, matchedRules)
     4b. analyzer.ExtractIOCs(ctx, &f)
     4c. analyzer.AssessSeverity(ctx, &f, category, matchedRules)
           LLM severity upgrades rule-based severity if higher
     4d. analyzer.Summarize(ctx, &f, category, severity)
  5. alertFn(enriched)   ← Prometheus metrics recorded here
  6. archive.MarkClassified(ctx, rc.ID, category, tags, severity, summary)
```

Default worker counts (applied when config values are zero):
- `ClassificationWorkers`: 2
- `EntityExtractionWorkers`: 1
- `ClassificationBatchSize`: 10

---

### 3. Matcher (`internal/matcher/`)

Evaluates all configured rules against each finding's content. Rules are compiled at startup; invalid regex patterns are fatal.

- **keyword** rules: case-insensitive substring match on `strings.ToLower(content)`
- **regex** rules: `regexp.MatchString` on original content

All rules are evaluated regardless of early matches. The result carries:
- `MatchedRules []string` — names of every rule that fired
- `Severity` — highest severity across matched rules
- `MatchType` — `"keyword"`, `"regex"`, or `"keyword+regex"`

Returns `(MatchResult, false)` if no rule matched.

---

### 4. Analyzer (`internal/analyzer/`)

Wraps an `llm.LLMClient` and four Go `text/template` prompt files loaded from `prompts/`:

| Method | Template | Returns |
|---|---|---|
| `Classify` | `classify.tmpl` | `{category, confidence}` JSON |
| `ExtractIOCs` | `extract_iocs.tmpl` | `[{type, value, context}]` JSON array |
| `AssessSeverity` | `severity.tmpl` | `{severity, reasoning}` JSON |
| `Summarize` | `summarize.tmpl` | plain text |

LLM responses that wrap JSON in markdown code fences are cleaned before unmarshalling. Template render failures and LLM errors are propagated to the caller, which logs them and continues.

**Categories** (`models.Category`): `credential_leak`, `malware_sample`, `vulnerability`, `threat_actor_comms`, `access_broker`, `data_dump`, `canary_hit`, `irrelevant`.

**Severity** (`models.Severity`): `info (0)` < `low (1)` < `medium (2)` < `high (3)` < `critical (4)`.

---

### 5. Alert Path (synchronous)

Triggered for findings that match at least one rule. Runs entirely within the `Process` call, blocking until all LLM calls complete.

```
matcher.Match → Classify → ExtractIOCs → AssessSeverity → Summarize
     → alertFn(EnrichedFinding)
     → archive.MarkClassified
```

The `alertFn` callback is injected at construction time. The production implementation calls `dispatcher.PrometheusMetrics.RecordFinding`, which increments:
- `noctis_findings_total{source, severity, category}`
- `noctis_ioc_extracted_total{type}` per IOC
- `noctis_channel_messages_total{channel}` for Telegram
- `noctis_actor_posts_total{actor}` when author is set

---

### 6. Archive Path (asynchronous)

Unmatched findings are written to `raw_content` with `classified = false`. Background workers poll for unclassified rows and process them at a controlled rate.

**Classification worker** (`classificationWorker`):
```
FetchUnclassified(ctx, batchSize) [ORDER BY collected_at ASC]
  for each entry:
    rateLimiter.Wait(ctx)   ← 2s minimum between LLM calls
    Classify
    AssessSeverity
    rateLimiter.Wait(ctx)
    Summarize
    MarkClassified
```

**Entity extraction worker** (`entityExtractionWorker`):
```
FetchClassifiedUnextracted(ctx, batchSize) [classified=true AND entities_extracted=false]
  for each entry:
    rateLimiter.Wait(ctx)
    ExtractIOCs
    for each ioc: archive.UpsertIOC (ON CONFLICT increment sighting_count)
    MarkEntitiesExtracted
```

Rate limiters are shared across workers of the same type (via `sync.Once` initialization). The TOCTOU fix: the time slot is claimed under the mutex before sleeping, so concurrent workers cannot both see `remaining <= 0` and both proceed without delay.

Workers sleep 30s (`workerIdleInterval`) when their queue returns zero rows, and immediately re-poll when work is available.

---

### 7. Discovery Engine (`internal/discovery/engine.go`)

Runs against every piece of collected content. Extracts URLs using four ordered regexes:

1. `.onion` URLs: `https?://[a-z2-7]{16,56}\.onion[/\S]*`
2. Telegram links: `(?:https?://)?t\.me/(?:joinchat/|\+)?[A-Za-z0-9_]+`
3. Pastebin-like sites: `https?://(?:pastebin\.com|ghostbin\.\w+|...)//[A-Za-z0-9]+`
4. Generic HTTP(S) catch-all

Each extracted URL is classified by heuristic:

| Pattern | Source type |
|---|---|
| `t.me/joinchat/` or `t.me/+` | `telegram_group` |
| `t.me/` | `telegram_channel` |
| `.onion` | `forum` |
| `pastebin.com`, `ghostbin.*`, `privatebin.*`, `rentry.co` | `paste_site` |
| `.xml`, `/feed`, `/rss`, `/atom` | `rss` |
| everything else | `web` |

Discovered URLs are inserted into the `sources` table:

```sql
INSERT INTO sources (type, identifier, name, status, discovered_from, metadata)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (identifier) DO NOTHING
```

`status` is `"discovered"` by default; `"approved"` if `discovery.autoApprove = true` in config.

**Filtering (applied before insertion):**
- Domain blacklist — configurable list of domains to skip (e.g., `nvd.nist.gov`, `github.com`)
- Telegram URL normalization — message-specific URLs like `t.me/channel/123` are stripped to `t.me/channel`; bot usernames (ending in "bot") are skipped; channels already in config are skipped to avoid duplicates

---

## Data Flow: End-to-End Example

```
Telegram channel message received
  │
  ▼
TelegramCollector.processMessage
  SHA-256(content) → in-memory dedup check
  telegramMessage → models.Finding
  send to out channel
  │
  ▼
IngestPipeline.Process(ctx, finding)
  │
  ├─► archive.Store.Insert      → raw_content row (classified=false)
  │     content_hash dedup via CTE
  │     rc.ID ← UUID from DB
  │
  ├─► matcher.Match(finding)
  │
  │   [no match] ──────────────────────────────────────────────────────►
  │                                                                      │
  │   [match]                                               Background workers
  │      │                                                  poll raw_content
  │      ▼                                                  WHERE classified=false
  │   analyzer.Classify                                     │
  │   analyzer.ExtractIOCs                                  ▼
  │   analyzer.AssessSeverity                           Classify+Assess+Summarize
  │   analyzer.Summarize                                    │
  │      │                                                  ▼
  │      ▼                                             MarkClassified
  │   alertFn(EnrichedFinding)                              │
  │   → PrometheusMetrics.RecordFinding                     ▼
  │      │                                             EntityExtraction workers
  │      ▼                                             poll WHERE classified=true
  │   archive.MarkClassified                                AND entities_extracted=false
  │      classified=true, category, tags, severity, summary │
  │                                                          ▼
  └─────────────────────────────────────────────────────► UpsertIOC → iocs table
                                                          MarkEntitiesExtracted

  Meanwhile (parallel, on every finding):
  discovery.Engine.ProcessContent(content, sourceContentID)
    ExtractURLs → classify → INSERT INTO sources ON CONFLICT DO NOTHING
```

---

## Database Schema

Three migrations; 7 active tables plus a legacy `findings` table.

### Migration 001: `001_init.sql`

**`findings`** — Legacy enriched-finding store (pre-archive-everything pivot). Columns: `id`, `source`, `source_id`, `source_name`, `content`, `content_hash`, `author`, `timestamp`, `collected_at`, `metadata`, `match_type`, `matched_rules`, `severity`, `category`, `iocs`, `llm_analysis`, `confidence`. Indexed on `content_hash`, `source`, `severity`, `collected_at`.

**`canary_tokens`** — Deployed canary tokens. Columns: `id`, `type`, `value` (unique), `planted_at`, `planted_in`, `triggered`, `triggered_at`, `triggered_in`. Indexed on `value`.

**`actor_profiles`** — Threat actor dossiers. Columns: `id`, `known_handles`, `platforms`, `style_embedding`, `posting_cadence`, `first_seen`, `last_seen`, `threat_level`, `linked_findings`.

### Migration 002: `002_graph.sql`

**`entities`** — Knowledge graph nodes. Columns: `id`, `type`, `properties` (JSONB), `created_at`, `updated_at`. Indexed on `type`.

**`edges`** — Knowledge graph relationships. Columns: `id`, `source_id → entities(id)`, `target_id → entities(id)`, `relationship`, `properties` (JSONB), `created_at`. Indexed on `source_id`, `target_id`, `relationship`.

### Migration 003: `003_pivot.sql`

**`raw_content`** — Primary archive. Every collected finding is written here regardless of rule match. Columns: `id` (UUID), `source_type`, `source_id`, `source_name`, `content`, `content_hash` (UNIQUE), `author`, `author_id`, `url`, `language`, `collected_at`, `posted_at`, `metadata`, `classified` (bool), `category`, `tags` (TEXT[]), `severity`, `summary`, `entities_extracted` (bool).

Partial indexes support worker queries:
- `WHERE classified = FALSE ORDER BY collected_at ASC` — classification worker feed
- `WHERE classified = TRUE AND entities_extracted = FALSE ORDER BY collected_at ASC` — extraction worker feed
- GIN index on `tags` for array containment queries

**`iocs`** — Deduplicated indicator store. Columns: `id`, `type` (ip/domain/hash_md5/hash_sha256/email/crypto_wallet/url/cve), `value`, `context`, `source_content_id → raw_content(id)`, `first_seen`, `last_seen`, `sighting_count` (incremented on conflict), `confidence`. UNIQUE on `(type, value)`.

**`artifacts`** — Downloaded file store. Columns: `id`, `source_content_id`, `filename`, `mime_type`, `size_bytes`, `sha256` (UNIQUE), `storage_path` (NFS path), `tags`, `collected_at`, `analyzed`, `analysis` (JSONB).

**`sources`** — Source registry. Columns: `id`, `type` (telegram_channel/telegram_group/forum/paste_site/web/rss), `identifier` (UNIQUE), `name`, `status` (discovered/approved/active/paused/dead/banned), `discovered_from`, `last_collected`, `collection_interval`, `error_count`, `metadata`, `created_at`, `updated_at`.

---

## Schema Relationships

```
raw_content ──────────┬──── iocs.source_content_id
                      └──── artifacts.source_content_id
                      └──── sources.discovered_from

entities ─────────────┬──── edges.source_id
                      └──── edges.target_id
```

---

## Concurrency Model

```
main goroutine
  │
  ├── TelegramCollector.Start goroutine
  ├── PasteCollector.Start goroutine
  │     ├── pollPastebin goroutine
  │     └── pollScraper goroutine (one per scraper config)
  ├── ForumCollector.Start goroutine
  │     └── pollForum goroutine (one per site)
  ├── WebCollector.Start goroutine
  │     └── feed goroutine (one per feed)
  │
  ├── IngestPipeline.Run goroutine
  │     ├── classificationWorker goroutine × N (default 2)
  │     └── entityExtractionWorker goroutine × M (default 1)
  │
  ├── Dashboard server goroutine (:3000, if enabled)
  └── HTTP servers (metrics :8080, health :8081)
```

Collectors write to their own buffered output channel (size 50 implied by the `Collector` interface contract; the fan-in wrapper in `pipeline.Pipeline.Run` uses size 100). `IngestPipeline.Process` is called synchronously from whichever goroutine reads from the collector channel; there is no separate processing goroutine — the caller blocks during LLM enrichment on the alert path.

Rate limiters (`rateLimiter`) are safe for concurrent use. The shared classification rate limiter is initialized once via `sync.Once` and shared across all classification workers; similarly for extraction workers.

---

## Configuration Reference (relevant keys)

```yaml
noctis:
  collection:
    archiveAll: true
    classificationWorkers: 2
    entityExtractionWorkers: 1
    classificationBatchSize: 10
  discovery:
    enabled: true
    autoApprove: false
    domainBlacklist: []
  storage:
    artifactPath: /mnt/artifacts
    maxArtifactSizeMB: 100
```

Worker defaults are applied when the configured value is `<= 0`.
