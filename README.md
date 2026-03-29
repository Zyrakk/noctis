# Noctis

**Autonomous dark web threat intelligence platform**

[![Go 1.25+](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/Zyrakk/noctis/actions/workflows/ci.yml/badge.svg)](https://github.com/Zyrakk/noctis/actions)
[![Container](https://img.shields.io/badge/container-ghcr.io%2Fzyrakk%2Fnoctis-blue?logo=github)](https://ghcr.io/zyrakk/noctis)

---

## What Noctis Is

Noctis is a long-running threat intelligence daemon written in Go. It autonomously collects content from Telegram channels (MTProto), paste sites, dark web forums, and RSS/web feeds, then archives everything in PostgreSQL. Each collected item is classified by severity and category, summarized, and processed through IOC and named entity extraction pipelines. Extracted entities form a persistent knowledge graph with typed relationships spanning actors, infrastructure, malware families, and vulnerabilities.

A correlation engine detects cross-source patterns across the graph. A separate LLM Analyst reviews each candidate correlation and issues a confirmed or rejected decision with a rationale, producing structured analytical notes. IOC threat scores decay exponentially over time through a lifecycle manager that deactivates stale indicators. A daily brief generator synthesizes the prior 24 hours of intelligence into a structured report. A natural language query engine translates human questions into SQL against the live archive.

Vulnerability intelligence arrives from NVD, EPSS, and CISA KEV feeds and is scored for priority. Collected IOCs are enriched asynchronously via AbuseIPDB, VirusTotal, and crt.sh. An autonomous source discovery engine extracts URLs from ingested content and queues new sources for operator review, allowing the collection network to grow without manual intervention. Everything is visible through a React dashboard embedded in the Go binary, secured by API key authentication.

---

## Architecture

```
+-----------------------------------------------------------------------------------+
| Layer 0: Collectors                                                               |
|                                                                                   |
|  Telegram MTProto    Paste Sites    Dark Web Forums    RSS / Web Feeds            |
|       |                  |                |                  |                    |
|       +------------------+----------------+------------------+                    |
|                                    |                                              |
|                            CollectorManager                                       |
+------------------------------------------+-----------------------------------------+
                                           |
                   +-----------------------+
                   |
+------------------v----------------+
| Layer 1: IngestPipeline           |
|                                   |
|  Dedup -> Matcher (keyword/regex) |
|       -> Archive -> Alert path    |
+------------------+----------------+
                   |
+------------------v--------------------------------------------------------+
| Layer 2: ProcessingEngine (background workers)                            |
|                                                                           |
|  Classifier        Groq / llama-4-scout      (category, severity)         |
|  Summarizer        Groq / llama-4-scout      (abstractive summary)        |
|  IOC Extractor     Groq / llama-4-scout      (IPs, domains, hashes, CVEs) |
|  Entity Extractor  GLM-5-Turbo               (actors, orgs, malware)      |
|  Graph Bridge                                 (entity -> graph write)      |
|  Librarian         GLM-5-Turbo               (sub-classification)         |
|  IOC Lifecycle                                (exponential score decay)    |
|  Content truncation: 4K classify, 6K summarize, 8K IOC extraction         |
+------------------+--------------------------------------------------------+
                   |
+------------------v--------------------------------------------------------+
| Layer 3: Brain (scheduled intelligence)                                   |
|                                                                           |
|  Correlator        rule-based cross-source pattern detection              |
|  Analyst           Gemini 3.1 Pro  (LLM confirmation of correlations)    |
|  Brief Generator   Gemini 3.1 Pro  (daily 24-hour intelligence summary)  |
|  Query Engine      Gemini 3.1 Pro  (natural language -> SQL)             |
+------------------+--------------------------------------------------------+
                   |
+------------------v--------------------------------------------------------+
| Layer 4: Infrastructure                                                   |
|                                                                           |
|  Vuln Ingestor       NVD / EPSS / CISA KEV -> priority scoring           |
|  Source Value Analyzer                                                    |
|  Enrichment Pipeline AbuseIPDB / VirusTotal / crt.sh                     |
|  Discovery Engine    URL extraction -> pending source queue               |
|  Triage Worker       LLM-powered URL classification (investigate/trash)  |
+------------------+--------------------------------------------------------+
                   |
+------------------v--------------------------------------------------------+
| Layer 5: Dashboard                                                        |
|                                                                           |
|  React SPA embedded in binary   14 pages   25+ API endpoints             |
|  X-API-Key auth on all data routes                                        |
+--------------------------------------------------------------------------+

Shared data store: PostgreSQL (20 tables, 12 migrations)
Metrics: Prometheus /metrics, /healthz, /readyz (health port, default 8080)
```

---

## Features

### Collection

- **Telegram MTProto** — Connects to channels and groups via [gotd/td](https://github.com/gotd/td). Joins public channels automatically. Supports private invite links (`t.me/+hash` and `t.me/joinchat/hash` formats) via the `inviteHash` channel config field. Identifier normalization converts URLs to bare usernames. Replays configurable backlog on reconnect. Session survives pod restarts via PVC.
- **Paste sites** — Scrapes Pastebin and custom paste targets via configurable HTTP scrapers.
- **Dark web forums** — CSS-selector-based scraping with per-forum authentication, pagination, and Tor proxy support.
- **RSS / web feeds** — Polls RSS, Atom, and scrapeable web pages on configurable intervals. RSS feeds are loaded from both the config file and the `sources` table (type `rss`, status `active`), refreshed from the database every 30 minutes. Discovery can approve new feeds at runtime without redeployment. The `sources.last_collected` timestamp is updated after each collection cycle.
- **Autonomous source discovery** — Extracts URLs from ingested content and filters them through a three-tier pipeline: configurable blacklist, allowlist (glob patterns + exact domains), and AI-powered batch triage. Allowlisted URLs are instantly queued; unknown URLs enter `pending_triage` status and are periodically evaluated by the fast LLM. Domains that accumulate repeated trash decisions are auto-blacklisted.

### Processing

- **LLM classification** — Groq (llama-4-scout) classifies each finding into category, severity, and sub-category on the alert path, optimized for throughput. Content is truncated to 4K bytes before classification.
- **Summarization** — Groq (llama-4-scout) generates abstractive summaries of raw collected content (truncated to 6K bytes). Summarization is skipped for items classified as irrelevant.
- **IOC extraction** — Groq (llama-4-scout) extracts IPs, domains, URLs, file hashes (MD5/SHA-1/SHA-256), CVEs, and email addresses with source context. Content is truncated to 8K bytes before extraction.
- **Entity extraction** — GLM-5-Turbo identifies named actors, organizations, malware families, and tools, written to the knowledge graph.
- **Graph bridge** — Connects extracted entities and IOCs with typed relationships across findings.
- **Librarian** — GLM-5-Turbo applies fine-grained sub-classification after initial categorization.
- **IOC lifecycle manager** — Applies configurable exponential decay to IOC threat scores and deactivates stale indicators.

### Intelligence

- **Correlation engine** — Detects cross-source patterns using shared IOCs, entity co-occurrence, and temporal proximity. Produces structured correlation candidates.
- **LLM Analyst** — Gemini 3.1 Pro reviews each correlation candidate and issues a confirmed or rejected decision with a rationale, stored as an analytical note.
- **Daily brief generator** — Gemini 3.1 Pro synthesizes the prior 24-hour collection window into a structured intelligence brief.
- **Natural language query engine** — Gemini 3.1 Pro translates human questions into SQL and executes them against the live archive. Trailing semicolons are stripped from LLM-generated SQL before execution.

### Enrichment and Vulnerability Intelligence

- **IOC enrichment** — Asynchronously queries AbuseIPDB (IPs), VirusTotal (hashes and domains), and crt.sh (domain certificate history).
- **Vulnerability intelligence** — Ingests NVD CVE data, EPSS exploit probability scores, and CISA KEV entries. Applies priority scoring combining CVSS, EPSS, and KEV membership.
- **Source value analysis** — Scores each source by the quality and volume of actionable intelligence it produces.

### Infrastructure

- **LLM budget management** — Monthly spending limits per LLM provider via `monthlyBudgetUSD`. A `SpendingTracker` monitors cumulative token usage and estimated cost using configurable `inputCostPer1M` and `outputCostPer1M` rates. When a provider's budget is exhausted, a circuit breaker pauses all workers using that provider for 30 minutes. Groq budget defaults to $10/mo.
- **Content truncation** — A configurable `maxContentLength` (default 8192 bytes) truncates content before LLM calls. Each processing stage applies its own limit: 4K for classification, 6K for summarization, 8K for IOC extraction.
- **Single binary** — The entire platform, including the React dashboard, compiles to one Go binary. No sidecar processes required.
- **Auto-migration** — Runs PostgreSQL migrations at startup.
- **Prometheus metrics** — Exposes collector throughput, LLM call rates, and error counters on a dedicated scrape endpoint.
- **Kubernetes-native** — Ships with manifests for namespace, secrets, PostgreSQL StatefulSet, ConfigMap, and Deployment. PVC provides session persistence for Telegram authentication.
- **Module registry** — All 16 active modules report structured status (running state, throughput, error counts, last activity, AI provider/model) to a shared registry visible from the System Status dashboard page.

---

## Quick Start

### Prerequisites

- Go 1.25+
- PostgreSQL 14+
- API key from [Z.ai](https://api.z.ai) (GLM-5-Turbo) — required for entity extraction and sub-classification
- Groq API key (Dev tier recommended) — required for classification, summarization, and IOC extraction
- Gemini API key — required for correlation analysis, briefs, and natural language queries

### Build

```sh
go build -o noctis ./cmd/noctis/
```

### Docker

```sh
docker pull ghcr.io/zyrakk/noctis:latest
```

Multi-arch (Intel + ARM):

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  -t ghcr.io/zyrakk/noctis:latest --push .
```

### Minimal run (RSS-only, no Telegram credentials required)

```yaml
# noctis-config.yaml
noctis:
  logLevel: info
  healthPort: 8080

  database:
    driver: postgres
    dsn: "${NOCTIS_DB_DSN}"

  llm:
    provider: glm
    baseURL: "https://api.z.ai/api/coding/paas/v4"
    model: "glm-5-turbo"
    apiKey: "${NOCTIS_LLM_API_KEY}"

  sources:
    telegram:
      enabled: false
    paste:
      enabled: false
    forums:
      enabled: false
    web:
      enabled: true
      feeds:
        - name: "bleeping-computer"
          url: "https://www.bleepingcomputer.com/feed/"
          type: rss
          interval: 900s

  collection:
    archiveAll: true
    classificationWorkers: 1
    entityExtractionWorkers: 1

  discovery:
    enabled: false

  dashboard:
    enabled: true
    port: 3000
    apiKey: "${NOCTIS_DASHBOARD_API_KEY}"
```

```sh
export NOCTIS_DB_DSN="postgres://user:pass@localhost:5432/noctis?sslmode=disable"
export NOCTIS_LLM_API_KEY="..."
export NOCTIS_DASHBOARD_API_KEY="..."

./noctis serve --config noctis-config.yaml
```

Migrations run automatically on startup. The dashboard is available at `http://localhost:3000`.

---

## Configuration

The config file requires a top-level `noctis:` key. Environment variable substitution (`${VAR_NAME}`) is applied before YAML parsing — unset variables expand to an empty string.

### Environment Variables

**Required:**

| Variable | Description |
|---|---|
| `NOCTIS_LLM_API_KEY` | Z.ai GLM-5-Turbo API key |
| `NOCTIS_GROQ_API_KEY` | Groq API key (Dev tier recommended) |
| `NOCTIS_GEMINI_API_KEY` | Google Gemini API key |
| `NOCTIS_DASHBOARD_API_KEY` | Dashboard API key (sent via `X-API-Key` header) |
| `NOCTIS_DB_DSN` | PostgreSQL connection string |

**Telegram (required if Telegram enabled):**

| Variable | Description |
|---|---|
| `NOCTIS_TG_API_ID` | Telegram API ID |
| `NOCTIS_TG_API_HASH` | Telegram API hash |
| `NOCTIS_TG_PHONE` | Phone number for Telegram auth |
| `NOCTIS_TG_PASSWORD` | 2FA password (if enabled) |

**Optional:**

| Variable | Description |
|---|---|
| `NOCTIS_NVD_API_KEY` | NVD API key (higher rate limit) |
| `NOCTIS_ABUSEIPDB_KEY` | AbuseIPDB enrichment key |
| `NOCTIS_VT_KEY` | VirusTotal enrichment key |

### Full Config Reference

```yaml
noctis:
  logLevel: info            # debug | info | warn | error
  metricsPort: 9090         # Prometheus scrape port
  healthPort: 8080          # /healthz, /readyz, /metrics, /auth/qr

  # --- LLM Clients ---

  # GLM-5-Turbo: entity extraction, sub-classification (Librarian)
  llm:
    provider: glm
    baseURL: "https://api.z.ai/api/coding/paas/v4"
    model: "glm-5-turbo"
    apiKey: "${NOCTIS_LLM_API_KEY}"
    maxTokens: 1024
    temperature: 0.1
    timeout: 30s
    retries: 3
    maxConcurrent: 2
    requestsPerMinute: 20
    tokensPerMinute: 1500
    monthlyBudgetUSD: 5.0        # monthly spending limit (0 = unlimited)
    inputCostPer1M: 0.50         # cost per 1M input tokens
    outputCostPer1M: 1.00        # cost per 1M output tokens

  # Groq / llama-4-scout: classification, summarization, IOC extraction
  llmFast:
    provider: groq
    baseURL: "https://api.groq.com/openai/v1"
    model: "meta-llama/llama-4-scout-17b-16e-instruct"
    apiKey: "${NOCTIS_GROQ_API_KEY}"
    maxConcurrency: 5
    tokensPerMinute: 300000
    tokensPerDay: 10000000       # 10M tokens/day
    monthlyBudgetUSD: 10.0       # monthly spending limit ($10/mo for Groq)
    inputCostPer1M: 0.11         # cost per 1M input tokens
    outputCostPer1M: 0.34        # cost per 1M output tokens

  # Gemini 3.1 Pro: analytical reasoning (correlations, briefs, NL queries)
  llmBrain:
    provider: gemini
    baseURL: "https://generativelanguage.googleapis.com/v1beta/openai"
    model: "gemini-3.1-pro-preview"
    apiKey: "${NOCTIS_GEMINI_API_KEY}"
    maxConcurrent: 1
    monthlyBudgetUSD: 17.0

  # --- Sources ---

  sources:
    telegram:
      enabled: true
      apiId: ${NOCTIS_TELEGRAM_API_ID}
      apiHash: "${NOCTIS_TELEGRAM_API_HASH}"
      phone: "${NOCTIS_TELEGRAM_PHONE}"
      password: "${NOCTIS_TELEGRAM_PASSWORD}"   # 2FA, optional
      sessionFile: "/data/telegram.session"
      catchupMessages: 100
      channels:
        - username: "RalfHackerChannel"
        - username: "zer0day1ab"
        - inviteHash: "abc123def"    # private channel via t.me/+abc123def

    paste:
      enabled: false
      pastebin:
        enabled: false
        apiKey: "${NOCTIS_PASTEBIN_API_KEY}"
        interval: 60s
      scrapers:
        - name: "paste-custom"
          url: "https://example.com/pastes"
          interval: 300s
          tor: false

    forums:
      enabled: false
      sites:
        - name: "example-forum"
          url: "https://forum.example.onion"
          tor: true
          interval: 1800s
          maxPagesPerCrawl: 5
          requestDelay: 5s
          auth:
            username: "${FORUM_USER}"
            password: "${FORUM_PASS}"
            loginURL: "https://forum.example.onion/login"
            usernameField: "username"
            passwordField: "password"
          scraper:
            threadListSelector: ".thread-list .thread"
            threadContentSelector: ".post-content"
            authorSelector: ".post-author"
            paginationSelector: "a.next-page"

    web:
      enabled: true
      feeds:
        - name: "bleeping-computer"
          url: "https://www.bleepingcomputer.com/feed/"
          type: rss        # rss | scrape | search
          interval: 900s
        - name: "the-hacker-news"
          url: "https://feeds.feedburner.com/TheHackersNews"
          type: rss
          interval: 900s
        - name: "cisa-advisories"
          url: "https://www.cisa.gov/cybersecurity-advisories/all.xml"
          type: rss
          interval: 1800s

    tor:
      socksProxy: "127.0.0.1:9050"
      requestTimeout: 30s

  # --- Matching ---

  matching:
    rules:
      - name: "ransomware-keywords"
        type: keyword       # keyword | regex
        patterns: ["ransomware", "lockbit", "blackcat", "alphv"]
        severity: high      # critical | high | medium | low | info
      - name: "credential-patterns"
        type: regex
        patterns:
          - '(?i)(password|passwd|pwd)\s*[:=]\s*\S+'
          - '(?i)(api[_-]?key|apikey)\s*[:=]\s*\S{20,}'
        severity: critical
      - name: "cve-mentions"
        type: regex
        patterns: ['CVE-20\d{2}-\d{4,}']
        severity: medium

  # --- Collection Workers ---

  collection:
    archiveAll: true              # archive every item, not just matched ones
    classificationWorkers: 4
    entityExtractionWorkers: 1
    librarianWorkers: 1
    classificationBatchSize: 10
    maxContentLength: 8192        # bytes; truncated per-stage (4K/6K/8K)

  # --- Correlation Engine ---

  correlation:
    enabled: true
    intervalMinutes: 30
    minEvidenceThreshold: 2
    temporalWindowHours: 48

  # --- LLM Analyst ---

  analyst:
    enabled: true
    intervalMinutes: 60
    batchSize: 5
    minSignalCount: 2
    promoteThreshold: 0.7

  # --- IOC Lifecycle ---

  iocLifecycle:
    enabled: true
    intervalMinutes: 360
    deactivateThreshold: 0.05    # deactivate when score drops below 5%

  # --- Daily Brief ---

  briefGenerator:
    enabled: true
    scheduleHour: 6              # UTC hour to generate the daily brief

  # --- Vulnerability Intelligence ---

  vuln:
    enabled: true
    intervalHours: 6
    nvdApiKey: "${NOCTIS_NVD_API_KEY}"

  # --- IOC Enrichment ---

  enrichment:
    enabled: true
    intervalMinutes: 60
    batchSize: 20
    abuseipdbKey: "${NOCTIS_ABUSEIPDB_KEY}"
    virusTotalKey: "${NOCTIS_VT_KEY}"

  # --- Source Discovery ---

  discovery:
    enabled: true
    autoApprove: false            # require operator review
    triageEnabled: true
    triageBatchSize: 100
    allowPatterns:
      - "*.onion"
      - "pastebin.com"
      - "ghostbin.*"
    allowDomains:
      - breachforums.st
      - exploit.in
      - xss.is
    domainBlacklist:
      - nvd.nist.gov
      - github.com
      - wikipedia.org

  # --- Database ---

  database:
    driver: postgres
    dsn: "${NOCTIS_DB_DSN}"

  # --- Dashboard ---

  dashboard:
    enabled: true
    port: 3000
    apiKey: "${NOCTIS_DASHBOARD_API_KEY}"

  # --- Graph ---

  graph:
    enabled: true

  # --- Storage ---

  storage:
    artifactPath: "/data/artifacts"
    maxArtifactSizeMB: 50

  # --- Dispatch ---

  dispatch:
    wazuh:
      enabled: false
      endpoint: ""
    webhooks: []                 # [{name, url, minSeverity}]
    crds:
      enabled: false
    networkPolicy:
      enabled: false
```

---

## Telegram Integration

Noctis connects to Telegram using the MTProto protocol. Authenticate once before starting the daemon:

```sh
# QR code login (scan with Telegram mobile app)
./noctis telegram-auth --config config.yaml --qr

# SMS code login
./noctis telegram-auth --config config.yaml --sms
```

The session file is written to the path configured in `sources.telegram.sessionFile`. It survives pod restarts when stored on a PVC.

**Runtime channel management** — add channels without restarting:

```sh
./noctis source add --type telegram_channel --identifier "channelname"
```

The Telegram collector merges config channels with DB sources of type `telegram_channel` and polls the database every 5 minutes, subscribing to newly added channels automatically. Public channels are joined via `ChannelsJoinChannel` — no manual join from the phone app is needed. Private channels are supported via the `inviteHash` field, which accepts `t.me/+hash` and `t.me/joinchat/hash` formats. Telegram identifier URLs are normalized to bare usernames before storage.

QR authentication is also available via the `/auth/qr` endpoint on the health port.

---

## Dashboard

The dashboard is a React SPA compiled and embedded in the Go binary. No separate frontend deployment is required.

**Access:**

```sh
# Kubernetes
kubectl port-forward deployment/noctis -n noctis 3000:3000
# then open http://localhost:3000

# Standalone — accessible at http://localhost:3000
```

Authentication uses the `X-API-Key` header instead of Bearer tokens. The login page accepts the key set in `dashboard.apiKey`. Key comparison uses constant-time evaluation for timing attack protection. Two public endpoints expose safe aggregate data without authentication.

### Pages

| Page | Description |
|---|---|
| Landing | Public home page with aggregate stats and recent findings (no auth) |
| Login | API key entry form |
| Overview | Charts: findings over time, category breakdown, source activity, IOC type distribution |
| Intelligence Overview | Cross-source intelligence picture: active IOCs, correlations, entity counts, brief status |
| Findings | Filterable table of all archived findings with category, severity, source, and full detail panel |
| IOC Explorer | IOC browser with type/active/enriched filters, threat score, enrichment data, CSV export |
| Sources | Source registry: approve, reject, and add new sources; type filter pills (All, RSS, Telegram, Web, Other); displays source value scores |
| Entity Graph | Force-directed visualization of the knowledge graph with entity type and relationship filters |
| Analytical Notes | LLM Analyst decisions on correlation candidates with rationale |
| Correlations | Correlation candidates and confirmed correlations with evidence summaries |
| Briefs | Paginated list of daily intelligence briefs with full text |
| Vulnerabilities | NVD/EPSS/KEV vulnerability table with priority scoring and CVE detail view |
| Query | Natural language query interface — type a question, get SQL and tabular results |
| System Status | Live status of all 16 modules: running state, throughput, errors, AI provider/model |

### API Endpoints

All endpoints except public ones require the `X-API-Key` header.

**GET (authenticated):**
`/api/stats`, `/api/findings`, `/api/findings/{id}`, `/api/iocs`, `/api/sources`, `/api/categories`, `/api/subcategories`, `/api/timeline`, `/api/entities`, `/api/graph`, `/api/correlations`, `/api/correlation-decisions`, `/api/notes`, `/api/actors/{id}/profile`, `/api/sources/value`, `/api/system/status`, `/api/intelligence/overview`, `/api/briefs`, `/api/briefs/latest`, `/api/vulnerabilities`, `/api/vulnerabilities/{cve}`

**POST (authenticated):**
`/api/sources`, `/api/sources/{id}/approve`, `/api/sources/{id}/reject`, `/api/query`, `/api/auth/check`

**GET (public):**
`/api/public-stats`, `/api/public-recent`

---

## Module Registry

All 16 active modules register with `modules.Registry` and expose a structured `ModuleStatus` with ID, running state, throughput counters, error counts, last activity timestamp, and AI provider/model info. The System Status dashboard page polls `/api/system/status` to display this in real time.

### Module IDs

| Category | Module ID |
|---|---|
| Collector | `collector.telegram`, `collector.rss` |
| Processing | `processor.classifier`, `processor.summarizer`, `processor.ioc_extractor`, `processor.entity_extractor`, `processor.graph_bridge`, `processor.librarian`, `processor.ioc_lifecycle` |
| Brain | `brain.correlator`, `brain.analyst`, `brain.brief_generator`, `brain.query_engine` |
| Infrastructure | `infra.ioc_enrichment`, `infra.vuln_ingestor`, `infra.source_analyzer` |

---

## Database Schema

PostgreSQL is the single shared data store. Migrations run automatically at startup from the `migrations/` directory.

| Migration | Tables created |
|---|---|
| 001\_init | `findings`, `canary_tokens`, `actor_profiles` |
| 002\_graph | `entities`, `edges` |
| 003\_pivot | `raw_content`, `iocs`, `artifacts`, `sources` |
| 004\_cleanup\_discovered | source lifecycle cleanup |
| 005\_provenance | `provenance` column on `raw_content` |
| 006\_correlations | `ioc_sightings`, `correlations`, `correlation_candidates` |
| 007\_phase2 | sub-classification columns, `analytical_notes`, `correlation_decisions`, source value columns |
| 008\_phase3 | IOC lifecycle columns, `intelligence_briefs`, `vulnerabilities` |
| 009\_enrichment | IOC enrichment columns on `iocs` |
| 010\_triage | `source_triage_log`, `discovered_blacklist` |
| 011\_normalize\_telegram\_identifiers | Telegram identifier URL-to-username normalization |
| 012\_purge\_legacy\_embedly\_urls | Purge legacy Embedly URLs from discovered sources |

---

## Project Structure

```
cmd/noctis/              CLI entry point (serve, telegram-auth, source, search, stats)
internal/
  analyzer/              LLM wrapper: Classify, Summarize, ExtractIOCs, ExtractEntities,
                           SubClassify, EvaluateCorrelation, GenerateBrief, RawCompletion
  archive/               PostgreSQL persistence: 20 tables, IOC lifecycle, brief metrics,
                           vulnerability methods
  brain/                 Intelligence layer: Correlator, Analyst, BriefGenerator, QueryEngine
  collector/             Telegram, Paste, Forum, Web collectors + CollectorManager
                           + SourceValueAnalyzer
  config/                Full config struct with 20+ sections; ${ENV_VAR} substitution
  dashboard/             25+ API handlers, embedded React SPA, X-API-Key auth middleware
  database/              pgxpool connection + migration runner
  discovery/             Source discovery engine (URL extraction, blacklist, queue, AI triage)
  dispatcher/            Prometheus metrics
  enrichment/            AbuseIPDB, VirusTotal, crt.sh providers + Enricher
  health/                /healthz, /readyz, QR auth state
  ingest/                IngestPipeline: dedup, keyword/regex matching, archive, alert path
  llm/                   OpenAI-compatible HTTP client, SpendingTracker, budget circuit breaker
  matcher/               Keyword and regex rule engine
  models/                Finding, IOC, Severity, Category types
  modules/               ModuleStatus, StatusTracker, Registry
  processor/             ProcessingEngine: Classifier, Summarizer, IOCExtractor,
                           EntityExtractor, GraphBridge, Librarian, IOCLifecycleManager
  vuln/                  NVD, EPSS, CISA KEV ingestion + priority scoring
migrations/              001 through 012 (SQL files, applied in order)
prompts/                 10 LLM prompt templates (classify, classify_detail, extract_iocs,
                           extract_entities, severity, summarize, evaluate_correlation,
                           daily_brief, stylometry, triage)
deploy/                  Kubernetes manifests: namespace, secrets, postgres, configmap,
                           noctis deployment, ingress
web/                     React frontend source (14 pages, built output embedded in binary)
```

---

## Deployment

### Kubernetes

Tested on k3s. Requires a StorageClass named `nfs-shared` for the PostgreSQL PVC.

**Step 1 — Namespace**

```sh
kubectl apply -f deploy/namespace.yaml
```

**Step 2 — Secrets**

```sh
cp deploy/secrets.yaml.example deploy/secrets.yaml
# Fill in real values — never commit this file
kubectl apply -f deploy/secrets.yaml
```

Required secret keys: `NOCTIS_LLM_API_KEY`, `NOCTIS_GROQ_API_KEY`, `NOCTIS_GEMINI_API_KEY`, `NOCTIS_DASHBOARD_API_KEY`, `NOCTIS_DB_PASSWORD`, `NOCTIS_DB_DSN`. Telegram keys (`NOCTIS_TELEGRAM_API_ID`, `NOCTIS_TELEGRAM_API_HASH`, `NOCTIS_TELEGRAM_PHONE`, `NOCTIS_TELEGRAM_PASSWORD`) are required if Telegram is enabled.

**Step 3 — PostgreSQL**

```sh
kubectl apply -f deploy/postgres.yaml
kubectl -n noctis get pods -w   # wait for noctis-postgres-0 1/1 Running
```

**Step 4 — ConfigMap**

```sh
kubectl apply -f deploy/configmap.yaml
```

The ConfigMap uses `${NOCTIS_DB_DSN}` and `${NOCTIS_LLM_API_KEY}` tokens resolved from env vars at runtime. The ConfigMap itself contains no credentials.

**Step 5 — Noctis**

```sh
kubectl apply -f deploy/noctis.yaml
kubectl -n noctis get pods -w   # wait for noctis 1/1 Running
```

**Step 6 — Verify**

```sh
kubectl -n noctis logs -f deploy/noctis
kubectl -n noctis port-forward svc/noctis-metrics 8080:8080
curl http://localhost:8080/healthz   # ok
curl http://localhost:8080/readyz    # ready
```

**Dashboard access (Kubernetes)**

```sh
kubectl -n noctis port-forward deployment/noctis 3000:3000
# Open http://localhost:3000
```

For public access, apply the included Traefik IngressRoute manifest:

```sh
kubectl apply -f deploy/ingress.yaml
```

This routes HTTPS traffic via Let's Encrypt TLS termination. Requires Traefik with a `letsencrypt` cert resolver and a DNS A record pointing to the cluster.

**Enabling additional sources**

Edit `deploy/configmap.yaml`, set `telegram.enabled: true` (or `paste`/`forums`), add the corresponding API keys to the secret, then:

```sh
kubectl apply -f deploy/configmap.yaml
kubectl -n noctis rollout restart deploy/noctis
```

### Standalone

```sh
./noctis serve --config config.yaml
```

Migrations run automatically. No init containers or sidecars required.

### Build and push image

```sh
make build
docker build -t ghcr.io/zyrakk/noctis:latest .
docker push ghcr.io/zyrakk/noctis:latest
```

---

## CLI Reference

All subcommands accept `--config`/`-c` (default: `noctis-config.yaml`).

### `noctis serve`

Start the daemon. Loads config, runs migrations, starts all collectors and background modules, and blocks until SIGINT/SIGTERM.

```sh
noctis serve --config config.yaml
```

### `noctis telegram-auth`

One-time interactive Telegram authentication. Writes the session file used by `serve`.

```sh
noctis telegram-auth --config config.yaml --qr   # QR code
noctis telegram-auth --config config.yaml --sms  # SMS code
```

### `noctis source`

Manage the source registry.

```sh
noctis source list    [--status discovered|approved|active|paused|dead|banned|pending_triage]
                      [--type telegram_channel|telegram_group|forum|paste_site|web|rss]
noctis source add     --type <type> --identifier <identifier>
noctis source approve <id>
noctis source pause   <id>
noctis source remove  <id>
```

`source add` inserts with status `active`. The Telegram collector picks up new channels within 5 minutes without a restart.

### `noctis search`

Query the full-text archive.

```sh
noctis search [text]
              [--category credential_leak|malware_sample|vulnerability|...]
              [--tag <tag>]
              [--since 7d|24h]
              [--author <handle>]
              [--limit <n>]
```

### `noctis stats`

Print collection statistics by source and category.

### `noctis config validate`

Validate the config file and report errors.

```sh
noctis config validate --config config.yaml
```

---

## License

MIT. See [LICENSE](LICENSE).
