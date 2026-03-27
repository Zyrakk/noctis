# Noctis Configuration Reference

Every configuration file must be wrapped in a top-level `noctis:` key. The
loader unwraps that key before parsing the rest of the structure; any YAML
without it will fail to load.

```yaml
noctis:
  logLevel: info
  # ... all other fields nested here
```

---

## Environment Variable Substitution

Any scalar value in the YAML file may reference an environment variable using
the `${VAR_NAME}` syntax. Substitution is applied to the raw file bytes before
YAML parsing, so it works inside quoted strings, bare scalars, and multi-line
blocks. The pattern matches `${[A-Za-z_][A-Za-z0-9_]*}`.

```yaml
noctis:
  database:
    dsn: ${NOCTIS_DB_DSN}
  llm:
    apiKey: ${NOCTIS_LLM_API_KEY}
```

If the referenced variable is not set in the process environment the token is
replaced with an empty string. In Kubernetes, inject secrets via `envFrom`
referencing a Secret object; those environment variables are then available for
substitution in the ConfigMap that holds the YAML.

### Required environment variables

| Variable | Used by |
|----------|---------|
| `NOCTIS_DB_DSN` | `database.dsn` |
| `NOCTIS_LLM_API_KEY` | `llm.apiKey` (Z.ai GLM-5-Turbo — entity extraction, sub-classification) |
| `NOCTIS_GROQ_API_KEY` | `llmFast.apiKey` (Groq — classification, summarization, IOC extraction) |
| `NOCTIS_GEMINI_API_KEY` | `llmBrain.apiKey` (Gemini analytical reasoning) |
| `NOCTIS_DASHBOARD_API_KEY` | `dashboard.apiKey` |

### Optional environment variables

| Variable | Used by |
|----------|---------|
| `NOCTIS_NVD_API_KEY` | `vuln.nvdApiKey` — unauthenticated NVD access is rate-limited to 5 req/30 s |
| `NOCTIS_ABUSEIPDB_KEY` | `enrichment.abuseipdbKey` |
| `NOCTIS_VT_KEY` | `enrichment.virusTotalKey` |
| `NOCTIS_TG_API_ID` | `sources.telegram.apiId` |
| `NOCTIS_TG_API_HASH` | `sources.telegram.apiHash` |
| `NOCTIS_TG_PHONE` | `sources.telegram.phone` |
| `NOCTIS_PROMPTS_DIR` | Override the default `/prompts` directory at runtime |

---

## Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `logLevel` | string | `"info"` | Log verbosity. Accepted values: `debug`, `info`, `warn`, `error`. |
| `metricsPort` | int | `9090` | Port on which the Prometheus `/metrics` endpoint is served. |
| `healthPort` | int | `8080` | Port on which `/healthz`, `/readyz`, and internal auth endpoints are served. |

---

## `llm`

Primary LLM client — GLM-5-Turbo. Used for entity extraction and sub-classification (Librarian).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | — | Provider label, e.g. `glm`. Informational; shown in the dashboard status view. |
| `baseURL` | string | — | API base URL without trailing path, e.g. `https://api.z.ai/api/coding/paas/v4`. |
| `model` | string | — | Model identifier forwarded in each request body, e.g. `glm-5-turbo`. |
| `apiKey` | string | — | API key for Bearer authentication. Use `${NOCTIS_LLM_API_KEY}`. |
| `maxTokens` | int | — | Maximum tokens per completion request. |
| `temperature` | float64 | — | Sampling temperature (0.0–2.0). |
| `timeout` | duration | — | Per-request HTTP timeout, e.g. `60s`. |
| `retries` | int | — | Retry attempts on transient errors. |
| `maxConcurrent` | int | `2` | Maximum simultaneous in-flight LLM requests. Used as the extraction concurrency cap and as the fallback for `llmFast.maxConcurrency` when that field is unset. |
| `requestsPerMinute` | int | — | Rate limit cap for outbound requests. |
| `tokensPerMinute` | int | — | Token-bucket rate limiter: maximum tokens per minute. The rate limiter (`internal/llm/ratelimit.go`) tracks consumption and delays requests when the budget is exhausted. 429 responses trigger exponential backoff (2s/4s/8s) with Retry-After header parsing. |

---

## `llmFast`

Fast LLM client — Groq. Used for the Classifier, Summarizer, and IOC Extractor stages. When `llmFast.model` is empty the
system falls back to `llm` for classification (single-LLM mode).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | — | Provider label, e.g. `groq`. |
| `baseURL` | string | — | API base URL, e.g. `https://api.groq.com/openai/v1`. |
| `model` | string | — | Model identifier, e.g. `meta-llama/llama-4-scout-17b-16e-instruct`. |
| `apiKey` | string | — | API key. Use `${NOCTIS_GROQ_API_KEY}`. |
| `maxConcurrency` | int | — | Maximum concurrent in-flight classification requests. Falls back to `llm.maxConcurrent` when unset. |
| `tokensPerMinute` | int | — | Token-bucket rate limiter: maximum tokens per minute. |
| `tokensPerDay` | int | `0` | Daily token budget. `0` disables the daily limit. |

---

## `llmBrain`

Brain LLM client — Gemini. Used for correlation evaluation (`evaluate_correlation`),
analytical note generation (`Analyst`), brief generation (`daily_brief`), and
natural language SQL queries. When `llmBrain.baseURL` is empty the system
reuses the `llm` client for brain operations.

Uses the same fields as `llm`:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | — | Provider label, e.g. `gemini`. |
| `baseURL` | string | — | API base URL for the Gemini OpenAI-compatible endpoint. |
| `model` | string | — | Model identifier, e.g. `gemini-3.1-pro-preview`. |
| `apiKey` | string | — | API key. Use `${NOCTIS_GEMINI_API_KEY}`. |
| `maxTokens` | int | — | Maximum tokens per completion. |
| `temperature` | float64 | — | Sampling temperature. |
| `timeout` | duration | — | Per-request HTTP timeout. |
| `retries` | int | — | Retry attempts. |
| `maxConcurrent` | int | `1` | Concurrency cap for brain operations. Defaults to 1 when unset. |
| `requestsPerMinute` | int | — | Rate limit cap. |
| `monthlyBudgetUSD` | float64 | — | Monthly spending budget in USD. The spending tracker (`internal/llm/spending.go`) estimates cost from token counts using `inputCostPer1M` and `outputCostPer1M` rates. When the budget is reached, brain LLM calls are skipped until the next calendar month. |
| `inputCostPer1M` | float64 | — | Cost per 1M input tokens in USD, used for budget tracking. |
| `outputCostPer1M` | float64 | — | Cost per 1M output tokens in USD, used for budget tracking. |
| `tokensPerMinute` | int | — | Token-bucket rate limiter: maximum tokens per minute. |

---

## `collection`

Controls archive-everything behavior and processing pipeline worker counts.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `archiveAll` | bool | `false` | When `true`, store every ingested item regardless of rule matches. |
| `classificationWorkers` | int | `8` | Goroutines running the Classifier → Summarizer pipeline. |
| `entityExtractionWorkers` | int | `1` | Goroutines running the IOC Extractor → Entity Extractor → Graph Bridge pipeline. |
| `librarianWorkers` | int | `1` | Goroutines running the Librarian (sub-classification) pipeline. |
| `classificationBatchSize` | int | `10` | Maximum items fetched per poll by classification workers. |
| `maxContentLength` | int | `0` | Truncate ingested content to this byte length before storage and LLM calls. `0` means no limit. |

---

## `correlation`

Controls the rule-based correlation engine (Correlator sub-module). Runs on a
periodic interval, detecting shared IOCs, handle reuse, temporal overlaps, and
entity clusters. Results are stored as `correlation_candidates`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the correlation engine. |
| `intervalMinutes` | int | `15` | How often the correlation engine runs (in minutes). |
| `minEvidenceThreshold` | int | `3` | Minimum number of signals required to emit a candidate correlation. |
| `temporalWindowHours` | int | `48` | Look-back window (in hours) used for temporal overlap detection. |

---

## `analyst`

Controls the LLM-powered Analyst sub-module (brain). The Analyst polls pending
`correlation_candidates` and uses the brain LLM to promote, reject, or defer
each one. Decisions are logged to `correlation_decisions`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the Analyst. |
| `intervalMinutes` | int | `60` | How often the Analyst processes pending candidates (in minutes). |
| `batchSize` | int | `10` | Maximum candidates processed per cycle. |
| `minSignalCount` | int | `2` | Candidates below this signal count are skipped by the Analyst. |
| `promoteThreshold` | float64 | `0.7` | Minimum LLM confidence score required to promote a candidate to a confirmed correlation. |

---

## `iocLifecycle`

Controls periodic IOC decay and deactivation. The IOCLifecycleManager runs on
a periodic interval, reducing threat scores and deactivating stale IOCs.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the IOC lifecycle manager. |
| `intervalMinutes` | int | `60` | How often the lifecycle manager runs (in minutes). |
| `deactivateThreshold` | float64 | `0.1` | IOCs with a threat score at or below this value are marked inactive. |

---

## `briefGenerator`

Controls the daily intelligence brief generator (brain). Runs on a schedule
tied to a UTC hour, gathering 24-hour metrics and synthesizing them via the
brain LLM into a structured brief stored in `intelligence_briefs`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the brief generator. |
| `scheduleHour` | int | `6` | UTC hour (0–23) at which the daily brief is generated. Default is 06:00 UTC. |

---

## `vuln`

Controls the vulnerability intelligence pipeline. Fetches CVE data from NVD,
EPSS scores, and CISA KEV status on a periodic interval.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the vulnerability ingestor. |
| `intervalHours` | int | `6` | How often to refresh vulnerability data (in hours). |
| `nvdApiKey` | string | — | NVD API key for higher rate limits. Use `${NOCTIS_NVD_API_KEY}`. Optional but recommended. |

---

## `enrichment`

Controls the IOC enrichment pipeline. Enriches IOCs with reputation data from
external APIs (AbuseIPDB, VirusTotal, crt.sh) on a periodic interval.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the enrichment pipeline. |
| `intervalMinutes` | int | `30` | How often the enricher runs (in minutes). |
| `batchSize` | int | `20` | Maximum IOCs enriched per cycle. |
| `abuseipdbKey` | string | — | AbuseIPDB API key. Use `${NOCTIS_ABUSEIPDB_KEY}`. Enables IP reputation enrichment. |
| `virusTotalKey` | string | — | VirusTotal API key. Use `${NOCTIS_VT_KEY}`. Enables hash and URL reputation enrichment. |

crt.sh (certificate transparency) is always active when enrichment is enabled;
it requires no API key.

---

## `discovery`

Controls the automatic source discovery engine. Extracts URLs and channel
references from ingested content, filters them through a three-tier system
(blacklist → allowlist → AI triage), and proposes new monitoring sources.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the discovery engine. |
| `autoApprove` | bool | `false` | Automatically add discovered sources without manual review. When `false`, sources enter `discovered` status and require approval via `noctis source approve`. |
| `triageEnabled` | bool | `false` | Enable the AI batch triage worker. When enabled, URLs that don't match the allowlist or blacklist enter `pending_triage` status and are periodically evaluated by the fast LLM. |
| `triageBatchSize` | int | `100` | Number of pending URLs that must accumulate before the AI triage worker fires a batch. |
| `allowPatterns` | []string | — | Glob patterns for instant-approve. URLs matching these patterns bypass triage and go directly to `discovered` status. Example: `"*.onion"`, `"pastebin.com"`, `"ghostbin.*"`. Patterns are normalized to lowercase for case-insensitive matching. |
| `allowDomains` | []string | — | Exact domain names that bypass triage. Example: `breachforums.st`, `exploit.in`, `xss.is`. |
| `domainBlacklist` | []string | — | Domains that the discovery engine will never propose as sources. Checked first in the filtering pipeline. |

### Three-tier filtering

When `ProcessContent` encounters a URL extracted from ingested content:

1. **Config blacklist** (`domainBlacklist`) — if the domain matches, the URL is silently dropped.
2. **Auto-blacklist** (learned from triage) — if the domain has been trashed 3+ times by the AI triage worker, the URL is dropped. Cannot override `allowDomains` or `allowPatterns`.
3. **Structural skip** — private IPs, `localhost`, `FUZZ` tokens, and image/media URLs (`.png`, `.jpg`, `.jpeg`, `.gif`, `.svg`, `.webp`, `.ico`, `.bmp`) are dropped.
4. **Allowlist** (`allowPatterns` + `allowDomains`) — if the URL matches, it is inserted with status `discovered`.
5. **Default** — the URL is inserted with status `pending_triage` (if triage is enabled) or `discovered` (if triage is disabled).

### AI triage worker

When `triageEnabled` is `true`, a background worker runs every 5 minutes:

- Checks the count of `pending_triage` sources.
- When the count reaches `triageBatchSize`, fetches a batch ordered by `created_at ASC`.
- Sends the URL list to the fast LLM (`llmFast`) using the `triage.tmpl` prompt template.
- URLs classified as `"investigate"` are promoted to status `discovered`.
- URLs classified as `"trash"` are hard-deleted from the `sources` table.
- All decisions are logged to the `source_triage_log` table with a `batch_id` UUID.

### Auto-blacklist learning

After each triage batch, domains from trashed URLs are counted in the
`discovered_blacklist` table. When a domain accumulates 3 or more trash
decisions across batches, it is automatically added to a runtime blacklist.

- The auto-blacklist is loaded on engine startup via `LoadAutoBlacklist()`.
- Refreshed after each triage batch via `RefreshAutoBlacklist()`.
- Cannot override `allowDomains` or `allowPatterns`.
- Checked between the config blacklist and the structural skip in `ProcessContent`.

---

## `dashboard`

Configures the web dashboard server. When enabled, Noctis serves a React SPA
and JSON API on a dedicated port, separate from the health/metrics server.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the web dashboard. |
| `port` | int | `3000` | Port on which the dashboard server listens. |
| `apiKey` | string | — | Bearer token required for all `/api/*` endpoints. Use `${NOCTIS_DASHBOARD_API_KEY}`. |

When `enabled` is `false`, no dashboard server is started and no port is bound.

---

## `database`

Configures the PostgreSQL persistence layer.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dsn` | string | — | PostgreSQL connection string. Use `${NOCTIS_DB_DSN}`. Example: `postgres://noctis:secret@localhost:5432/noctis?sslmode=require`. |

---

## `sources`

Groups all ingest source configurations.

### `sources.telegram`

Configures the Telegram MTProto source (via `gotd/td`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable or disable this source. |
| `apiId` | int | — | Application ID from [my.telegram.org](https://my.telegram.org). Use `${NOCTIS_TG_API_ID}`. |
| `apiHash` | string | — | Application hash from [my.telegram.org](https://my.telegram.org). Use `${NOCTIS_TG_API_HASH}`. |
| `phone` | string | — | Account phone number in international format, e.g. `+14155552671`. Use `${NOCTIS_TG_PHONE}`. |
| `password` | string | — | Two-factor authentication password, if enabled on the account. |
| `channels` | []ChannelConfig | — | List of channels to monitor. See below. |
| `catchupMessages` | int | — | Number of most-recent messages to fetch per channel on startup. |
| `sessionFile` | string | — | File path used to persist the MTProto session across restarts. |

#### `sources.telegram.channels[]`

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | Public channel username, without the leading `@`. |
| `id` | int64 | Numeric channel ID. |

At least one of `username` or `id` must be provided.

---

### `sources.paste`

Configures paste-site scraping.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable or disable all paste sources. |
| `pastebin` | PastebinConfig | — | Pastebin-specific settings. See below. |
| `scrapers` | []ScraperConfig | — | Generic HTTP scrapers. See below. |

#### `sources.paste.pastebin`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable the Pastebin API scraper. |
| `apiKey` | string | — | Pastebin API key. |
| `interval` | duration | — | Polling interval, e.g. `5m`, `1h`. |

#### `sources.paste.scrapers[]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Human-readable label for logging and metrics. |
| `url` | string | — | Target URL to fetch. |
| `interval` | duration | — | How often to re-fetch this URL. |
| `tor` | bool | `false` | Route requests through the Tor SOCKS proxy (`sources.tor.socksProxy`). |

---

### `sources.forums`

Configures forum-based threat intelligence collection.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable or disable all forum sources. |
| `sites` | []ForumConfig | — | List of forum sites to crawl. See below. |

#### `sources.forums.sites[]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Human-readable label. |
| `url` | string | — | Base URL of the forum. |
| `tor` | bool | `false` | Route requests through Tor. |
| `auth` | ForumAuthConfig | — | Login credentials. See below. |
| `scraper` | ForumScraperConfig | — | CSS selectors for extracting content. See below. |
| `interval` | duration | — | Crawl frequency. |
| `maxPagesPerCrawl` | int | — | Maximum pages to visit in a single crawl run. |
| `requestDelay` | duration | — | Delay between individual HTTP requests. |

##### `sources.forums.sites[].auth`

| Field | Type | Description |
|-------|------|-------------|
| `loginURL` | string | URL of the login form submission endpoint. |
| `username` | string | Account username. |
| `password` | string | Account password. |
| `usernameField` | string | HTML form field name for the username. |
| `passwordField` | string | HTML form field name for the password. |

##### `sources.forums.sites[].scraper`

| Field | Type | Description |
|-------|------|-------------|
| `threadListSelector` | string | CSS selector matching thread links on a listing page. |
| `threadContentSelector` | string | CSS selector for the main post body within a thread page. |
| `authorSelector` | string | CSS selector for the post author field. |
| `paginationSelector` | string | CSS selector for the "next page" link. |

---

### `sources.web`

Configures web/RSS-based threat intelligence collection.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable or disable all web feeds. |
| `feeds` | []WebConfig | — | List of web feed sources. See below. |

#### `sources.web.feeds[]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Human-readable label. |
| `url` | string | — | Feed URL. |
| `type` | string | — | Feed type: `rss`, `scrape`, or `search`. |
| `contentSelector` | string | — | CSS selector used when `type` is `scrape`. |
| `queries` | []string | — | Search queries used when `type` is `search`. |
| `interval` | duration | — | How often to fetch this feed. |
| `tor` | bool | `false` | Route requests through Tor. |

---

### `sources.tor`

Configures the Tor SOCKS5 proxy used by any source with `tor: true`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `socksProxy` | string | — | SOCKS5 proxy address, e.g. `socks5://127.0.0.1:9050`. |
| `requestTimeout` | duration | — | Per-request timeout for Tor-routed connections. |

---

## `matching`

### `matching.rules[]`

Pattern-matching rules applied to all ingested content in real time. A finding
that matches at least one rule triggers the alert callback and is persisted.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Rule identifier used in alert metadata and Prometheus labels. |
| `type` | string | — | Match type: `keyword`, `regex`, or `ioc`. |
| `patterns` | []string | — | Keywords or regular expression patterns. |
| `severity` | string | — | Severity label attached to matches: `low`, `medium`, `high`, `critical`. |

---

## Full Example Configuration

```yaml
noctis:
  logLevel: info
  metricsPort: 9090
  healthPort: 8080

  llm:
    provider: glm
    baseURL: https://api.z.ai/api/coding/paas/v4
    model: glm-5-turbo
    apiKey: ${NOCTIS_LLM_API_KEY}
    maxTokens: 2048
    temperature: 0.1
    timeout: 60s
    retries: 2
    maxConcurrent: 4
    requestsPerMinute: 60

  llmFast:
    provider: groq
    baseURL: https://api.groq.com/openai/v1
    model: meta-llama/llama-4-scout-17b-16e-instruct
    apiKey: ${NOCTIS_GROQ_API_KEY}
    maxConcurrency: 8

  llmBrain:
    provider: gemini
    baseURL: https://generativelanguage.googleapis.com/v1beta/openai
    model: gemini-3.1-pro-preview
    apiKey: ${NOCTIS_GEMINI_API_KEY}
    maxTokens: 8192
    temperature: 0.3
    timeout: 120s
    retries: 2
    maxConcurrent: 1

  collection:
    archiveAll: true
    classificationWorkers: 8
    entityExtractionWorkers: 1
    librarianWorkers: 1
    classificationBatchSize: 10
    maxContentLength: 65536

  correlation:
    enabled: true
    intervalMinutes: 15
    minEvidenceThreshold: 3
    temporalWindowHours: 48

  analyst:
    enabled: true
    intervalMinutes: 60
    batchSize: 10
    minSignalCount: 2
    promoteThreshold: 0.7

  iocLifecycle:
    enabled: true
    intervalMinutes: 60
    deactivateThreshold: 0.1

  briefGenerator:
    enabled: true
    scheduleHour: 6

  vuln:
    enabled: true
    intervalHours: 6
    nvdApiKey: ${NOCTIS_NVD_API_KEY}

  enrichment:
    enabled: true
    intervalMinutes: 30
    batchSize: 20
    abuseipdbKey: ${NOCTIS_ABUSEIPDB_KEY}
    virusTotalKey: ${NOCTIS_VT_KEY}

  discovery:
    enabled: true
    autoApprove: false
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
      - google.com
      - youtube.com

  dashboard:
    enabled: true
    port: 3000
    apiKey: ${NOCTIS_DASHBOARD_API_KEY}

  database:
    dsn: ${NOCTIS_DB_DSN}

  sources:
    telegram:
      enabled: true
      apiId: ${NOCTIS_TG_API_ID}
      apiHash: ${NOCTIS_TG_API_HASH}
      phone: ${NOCTIS_TG_PHONE}
      catchupMessages: 100
      sessionFile: /data/noctis-session.json
      channels:
        - username: somedarkchannel
        - id: -1001234567890

    paste:
      enabled: true
      pastebin:
        enabled: true
        apiKey: ${NOCTIS_PASTEBIN_KEY}
        interval: 10m
      scrapers:
        - name: ghostbin
          url: https://ghostbin.com/pastes/recent
          interval: 15m
          tor: false

    forums:
      enabled: true
      sites:
        - name: example-forum
          url: https://forum.example.onion
          tor: true
          auth:
            loginURL: https://forum.example.onion/login
            username: ${NOCTIS_FORUM_USER}
            password: ${NOCTIS_FORUM_PASS}
            usernameField: user
            passwordField: pass
          scraper:
            threadListSelector: "ul.threads li a"
            threadContentSelector: "div.post-content"
            authorSelector: "span.author"
            paginationSelector: "a.next-page"
          interval: 30m
          maxPagesPerCrawl: 20
          requestDelay: 2s

    web:
      enabled: true
      feeds:
        - name: threat-intel-rss
          url: https://example.com/feed.xml
          type: rss
          interval: 1h
        - name: darkweb-scrape
          url: https://example.onion/posts
          type: scrape
          contentSelector: "div.entry"
          interval: 2h
          tor: true
        - name: search-leaks
          url: https://search.example.com/
          type: search
          queries:
            - "credential dump site:paste.example"
            - "leaked database"
          interval: 6h

    tor:
      socksProxy: socks5://127.0.0.1:9050
      requestTimeout: 30s

  matching:
    rules:
      - name: company-domain
        type: keyword
        patterns:
          - example.com
          - corp.example.com
        severity: high
      - name: ip-range
        type: regex
        patterns:
          - '203\.0\.113\.\d+'
        severity: medium
```

---

## Kubernetes Integration

Secrets (API keys, DSNs, passwords) must never be embedded in ConfigMaps.
Recommended pattern:

1. Create a `Secret` containing each sensitive value.
2. Reference the `Secret` in the Pod spec via `envFrom`.
3. Reference the environment variables in `noctis-config.yaml` using `${VAR_NAME}`.

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: noctis-secrets
  namespace: noctis
stringData:
  NOCTIS_DB_DSN: "postgres://noctis:hunter2@postgres.noctis.svc/noctis?sslmode=require"
  NOCTIS_LLM_API_KEY: "..."
  NOCTIS_GROQ_API_KEY: "..."
  NOCTIS_GEMINI_API_KEY: "..."
  NOCTIS_DASHBOARD_API_KEY: "..."
```

```yaml
# deployment.yaml (partial)
spec:
  containers:
    - name: noctis
      image: noctis:latest
      envFrom:
        - secretRef:
            name: noctis-secrets
      volumeMounts:
        - name: config
          mountPath: /etc/noctis
  volumes:
    - name: config
      configMap:
        name: noctis-config
```

The config file mounted from the ConfigMap uses `${NOCTIS_DB_DSN}` etc., which
are expanded at startup before YAML parsing begins.
