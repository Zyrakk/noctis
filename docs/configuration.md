# Noctis Configuration Reference

Every configuration file must be wrapped in a top-level `noctis:` key. The
loader unwraps that key before parsing the rest of the structure, so any YAML
without it will fail to load.

```yaml
noctis:
  logLevel: info
  # ... all other fields nested here
```

## Environment Variable Substitution

Any value in the YAML file may reference an environment variable using the
`${VAR_NAME}` syntax. The pattern is replaced before YAML parsing, so it works
inside quoted strings, bare scalars, and multi-line blocks.

```yaml
noctis:
  database:
    dsn: ${NOCTIS_DB_DSN}
  llm:
    apiKey: ${NOCTIS_LLM_API_KEY}
```

If the referenced variable is not set the token is replaced with an empty
string. In Kubernetes, inject secrets via `envFrom` pointing at a Secret
object; those environment variables are then available for substitution in the
config map that holds the YAML.

---

## Top-level fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `logLevel` | string | `"info"` | Log verbosity. Accepted values: `debug`, `info`, `warn`, `error`. |
| `metricsPort` | int | `9090` | Port on which the Prometheus `/metrics` endpoint is served. |
| `healthPort` | int | `8080` | Port on which `/healthz`, `/readyz`, and internal auth endpoints are served. |

---

## `sources`

Groups all ingest source configurations.

### `sources.telegram`

Configures the Telegram MTProto source (via `gotd/td`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable or disable this source. |
| `apiId` | int | — | Application ID from [my.telegram.org](https://my.telegram.org). |
| `apiHash` | string | — | Application hash from [my.telegram.org](https://my.telegram.org). |
| `phone` | string | — | Account phone number in international format, e.g. `+14155552671`. |
| `password` | string | — | Two-factor authentication password, if enabled on the account. |
| `channels` | []ChannelConfig | — | List of channels to monitor. See below. |
| `catchupMessages` | int | — | Number of most-recent messages to fetch per channel on startup. |
| `sessionFile` | string | — | File path used to persist the MTProto session across restarts. |

#### `sources.telegram.channels[]`

Each entry in the `channels` list may specify a username, a numeric ID, or
both. At least one must be provided.

| Field | Type | Description |
|-------|------|-------------|
| `username` | string | Public channel username, without the leading `@`. |
| `id` | int64 | Numeric channel ID. |

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
| `tor` | bool | — | Route requests through the Tor SOCKS proxy (`sources.tor.socksProxy`). |

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
| `tor` | bool | — | Route requests through Tor. |
| `auth` | ForumAuthConfig | — | Login credentials. See below. |
| `scraper` | ForumScraperConfig | — | CSS selectors for extracting content. See below. |
| `interval` | duration | — | Crawl frequency. |
| `maxPagesPerCrawl` | int | — | Maximum pages to visit in a single crawl run. |
| `requestDelay` | duration | — | Delay between individual HTTP requests to reduce fingerprinting. |

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
| `threadListSelector` | string | CSS selector that matches thread links on a listing page. |
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
| `tor` | bool | — | Route requests through Tor. |

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

Pattern-matching rules applied to all ingested content.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Rule identifier used in alert metadata. |
| `type` | string | — | Match type: `keyword` or `regex`. |
| `patterns` | []string | — | List of keywords or regular expression patterns. |
| `severity` | string | — | Severity label attached to matches, e.g. `low`, `medium`, `high`, `critical`. |

---

## `llm`

Configures the language model client used for classification and entity extraction.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `provider` | string | — | LLM provider identifier, e.g. `openai`, `ollama`. |
| `baseURL` | string | — | API base URL. Required for self-hosted or OpenAI-compatible endpoints. |
| `model` | string | — | Model name, e.g. `gpt-4o`, `llama3`. |
| `apiKey` | string | — | API key. Use `${VAR}` to inject from an environment variable. |
| `maxTokens` | int | — | Maximum tokens per completion request. |
| `temperature` | float64 | — | Sampling temperature (0.0–2.0). |
| `timeout` | duration | — | Per-request timeout. |
| `retries` | int | — | Number of retry attempts on transient errors. |
| `maxConcurrent` | int | — | Maximum number of simultaneous in-flight LLM requests. |
| `requestsPerMinute` | int | — | Rate limit cap for outbound LLM requests. |

---

## `collection`

Controls archive-everything behavior and background worker concurrency.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `archiveAll` | bool | — | When `true`, store every ingested item regardless of rule matches. |
| `classificationWorkers` | int | `2` | Number of goroutines running LLM classification. |
| `entityExtractionWorkers` | int | `1` | Number of goroutines running LLM entity extraction. |
| `classificationBatchSize` | int | `10` | Maximum items bundled into a single classification request. |
| `maxContentLength` | int | — | Truncate ingested content to this byte length before storage and LLM calls. `0` means no limit. |

---

## `discovery`

Controls the automatic source discovery engine.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable the discovery engine. |
| `autoApprove` | bool | — | Automatically add discovered sources without manual review. |
| `domainBlacklist` | []string | — | Domains that the discovery engine will never propose as sources. |

---

## `dashboard`

Configures the web dashboard server. When enabled, Noctis serves a React SPA and JSON API on a dedicated port, separate from the health/metrics server.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Enable the web dashboard. |
| `port` | int | `3000` | Port on which the dashboard server listens. |
| `apiKey` | string | — | Bearer token required for all `/api/*` endpoints. Use `${VAR}` to inject from an environment variable. |

When `enabled` is `false`, no dashboard server is started and no port is bound. The dashboard serves a public landing page at `/` and requires the API key for all data endpoints.

---

## `database`

Configures the persistence layer.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `driver` | string | — | Database driver name, e.g. `sqlite3`, `postgres`. |
| `dsn` | string | — | Data source name / connection string. Use `${VAR}` to inject credentials. |

---

## `graph`

Configures the relationship graph store.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable graph persistence for entity relationships. |

---

## `dispatch`

Configures all alert dispatch backends.

### `dispatch.wazuh`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable the Wazuh dispatch backend. |
| `endpoint` | string | — | Wazuh manager endpoint URL or address. |
| `format` | string | — | Alert format sent to Wazuh, e.g. `json`. |

### `dispatch.webhooks[]`

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | — | Human-readable label for this webhook. |
| `url` | string | — | Outbound POST target URL. |
| `minSeverity` | string | — | Minimum severity that triggers this webhook. Alerts below this level are dropped. |

### `dispatch.crds`

Configures Kubernetes CRD persistence for alerts.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable CRD dispatch. |
| `namespace` | string | — | Kubernetes namespace where alert CRD objects are written. |
| `gcStaleAfterDays` | int | — | Delete alert CRDs older than this many days. |

### `dispatch.networkPolicy`

Configures automatic Kubernetes NetworkPolicy generation from threat intelligence.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable NetworkPolicy generation. |
| `dryRun` | bool | — | Log policies that would be created without applying them to the cluster. |
| `namespace` | string | — | Namespace in which generated NetworkPolicies are applied. |
| `whitelistCIDRs` | []string | — | CIDRs that are never blocked, regardless of threat intelligence. |
| `maxPolicies` | int | — | Maximum number of active NetworkPolicies managed by Noctis. |
| `ttlHours` | int | — | Hours after which a generated policy is automatically deleted. |

---

## `storage`

Controls artifact storage (raw downloaded files, screenshots, etc.).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `artifactPath` | string | — | Directory path for artifact storage. Mount an NFS PVC here in Kubernetes. |
| `maxArtifactSizeMB` | int | — | Artifacts larger than this size (in MiB) are discarded. `0` means no limit. |

---

## `profiling`

Configures actor profiling behaviour.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable actor profiling. |
| `activityThreshold` | int | — | Minimum number of observed events before a profile is created for an actor. |
| `similarityThreshold` | float64 | — | Cosine similarity threshold (0.0–1.0) for linking activity to an existing profile. |
| `storage` | string | — | Backend used to persist profiles, e.g. a file path or connection string. |

---

## `canary`

Configures canary token monitoring.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | — | Enable canary token tracking. |
| `storage` | string | — | Backend used to persist canary token state. |

---

## Full Example Configuration

```yaml
noctis:
  logLevel: info
  metricsPort: 9090
  healthPort: 8080

  sources:
    telegram:
      enabled: true
      apiId: ${NOCTIS_TG_API_ID}
      apiHash: ${NOCTIS_TG_API_HASH}
      phone: ${NOCTIS_TG_PHONE}
      password: ${NOCTIS_TG_PASSWORD}
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
          tor: false
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
          tor: false

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

  dashboard:
    enabled: true
    port: 3000
    apiKey: ${NOCTIS_DASHBOARD_API_KEY}

  llm:
    provider: openai
    baseURL: https://api.openai.com/v1
    model: gpt-4o-mini
    apiKey: ${NOCTIS_LLM_API_KEY}
    maxTokens: 1024
    temperature: 0.2
    timeout: 60s
    retries: 3
    maxConcurrent: 4
    requestsPerMinute: 60

  collection:
    archiveAll: false
    classificationWorkers: 2
    entityExtractionWorkers: 1
    classificationBatchSize: 10
    maxContentLength: 65536

  discovery:
    enabled: true
    autoApprove: false
    domainBlacklist:
      - google.com
      - youtube.com

  database:
    driver: postgres
    dsn: ${NOCTIS_DB_DSN}

  graph:
    enabled: true

  dispatch:
    wazuh:
      enabled: false
      endpoint: https://wazuh.internal:55000
      format: json
    webhooks:
      - name: slack-soc
        url: ${NOCTIS_SLACK_WEBHOOK}
        minSeverity: high
    crds:
      enabled: true
      namespace: noctis
      gcStaleAfterDays: 30
    networkPolicy:
      enabled: true
      dryRun: false
      namespace: noctis
      whitelistCIDRs:
        - 10.0.0.0/8
        - 172.16.0.0/12
      maxPolicies: 100
      ttlHours: 72

  storage:
    artifactPath: /artifacts
    maxArtifactSizeMB: 50

  profiling:
    enabled: true
    activityThreshold: 5
    similarityThreshold: 0.75
    storage: /data/profiles

  canary:
    enabled: true
    storage: /data/canaries
```

---

## Kubernetes Integration

Noctis is designed to run as a Kubernetes workload. Secrets (API keys, DSNs,
passwords) should never be embedded in ConfigMaps. The recommended pattern is:

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
  NOCTIS_LLM_API_KEY: "sk-..."
  NOCTIS_TG_API_ID: "12345678"
  NOCTIS_TG_API_HASH: "abcdef1234567890abcdef1234567890"
  NOCTIS_TG_PHONE: "+14155552671"
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

The config file mounted from the ConfigMap then uses `${NOCTIS_DB_DSN}` etc.,
which are expanded at startup before YAML parsing begins.
