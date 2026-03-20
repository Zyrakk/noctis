# Noctis

**Kubernetes-native threat intelligence daemon**

[![Go 1.25+](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/Zyrakk/noctis/actions/workflows/ci.yml/badge.svg)](https://github.com/Zyrakk/noctis/actions)
[![Container](https://img.shields.io/badge/container-ghcr.io%2Fzyrakk%2Fnoctis-blue?logo=github)](https://ghcr.io/zyrakk/noctis)

Noctis is a long-running daemon that ingests threat intelligence from Telegram channels, paste sites, dark web forums, and RSS/web feeds — then classifies, enriches, and archives everything it finds. It is built for threat intelligence analysts, blue team operators, and security researchers who need continuous, autonomous collection across multiple source types without managing a sprawling pipeline of one-off scripts. Noctis runs as a single binary or a Kubernetes workload, persists findings in PostgreSQL, exposes Prometheus metrics, and grows its own source network through autonomous discovery.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                          Sources                                │
│  Telegram MTProto  │  Paste Sites  │  Forums  │  RSS / Web      │
└────────────────────┴───────────────┴──────────┴─────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       Ingest Pipeline                           │
│   Dedup → Matcher (keyword/regex) → Archive → Work Queue        │
└─────────────────────────────────────────────────────────────────┘
                              │
                ┌─────────────┴──────────────┐
                ▼                            ▼
┌───────────────────────┐      ┌─────────────────────────────┐
│      AI Analysis      │      │     Source Discovery         │
│  Classification       │      │  URL extraction → upsert     │
│  IOC Extraction       │      │  pending sources             │
│  (GLM / OpenAI /      │      └─────────────────────────────┘
│   Ollama-compat)      │
└───────────────────────┘
                │
    ┌───────────┴────────────┐
    ▼                        ▼
┌──────────────┐    ┌────────────────────┐
│    Archive   │    │    Entity Graph     │
│  PostgreSQL  │    │  IOCs, Actors,      │
│  full-text   │    │  Relationships      │
│  search      │    └────────────────────┘
└──────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Dispatch                                │
│    Alerts (log / webhook / Wazuh)  │  Prometheus metrics        │
└─────────────────────────────────────────────────────────────────┘
                │
                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Web Dashboard                              │
│   Landing page  │  Stats  │  Findings  │  IOCs  │  Sources      │
│   Entity graph  │  Bearer-token auth  │  Embedded in binary     │
└─────────────────────────────────────────────────────────────────┘
```

---

## Features

- **Multi-source collection** — Telegram MTProto (channels and groups), paste sites, dark web forums, and RSS/web feeds run as concurrent collectors feeding a shared ingest pipeline.
- **AI-powered classification and IOC extraction** — An OpenAI-compatible LLM client (tested with GLM, works with any OpenAI-compatible endpoint including Ollama) classifies each finding and extracts IOCs in parallel background workers.
- **Autonomous source discovery** — The discovery engine extracts URLs from ingested content, resolves them against a configurable blacklist, and queues new sources for operator review. The intelligence net grows itself.
- **Full content archive** — Every collected item is stored in PostgreSQL with full-text search. The `noctis search` command queries the archive with filters for category, tag, author, and time window.
- **Entity graph with relationship mapping** — IOCs, actors, and findings are linked in a graph structure for relationship traversal.
- **Real-time alerts on keyword/regex matches** — A rule engine evaluates each finding against configurable keyword and regex rules before it reaches the archive. Matched findings trigger alert callbacks.
- **Prometheus metrics** — `/metrics`, `/healthz`, and `/readyz` are served by the built-in health server (default port 8080).
- **Web dashboard** — A React SPA embedded in the Go binary, served on a dedicated port. Provides an overview with charts, a findings browser, IOC explorer, source management, and entity graph visualization. Secured with a Bearer-token API key.
- **Canary token system** — Planned (Phase 2C).
- **Humanlike forum scraping scheduler** — Planned (Phase 2C).
- **Interactive investigation CLI** — Planned (Phase 2C).

---

## Quick Start

### Prerequisites

- Go 1.25+
- PostgreSQL (14+ recommended)
- Kubernetes cluster or standalone host

### Build

```sh
go build -o noctis ./cmd/noctis/
```

### Docker

```sh
docker pull ghcr.io/zyrakk/noctis:latest
```

### Minimal config (RSS-only, no credentials required)

```yaml
noctis:
  logLevel: info
  healthPort: 8080

  database:
    driver: postgres
    dsn: "postgres://user:pass@localhost:5432/noctis?sslmode=disable"

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
```

### Run

```sh
noctis serve --config config.yaml
```

---

## Telegram Integration

Noctis connects to Telegram using the MTProto protocol via [gotd/td](https://github.com/gotd/td). Authenticate once with `noctis telegram-auth` or via the `/auth/qr` web page — the session is stored on a PVC and survives pod restarts.

- **Auto-join** — public channels configured by username are joined automatically via `ChannelsJoinChannel`. No need to manually join from the phone app.
- **Runtime channel management** — add channels without restarting: `noctis source add --type telegram_channel --identifier "channelname"`. The collector polls the database every 5 minutes and subscribes to new channels automatically.
- **QR login** (`--qr`) — displays a QR code in the terminal or via `/auth/qr` on the health port. Scan with the Telegram app.
- **Code login** (default) — sends an auth code to the configured phone; `--sms` forces SMS delivery.

See [docs/telegram.md](docs/telegram.md) for the full setup guide.

---

## Configuration Reference

The config file must have a top-level `noctis:` key. Environment variable substitution (`${VAR_NAME}`) is applied before parsing — unset variables expand to an empty string.

```yaml
noctis:
  logLevel: info          # debug | info | warn | error
  metricsPort: 9090       # Prometheus scrape port
  healthPort: 8080        # /healthz, /readyz, /metrics, /auth/qr

  sources:
    telegram:
      enabled: true
      apiId: ${NOCTIS_TELEGRAM_API_ID}
      apiHash: "${NOCTIS_TELEGRAM_API_HASH}"
      phone: "${NOCTIS_TELEGRAM_PHONE}"
      password: "${NOCTIS_TELEGRAM_PASSWORD}"  # 2FA password, optional
      sessionFile: "/data/telegram.session"
      catchupMessages: 100     # messages to replay on reconnect
      channels:
        - username: "ad_poheque"
        - username: "RalfHackerChannel"
        - username: "zer0day1ab"
      autoDiscovery: true      # extract Telegram channel refs from messages

    paste:
      enabled: false           # paste-site scraping (Pastebin, custom scrapers)

    forums:
      enabled: false           # dark web forum scraping with CSS selector config

    web:
      enabled: true
      feeds:
        - name: "bleeping-computer"
          url: "https://www.bleepingcomputer.com/feed/"
          type: rss            # rss | scrape | search
          interval: 900s
        - name: "the-hacker-news"
          url: "https://feeds.feedburner.com/TheHackersNews"
          type: rss
          interval: 900s
        - name: "krebs-on-security"
          url: "https://krebsonsecurity.com/feed/"
          type: rss
          interval: 900s
        - name: "cisa-advisories"
          url: "https://www.cisa.gov/cybersecurity-advisories/all.xml"
          type: rss
          interval: 1800s

    tor:
      socksProxy: "127.0.0.1:9050"
      requestTimeout: 30s

  matching:
    rules:
      - name: "ransomware-keywords"
        type: keyword           # keyword | regex
        patterns: ["ransomware", "lockbit", "blackcat", "alphv"]
        severity: high          # critical | high | medium | low | info
      - name: "credential-patterns"
        type: regex
        patterns:
          - '(?i)(password|passwd|pwd)\s*[:=]\s*\S+'
          - '(?i)(api[_-]?key|apikey)\s*[:=]\s*\S{20,}'
        severity: critical
      - name: "cve-mentions"
        type: regex
        patterns:
          - 'CVE-20\d{2}-\d{4,}'
        severity: medium

  llm:
    provider: glm               # label only; any OpenAI-compatible endpoint works
    baseURL: "https://open.bigmodel.cn/api/coding/paas/v4"
    model: "glm-5"
    apiKey: "${NOCTIS_LLM_API_KEY}"
    maxTokens: 1024
    temperature: 0.1
    timeout: 30s
    retries: 3
    maxConcurrent: 2
    requestsPerMinute: 20

  collection:
    archiveAll: true            # archive every finding, not just matched ones
    classificationWorkers: 2
    entityExtractionWorkers: 1
    classificationBatchSize: 10
    maxContentLength: 50000

  discovery:
    enabled: true
    autoApprove: false          # require operator approval before collecting
    domainBlacklist:
      - nvd.nist.gov
      - github.com
      - wikipedia.org

  database:
    driver: postgres
    dsn: "${NOCTIS_DB_DSN}"

  dashboard:
    enabled: true               # web dashboard served on a dedicated port
    port: 3000                  # default 3000
    apiKey: "${NOCTIS_DASHBOARD_API_KEY}"

  graph:
    enabled: true               # entity graph (IOCs, actors, relationships)

  dispatch:
    wazuh:
      enabled: false
      endpoint: ""
    webhooks: []                # [{name, url, minSeverity}]
    crds:
      enabled: false            # persist findings as Kubernetes CRDs
    networkPolicy:
      enabled: false            # auto-generate NetworkPolicy from IOCs
```

See [docs/configuration.md](docs/configuration.md) for the full reference including all forum, paste, and dispatch options.

---

## CLI Reference

All subcommands accept `--config`/`-c` (default: `noctis-config.yaml`).

### `noctis serve`

Start the daemon. Loads config, runs migrations, starts collectors and background workers, and blocks until SIGINT/SIGTERM.

```
noctis serve --config config.yaml
```

### `noctis telegram-auth`

One-time interactive authentication. Writes a session file for reuse by `noctis serve`. The `--qr` and `--sms` flags are mutually exclusive.

```
noctis telegram-auth --config config.yaml --qr
noctis telegram-auth --config config.yaml --sms
```

### `noctis source`

Manage the source registry maintained by the discovery engine.

```
noctis source list    [--status discovered|approved|active|paused|dead|banned]
                      [--type telegram_channel|telegram_group|forum|paste_site|web|rss]
noctis source add     --type <type> --identifier <identifier>
noctis source approve <id>
noctis source pause   <id>
noctis source remove  <id>
```

`source add` inserts a new source with status `active`. For Telegram channels, the collector picks it up within 5 minutes — no restart needed.

### `noctis search`

Query the full-text archive.

```
noctis search [text]
              [--category credential_leak|malware_sample|vulnerability|threat_actor_comms|...]
              [--tag <tag>]        # repeatable
              [--since 7d|24h]     # h (hours) or d (days)
              [--author <handle>]
              [--limit <n>]        # default 50
```

### `noctis stats`

Print archive collection statistics broken down by source and category.

```
noctis stats
```

### `noctis config validate`

Validate the configuration file and report errors.

```
noctis config validate --config config.yaml
```

---

## Deployment

### Kubernetes

The `deploy/` directory contains manifests for namespace, secrets, PostgreSQL, ConfigMap, and the Noctis deployment (including a PVC for session persistence). Apply in order:

```sh
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/secrets.yaml
kubectl apply -f deploy/postgres.yaml
kubectl apply -f deploy/configmap.yaml
kubectl apply -f deploy/noctis.yaml
```

See [docs/deployment.md](docs/deployment.md) for configuration of the ConfigMap, secret references, persistent volumes, and health probe setup.

### Standalone

```sh
# Start PostgreSQL separately, then:
./noctis serve --config config.yaml
```

The binary runs migrations automatically on startup. No init containers or sidecar processes are required for basic operation.

---

## Dashboard

Noctis includes a built-in web dashboard for browsing findings, exploring IOCs, managing sources, and visualizing entity relationships. The dashboard is a React SPA embedded in the Go binary — no separate frontend deployment required.

**Enable it** by adding the dashboard block to your config:

```yaml
noctis:
  dashboard:
    enabled: true
    apiKey: "${NOCTIS_DASHBOARD_API_KEY}"
```

**Access it** via port-forward (Kubernetes) or directly (standalone):

```sh
# Kubernetes
kubectl port-forward deployment/noctis -n noctis 3000:3000

# Standalone — already accessible at http://localhost:3000
```

The dashboard serves a public landing page at `/` and requires the API key to access data pages. Pages include an overview with charts, a findings browser with filters and detail panel, an IOC explorer with CSV export, a source manager with approve/add functionality, and an entity graph visualizer.

See [docs/dashboard.md](docs/dashboard.md) for the full setup guide and API reference.

---

## Production Stats

The following numbers come from a live deployment running against 13 sources (8 Telegram channels, 4 RSS feeds, 1 security blog).

**Archive**

| Metric | Count |
|--------|-------|
| Total archived entries | 674 (528 Telegram, 146 web/RSS) |
| Classified | 674 |
| IOCs extracted | 607 |
| Sources auto-discovered | 310 |

**Classification breakdown**

| Category | Count |
|----------|-------|
| irrelevant | 493 |
| malware_sample | 111 |
| threat_actor_comms | 55 |
| credential_leak | 9 |
| data_dump | 4 |
| access_broker | 1 |

**IOC breakdown**

| Type | Count |
|------|-------|
| CVE | 303 |
| URL | 176 |
| domain | 65 |
| SHA-1 | 27 |
| IP | 19 |
| email | 13 |
| SHA-256 | 2 |
| MD5 | 2 |

**Per-source collection**

| Source | Entries |
|--------|---------|
| RalfHackerChannel | 98 |
| ad_poheque | 90 |
| APT_Notes | 86 |
| securixy_kz | 84 |
| P0x3k_1N73LL1G3NC3 | 79 |
| the-hacker-news | 63 |
| zer0day1ab | 53 |
| cisa-advisories | 40 |
| ThreatHuntingFather | 36 |
| bleeping-computer | 33 |
| krebs-on-security | 10 |

**Example findings (sanitized)**

| Category | Severity | Source | Summary |
|----------|----------|--------|---------|
| malware_sample | high | zer0day1ab | PoC exploit for Nagios XI SQL injection publicly disclosed |
| threat_actor_comms | high | zer0day1ab | Technique to abuse Kaspersky tdsskiller.exe for defense evasion |
| malware_sample | high | zer0day1ab | Exploit PoC targeting TeamViewer privilege escalation (CVE-2024-7479) |
| credential_leak | medium | zer0day1ab | Credential leak for XAMN Pro mobile forensics tool |
| malware_sample | high | zer0day1ab | Exploit chain targeting Linux OpenPrinting CUPS vulnerabilities |

**Example IOCs**

| Type | Value | Context |
|------|-------|---------|
| url | github.com/safedv/RustPotato | RustPotato privilege escalation tool |
| url | adaptix-framework.gitbook.io/adaptix-framework | Adaptix C2 framework |
| url | github.com/Darkrain2009/RedExt | RedExt browser-based C2 framework |

---

## Roadmap

**Phase 2B**
- Modular downloader and file parser (PDFs, Office documents, archives)

**Phase 2C**
- Interactive investigation CLI
- Retroactive matching against archived content
- Canary token system for breach detection

**Future**
- Tor sidecar with humanlike request scheduling for forum scraping
- Attack path prediction derived from collected intelligence
- Counter-OSINT scanner
- Peer intelligence sharing between Noctis instances

---

## Contributing

1. Fork the repository and create a feature branch.
2. Run `go test ./...` before opening a pull request.
3. Keep commits focused; one logical change per commit.
4. Open an issue first for significant changes.

---

## License

MIT. See [LICENSE](LICENSE).
