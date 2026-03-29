# Web Dashboard

## Overview

Noctis includes a built-in web dashboard for browsing findings, exploring IOCs, managing sources, visualizing entity relationships, and running natural language queries. The dashboard is a React single-page application embedded directly in the Go binary via `embed.FS` and served by a dedicated HTTP server on a configurable port.

No external web server, reverse proxy, or separate frontend deployment is required. The dashboard starts alongside the main Noctis daemon and reads directly from PostgreSQL via `pgxpool`.

**Architecture:**
- **Go API backend** — `internal/dashboard/` — HTTP server with parameterized SQL queries, `X-API-Key` auth middleware (constant-time comparison), and static file server for the embedded frontend. Routes registered in `server.go`, handlers in `handlers.go`, query logic in `queries.go`.
- **React frontend** — `web/` — Single-page application built with Vite into embedded static files. Client-side routing via `window.history.pushState` (no react-router dependency). React, recharts, lucide-react, and Tailwind CSS loaded from CDN at runtime.

---

## Enabling the Dashboard

```yaml
noctis:
  dashboard:
    enabled: true
    port: 3000
    apiKey: "${NOCTIS_DASHBOARD_API_KEY}"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Start the dashboard server. When `false`, no port is bound. |
| `port` | int | `3000` | HTTP listen port. |
| `apiKey` | string | — | Shared secret sent as `X-API-Key` header on all authenticated requests. |

---

## Pages

The SPA uses client-side routing. All protected pages require authentication (API key stored in `localStorage`). Unknown paths inside `/dashboard/*` fall back to Overview.

### `/` — Landing

Public landing page. Shows aggregate counts from `/api/public-stats` (total findings, IOCs, sources, entities) and up to 4 recent sanitized findings from `/api/public-recent`. No API key required. Includes a login button.

### `/login` — Login

API key entry form. Validates the key against `POST /api/auth/check`. On success, stores the key in `localStorage` and redirects to `/dashboard`.

### `/dashboard` — Overview

Main dashboard. Stat cards for total content, classified items, IOC count, active sources, discovered sources, and paused sources. Charts: category distribution (pie), severity distribution (bar), findings timeline (area chart, 7-day window, 1-hour buckets). Data from `GET /api/stats`, `GET /api/categories`, `GET /api/timeline`.

### `/dashboard/intelligence` — Intelligence

Full intelligence picture assembled from `GET /api/intelligence/overview`. Shows seven top-level metrics (total findings, active IOCs, confirmed correlations, analytical notes, tracked actors, tracked vulnerabilities, KEV-listed CVEs), a list of up to 10 active threat actors with linked malware and latest analytical note, up to 10 recent high-confidence correlations (>0.5), trending entities comparing 7-day vs prior 7-day mention counts, top 5 priority vulnerabilities, and the latest daily brief (expandable). Auto-refreshes every 60 seconds.

### `/dashboard/findings` — Findings

Paginated archive browser (30 per page). Filters: category (dropdown from `/api/categories`), sub-category (dropdown from `/api/subcategories`), severity (critical/high/medium/low/info), source type (text), full-text search (`q` parameter). Results ordered by `collected_at DESC`. Selecting a row fetches full detail from `GET /api/findings/{id}` and shows a slide-up panel with content, tags, URL, and linked IOCs. IOC values are copyable. Swipe-to-dismiss on mobile.

### `/dashboard/iocs` — IOCs

Paginated IOC browser (50 per page). Type filter tabs: All, IPs, Domains, MD5, SHA256, Emails, CVEs, URLs. Full-text search on IOC value. Toggle: active only (default) / include inactive. Toggle: enriched only. Results sorted by `threat_score DESC`. Each row shows type, value, sighting count, threat score, active status, and enrichment data if available. CSV export button downloads all visible results.

### `/dashboard/sources` — Sources

Source management interface. Tabs: Active, Discovered, Paused, Rejected. Each tab fetches `GET /api/sources?status=<tab>&limit=500` (default limit increased to 500 for client-side filtering). Type filter pills below the tabs: All, RSS, Telegram, Web, Other. Type categorization groups sources by family (e.g., `telegram_channel` and `telegram_group` both map to Telegram). Shows source type icon, identifier, name, status, last collected timestamp, error count, and content count. Discovered sources have Approve / Reject action buttons (`POST /api/sources/{id}/approve`, `POST /api/sources/{id}/reject`). Add Source form at the top (`POST /api/sources`) accepts type and identifier.

### `/dashboard/graph` — Graph

Interactive entity relationship graph. Entity search box queries `GET /api/entities?q=` with 300ms debounce. Selecting an entity fetches `GET /api/graph?entity_id=&hops=2` and renders a force-directed canvas graph with colored nodes by entity type (threat_actor=red, ip/domain=yellow, malware=purple, cve=cyan, url=orange, email=green). Node click shows entity properties panel. Hop depth configurable (1–5). Entity list sidebar shows connected nodes with edge counts.

### `/dashboard/correlations` — Correlations

Two-tab view. "Correlations" tab: paginated list (20/page) of confirmed correlations from `GET /api/correlations`. Shows cluster ID, type (shared_ioc, handle_reuse, temporal_ioc_overlap, campaign_cluster), confidence bar, entity IDs, and evidence JSONB. "Decisions" tab: analyst LLM decisions from `GET /api/correlation-decisions`, filterable by decision outcome (promote/reject/defer). Shows candidate ID, decision badge, confidence, reasoning, and linked promoted correlation if applicable.

### `/dashboard/notes` — Analytical Notes

Paginated list (20/page) of analytical notes from `GET /api/notes`. Filters: note type (correlation_judgment, attribution, pattern, prediction, warning, context), status (active/superseded/retracted, defaults to active), entity ID. Each note shows type badge, confidence bar, title, creator (analyst/correlator/human), model used, and full content (expandable). Color-coded by note type and creator.

### `/dashboard/vulns` — Vulnerabilities

Paginated CVE browser (50/page) from `GET /api/vulnerabilities`. Toggle filters: KEV listed, has exploit, has dark web mentions. Full-text search on CVE ID and description. Results sorted by `priority_score DESC`. Each row shows CVE ID, CVSS score + severity, EPSS score, KEV badge, exploit/dark web indicators, priority label, and publish date. Clicking a CVE fetches `GET /api/vulnerabilities/{cve}` for full detail (CVSS vector, CWE IDs, affected products, reference URLs, KEV dates, EPSS percentile, Noctis first/last seen).

### `/dashboard/briefs` — Intelligence Briefs

Two views: "Latest" (default) and "Archive". Latest view fetches `GET /api/briefs/latest?type=daily` and renders the most recent daily brief with executive summary, structured sections (Key Threats, Correlation Insights, Emerging Trends, Collection Gaps, Recommended Actions), and generation metadata (model, duration). Archive view fetches `GET /api/briefs?type=daily` with pagination (10/page), showing brief titles, period ranges, and metric summaries.

### `/dashboard/system` — System Status

Live status of all Noctis modules from `GET /api/system/status`. Modules grouped by category: Collectors, Processing Engine, Intelligence Brain, Infrastructure. Each module card shows: running/stopped/disabled status dot, last run time (relative), last error if any, AI provider/model badge if applicable, and extra metadata (intervals, counts, etc.). Auto-refreshes every 30 seconds via polling.

### `/dashboard/query` — Natural Language Query

Natural language query interface backed by `POST /api/query`. Accepts free-text questions in English; the query engine (`internal/brain/query_engine.go`) translates to SQL using an LLM and executes against the database. Response includes the original question, generated SQL (collapsible), column headers, result rows (rendered as a table), row count, and execution duration. Includes six example queries. Query history persisted in component state for the session.

---

## API Reference

All responses are JSON. Error responses: `{"error": "message"}` with appropriate HTTP status. All authenticated endpoints require `X-API-Key: <key>` header.

The `since` parameter on time-filtered endpoints accepts relative shorthand (`7d`, `24h`, `30m`) or RFC3339 timestamps.

---

### Public Endpoints (No Authentication)

#### `GET /api/public-stats`

Aggregate counts safe for unauthenticated display.

**Response:**
```json
{
  "totalFindings": 12340,
  "totalIocs": 4521,
  "activeSources": 47,
  "totalEntities": 892
}
```

#### `GET /api/public-recent`

Up to 4 recent classified, relevant findings with content truncated to 100 characters. No source identifiers, authors, or full content exposed.

**Response:**
```json
[
  {
    "category": "credential_leak",
    "severity": "high",
    "sourceType": "telegram",
    "summary": "Database dump allegedly from...",
    "collectedAt": "2026-03-25T14:22:00Z"
  }
]
```

#### `POST /api/auth/check`

Validates the API key by running it through the auth middleware. Requires `X-API-Key` header.

**Response (200):** `{"valid": true}`
**Response (401):** `{"error": "unauthorized"}`

---

### Authenticated Endpoints

All endpoints below require `X-API-Key: <key>`.

---

#### `GET /api/stats`

Full aggregate statistics including per-source and per-severity breakdowns.

**Response:**
```json
{
  "totalContent": 15200,
  "classified": 14100,
  "totalIocs": 4521,
  "activeSources": 47,
  "discoveredSources": 12,
  "pausedSources": 3,
  "bySource": {"telegram": 9800, "forum": 3200, "paste": 2200},
  "bySeverity": {"critical": 340, "high": 1200, "medium": 4500, "low": 7100, "info": 1600, "unclassified": 1100}
}
```

---

#### `GET /api/findings`

Paginated findings list from `raw_content`. All parameters optional.

| Parameter | Type | Description |
|-----------|------|-------------|
| `category` | string | Filter by top-level category (exact match) |
| `sub_category` | string | Filter by Librarian sub-category (exact match) |
| `severity` | string | Filter by severity (critical, high, medium, low, info) |
| `source` | string | Filter by `source_type` (telegram, paste, forum, web, rss) |
| `since` | string | Filter by `collected_at >=` (shorthand or RFC3339) |
| `q` | string | Full-text ILIKE search on `content` and `summary` |
| `limit` | int | Page size, default 50, max 500 |
| `offset` | int | Pagination offset, default 0 |

**Response:**
```json
{
  "findings": [
    {
      "id": "uuid",
      "sourceType": "telegram",
      "sourceName": "some_channel",
      "category": "credential_leak",
      "subCategory": "combo_list",
      "severity": "high",
      "summary": "Large combo list posted...",
      "author": "username",
      "collectedAt": "2026-03-25T14:22:00Z",
      "postedAt": "2026-03-25T14:20:00Z",
      "subMetadata": {"record_count": 50000, "target": "banking"}
    }
  ],
  "total": 1430
}
```

---

#### `GET /api/findings/{id}`

Full finding detail including raw content, tags, and linked IOCs. `id` is the UUID from `raw_content`.

**Response:** Full `FindingDetail` object including:
- All `FindingSummary` fields
- `content` — full raw text
- `url` — original URL if available
- `tags` — AI-generated tag array
- `metadata` — source-specific JSONB metadata
- `iocs` — array of `IOCItem` linked via `source_content_id`, sorted by `sighting_count DESC`

**404** if ID not found.

---

#### `GET /api/iocs`

Paginated IOC list sorted by `threat_score DESC NULLS LAST`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by IOC type (ip, domain, hash_md5, hash_sha256, email, cve, url, crypto_wallet) |
| `q` | string | ILIKE search on `value` |
| `active` | string | `false` to include inactive IOCs; defaults to active-only |
| `enriched` | string | `true` to show only enriched IOCs (`enriched_at IS NOT NULL`) |
| `limit` | int | Default 50, max 500 |
| `offset` | int | Default 0 |

**Response:**
```json
{
  "iocs": [
    {
      "id": "uuid",
      "type": "ip",
      "value": "192.0.2.1",
      "context": "C2 server mentioned in...",
      "firstSeen": "2026-01-10T09:00:00Z",
      "lastSeen": "2026-03-24T18:30:00Z",
      "sightingCount": 7,
      "threatScore": 0.82,
      "active": true,
      "enrichment": {"virustotal": {"malicious": 12, "total": 72}},
      "enrichedAt": "2026-03-24T20:00:00Z",
      "enrichmentSources": ["virustotal"]
    }
  ],
  "total": 4521
}
```

---

#### `GET /api/sources`

Paginated source list with content counts.

| Parameter | Type | Description |
|-----------|------|-------------|
| `status` | string | Filter by status; `active` matches both `active` and `approved` |
| `type` | string | Filter by source type |
| `limit` | int | Default 50, max 500 |
| `offset` | int | Default 0 |

**Response:** `{"sources": [...], "total": N}` — each source includes `id`, `type`, `identifier`, `name`, `status`, `lastCollected`, `errorCount`, `createdAt`, `contentCount` (LEFT JOIN count from `raw_content`).

---

#### `POST /api/sources`

Add a new source directly to `active` status. If the identifier already exists, updates status to `active`.

**Body:** `{"type": "telegram_channel", "identifier": "@channel_name"}`

Valid types: `telegram_channel`, `telegram_group`, `forum`, `paste_site`, `web`, `rss`.

**Response (201):** `{"id": "uuid", "status": "active"}`

---

#### `POST /api/sources/{id}/approve`

Approve a discovered source, setting `status = 'approved'`. The collector will begin monitoring it on next cycle.

**Response (200):** `{"status": "approved"}`
**Response (404):** Source not found.

---

#### `POST /api/sources/{id}/reject`

Reject a discovered source, setting `status = 'rejected'`.

**Response (200):** `{"status": "rejected"}`
**Response (404):** Source not found.

---

#### `GET /api/categories`

Category distribution for classified content.

**Response:**
```json
[
  {"category": "credential_leak", "count": 3200},
  {"category": "malware", "count": 1800}
]
```

Ordered by count DESC. Only returns categories where `classified = true AND category IS NOT NULL`.

---

#### `GET /api/subcategories`

Sub-category distribution grouped with parent category.

**Response:**
```json
[
  {"sub_category": "combo_list", "category": "credential_leak", "count": 1400},
  {"sub_category": "ransomware", "category": "malware", "count": 620}
]
```

Ordered by `category, count DESC`.

---

#### `GET /api/timeline`

Findings volume over time, bucketed by interval.

| Parameter | Type | Description |
|-----------|------|-------------|
| `since` | string | Start time, default 7 days ago |
| `interval` | string | Bucket size: `1 hour` (default), `6 hours`, `1 day`, `1 week` |

**Response:**
```json
[
  {"bucket": "2026-03-25T13:00:00Z", "count": 42},
  {"bucket": "2026-03-25T14:00:00Z", "count": 67}
]
```

Uses PostgreSQL `date_bin` for aligned buckets.

---

#### `GET /api/entities`

Paginated entity list with edge counts.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by entity type (threat_actor, malware, tool, ip, domain, url, campaign) |
| `q` | string | ILIKE search on entity ID and properties JSON text |
| `limit` | int | Default 20, max 100 |
| `offset` | int | Default 0 |

**Response:** `{"entities": [...], "total": N}` — each entity includes `id`, `type`, `properties`, `createdAt`, `edgeCount` (total edges in both directions).

---

#### `GET /api/graph`

Graph traversal from a starting entity node.

| Parameter | Type | Description |
|-----------|------|-------------|
| `entity_id` | string | Required. Starting entity ID (e.g., `entity:threat_actor:apt28`) |
| `hops` | int | Traversal depth, default 2, max 5 |

Uses a recursive CTE to find all reachable nodes, then fetches edges between them and their properties.

**Response:**
```json
{
  "nodes": [
    {"id": "entity:threat_actor:apt28", "type": "threat_actor", "properties": {"name": "APT28"}}
  ],
  "edges": [
    {"source": "entity:threat_actor:apt28", "target": "entity:malware:x-agent", "relationship": "uses"}
  ]
}
```

Returns empty nodes/edges arrays if the starting entity has no edges.

---

#### `GET /api/correlations`

Paginated confirmed correlation list ordered by `created_at DESC`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by `correlation_type` (shared_ioc, handle_reuse, temporal_ioc_overlap, campaign_cluster) |
| `min_confidence` | float | Minimum confidence threshold (0.0–1.0) |
| `since` | string | Filter by `created_at >=` |
| `limit` | int | Default 50, max 500 |
| `offset` | int | Default 0 |

**Response:** `{"correlations": [...], "total": N}` — each correlation includes `id`, `clusterId`, `entityIds`, `findingIds`, `correlationType`, `confidence`, `method`, `evidence`, `createdAt`, `updatedAt`.

---

#### `GET /api/correlation-decisions`

Paginated LLM correlation decision audit log ordered by `created_at DESC`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `decision` | string | Filter by outcome (promote, reject, defer) |
| `limit` | int | Default 20, max 200 |
| `offset` | int | Default 0 |

**Response:** `{"decisions": [...], "total": N}` — each decision includes `id`, `candidateId`, `clusterId`, `decision`, `confidence`, `reasoning`, `promotedCorrelationId`, `modelUsed`, `createdAt`.

---

#### `GET /api/notes`

Paginated analytical notes ordered by `created_at DESC`. Defaults to `status = 'active'` unless `status` parameter is set.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Filter by `note_type` (correlation_judgment, attribution, pattern, prediction, warning, context) |
| `entity_id` | string | Filter notes linked to a specific entity ID |
| `limit` | int | Default 20, max 200 |
| `offset` | int | Default 0 |

Note: the `status` parameter is available (active, superseded, retracted) but not exposed in the UI filter by default.

**Response:** `{"notes": [...], "total": N}` — each note includes `id`, `findingId`, `entityId`, `correlationId`, `noteType`, `title`, `content`, `confidence`, `createdBy`, `modelUsed`, `status`, `createdAt`.

---

#### `GET /api/actors/{id}/profile`

Comprehensive actor dossier assembled from multiple queries. `id` is the entity graph ID (e.g., `entity:threat_actor:apt28`).

**Response:**
```json
{
  "entityId": "entity:threat_actor:apt28",
  "name": "APT28",
  "type": "threat_actor",
  "aliases": ["Fancy Bear", "Sofacy"],
  "properties": {...},
  "malware": [...],
  "tools": [...],
  "infrastructure": [...],
  "targets": [...],
  "campaigns": [...],
  "recentFindings": [...],
  "findingCount": 47,
  "correlations": [...],
  "analyticalNotes": [...],
  "firstSeen": "2024-01-15T00:00:00Z",
  "lastSeen": "2026-03-24T00:00:00Z",
  "threatLevel": "critical"
}
```

Linked entities (malware, tools, infrastructure, campaigns, targets) are resolved from graph edges. Findings are inferred via `edges` → `source:<source_name>` → `raw_content`. Returns 404 if entity not found.

---

#### `GET /api/sources/value`

All active/approved/discovered sources ranked by `value_score DESC`. Value metrics are computed periodically by the source value tracker.

**Response:**
```json
{
  "sources": [
    {
      "id": "uuid",
      "type": "telegram_channel",
      "identifier": "@channel",
      "name": "Channel Name",
      "status": "active",
      "uniqueIocs": 340,
      "correlationContributions": 12,
      "avgSeverity": 0.72,
      "signalToNoise": 0.68,
      "valueScore": 0.81,
      "valueComputedAt": "2026-03-25T06:00:00Z",
      "contentCount": 1240
    }
  ]
}
```

---

#### `GET /api/system/status`

Real-time status of all registered modules grouped by category.

**Response:**
```json
{
  "available": true,
  "modules": {
    "collector": [...],
    "processor": [...],
    "brain": [...],
    "infra": [...]
  },
  "timestamp": "2026-03-25T14:30:00Z"
}
```

Returns `{"available": false}` if the module registry was not injected (e.g., in test builds).

---

#### `GET /api/intelligence/overview`

Full intelligence picture for the Intelligence dashboard page.

**Response:**
```json
{
  "activeActors": [...],
  "activeCampaigns": [...],
  "recentNotes": [...],
  "trendingEntities": [
    {"id": "entity:malware:lockbit", "type": "malware", "mentionCount": 47, "prevCount": 12}
  ],
  "topVulnerabilities": [...],
  "latestBrief": {
    "id": "uuid",
    "briefType": "daily",
    "title": "Daily Brief — 25 Mar 2026",
    "executiveSummary": "...",
    "generatedAt": "2026-03-25T06:05:00Z"
  },
  "metrics": {
    "totalFindings": 15200,
    "activeIocs": 3800,
    "confirmedCorrelations": 214,
    "analyticalNotes": 89,
    "trackedActors": 43,
    "trackedVulns": 127,
    "kevCount": 18
  }
}
```

---

#### `GET /api/briefs`

Paginated intelligence brief list ordered by `period_end DESC`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Brief type: `daily` (default), `weekly`, `monthly`, `incident`, `threat_actor` |
| `limit` | int | Default 20, max 100 |
| `offset` | int | Default 0 |

**Response:** `{"briefs": [...], "total": N}` — list items include `id`, `periodStart`, `periodEnd`, `briefType`, `title`, `executiveSummary`, `metrics`, `generatedAt`. Does not include full `content` or `sections` to keep list responses compact.

---

#### `GET /api/briefs/latest`

Most recent brief of the given type. Returns 404 if none exist.

| Parameter | Type | Description |
|-----------|------|-------------|
| `type` | string | Brief type, default `daily` |

**Response:** Full `BriefDetail` including all list fields plus `content` (full markdown text), `sections` (structured JSONB keyed by section name), `modelUsed`, `generationDurationMs`.

---

#### `GET /api/vulnerabilities`

Paginated vulnerability list sorted by `priority_score DESC NULLS LAST`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `q` | string | Full-text search on `cve_id` and `description` |
| `kev` | string | `true` to return only KEV-listed CVEs |
| `exploit` | string | `true` to return only CVEs with known exploits |
| `mentions` | string | `true` to return only CVEs with dark web mentions > 0 |
| `min_priority` | float | Minimum `priority_score` (0.0–1.0) |
| `min_epss` | float | Minimum `epss_score` |
| `limit` | int | Default 50, max 500 |
| `offset` | int | Default 0 |

**Response:** `{"vulnerabilities": [...], "total": N}` — list items include `id`, `cveId`, `description`, `cvssScore`, `cvssSeverity`, `epssScore`, `epssPercentile`, `kevListed`, `kevRansomwareUse`, `exploitAvailable`, `darkWebMentions`, `priorityScore`, `priorityLabel`, `publishedAt`, `updatedAt`.

---

#### `GET /api/vulnerabilities/{cve}`

Full vulnerability detail. `cve` path parameter is the CVE ID (e.g., `CVE-2024-12345`).

**Response:** All list fields plus `cvssV31Vector`, `cweIds`, `affectedProducts`, `referenceUrls`, `lastModifiedAt`, `epssUpdatedAt`, `kevDateAdded`, `kevDueDate`, `firstSeenNoctis`, `lastSeenNoctis`, `createdAt`.

**404** if CVE not tracked.

---

#### `POST /api/query`

Natural language query interface. The Brain's query engine translates the question to SQL using an LLM and executes it against the live database.

**Request body:** `{"question": "Show me critical findings from the last 7 days"}`

Body is limited to 64KB. Returns 503 if the query engine is not configured.

**Response:**
```json
{
  "query": "Show me critical findings from the last 7 days",
  "sql": "SELECT id, category, severity, summary, collected_at FROM raw_content WHERE ...",
  "columns": ["id", "category", "severity", "summary", "collected_at"],
  "rows": [["uuid-1", "credential_leak", "critical", "...", "2026-03-25T..."]],
  "row_count": 12,
  "duration": "142ms"
}
```

The generated SQL is read-only (SELECT only). The query engine includes schema context and table descriptions in its prompt to constrain output to valid Noctis tables.

---

## Authentication

All authenticated endpoints use a simple shared-secret scheme. The middleware checks the `X-API-Key` header against the configured `apiKey` value using constant-time comparison to prevent timing attacks. There is no session management, token expiry, or role system — the single key grants full read/write access to all API endpoints.

The dashboard server wires a SpendingTracker for both the brain LLM and the fast (Groq) LLM, providing budget visibility across all LLM-powered endpoints (query engine, briefs, correlation decisions, etc.).

For production deployments, place a reverse proxy in front of the dashboard and restrict network access to trusted clients.
