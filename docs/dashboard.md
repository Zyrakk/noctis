# Web Dashboard

Noctis includes a built-in web dashboard for browsing findings, exploring IOCs, managing sources, and visualizing entity relationships. The dashboard is a React single-page application embedded directly in the Go binary via `embed.FS` and served by a dedicated HTTP server on a configurable port.

No external web server, reverse proxy, or separate frontend deployment is required. When enabled, the dashboard starts alongside the main Noctis daemon and reads directly from PostgreSQL.

---

## Overview

**Architecture:** The dashboard consists of two parts:

1. **Go API backend** (`internal/dashboard/`) — An HTTP server with 11 JSON API endpoints, a Bearer-token auth middleware, and a static file server for the embedded frontend. All endpoints query PostgreSQL directly via `pgxpool` with parameterized SQL.

2. **React frontend** (`web/`) — A single-page application built with Vite into two static files (`index.html` + `app.js`) and embedded in the Go binary at compile time. React, recharts, lucide-react, and Tailwind CSS are loaded from CDN at runtime.

**What it provides:**

- Real-time overview with stats cards, category/severity charts, and a findings timeline
- Full-text search and filtered browsing of all archived findings
- IOC explorer with type filtering, value search, and CSV export
- Source management: view active/discovered/paused sources, approve and add sources from the UI
- Entity graph visualization with interactive node-link diagram

---

## Enabling the Dashboard

Add the `dashboard` block to your Noctis configuration:

```yaml
noctis:
  dashboard:
    enabled: true
    port: 3000                              # optional, default 3000
    apiKey: "${NOCTIS_DASHBOARD_API_KEY}"    # required when enabled
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Start the dashboard server. When `false`, no port is bound. |
| `port` | int | `3000` | Port on which the dashboard server listens. |
| `apiKey` | string | — | Shared secret for authenticating API requests. Use `${VAR}` to inject from an environment variable. |

### Kubernetes

1. Add `NOCTIS_DASHBOARD_API_KEY` to your `deploy/secrets.yaml`:

   ```yaml
   stringData:
     NOCTIS_DASHBOARD_API_KEY: "your-dashboard-key-here"
   ```

2. Enable the dashboard in `deploy/configmap.yaml`:

   ```yaml
   noctis:
     dashboard:
       enabled: true
       apiKey: "${NOCTIS_DASHBOARD_API_KEY}"
   ```

3. Apply and restart:

   ```bash
   kubectl apply -f deploy/secrets.yaml -f deploy/configmap.yaml
   kubectl rollout restart deployment/noctis -n noctis
   ```

4. Port-forward to access:

   ```bash
   kubectl port-forward deployment/noctis -n noctis 3000:3000
   ```

5. Open `http://localhost:3000` in a browser.

### Standalone

1. Set the environment variable:

   ```bash
   export NOCTIS_DASHBOARD_API_KEY="your-dashboard-key-here"
   ```

2. Add `dashboard.enabled: true` to your config file.

3. Run `noctis serve --config config.yaml`.

4. Open `http://localhost:3000` in a browser.

---

## Authentication

The dashboard uses a single shared API key for authentication. There is no user management, no sessions, and no cookies.

**Login flow:**

1. Open the dashboard URL. The landing page is public and requires no authentication.
2. Click "Access Dashboard" to reach the login page.
3. Enter the API key configured in `dashboard.apiKey`.
4. The frontend validates the key by calling `POST /api/auth/check` with a `Bearer` token.
5. On success, the key is stored in browser session memory (`sessionStorage`). It is cleared when the browser tab is closed.
6. All subsequent API requests include the key as `Authorization: Bearer <key>`.

**Security details:**

- The API key is compared using `crypto/subtle.ConstantTimeCompare` to prevent timing attacks.
- The key is stored in `sessionStorage`, not `localStorage`. It does not survive browser restarts.
- All `/api/*` endpoints return `401 Unauthorized` with `{"error": "missing or invalid Authorization header"}` if the key is missing or wrong.
- The landing page (`/`) and static assets are served without authentication.

---

## Pages

### Landing Page

**Route:** `/`
**Auth:** None

A public marketing-style page presenting Noctis capabilities. Features a hero section with animated gradient background, feature cards (Multi-source Collection, AI Classification, IOC Extraction, Entity Graph, Real-time Alerts), animated counters, and a call-to-action button leading to login.

### Login

**Route:** `/login`
**Auth:** None

A centered card with a single password-type input for the API key. Displays inline error messages on authentication failure. On success, redirects to `/dashboard`.

### Overview Dashboard

**Route:** `/dashboard`
**Auth:** Required

The main dashboard view. Displays:

- **Stats cards** — Total content, classified count, IOC count, active sources, discovered sources. Data from `GET /api/stats`.
- **Category distribution** — Donut chart showing findings per category. Data from `GET /api/categories`.
- **Severity distribution** — Bar chart showing findings per severity level. Data from `GET /api/stats` (`bySeverity` field).
- **Timeline** — Area chart showing findings collected per hour over the last 7 days. Data from `GET /api/timeline?since=7d&interval=1 hour`.
- **Recent critical findings** — List of the 10 most recent critical-severity findings with severity badges. Data from `GET /api/findings?severity=critical&limit=10`.

### Findings Browser

**Route:** `/dashboard/findings`
**Auth:** Required

A full-width data table with left-sidebar filters:

- **Filters:** Category dropdown, severity dropdown, source type dropdown, full-text search input. All filters are combined as AND conditions.
- **Table columns:** Time (collected_at), Source (source_type), Category, Severity, Summary.
- **Detail panel:** Click any row to open a slide-in panel showing the full content, linked IOCs as pills, AI summary, tags, metadata, and original URL. Data from `GET /api/findings/{id}`.
- **Pagination:** Bottom navigation with page number and prev/next buttons. Page size is 30 rows.
- **Severity badges:** Color-coded — critical (red with glow), high (orange), medium (yellow), low (blue), info (gray).

### IOC Explorer

**Route:** `/dashboard/iocs`
**Auth:** Required

- **Type filter tabs:** All, IPs, Domains, MD5, SHA256, Emails, CVEs, URLs. Maps to the `type` query parameter.
- **Search:** Text input filtering by IOC value substring.
- **Table columns:** Type (with colored badge), Value (monospace), Context, First Seen, Sightings.
- **Copy to clipboard:** Click the copy icon next to any IOC value. Shows a checkmark confirmation for 2 seconds.
- **CSV export:** "Export CSV" button in the header downloads all currently displayed IOCs as a CSV file named `noctis-iocs-YYYY-MM-DD.csv`.
- **Pagination:** Page size is 50 rows.

### Source Manager

**Route:** `/dashboard/sources`
**Auth:** Required

Three tabs with status indicator dots:

- **Active** (green dot) — Card grid showing each active source with type icon, name, content count, last collected timestamp, and error count.
- **Discovered** (yellow dot) — Table with "Approve" button per row. Calls `POST /api/sources/{id}/approve`.
- **Paused** (gray dot) — Table showing paused sources with status.

**Add Source:** "Add Source" button opens a modal with a type dropdown (`telegram_channel`, `telegram_group`, `forum`, `paste_site`, `web`, `rss`) and an identifier text input. Calls `POST /api/sources`.

### Entity Graph

**Route:** `/dashboard/graph`
**Auth:** Required

Interactive entity relationship visualization:

- **Search:** Enter an entity ID and select hop count (1-5, default 2).
- **Visualization:** Canvas-based force-directed graph. Nodes are colored by type: actor (red), ioc (yellow), channel (blue), finding (purple).
- **Interaction:** Node labels show entity name or ID. Edge labels show relationship type.
- **Empty state:** Displays a placeholder message when no entity ID is entered or no connections are found.

Data from `GET /api/graph?entity_id=X&hops=N`.

---

## API Reference

All API endpoints require the `Authorization: Bearer <key>` header unless noted otherwise. All responses are `Content-Type: application/json`.

### `POST /api/auth/check`

Validates the API key without returning data.

**Response (200):**
```json
{"valid": true}
```

**Response (401):**
```json
{"error": "invalid API key"}
```

---

### `GET /api/stats`

Returns aggregate counts for the overview dashboard.

**Parameters:** None.

**Response (200):**
```json
{
  "totalContent": 674,
  "classified": 674,
  "totalIocs": 607,
  "activeSources": 3,
  "discoveredSources": 310,
  "pausedSources": 0,
  "bySource": {
    "telegram": 528,
    "web": 146
  },
  "bySeverity": {
    "info": 120,
    "low": 45,
    "medium": 200,
    "high": 180,
    "critical": 15,
    "unclassified": 114
  }
}
```

---

### `GET /api/findings`

Returns a paginated list of findings with optional filters.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `category` | string | — | Filter by classification category (e.g., `malware_sample`, `credential_leak`) |
| `severity` | string | — | Filter by severity level (`critical`, `high`, `medium`, `low`, `info`) |
| `source` | string | — | Filter by source type (`telegram`, `paste`, `forum`, `web`) |
| `since` | string | — | Only return findings collected after this time. Accepts duration shorthand (`7d`, `24h`, `30m`) or RFC 3339 timestamp. |
| `q` | string | — | Full-text search across content and summary (case-insensitive substring match) |
| `limit` | int | `50` | Maximum results per page (capped at 500) |
| `offset` | int | `0` | Number of results to skip for pagination |

**Response (200):**
```json
{
  "findings": [
    {
      "id": "a1b2c3d4-...",
      "sourceType": "telegram",
      "sourceName": "RalfHackerChannel",
      "category": "malware_sample",
      "severity": "high",
      "summary": "New PoC exploit for CVE-2024-7479 targeting TeamViewer...",
      "author": "ralfhacker",
      "collectedAt": "2025-10-15T14:32:00Z",
      "postedAt": "2025-10-15T14:30:00Z"
    }
  ],
  "total": 674
}
```

Fields `category`, `severity`, `summary`, `author`, and `postedAt` may be `null` for unclassified or anonymous content.

---

### `GET /api/findings/{id}`

Returns full details for a single finding, including raw content and linked IOCs.

**Path Parameter:** `id` — UUID of the finding.

**Response (200):**
```json
{
  "id": "a1b2c3d4-...",
  "sourceType": "telegram",
  "sourceName": "zer0day1ab",
  "category": "malware_sample",
  "severity": "high",
  "summary": "Exploit PoC targeting TeamViewer privilege escalation...",
  "author": null,
  "collectedAt": "2025-10-15T14:32:00Z",
  "postedAt": null,
  "content": "Full raw text of the finding...",
  "url": null,
  "tags": ["exploit", "teamviewer", "privilege-escalation"],
  "iocs": [
    {
      "id": "e5f6a7b8-...",
      "type": "cve",
      "value": "CVE-2024-7479",
      "context": "TeamViewer privilege escalation vulnerability",
      "firstSeen": "2025-10-15T14:32:00Z",
      "lastSeen": "2025-10-15T14:32:00Z",
      "sightingCount": 1
    }
  ],
  "metadata": {}
}
```

**Response (404):** `{"error": "finding not found"}`

---

### `GET /api/iocs`

Returns a paginated list of indicators of compromise.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | string | — | Filter by IOC type (`ip`, `domain`, `hash_md5`, `hash_sha1`, `hash_sha256`, `email`, `crypto_wallet`, `url`, `cve`) |
| `q` | string | — | Search by value substring (case-insensitive) |
| `limit` | int | `50` | Maximum results per page (capped at 500) |
| `offset` | int | `0` | Pagination offset |

**Response (200):**
```json
{
  "iocs": [
    {
      "id": "f1e2d3c4-...",
      "type": "cve",
      "value": "CVE-2024-7479",
      "context": "TeamViewer privilege escalation",
      "firstSeen": "2025-10-15T14:32:00Z",
      "lastSeen": "2025-10-16T09:15:00Z",
      "sightingCount": 3
    }
  ],
  "total": 607
}
```

---

### `GET /api/sources`

Returns a list of sources with optional status and type filters. Includes a `contentCount` field showing the number of archived items per source.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `status` | string | — | Filter by status (`active`, `discovered`, `approved`, `paused`, `dead`, `banned`) |
| `type` | string | — | Filter by source type (`telegram_channel`, `telegram_group`, `forum`, `paste_site`, `web`, `rss`) |

**Response (200):**
```json
[
  {
    "id": "b2c3d4e5-...",
    "type": "telegram_channel",
    "identifier": "RalfHackerChannel",
    "name": "RalfHackerChannel",
    "status": "active",
    "lastCollected": "2025-10-16T12:00:00Z",
    "errorCount": 0,
    "createdAt": "2025-09-01T00:00:00Z",
    "contentCount": 98
  }
]
```

---

### `POST /api/sources/{id}/approve`

Transitions a discovered source to `approved` status, making it eligible for collection.

**Path Parameter:** `id` — UUID of the source.

**Request Body:** None.

**Response (200):** `{"status": "approved"}`

**Response (404):** `{"error": "source not found"}`

---

### `POST /api/sources`

Adds a new source with status `active`. If a source with the same identifier already exists, it is reactivated.

**Request Body:**
```json
{
  "type": "telegram_channel",
  "identifier": "some_channel_name"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | One of: `telegram_channel`, `telegram_group`, `forum`, `paste_site`, `web`, `rss` |
| `identifier` | string | Yes | Channel username, URL, or other unique identifier |

**Response (201):** `{"id": "c3d4e5f6-...", "status": "active"}`

**Response (400):** `{"error": "type and identifier are required"}` or `{"error": "invalid source type"}`

---

### `GET /api/categories`

Returns the count of classified findings per category, ordered by count descending.

**Parameters:** None.

**Response (200):**
```json
[
  {"category": "irrelevant", "count": 493},
  {"category": "malware_sample", "count": 111},
  {"category": "threat_actor_comms", "count": 55},
  {"category": "credential_leak", "count": 9},
  {"category": "data_dump", "count": 4},
  {"category": "access_broker", "count": 1}
]
```

---

### `GET /api/timeline`

Returns finding counts bucketed by time interval, for plotting collection activity over time.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `since` | string | `7d` | Start time. Accepts duration shorthand (`7d`, `24h`) or RFC 3339 timestamp. |
| `interval` | string | `1 hour` | Bucket size. Accepted values: `1 hour`, `6 hours`, `1 day`, `1 week`. Invalid values fall back to `1 hour`. |

**Response (200):**
```json
[
  {"bucket": "2025-10-15T14:00:00Z", "count": 12},
  {"bucket": "2025-10-15T15:00:00Z", "count": 8},
  {"bucket": "2025-10-15T16:00:00Z", "count": 15}
]
```

---

### `GET /api/graph`

Performs a breadth-first traversal of the entity graph starting from a given entity.

**Query Parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `entity_id` | string | — | **Required.** ID of the starting entity. |
| `hops` | int | `2` | Maximum traversal depth (clamped to 1-5). |

**Response (200):**
```json
{
  "nodes": [
    {
      "id": "entity-123",
      "type": "actor",
      "properties": {"name": "threat_actor_x"}
    },
    {
      "id": "entity-456",
      "type": "ioc",
      "properties": {"value": "192.0.2.1", "ioc_type": "ip"}
    }
  ],
  "edges": [
    {
      "source": "entity-123",
      "target": "entity-456",
      "relationship": "uses"
    }
  ]
}
```

Returns empty arrays when no connections are found: `{"nodes": [], "edges": []}`.

**Response (400):** `{"error": "entity_id is required"}`

---

## Error Responses

All endpoints return errors in the same format:

```json
{"error": "description of the problem"}
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request — missing or invalid parameters |
| 401 | Unauthorized — missing, malformed, or incorrect API key |
| 404 | Not found — the requested resource does not exist |
| 500 | Internal server error — database query failure (check Noctis logs) |

---

## Deployment Considerations

**Never expose the dashboard directly to the internet.** The dashboard provides read access to all collected threat intelligence and write access to the source registry. It should only be accessed through:

- `kubectl port-forward` (recommended for Kubernetes)
- A VPN or internal network
- An ingress controller with mTLS or IP allowlisting

**API key rotation:** The API key is a shared secret. Rotate it periodically by updating the `NOCTIS_DASHBOARD_API_KEY` environment variable in your secrets and restarting the pod.

**Disable when not needed:** If you only use the CLI and Prometheus metrics for monitoring, keep `dashboard.enabled: false`. No port is bound and no resources are consumed.

**Port selection:** The default port is 3000. If this conflicts with another service, change it via `dashboard.port`. The dashboard port is independent of the health server port (8080) and the metrics port (9090).

**Graceful shutdown:** The dashboard server shuts down cleanly when Noctis receives SIGINT or SIGTERM. Active API requests are given 5 seconds to complete before the server is forcefully closed.

---

## Frontend Stack

The dashboard frontend loads its dependencies from CDN at runtime:

| Library | Purpose | CDN |
|---------|---------|-----|
| React 19 | UI framework | esm.sh |
| recharts | Charts (pie, bar, area) | esm.sh |
| lucide-react | Icons | esm.sh |
| Tailwind CSS | Styling | cdn.tailwindcss.com |
| Fira Code / Fira Sans | Typography | Google Fonts |

The browser must have internet access to load these dependencies. The dashboard is not designed for airgapped environments.

**Design system:**

- Dark theme: backgrounds `#0a0a0f` / `#12121a`, borders `#2a2a3e`
- Purple accents: `#7c3aed` / `#8b5cf6`
- Blue accents: `#3b82f6` / `#60a5fa`
- Severity colors: critical (red `#ef4444`), high (orange `#f97316`), medium (yellow `#eab308`), low (blue `#3b82f6`), info (gray `#6b7280`)
- Typography: Fira Sans for UI text, Fira Code for monospace values (IOCs, IDs, timestamps)
