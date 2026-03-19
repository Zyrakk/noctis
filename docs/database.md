# Database Schema

## Overview

Noctis uses PostgreSQL 16 (`postgres:16-alpine` in production) with a pgx/v5 connection pool. The schema is applied through 3 additive migration files totalling 8 tables. Migrations run automatically at startup via `database.RunMigrations` in `serve.go` — no manual steps required.

Connection is managed through a `pgxpool.Pool` configured via the `DATABASE_URL` environment variable (see `docs/configuration.md`).

---

## Migration 001_init.sql — Core Tables

These three tables form the original schema: enriched findings, honeytokens, and threat actor profiles.

### `findings`

Legacy enriched findings produced by the rule-matching and LLM classification pipeline. Superseded by `raw_content` + `iocs` in migration 003, but retained for backward compatibility.

```sql
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    author TEXT,
    timestamp TIMESTAMPTZ NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata JSONB DEFAULT '{}',
    match_type TEXT,
    matched_rules JSONB DEFAULT '[]',
    severity TEXT DEFAULT 'info',
    category TEXT,
    iocs JSONB DEFAULT '[]',
    llm_analysis TEXT,
    confidence REAL DEFAULT 0.0
);
```

Key fields:
- `source` / `source_id` / `source_name` — origin platform and channel identifiers
- `content_hash` — SHA-256 for deduplication
- `matched_rules` — JSONB array of triggered Sigma/custom rules
- `iocs` — JSONB array of extracted indicators (superseded by the `iocs` table in 003)
- `llm_analysis` — raw LLM output text
- `confidence` — float score from classifier

Indexes: `content_hash`, `source`, `severity`, `collected_at`

---

### `canary_tokens`

Planted honeytokens monitored for exfiltration. When a token appears in the wild, `triggered` flips to TRUE and the sighting context is recorded.

```sql
CREATE TABLE IF NOT EXISTS canary_tokens (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    value TEXT NOT NULL UNIQUE,
    planted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    planted_in TEXT NOT NULL,
    triggered BOOLEAN NOT NULL DEFAULT FALSE,
    triggered_at TIMESTAMPTZ,
    triggered_in TEXT
);
```

Key fields:
- `type` — token category (e.g. `api_key`, `credential`, `document`)
- `value` — the unique token string; UNIQUE constraint prevents duplicate plants
- `planted_in` — description of where the token was seeded
- `triggered_in` — context or platform where the token was observed

Index: `value` (fast lookup during content scanning)

---

### `actor_profiles`

Threat actor profiling records. Aggregates signals across multiple findings to build a behavioral fingerprint.

```sql
CREATE TABLE IF NOT EXISTS actor_profiles (
    id TEXT PRIMARY KEY,
    known_handles JSONB NOT NULL DEFAULT '[]',
    platforms JSONB NOT NULL DEFAULT '[]',
    style_embedding JSONB,
    posting_cadence JSONB,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    threat_level TEXT DEFAULT 'info',
    linked_findings JSONB NOT NULL DEFAULT '[]'
);
```

Key fields:
- `known_handles` — JSONB array of observed usernames/aliases
- `platforms` — JSONB array of platforms the actor was active on
- `style_embedding` — vector representation of writing style (for similarity matching)
- `posting_cadence` — JSONB object describing temporal activity patterns
- `threat_level` — `info`, `low`, `medium`, `high`, `critical`
- `linked_findings` — JSONB array of `findings.id` references

---

## Migration 002_graph.sql — Entity Graph

A lightweight property graph stored in two tables: nodes (`entities`) and directed edges (`edges`). Used for relationship mapping between actors, infrastructure, malware families, and other extracted objects.

### `entities`

Graph nodes. Each entity has a type and an arbitrary properties bag.

```sql
CREATE TABLE IF NOT EXISTS entities (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

`type` examples: `ip`, `domain`, `actor`, `malware`, `wallet`, `cve`, `organization`

Index: `type` (filter nodes by category)

---

### `edges`

Directed relationships between entities. Both FK columns cascade on delete — removing an entity automatically removes all edges that reference it.

```sql
CREATE TABLE IF NOT EXISTS edges (
    id TEXT PRIMARY KEY,
    source_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    target_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    relationship TEXT NOT NULL,
    properties JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

`relationship` examples: `communicates_with`, `hosts`, `attributed_to`, `drops`, `resolves_to`

Indexes: `source_id`, `target_id`, `relationship` (graph traversal and relationship filtering)

---

## Migration 003_pivot.sql — Archive-Everything

The pivot migration introduces the primary intelligence archive. All collected content is stored in `raw_content` regardless of relevance; classification and entity extraction happen asynchronously. This migration is additive — tables from 001 and 002 are untouched.

### `raw_content`

The central archive table. Every message, post, paste, or page collected by any collector lands here first.

```sql
CREATE TABLE IF NOT EXISTS raw_content (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    source_name TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL UNIQUE,
    author TEXT,
    author_id TEXT,
    url TEXT,
    language TEXT,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    posted_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',

    -- AI classification (filled asynchronously after collection)
    classified BOOLEAN DEFAULT FALSE,
    category TEXT,
    tags TEXT[] DEFAULT '{}',
    severity TEXT,
    summary TEXT,
    entities_extracted BOOLEAN DEFAULT FALSE
);
```

Key fields:
- `source_type` — collector origin: `telegram`, `paste`, `forum`, `web`, `rss`
- `content_hash` — SHA-256; UNIQUE constraint enforces deduplication at the DB level
- `author_id` — platform-native author identifier (distinct from the human-readable `author`)
- `posted_at` — original publication timestamp (may differ significantly from `collected_at`)
- `metadata` — source-specific structured data (e.g. Telegram message attributes, forum thread metadata)
- `classified` — FALSE until the background classifier processes this row
- `category` — AI-assigned category: `credential_leak`, `malware`, `access_broker`, etc.
- `tags` — TEXT array of AI-generated tags; searchable via GIN index
- `severity` — `critical`, `high`, `medium`, `low`, `info`, `none`
- `summary` — AI-generated one-line summary
- `entities_extracted` — FALSE until the entity extraction worker processes this row

---

### `iocs`

Normalized indicator-of-compromise store. All indicators extracted from `raw_content` across all sources are deduplicated here by `(type, value)`.

```sql
CREATE TABLE IF NOT EXISTS iocs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,
    value TEXT NOT NULL,
    context TEXT,
    source_content_id UUID REFERENCES raw_content(id),
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    sighting_count INTEGER DEFAULT 1,
    confidence REAL DEFAULT 0.5,
    UNIQUE(type, value)
);
```

Key fields:
- `type` — `ip`, `domain`, `hash_md5`, `hash_sha256`, `email`, `crypto_wallet`, `url`, `cve`
- `context` — surrounding text snippet from source content
- `source_content_id` — FK to `raw_content.id` (the first or most recent sighting)
- `sighting_count` — incremented on each re-observation (upsert pattern)
- `confidence` — extraction confidence score (0.0–1.0)

Indexes: `type`, `value`

---

### `artifacts`

Downloaded binary files and attachments. Stored on an NFS volume; this table holds the metadata and analysis results.

```sql
CREATE TABLE IF NOT EXISTS artifacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_content_id UUID REFERENCES raw_content(id),
    filename TEXT,
    mime_type TEXT,
    size_bytes BIGINT,
    sha256 TEXT NOT NULL UNIQUE,
    storage_path TEXT NOT NULL,
    tags TEXT[] DEFAULT '{}',
    collected_at TIMESTAMPTZ DEFAULT NOW(),
    analyzed BOOLEAN DEFAULT FALSE,
    analysis JSONB DEFAULT '{}'
);
```

Key fields:
- `sha256` — UNIQUE; prevents storing the same binary twice
- `storage_path` — absolute path on the NFS volume mount
- `analyzed` — FALSE until the artifact analysis worker processes this file
- `analysis` — JSONB blob from AI/static analysis results

Indexes: `sha256` (dedup lookup), `tags` GIN (tag-based filtering)

---

### `sources`

Registry of all known collection targets. Sources may be discovered automatically (e.g. a Telegram channel link found in collected content) and move through a lifecycle before active collection begins.

```sql
CREATE TABLE IF NOT EXISTS sources (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,
    identifier TEXT NOT NULL UNIQUE,
    name TEXT,
    status TEXT DEFAULT 'discovered',
    discovered_from UUID,
    last_collected TIMESTAMPTZ,
    collection_interval TEXT DEFAULT '60s',
    error_count INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

Key fields:
- `type` — `telegram_channel`, `telegram_group`, `forum`, `paste_site`, `web`, `rss`
- `identifier` — canonical unique identifier (channel username, forum URL, RSS URL); UNIQUE
- `status` — lifecycle state: `discovered` → `approved` → `active`; also `paused`, `dead`, `banned`
- `discovered_from` — `raw_content.id` of the content that led to this source being found
- `collection_interval` — Go duration string (default `60s`)
- `error_count` — consecutive collection errors; used for automatic pausing

Indexes: `status`, `type`

---

## Index Strategy

| Index | Table | Columns | Purpose |
|---|---|---|---|
| `idx_raw_content_hash` | `raw_content` | `content_hash` | Deduplication — fast existence check before insert |
| `idx_raw_content_source` | `raw_content` | `(source_type, source_id)` | Filter all content from a specific channel or source |
| `idx_raw_content_collected` | `raw_content` | `collected_at DESC` | Time-ordered queries; DESC puts most recent rows first |
| `idx_raw_content_category` | `raw_content` | `category` | Filter classified content by threat category |
| `idx_raw_content_tags` | `raw_content` | `tags` (GIN) | Array containment queries (`tags @> ARRAY['ransomware']`) |
| `idx_raw_content_unclassified` | `raw_content` | `collected_at ASC` WHERE `classified = FALSE` | Partial index — background classifier worker queue |
| `idx_raw_content_unextracted` | `raw_content` | `collected_at ASC` WHERE `classified = TRUE AND entities_extracted = FALSE` | Partial index — entity extraction worker queue |
| `idx_iocs_type` | `iocs` | `type` | IOC lookup by indicator type |
| `idx_iocs_value` | `iocs` | `value` | IOC lookup by indicator value |
| `idx_sources_status` | `sources` | `status` | Source management — filter by lifecycle state |
| `idx_sources_type` | `sources` | `type` | Source management — filter by collector type |
| `idx_edges_source` | `edges` | `source_id` | Graph traversal — outbound edges from a node |
| `idx_edges_target` | `edges` | `target_id` | Graph traversal — inbound edges to a node |
| `idx_edges_relationship` | `edges` | `relationship` | Filter edges by relationship type |

The two partial indexes on `raw_content` are the most important for operational performance: they give the classifier and entity extraction workers an efficient queue of pending rows without scanning the full table.

---

## Common Analyst Queries

```sql
-- Recent high-severity findings
SELECT category, severity, source_name, LEFT(summary, 150)
FROM raw_content WHERE severity IN ('high', 'critical')
ORDER BY collected_at DESC LIMIT 20;

-- IOCs by type
SELECT type, count(*) FROM iocs GROUP BY type ORDER BY count DESC;

-- Search by content
SELECT source_name, category, LEFT(content, 200)
FROM raw_content WHERE content ILIKE '%ransomware%'
ORDER BY collected_at DESC;

-- Discovered sources pending approval
SELECT type, identifier, created_at FROM sources
WHERE status = 'discovered' ORDER BY created_at DESC;

-- Classification progress
SELECT classified, count(*) FROM raw_content GROUP BY classified;

-- Sources by collection volume
SELECT source_name, count(*) FROM raw_content GROUP BY source_name ORDER BY count DESC;

-- IOCs with multiple sightings
SELECT type, value, sighting_count, first_seen, last_seen
FROM iocs WHERE sighting_count > 1 ORDER BY sighting_count DESC;
```

---

## Graph Traversal

The entity graph supports recursive CTE queries for multi-hop traversal. The example below finds all entities reachable within 3 hops from a given starting node:

```sql
-- Find all entities connected to a given entity (up to 3 hops)
WITH RECURSIVE connected AS (
    SELECT target_id AS id, relationship, 1 AS depth
    FROM edges WHERE source_id = '<entity-id>'
    UNION ALL
    SELECT e.target_id, e.relationship, c.depth + 1
    FROM edges e JOIN connected c ON e.source_id = c.id
    WHERE c.depth < 3
)
SELECT DISTINCT e.id, e.type, e.properties, c.relationship, c.depth
FROM connected c JOIN entities e ON e.id = c.id;
```

Adjust the depth limit (`< 3`) and starting `source_id` as needed. For large graphs, consider adding a `visited` set via array accumulation to avoid cycles.
