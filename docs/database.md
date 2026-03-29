# Database Schema

## Overview

Noctis uses PostgreSQL 16 (`postgres:16-alpine` in production) with a pgx/v5 connection pool. The schema is applied through 12 sequential migration files run automatically at startup via `database.RunMigrations` in `serve.go`. No manual steps required.

Connection is configured via the `DATABASE_URL` environment variable (see `docs/configuration.md`). All queries use parameterized SQL via `pgxpool.Pool`.

---

## Migration History

### 001_init.sql — Core Tables

Establishes the original three-table schema: enriched findings, honeytokens, and threat actor profiles.

**Tables created:** `findings`, `canary_tokens`, `actor_profiles`

- `findings` — Legacy enriched findings from the original rule-matching and LLM classification pipeline. Superseded by `raw_content` + `iocs` in 003 but retained for backward compatibility. Key columns: `id TEXT PK`, `source`, `source_id`, `source_name`, `content`, `content_hash` (SHA-256, indexed), `metadata JSONB`, `matched_rules JSONB`, `severity`, `category`, `iocs JSONB`, `llm_analysis`, `confidence REAL`.
- `canary_tokens` — Honeytokens planted in monitored environments to detect breaches. Key columns: `id TEXT PK`, `type`, `value TEXT UNIQUE`, `planted_at`, `planted_in`, `triggered BOOL`, `triggered_at`, `triggered_in`.
- `actor_profiles` — Threat actor dossiers with behavioral fingerprints. Key columns: `id TEXT PK`, `known_handles JSONB`, `platforms JSONB`, `style_embedding JSONB`, `posting_cadence JSONB`, `first_seen`, `last_seen`, `threat_level`, `linked_findings JSONB`.

---

### 002_graph.sql — Entity Graph

Adds the property graph for entity relationship tracking.

**Tables created:** `entities`, `edges`

- `entities` — Typed nodes in the knowledge graph. `id TEXT PK` (format: `entity:type:name`), `type TEXT` (threat_actor, malware, tool, ip, domain, url, campaign), `properties JSONB`, `created_at`, `updated_at`. Indexed on `type`.
- `edges` — Directed relationships between entities. `id TEXT PK`, `source_id TEXT FK → entities(id) ON DELETE CASCADE`, `target_id TEXT FK → entities(id) ON DELETE CASCADE`, `relationship TEXT`, `properties JSONB`, `created_at`. Indexed on `source_id`, `target_id`, `relationship`.

---

### 003_pivot.sql — Intelligence Archive, IOC Store, Artifacts, Source Registry

The pivot migration that introduces the full intelligence pipeline tables. These are the primary operational tables.

**Tables created:** `raw_content`, `iocs`, `artifacts`, `sources`

- `raw_content` — Central archive storing every collected item regardless of relevance. UUID PK. Key columns: `source_type` (telegram, paste, forum, web, rss), `source_id`, `source_name`, `content TEXT`, `content_hash TEXT UNIQUE` (SHA-256, deduplication), `author`, `author_id`, `url`, `language`, `collected_at TIMESTAMPTZ`, `posted_at TIMESTAMPTZ`, `metadata JSONB`, `classified BOOL DEFAULT FALSE`, `category TEXT`, `tags TEXT[]`, `severity TEXT`, `summary TEXT`, `entities_extracted BOOL DEFAULT FALSE`. Indexes include a partial index on `collected_at ASC WHERE classified = FALSE` for efficient queue processing.
- `iocs` — All indicators of compromise extracted across all content. UUID PK. Key columns: `type TEXT` (ip, domain, hash_md5, hash_sha256, email, crypto_wallet, url, cve), `value TEXT`, `context TEXT`, `source_content_id UUID FK → raw_content(id)`, `first_seen`, `last_seen`, `sighting_count INT DEFAULT 1`, `confidence REAL DEFAULT 0.5`. `UNIQUE(type, value)` constraint deduplicates across sources.
- `artifacts` — Downloaded binary files and attachments. UUID PK. Key columns: `source_content_id UUID FK → raw_content(id)`, `filename`, `mime_type`, `size_bytes BIGINT`, `sha256 TEXT UNIQUE`, `storage_path TEXT` (NFS volume path), `tags TEXT[]`, `analyzed BOOL`, `analysis JSONB`.
- `sources` — Registry of all monitored and discovered sources. UUID PK. Key columns: `identifier TEXT UNIQUE`, `name TEXT`, `type TEXT` (telegram_channel, telegram_group, forum, paste_site, web, rss), `status TEXT` (discovered, approved, active, paused, dead, banned, pending_triage), `discovered_from UUID`, `last_collected`, `collection_interval TEXT`, `error_count INT`, `metadata JSONB`. Indexed on `status` and `type`.

---

### 004_cleanup_discovered.sql — Junk Source Purge

A one-time data migration (no schema changes). Deletes rows from `sources` where `status = 'discovered'` and the identifier matches known noise: social media platforms (LinkedIn, YouTube, Twitter/X, Discord), URL shorteners, documentation sites (W3C, Microsoft, Habr, Medium), fuzzing artifacts (`FUZZ`), localhost references, and truncated IP patterns (`^\d+\.\d+\.\d+$`).

---

### 005_provenance.sql — Classification Provenance

Adds two columns to `raw_content` for reclassification support:

- `provenance TEXT DEFAULT ''` — Records which collector or pipeline version produced the item. Indexed.
- `classification_version INT DEFAULT 1` — Incremented when the classifier is updated, enabling `ResetOldClassifications` to re-queue stale items.

---

### 006_correlations.sql — Cross-Source Correlation Engine

Adds multi-source IOC sighting tracking and the two-tier correlation tables.

**Tables created:** `ioc_sightings`, `correlations`, `correlation_candidates`

- `ioc_sightings` — Records every IOC sighting across raw_content entries, preserving multi-source provenance that the single `source_content_id` FK on `iocs` cannot capture. Composite PK: `(ioc_type, ioc_value, raw_content_id)`. Columns: `ioc_type`, `ioc_value`, `raw_content_id UUID FK → raw_content(id)`, `source_id`, `source_name`, `created_at`. Used by the correlation rules to query shared IOC signals.
- `correlations` — Confirmed correlations that met the evidence threshold. UUID PK. Key columns: `cluster_id TEXT UNIQUE` (deterministic SHA-256 hash of type + inputs), `entity_ids TEXT[]`, `finding_ids TEXT[]`, `correlation_type TEXT` (shared_ioc, handle_reuse, temporal_ioc_overlap, campaign_cluster), `confidence REAL`, `method TEXT DEFAULT 'rule'`, `evidence JSONB`. Indexed on `cluster_id UNIQUE`, `correlation_type`, `created_at DESC`.
- `correlation_candidates` — Weak signals below the evidence threshold, queued for LLM evaluation. UUID PK. Key columns: `cluster_id TEXT UNIQUE`, `entity_ids TEXT[]`, `finding_ids TEXT[]`, `candidate_type TEXT`, `signal_count INT`, `signals JSONB`, `seen_count INT DEFAULT 1`, `status TEXT DEFAULT 'pending'` (pending, reviewed, promoted, rejected). Indexed on `cluster_id UNIQUE`, `status`, `candidate_type`.

---

### 007_phase2.sql — Sub-Classification, Analytical Notes, Correlation Decisions, Source Value

Phase 2 additions enabling fine-grained content classification, LLM memory, analyst audit trail, and source quality tracking.

**Schema changes to `raw_content`:**
- `sub_category TEXT` — Fine-grained content type determined by the Librarian module (e.g., specific malware family, tool category, access type within a top-level category).
- `sub_metadata JSONB DEFAULT '{}'` — Structured key-value metadata from the Librarian (tool names, availability, hosting type, etc.).
- `sub_classified BOOL DEFAULT FALSE` — Whether the Librarian has processed this item.
- Partial index: `WHERE classified = TRUE AND entities_extracted = TRUE AND sub_classified = FALSE` for Librarian queue processing.

**Tables created:** `analytical_notes`, `correlation_decisions`

- `analytical_notes` — The Brain's persistent memory: LLM-generated and human analytical conclusions. UUID PK. Subject linkage: at least one of `finding_id UUID FK → raw_content(id)`, `entity_id TEXT`, `correlation_id UUID FK → correlations(id)`, `ioc_type + ioc_value` must be set. Key columns: `note_type TEXT` (correlation_judgment, attribution, pattern, prediction, warning, context), `title TEXT`, `content TEXT`, `confidence REAL`, `created_by TEXT` (analyst, correlator, human), `model_used TEXT`, `status TEXT` (active, superseded, retracted), `superseded_by UUID FK → analytical_notes(id)`. Indexed on `finding_id`, `entity_id`, `correlation_id`, `note_type`, `status = 'active'`, `created_at DESC`.
- `correlation_decisions` — Audit trail of every LLM decision on correlation candidates, serving as a fine-tuning dataset. UUID PK. Key columns: `candidate_id UUID FK → correlation_candidates(id)`, `cluster_id TEXT`, `decision TEXT` (promote, reject, defer), `confidence REAL`, `reasoning TEXT`, `promoted_correlation_id UUID FK → correlations(id)`, `context_snapshot JSONB` (evidence + graph context fed to the model), `model_used TEXT`. Indexed on `candidate_id`, `cluster_id`, `decision`.

**Schema changes to `sources`:**
- `unique_iocs INT DEFAULT 0`
- `correlation_contributions INT DEFAULT 0`
- `avg_severity REAL DEFAULT 0.0`
- `signal_to_noise REAL DEFAULT 0.0`
- `value_score REAL DEFAULT 0.0`
- `value_computed_at TIMESTAMPTZ`

---

### 008_phase3.sql — IOC Lifecycle, Intelligence Briefs, Vulnerabilities

**Schema changes to `iocs`:**
- `threat_score REAL DEFAULT 0.5` — Current decayed score; primary sort key for active IOC queries.
- `base_score REAL DEFAULT 0.5` — Score at last sighting; decay anchor.
- `active BOOL DEFAULT TRUE` — False when threat_score drops below the deactivation threshold.
- `deactivated_at TIMESTAMPTZ`
- `lifetime_days INT` — Expected half-life by type; drives decay rate.
- `publicly_reported BOOL DEFAULT FALSE`
- Partial indexes: `WHERE active = TRUE` on `active` and `threat_score DESC`.

**Tables created:** `intelligence_briefs`, `vulnerabilities`

- `intelligence_briefs` — LLM-generated periodic summaries for analysts. UUID PK. Key columns: `period_start TIMESTAMPTZ`, `period_end TIMESTAMPTZ`, `brief_type TEXT DEFAULT 'daily'` (daily, weekly, monthly, incident, threat_actor), `title TEXT`, `executive_summary TEXT`, `content TEXT`, `sections JSONB` (keyed by section name), `metrics JSONB` (quantitative counts), `model_used TEXT`, `generated_at TIMESTAMPTZ`, `generation_duration_ms INT`. Indexed on `period_end DESC` and `brief_type`.
- `vulnerabilities` — CVE/CVSS/EPSS/KEV tracking. UUID PK. Key columns: `cve_id TEXT UNIQUE`, `description TEXT`, `cvss_v31_score REAL`, `cvss_v31_vector TEXT`, `cvss_severity TEXT` (CRITICAL, HIGH, MEDIUM, LOW, NONE), `cwe_ids TEXT[]`, `affected_products JSONB`, `reference_urls JSONB`, `published_at`, `last_modified_at`, `epss_score REAL`, `epss_percentile REAL`, `epss_updated_at`, `kev_listed BOOL DEFAULT FALSE`, `kev_date_added`, `kev_due_date`, `kev_ransomware_use BOOL`, `exploit_available BOOL DEFAULT FALSE`, `dark_web_mentions INT DEFAULT 0`, `first_seen_noctis`, `last_seen_noctis`, `priority_score REAL`, `priority_label TEXT`. Indexed on `cve_id`, `priority_score DESC NULLS LAST`, `kev_listed WHERE kev_listed = TRUE`, `epss_score DESC NULLS LAST`, `dark_web_mentions DESC WHERE > 0`.

---

### 009_enrichment.sql — IOC Enrichment

**Schema changes to `iocs`:**
- `enrichment JSONB DEFAULT '{}'` — Results from external threat intelligence APIs (VirusTotal, Shodan, etc.).
- `enriched_at TIMESTAMPTZ` — Timestamp of last enrichment run.
- `enrichment_sources TEXT[] DEFAULT '{}'` — Which APIs contributed data.
- Partial index: `WHERE active = TRUE AND enriched_at IS NULL` on `first_seen ASC` for enrichment queue ordering.

---

### 010_triage.sql — AI Triage Audit Log and Auto-Blacklist

Adds tables for the AI-powered source triage system and learned domain blacklisting.

**Tables created:** `source_triage_log`, `discovered_blacklist`

- `source_triage_log` — Audit trail of every AI triage decision. `id UUID PK DEFAULT gen_random_uuid()`, `batch_id TEXT NOT NULL` (groups decisions from the same triage run), `identifier TEXT NOT NULL` (the source URL/identifier evaluated), `decision TEXT NOT NULL` (investigate or trash), `model_used TEXT`, `created_at TIMESTAMPTZ DEFAULT NOW()`. Indexed on `batch_id` and `created_at DESC`.
- `discovered_blacklist` — Domains automatically blocked after repeated trash decisions by the triage worker. `domain TEXT PK`, `trash_count INTEGER NOT NULL DEFAULT 1`, `auto_added BOOLEAN NOT NULL DEFAULT TRUE`, `created_at TIMESTAMPTZ DEFAULT NOW()`. When `trash_count` reaches 3, the domain is loaded into a runtime blacklist that prevents future URLs from that domain from entering the triage pipeline.

---

### 011_normalize_telegram_identifiers.sql — Telegram Identifier Normalization

A data-only migration (no schema changes). Normalizes Telegram channel identifiers in the `sources` table from full URLs (`https://t.me/username` or `t.me/username`) to bare usernames. This resolves a mismatch where the discovery engine stored full URLs but the config and collector used bare usernames, preventing reliable matching for `last_collected` updates.

```sql
UPDATE sources
SET identifier = regexp_replace(identifier, '^(https?://)?t\.me/', ''),
    name = regexp_replace(name, '^(https?://)?t\.me/', ''),
    updated_at = NOW()
WHERE type = 'telegram_channel'
  AND identifier ~ '(^https?://t\.me/|^t\.me/)';
```

---

### 012_purge_legacy_embedly_urls.sql — Legacy Embedly/Redirect URL Purge

A data-only migration (no schema changes). Removes problematic URLs from `sources` where `status = 'pending_triage'` and the identifier matches embedly.com, Outlook safelinks, Blogger video widgets, Vimeo player embeds, or t.co shortlinks. These URLs produced responses exceeding the LLM output token limit, causing truncated JSON and batch failures in the triage worker.

```sql
DELETE FROM sources
WHERE status = 'pending_triage'
  AND (
    identifier LIKE '%embedly.com%'
    OR identifier LIKE '%safelinks.protection.outlook.com%'
    OR identifier LIKE '%blogger.com/video.g%'
    OR identifier LIKE '%player.vimeo.com%'
    OR identifier LIKE '%t.co/%'
  );
```

---

## Table Reference

| Table | Purpose | Key Columns |
|-------|---------|-------------|
| `findings` | Legacy enriched findings (pre-pivot) | `id TEXT PK`, `content_hash`, `matched_rules JSONB`, `iocs JSONB`, `llm_analysis`, `confidence` |
| `canary_tokens` | Honeytoken breach detection | `value TEXT UNIQUE`, `planted_in`, `triggered BOOL`, `triggered_at` |
| `actor_profiles` | Threat actor behavioral fingerprints | `known_handles JSONB`, `style_embedding JSONB`, `threat_level` |
| `entities` | Knowledge graph nodes | `id TEXT PK`, `type TEXT`, `properties JSONB` |
| `edges` | Knowledge graph directed edges | `source_id FK`, `target_id FK`, `relationship TEXT`, `properties JSONB` |
| `raw_content` | Central intelligence archive (all collected items) | `content_hash UNIQUE`, `source_type`, `classified BOOL`, `category`, `severity`, `summary`, `sub_category`, `sub_classified` |
| `iocs` | Extracted indicators of compromise | `UNIQUE(type,value)`, `threat_score`, `base_score`, `active`, `lifetime_days`, `enrichment JSONB` |
| `ioc_sightings` | Multi-source IOC provenance log | `PK(ioc_type, ioc_value, raw_content_id)`, `source_id`, `source_name` |
| `artifacts` | Downloaded binary files | `sha256 UNIQUE`, `storage_path`, `analyzed BOOL`, `analysis JSONB` |
| `sources` | Source registry (status: discovered, approved, active, paused, dead, banned, pending_triage) | `identifier UNIQUE`, `status`, `type`, `value_score`, `signal_to_noise` |
| `correlations` | Confirmed cross-source correlations | `cluster_id UNIQUE`, `correlation_type`, `confidence`, `entity_ids TEXT[]`, `evidence JSONB` |
| `correlation_candidates` | Weak signals pending LLM evaluation | `cluster_id UNIQUE`, `status`, `signal_count`, `signals JSONB` |
| `analytical_notes` | LLM and human analytical conclusions | `note_type`, `confidence`, `status`, `superseded_by FK` |
| `correlation_decisions` | Analyst LLM decision audit trail | `candidate_id FK`, `decision`, `reasoning`, `context_snapshot JSONB` |
| `intelligence_briefs` | Periodic LLM-generated intelligence summaries | `brief_type`, `period_start/end`, `sections JSONB`, `metrics JSONB` |
| `vulnerabilities` | CVE tracking with CVSS/EPSS/KEV enrichment | `cve_id UNIQUE`, `priority_score`, `kev_listed`, `epss_score`, `dark_web_mentions` |
| `source_triage_log` | AI triage decision audit trail | `batch_id TEXT`, `identifier TEXT`, `decision TEXT`, `model_used TEXT` |
| `discovered_blacklist` | Auto-learned domain blacklist from triage | `domain TEXT PK`, `trash_count INT`, `auto_added BOOL` |

---

## Key Queries

### FetchUnclassified

Used by the classification pipeline workers to pull a batch of unprocessed items in FIFO order:

```sql
SELECT id, source_type, source_id, source_name, content, content_hash,
       author, author_id, url, language, collected_at, posted_at,
       metadata, classified, category, tags, severity, summary,
       entities_extracted, provenance, classification_version,
       sub_category, sub_metadata, sub_classified
FROM raw_content
WHERE classified = false
ORDER BY collected_at ASC
LIMIT $1
```

Hits the partial index `idx_raw_content_unclassified`. An analogous `FetchClassifiedUnextracted` query (using `WHERE classified = true AND entities_extracted = false`) feeds the entity extraction pipeline.

---

### UpdateIOCScores (Decay Formula)

Applied periodically by `IOCLifecycleManager`. Two-pass update:

**Pass 1 — Apply exponential decay to all active IOCs:**

```sql
UPDATE iocs
SET threat_score = base_score * exp(
    -0.3 * (EXTRACT(EPOCH FROM (NOW() - last_seen)) / 86400.0)
    / COALESCE(NULLIF(lifetime_days, 0), CASE type
        WHEN 'ip'           THEN 30
        WHEN 'domain'       THEN 90
        WHEN 'url'          THEN 14
        WHEN 'hash_md5'     THEN 365
        WHEN 'hash_sha256'  THEN 365
        WHEN 'email'        THEN 180
        WHEN 'cve'          THEN 180
        WHEN 'crypto_wallet' THEN 365
        ELSE 90
    END)
)
WHERE active = TRUE
```

Formula: `threat_score = base_score × e^(-0.3 × days_since_last_seen / lifetime_days)`

The decay constant `0.3` means an IOC reaches approximately 74% of its base score at one lifetime, 55% at two lifetimes, and drops below the default deactivation threshold of `0.1` at roughly 7.7 lifetimes. The `lifetime_days` column can be set per-IOC; if null, the type-based default applies.

**Pass 2 — Deactivate IOCs below threshold:**

```sql
UPDATE iocs
SET active = FALSE, deactivated_at = NOW()
WHERE active = TRUE AND threat_score < $1
```

The threshold defaults to `0.1` if not configured. Deactivated IOCs are excluded from `GET /api/iocs` (default `active=true`) but remain in the database for historical queries.

---

### Correlation Rules

The correlation engine runs four rules per cycle. All rules use a `MinEvidenceThreshold` (default 3) to split results into confirmed correlations or weak candidates. Confidence is clamped to `[0.0, 1.0]`.

**Rule 1 — shared_ioc**

Finds IOC values appearing across at least 2 distinct sources. Signal count = number of sources. Confidence formula:

```
confidence = clamp(signal_count × 0.15 + 0.5)
```

Cluster ID: `corr:shared_ioc:sha256(ioc_type:ioc_value)`. Entity IDs include the IOC entity and all source entities.

**Rule 2 — handle_reuse**

Finds author handles appearing in content from at least 2 distinct sources. Creates or updates a `threat_actor` entity in the graph. Confidence formula:

```
confidence = clamp(signal_count × 0.20 + 0.4)
```

Cluster ID: `corr:handle_reuse:sha256(author:author_id)`.

**Rule 3 — temporal_ioc_overlap**

Finds pairs of findings (from different sources) that share at least 2 IOCs within a configurable time window (default 48 hours). Signal count = number of shared IOCs. Confidence formula:

```
confidence = clamp(signal_count × 0.20 + 0.3)
```

Cluster ID: `corr:temporal:sha256(finding_a:finding_b)` (finding IDs sorted for determinism).

**Rule 4 — campaign_cluster**

Finds pairs of `threat_actor` or `malware` entities sharing downstream graph connections (infrastructure, tools, malware families) with at least 2 shared connections. Filters out clusters where all shared entities are whitelisted common tools (Mimikatz, Metasploit, Nmap, etc.). Confidence formula:

```
confidence = clamp(signal_count × 0.15 + 0.4)
```

Cluster ID: `corr:campaign:sha256(entity_a:entity_b)` (entity IDs sorted). Candidates below threshold are queued for LLM evaluation by the Analyst module.

---

### ComputePriority (Vulnerability Priority Score)

Computed by `internal/vuln/priority.go` and written to `vulnerabilities.priority_score` and `priority_label` after each enrichment pass.

**Formula:**

```
if kev_listed:
    score = 1.0   →  label = "critical"
else:
    score = (epss_score × 0.4)
          + ((cvss_v31_score / 10.0) × 0.3)
          + (min(dark_web_mentions / 10.0, 1.0) × 0.2)
          + (exploit_available ? 0.1 : 0.0)
```

**Label thresholds:**

| Score range | Label |
|-------------|-------|
| 1.0 (KEV) | critical |
| ≥ 0.8 | critical |
| ≥ 0.6 | high |
| ≥ 0.3 | medium |
| ≥ 0.1 | low |
| < 0.1 | info |

The KEV override is absolute: any KEV-listed CVE is automatically `critical` regardless of EPSS or CVSS values, reflecting confirmed active exploitation in the wild.
