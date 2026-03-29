# LLM Analysis Pipeline

This document describes how Noctis uses three LLM providers across a
multi-stage pipeline to classify, enrich, correlate, and synthesize findings
ingested from threat intelligence sources.

---

## LLM Client Abstraction

**Package:** `internal/llm`

The `LLMClient` interface decouples all analysis logic from any specific model
provider:

```go
type LLMClient interface {
    ChatCompletion(ctx context.Context, messages []Message, opts ...Option) (*Response, error)
}
```

`Message` carries a role (`"user"`, `"assistant"`, `"system"`) and a content
string. `Response` carries only the assistant's reply text.

Callers may tune individual requests with functional options:

| Option | Effect |
|--------|--------|
| `WithTemperature(float64)` | Sets sampling temperature for the request |
| `WithMaxTokens(int)` | Caps the number of tokens the model may generate |

**Implementation:** `internal/llm/openai_compat.go` — `OpenAICompatClient`
posts to `{baseURL}/chat/completions` following the OpenAI chat completions
specification. Tested with GLM, Groq, Gemini (OpenAI-compatible endpoint), and
Ollama. Authentication is `Authorization: Bearer <apiKey>`; the header is
omitted entirely if `apiKey` is empty.

---

## Three LLM Providers

Noctis operates three distinct LLM clients, each purpose-matched to its task:

| Config key | Provider | Role | Prompt templates used |
|------------|----------|------|-----------------------|
| `llm` | GLM-5-Turbo (via api.z.ai) | Entity extraction, sub-classification | `extract_entities`, `classify_detail`, `severity` |
| `llmFast` | Groq (llama-4-scout) | Classification, summarization, IOC extraction | `classify`, `summarize`, `extract_iocs` |
| `llmBrain` | Gemini 3.1 Pro | Correlation analysis, brief generation, NL queries | `evaluate_correlation`, `daily_brief`, (NL→SQL) |

When `llmFast.model` is empty the system falls back to `llm` for classification
(single-LLM mode). When `llmBrain.baseURL` is empty the system falls back to
`llm` for brain operations.

---

## Prompt Templates

All templates live in `prompts/`. They use Go `text/template` syntax
(`{{.Field}}`). The `Analyzer.New(client, promptsDir)` constructor reads every
`*.tmpl` file at startup; templates are keyed by filename without extension. A
missing or unparseable template logs a warning rather than a fatal error.

### `extractJSON`

LLM responses frequently arrive wrapped in markdown code fences, prefixed with
conversational prose, or truncated mid-object. `extractJSON` (in
`internal/analyzer/analyzer.go`) uses a brace-depth-counting parser to locate
and extract the first complete JSON object or array from the response text. It
handles nested braces, strings with escaped characters, and ignores braces
inside string literals. This replaced the earlier `stripCodeFences` approach,
which only removed fences and failed on responses with leading prose or
multiple JSON fragments.

### Template index

| Template | LLM | Input variables | Output |
|----------|-----|-----------------|--------|
| `classify` | llmFast (Groq) | `Source`, `SourceName`, `Content`, `MatchedRules` | `{"category", "confidence", "provenance", "severity", "reasoning"}` |
| `classify_detail` | llm (GLM-5-Turbo) | `Category`, `Source`, `SourceName`, `Provenance`, `Entities`, `IOCs`, `Content`, `ValidSubCategories` | `{"sub_category", "sub_metadata", "confidence", "reasoning"}` |
| `extract_iocs` | llmFast (Groq) | `Content` | `[{"type", "value", "context", "malicious"}]` |
| `extract_entities` | llm (GLM-5-Turbo) | `Content`, `Category`, `Summary` | `[{"type", "name", "properties"}]` |
| `severity` | llm (GLM-5-Turbo) | `Source`, `SourceName`, `Content`, `Category`, `MatchedRules` | `{"severity", "reasoning"}` |
| `summarize` | llmFast (Groq) | `Source`, `SourceName`, `Content`, `Category`, `Severity`, `Author`, `Timestamp` | plain text paragraph |
| `evaluate_correlation` | llmBrain (Gemini) | `CandidateType`, `SignalCount`, `Evidence`, `Findings[]`, `Entities[]`, `Notes[]` | `{"decision", "confidence", "reasoning", "missing_evidence"}` |
| `daily_brief` | llmBrain (Gemini) | metrics snapshot, top findings, entity trends, source health | `{"title", "executive_summary", "sections": {...}}` |
| `triage` | llmFast (Groq) | `URLs` | `{"investigate": [...], "trash": [...]}` |
| `stylometry` | any | `Author`, `Source`, `Content` | stylometric feature JSON object |

---

## Classification Categories

Defined in `internal/models/finding.go`. The `classify` prompt assigns exactly
one category per finding.

| Category | Meaning |
|----------|---------|
| `credential_leak` | Leaked usernames, passwords, API keys, session tokens |
| `malware_sample` | Malware hashes, C2 infrastructure, download links |
| `vulnerability` | CVE disclosures, exploit PoCs, security advisories with technical details, weaponized exploit code |
| `threat_actor_comms` | Actor discussions, planning, coordination |
| `access_broker` | Initial access being sold (RDP, VPN, shell) |
| `data_dump` | Bulk data leaks — databases, PII, financial records |
| `canary_hit` | A planted honeytoken was triggered |
| `irrelevant` | Content matched a rule but has no actionable threat intelligence value |

Classification also returns `provenance`: `first_party` (direct observation),
`third_party_reporting` (reporting about an event), or `unknown`.

---

## Sub-classification (Librarian)

After IOC and entity extraction, the Librarian worker runs the
`classify_detail` prompt on each finding to assign a fine-grained
`sub_category` and structured `sub_metadata` JSONB. The Librarian uses the GLM-5-Turbo
client and a separate concurrency limiter.

Per-category sub-category taxonomies are defined and passed to the template as
`ValidSubCategories`. Examples:

- `credential_leak`: `combo_list`, `stealer_log`, `database_breach`, `api_key_leak`, `session_token`, `other`
- `malware_sample`: `ransomware`, `infostealer`, `rat`, `loader`, `backdoor`, `dropper`, `botnet`, `wiper`, `other`
- `vulnerability`: `rce`, `sqli`, `lfi_rfi`, `authentication_bypass`, `privilege_escalation`, `dos`, `zero_day`, `n_day`, `other`
- `access_broker`: `rdp_access`, `vpn_access`, `shell_access`, `domain_admin`, `cloud_access`, `other`
- `data_dump`: `pii`, `financial`, `healthcare`, `government`, `corporate`, `other`

`sub_metadata` fields are category-specific structured data (e.g., for
`malware_sample`: `malware_family`, `delivery_method`, `c2_addresses`; for
`credential_leak`: `source_breach`, `estimated_count`, `data_types`).

---

## IOC Types

Defined in `internal/models/ioc.go`. The `extract_iocs` prompt extracts these
types:

`ip`, `domain`, `hash_md5`, `hash_sha1`, `hash_sha256`, `email`,
`crypto_wallet`, `url`, `cve`

Only IOCs with `"malicious": true` are stored in the `iocs` table. IOCs marked
`false` (research references, documentation domains, benign infrastructure) are
discarded before `UpsertIOC`. This prevents pollution of the IOC database with
non-threatening indicators that appear in security research content.

---

## Processing Pipeline (ProcessingEngine)

**Package:** `internal/processor`

`ProcessingEngine` orchestrates seven sub-modules, each with its own
`StatusTracker` registered in the module registry:

| Sub-module | Module ID | LLM | Workers |
|------------|-----------|-----|---------|
| Classifier | `processor.classifier` | llmFast | `classificationWorkers` |
| Summarizer | `processor.summarizer` | llmFast | `classificationWorkers` |
| IOCExtractor | `processor.ioc_extractor` | llmFast | `entityExtractionWorkers` |
| EntityExtractor | `processor.entity_extractor` | llm | `entityExtractionWorkers` |
| GraphBridge | `processor.graph_bridge` | — | `entityExtractionWorkers` |
| Librarian | `processor.librarian` | llm | `librarianWorkers` |
| IOCLifecycleManager | `processor.ioc_lifecycle` | — | periodic |

Concurrency is enforced per sub-module via `ConcurrencyLimiter` (buffered
channel semaphore). Workers poll the archive on a 30-second idle interval when
no work is available.

### Classification pipeline worker

Runs `classificationWorkers` goroutines, each looping:

1. `FetchUnclassified(ctx, batchSize)` — entries not yet classified.
2. `Classifier.Classify` — assigns category, confidence, severity, provenance (llmFast).
3. Severity override: items classified as `irrelevant` are clamped to `info` severity
   regardless of the LLM's response.
4. `Summarizer.Summarize` — produces analyst-readable paragraph (llmFast). Skipped
   entirely for `irrelevant` items to save tokens.
5. `MarkClassified` — persists category, severity, summary, provenance, classification version.

### Extraction pipeline worker

Runs `entityExtractionWorkers` goroutines, each looping:

1. `FetchClassifiedUnextracted` — entries classified but not entity-extracted.
2. `IOCExtractor.ExtractIOCs` — extracts IOCs (llm); only `malicious: true` IOCs are stored.
3. `EntityExtractor.ExtractEntities` — extracts knowledge graph nodes (llm).
4. `GraphBridge` — writes entity nodes and edges to the `entities`/`edges` tables.
5. `MarkEntitiesExtracted` — marks entry complete.

### Librarian pipeline worker

Runs `librarianWorkers` goroutines, each looping:

1. `FetchExtractedUnsubclassified` — entries with entities extracted but no sub-classification.
2. `Librarian.SubClassify` — assigns sub-category and sub-metadata (llm, `classify_detail`).
3. `MarkSubclassified` — persists sub-category and sub-metadata JSONB.

### IOC lifecycle

Periodic goroutine (not a poll loop). Runs on `iocLifecycle.intervalMinutes`,
applies exponential decay to threat scores, and deactivates IOCs below
`deactivateThreshold`.

---

## Data Flow Summary

```
Collector → ingest pipeline → archive (raw_content)
                                       |
                          ┌────────────┴────────────┐
                          │   Classification worker   │
                          │  Classifier (llmFast)     │
                          │  Summarizer (llmFast)     │
                          └────────────┬────────────┘
                                       │ MarkClassified
                          ┌────────────┴────────────┐
                          │   Extraction worker       │
                          │  IOCExtractor (llmFast)   │
                          │  EntityExtractor (llm)    │
                          │  GraphBridge              │
                          └────────────┬────────────┘
                                       │ MarkEntitiesExtracted
                          ┌────────────┴────────────┐
                          │   Librarian worker        │
                          │  Librarian (llm)          │
                          └────────────┬────────────┘
                                       │ MarkSubclassified
                                       ▼
                               fully enriched entry
```

### Poison Item Handling

All three pipeline stages (classification, extraction, librarian) maintain
separate failure counters per content ID (`classifyFailCounts`,
`extractFailCounts`, `librarianFailCounts`). After 5 consecutive LLM failures
on the same item, the worker marks it as poison and advances:

- **Classification:** marked as `irrelevant` with tags `unclassifiable`,
  `poison_item`.
- **Extraction:** marked as entities-extracted (skips remaining extraction).
- **Librarian:** marked as sub-classified with sub-category `unclassifiable`.

Poison map entries are cleaned up after an item is successfully processed,
preventing unbounded map growth. This ensures a single malformed or
adversarial item cannot permanently block pipeline progress.

### Budget Circuit Breaker

Processing workers check the budget before each LLM call via
`SpendingTracker` (`internal/llm/spending.go`). The tracker monitors
per-model monthly spend against the `monthlyBudgetUSD` config limit, estimating
cost from token counts using `inputCostPer1M` and `outputCostPer1M` rates.
When `ErrBudgetExhausted` is returned, the `budgetExhausted` atomic flag is
set on the engine and all workers of that pipeline stage pause for 30 minutes
(`budgetPauseDuration`). After the pause, the flag is cleared and workers
resume. The OpenAI-compatible client also detects Groq's `spend_limit_reached`
and `spend_alert` HTTP 400 errors and maps them to `ErrBudgetExhausted`, so
provider-side spend caps trigger the same circuit breaker.

### Content Truncation

The `maxContentLength` config (default 8192 bytes) caps content passed to
pipeline workers via `FindingFromRawContentWithLimit`. Additionally, the
analyzer applies per-stage limits before rendering prompt templates:

| Stage | Limit | Constant |
|-------|-------|----------|
| Classification | 4096 chars | `classifyContentLimit` |
| Summarization | 6144 chars | `summarizeContentLimit` |
| IOC extraction | 8192 chars | `iocExtractContentLimit` |

This prevents token waste and LLM failures on long content. Classification
needs minimal context; IOC extraction receives the most.

---

## Triage Analysis (Discovery)

**Package:** `internal/discovery`

The `TriageURLs()` method on `Analyzer` batch-classifies discovered URLs as
`"investigate"` or `"trash"` using the `triage.tmpl` prompt template
(llmFast). The response is a JSON object with two string arrays. JSON
extraction uses `ExtractJSON` with multiple fallbacks for malformed LLM output:

1. Standard `triageResponse` object parse.
2. Array-of-objects fallback (LLM wraps result in an array).
3. Bare string-array fallback (treated as all-investigate).
4. Empty bare-array fallback (degrades gracefully; URLs stay pending for the
   next cycle).

---

## Correlation Evaluation Flow (Brain — Analyst)

**Package:** `internal/brain`

The Correlator runs on a periodic interval and produces `correlation_candidates`
by detecting:

- Shared IOCs across multiple findings (≥ `minEvidenceThreshold` signals)
- Handle reuse across sources
- Temporal IOC overlap within `temporalWindowHours`
- Entity cluster formation

The Analyst polls pending candidates and evaluates each one using the brain LLM
(`evaluate_correlation` prompt). The prompt receives the candidate type, signal
count, related finding summaries, entity graph context, and any prior analytical
notes.

**Decision outcomes:**

| Decision | Effect |
|----------|--------|
| `promote` | Candidate promoted to `correlations` table as a confirmed correlation; analytical note created |
| `reject` | Candidate marked rejected; note created with reasoning |
| `defer` | Candidate left pending; note created describing missing evidence |

The `promoteThreshold` config field sets the minimum confidence score for
`promote` to take effect. Decisions are logged to `correlation_decisions` for
auditability.

---

## Brief Generation Flow (Brain — BriefGenerator)

Runs at `scheduleHour` UTC each day. Flow:

1. `GatherBriefMetrics` — queries the archive for 24-hour window statistics:
   total findings by severity, IOC counts, new/confirmed correlations, new
   analytical notes, deactivated IOCs, top findings by severity, trending
   entities, source health.
2. Renders `daily_brief.tmpl` with the metrics as template variables.
3. Sends to brain LLM (`llmBrain`).
4. Parses structured JSON response: `title`, `executive_summary`, `sections`
   (key_threats, correlation_insights, emerging_trends, collection_gaps,
   recommended_actions).
5. Persists to `intelligence_briefs` table.

---

## Query Engine Flow (Brain — QueryEngine)

On-demand; not periodic. Called by the dashboard API when a user submits a
natural language query.

1. Receives a natural language question string.
2. Constructs a prompt that includes the full database schema context (table
   names, column names, types, enums) and the user question.
3. Sends to brain LLM, which generates a PostgreSQL `SELECT` statement.
4. Strips trailing semicolons from the generated SQL (LLMs frequently append
   them). The subsequent semicolon check then enforces single-statement
   queries — any remaining `;` causes rejection.
5. Validates the generated SQL: rejects non-SELECT statements, statements
   referencing disallowed tables, and statements exceeding a size limit.
6. Executes the validated SQL against the live database with a query timeout.
7. Returns `QueryResult{Query, SQL, Columns, Rows, RowCount, Duration}` to the
   dashboard.

Schema context tables available to the query engine: `raw_content`, `iocs`,
`entities`, `edges`, `correlations`, `analytical_notes`, `vulnerabilities`,
`sources`.
