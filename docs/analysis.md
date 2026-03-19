# LLM Analysis Pipeline

This document describes how Noctis uses a large language model to classify, enrich, and summarise findings ingested from threat intelligence sources.

---

## LLM Client Abstraction

**Package:** `internal/llm`
**File:** `internal/llm/client.go`

The `LLMClient` interface decouples all analysis logic from any specific model provider:

```go
type LLMClient interface {
    ChatCompletion(ctx context.Context, messages []Message, opts ...Option) (*Response, error)
}
```

**Message** carries a role (`"user"`, `"assistant"`, `"system"`) and a content string. **Response** carries only the assistant's reply text — the rest of the OpenAI response envelope is discarded.

Callers may tune individual requests with functional options:

| Option | Effect |
|---|---|
| `WithTemperature(float64)` | Sets sampling temperature for the request |
| `WithMaxTokens(int)` | Caps the number of tokens the model may generate |

Both options are applied to an `Options` struct before the request is serialised, and both are omitted from the JSON payload when not set (using `omitempty`).

---

## OpenAI-Compatible Client

**File:** `internal/llm/openai_compat.go`

`OpenAICompatClient` is the only concrete implementation of `LLMClient`. It sends a POST request to `{baseURL}/chat/completions` following the OpenAI chat completions specification.

**Tested with:**
- GLM (open.bigmodel.cn) — primary target
- OpenAI API
- Ollama local inference
- Any other OpenAI-compatible endpoint

**Authentication:** Bearer token via `Authorization: Bearer <apiKey>` header. The header is omitted entirely if `apiKey` is empty (e.g. for unauthenticated Ollama).

**Configuration fields** (from `noctis.yaml`):

| Field | Purpose |
|---|---|
| `llm.provider` | Provider label (informational) |
| `llm.baseURL` | Base URL without trailing path (e.g. `https://open.bigmodel.cn/api/paas/v4`) |
| `llm.model` | Model identifier forwarded in each request body |
| `llm.apiKey` | API key for Bearer auth |

**Request flow:**

1. Apply functional options to build the request struct.
2. Marshal to JSON: `{"model": "...", "messages": [...], "temperature": ..., "max_tokens": ...}`.
3. POST to `{baseURL}/chat/completions` with `Content-Type: application/json` and `Authorization: Bearer ...`.
4. Unmarshal the `choices[0].message.content` field from the response.
5. Return an error wrapping the HTTP status and body on any non-200 response.

---

## Analyzer

**Package:** `internal/analyzer`
**File:** `internal/analyzer/analyzer.go`

`Analyzer` wraps an `LLMClient` and a set of loaded Go `text/template` prompt templates. It exposes one method per analysis step.

### Template loading

At construction, `New(client, promptsDir)` reads every `*.tmpl` file from `promptsDir` (configurable via the `NOCTIS_PROMPTS_DIR` environment variable). Templates are keyed by filename without extension. A missing or unparseable template logs a warning rather than returning an error, so the analyzer remains usable for templates that did load.

### `stripCodeFences`

GLM (and some other models) wrap JSON responses in markdown code fences:

```
```json
{"category": "credential_leak", "confidence": 0.92}
```
```

`stripCodeFences` removes the opening ` ``` ` or ` ```json ` fence and the closing ` ``` ` fence before JSON unmarshalling. This is a required compatibility fix — without it, every structured response from GLM would fail to parse.

### Methods

#### `Classify`

Template input variables: `Source`, `SourceName`, `Content`, `MatchedRules`
LLM call: single user message
Expected JSON output: `{"category": "<category>", "confidence": <0.0-1.0>}`
Returns: `*classifyResponse{Category string, Confidence float64}`

#### `AssessSeverity`

Template input variables: `Source`, `SourceName`, `Content`, `Category`, `MatchedRules`
LLM call: single user message
Expected JSON output: `{"severity": "<level>", "reasoning": "<one sentence>"}`
Returns: `models.Severity` (parsed and validated; falls back to `SeverityInfo` on error)

#### `ExtractIOCs`

Template input variables: `Content`
LLM call: single user message
Expected JSON output: array of `{"type": "<type>", "value": "<value>", "context": "<brief context>"}`
Returns: `[]models.IOC`

#### `Summarize`

Template input variables: `Source`, `SourceName`, `Content`, `Category`, `Severity`, `Author`, `Timestamp`
LLM call: single user message
Returns: raw response text (no JSON parsing); plain prose paragraph

---

## Prompt Templates

All templates live in the `prompts/` directory. They use Go `text/template` syntax (`{{.Field}}`).

### `classify.tmpl`

Instructs the model to act as a CTI analyst and assign exactly one category from a fixed list.

**Full template:**

```
You are a cyber threat intelligence analyst. Classify the following content found on {{.Source}} (channel/site: {{.SourceName}}).

The content matched these detection rules: {{range .MatchedRules}}{{.}}, {{end}}

Content:
---
{{.Content}}
---

Classify into exactly ONE of these categories:
- credential_leak: Leaked usernames, passwords, session tokens, API keys
- malware_sample: Malware hashes, download links, C2 infrastructure
- threat_actor_comms: Threat actor discussions, planning, coordination
- access_broker: Initial access being sold (RDP, VPN, shell access)
- data_dump: Bulk data leaks (databases, PII, financial records)
- canary_hit: A known planted honeytoken was detected
- irrelevant: Content matched a rule but is not a real threat

Respond with ONLY a JSON object:
{"category": "<category>", "confidence": <0.0-1.0>}
```

### `extract_iocs.tmpl`

Extracts all indicators of compromise from raw content.

**Full template:**

```
You are a cyber threat intelligence analyst. Extract ALL indicators of compromise (IOCs) from the following content.

Content:
---
{{.Content}}
---

Extract IOCs of these types:
- ip: IPv4 or IPv6 addresses
- domain: Domain names (not common ones like google.com, github.com)
- hash_md5: MD5 hashes (32 hex chars)
- hash_sha1: SHA-1 hashes (40 hex chars)
- hash_sha256: SHA-256 hashes (64 hex chars)
- email: Email addresses involved in malicious activity
- crypto_wallet: Bitcoin, Ethereum, or Monero wallet addresses
- url: Full URLs pointing to malicious resources
- cve: CVE identifiers (CVE-YYYY-NNNNN)

Respond with ONLY a JSON array. Each element: {"type": "<type>", "value": "<value>", "context": "<brief context>"}
If no IOCs found, respond with: []
```

### `severity.tmpl`

Assesses operational severity based on actionability and immediacy of the threat.

**Full template:**

```
You are a cyber threat intelligence analyst. Assess the severity of this finding.

Source: {{.Source}} ({{.SourceName}})
Category: {{.Category}}
Matched rules: {{range .MatchedRules}}{{.}}, {{end}}

Content:
---
{{.Content}}
---

Consider:
1. How actionable is this intelligence?
2. Is there immediate risk to the monitored entities?
3. How specific and credible is the threat?
4. Are there verifiable IOCs?

Severity levels:
- critical: Immediate action required (active breach, live credentials, canary triggered)
- high: Significant threat requiring prompt investigation
- medium: Notable activity worth tracking
- low: Background noise with some intelligence value
- info: Contextual information, no direct threat

Respond with ONLY a JSON object:
{"severity": "<level>", "reasoning": "<one sentence>"}
```

### `summarize.tmpl`

Produces a concise analyst-readable paragraph. Returns plain text, not JSON.

**Full template:**

```
You are a cyber threat intelligence analyst. Write a concise, analyst-readable summary of this finding.

Source: {{.Source}} ({{.SourceName}})
Category: {{.Category}}
Severity: {{.Severity}}
Author: {{.Author}}
Timestamp: {{.Timestamp}}

Content:
---
{{.Content}}
---

Write ONE paragraph (3-5 sentences) summarizing:
1. What was found
2. Who is involved (if identifiable)
3. What entities are affected
4. Recommended next steps

Be specific. Include IOC values directly in the summary. Do not pad with generic advice.
```

### `stylometry.tmpl`

Performs authorship attribution for actor profiling. Used outside the standard classification pipeline.

**Full template:**

```
You are a linguistic analyst specializing in authorship attribution. Analyze the writing style of this text.

Author handle: {{.Author}}
Platform: {{.Source}}

Text:
---
{{.Content}}
---

Extract these stylometric features as a JSON object:
{
  "avg_sentence_length": <float>,
  "vocabulary_richness": <float 0-1>,
  "punctuation_frequency": {"period": <float>, "comma": <float>, "exclamation": <float>, "question": <float>},
  "emoji_usage": <float 0-1>,
  "capitalization_style": "<all_lower|all_upper|mixed|title_case>",
  "common_typos": ["<list of recurring misspellings>"],
  "language_markers": ["<slang, dialect indicators, or language quirks>"],
  "formality_score": <float 0-1>,
  "technical_depth": <float 0-1>
}
```

---

## Classification Categories

Defined in `internal/models/finding.go`:

| Category | Meaning |
|---|---|
| `credential_leak` | Leaked credentials — usernames, passwords, API keys, session tokens |
| `malware_sample` | Malware hashes, C2 infrastructure, download links |
| `threat_actor_comms` | Actor discussions, planning, coordination |
| `access_broker` | Initial access being sold (RDP, VPN, shell) |
| `data_dump` | Bulk data leaks — databases, PII, financial records |
| `canary_hit` | A planted honeytoken was triggered |
| `irrelevant` | False positive — content matched a rule but is not a real threat |

---

## IOC Types

Defined in `internal/models/ioc.go`:

`ip`, `domain`, `hash_md5`, `hash_sha1`, `hash_sha256`, `email`, `crypto_wallet`, `url`, `cve`

---

## Background Workers

**File:** `internal/ingest/workers.go`

Two worker types process findings asynchronously after ingestion. Both are long-running goroutines managed by the ingest pipeline.

### Classification workers

1. Poll `archive.FetchUnclassified(ctx, batchSize)` — returns up to `batchSize` unprocessed entries.
2. For each entry, wait on the rate limiter, then call `Classify`.
3. Call `AssessSeverity` (no additional rate limit wait — severity is part of the same logical unit).
4. Wait on the rate limiter again, then call `Summarize`.
5. Persist results with `archive.MarkClassified(ctx, id, category, tags, severity, summary)`.

### Entity extraction workers

1. Poll `archive.FetchClassifiedUnextracted(ctx, batchSize)` — returns classified entries that have not yet had IOCs extracted.
2. For each entry, wait on the rate limiter, then call `ExtractIOCs`.
3. Upsert each returned IOC with `archive.UpsertIOC`.
4. Mark the entry complete with `archive.MarkEntitiesExtracted`.

### Rate limiting

Each worker type has its own shared `rateLimiter` instance (classification workers share one; entity extraction workers share another). The limiter enforces a **2-second minimum gap** between LLM API calls across all workers of the same type.

The implementation is TOCTOU-safe: the next available time slot is claimed under the mutex before releasing the lock, so two goroutines waking up simultaneously cannot both read the same `lastCall` value and both proceed without delay.

### Operational constants

| Constant | Value | Purpose |
|---|---|---|
| `defaultRateLimitDelay` | 2 seconds | Minimum gap between LLM calls per worker type |
| `workerIdleInterval` | 30 seconds | Sleep duration when no work is available |
| `workerLogInterval` | 10 items | Progress log frequency |
| `ClassificationBatchSize` | 10 (default) | Items fetched per poll (configurable) |

---

## Data Flow Summary

```
Raw content ingested
        |
        v
FetchUnclassified
        |
        v
  [rate limit wait]
        |
        v
    Classify ──> category + confidence
        |
        v
 AssessSeverity ──> severity + reasoning
        |
        v
  [rate limit wait]
        |
        v
   Summarize ──> plain text paragraph
        |
        v
  MarkClassified (persisted to archive)
        |
        v
FetchClassifiedUnextracted
        |
        v
  [rate limit wait]
        |
        v
  ExtractIOCs ──> []IOC
        |
        v
   UpsertIOC (for each IOC)
        |
        v
MarkEntitiesExtracted
```
