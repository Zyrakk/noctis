# Collectors

Noctis collects threat intelligence through a set of pluggable collectors. Each collector runs as a long-lived goroutine, sends findings into a buffered channel, and shuts down cleanly on context cancellation.

---

## Collector Interface

**File:** `internal/collector/collector.go`

```go
type Collector interface {
    Name() string
    Start(ctx context.Context, out chan<- models.Finding) error
}
```

**Contract:**

- `Name()` returns a human-readable identifier used in logs and metrics.
- `Start()` blocks until `ctx` is cancelled. It **must** close `out` before returning.
- The channel `out` is buffered (size 50, allocated in `cmd/noctis/serve.go`). Collectors should respect `ctx.Done()` when the channel is full to avoid blocking indefinitely.
- Context cancellation is the graceful shutdown signal. Collectors must not leak goroutines after `Start()` returns.

---

## Tor Transport

**File:** `internal/collector/tor.go`

`NewTorTransport(proxyAddr string, timeout time.Duration) (*http.Transport, error)` creates an `http.Transport` that routes all connections through a SOCKS5 proxy (typically a local Tor daemon).

- Uses `golang.org/x/net/proxy` for SOCKS5 dialing with `DialContext` support.
- Returns an error if `proxyAddr` is empty or if the dialer does not implement `proxy.ContextDialer`.
- Collectors opt in by setting `tor: true` in their per-source config. The transport is shared across all Tor-enabled requests within a single collector instance.

**Config keys** (under `noctis.sources.tor`):

| Key | Type | Description |
|-----|------|-------------|
| `socksProxy` | string | SOCKS5 address, e.g. `127.0.0.1:9050` |
| `requestTimeout` | duration | Per-request timeout (default 60s when Tor is active) |

---

## Telegram Collector

**File:** `internal/collector/telegram.go`

Collects messages from Telegram channels via the MTProto protocol using the `gotd/td` library.

### How it works

1. **Session management:** On startup, checks for a valid stored session (`session.FileStorage` at the path given by `sessionFile`). If the session is not authorized, launches an interactive QR login flow.
2. **QR login:** Prints a `tg://login?token=…` URL to stdout and to the structured log. The URL is also exposed via the health server's `/qr` endpoint (`health.QRAuthState`). The user must scan the URL from Telegram on their phone within 5 minutes.
3. **2FA:** If the account has a Two-Step Verification password, the collector reads it from `password` in config and submits it automatically via `client.Auth().Password()`.
4. **Channel resolution:** For channels configured by `username`, resolves via `ContactsResolveUsername`. For numeric `id` entries, uses the raw ID with a zero access hash (works for already-joined channels).
5. **Catchup:** If `catchupMessages > 0`, fetches that many recent messages per channel via `MessagesGetHistory` before entering real-time mode.
6. **Real-time:** Registers `OnNewChannelMessage` on the update dispatcher. Extracts channel name, author username, forward source, message text, and media caption.
7. **Deduplication:** SHA-256 of message content, tracked in an in-memory `map[string]bool` guarded by a mutex. Duplicate content is silently dropped.

### Discovery engine integration

The collector accepts an optional `SourceQuerier` interface (the discovery engine) for runtime channel management.

- **On startup:** merges channels from config with all approved/active sources returned by the `SourceQuerier`. Both sets are deduplicated before the collector subscribes.
- **Every 5 minutes:** polls the `SourceQuerier` for newly added or approved channels (added via `noctis source add` or `noctis source approve`) and subscribes to any that are not already active.
- **When `nil`** (tests, standalone usage without a database): the collector falls back to config-only behavior. No database queries are made and no runtime polling occurs.

### Internal type

`telegramMessage` decouples message data from `gotd/td` types, enabling unit testing without a live Telegram connection. `toFinding()` converts it to `models.Finding`, using `MediaCaption` as fallback content when `Text` is empty.

### Metadata emitted

| Field | Value |
|-------|-------|
| `Finding.Source` | `"telegram"` |
| `Finding.SourceID` | Channel ID (string) |
| `Finding.SourceName` | Channel title |
| `Finding.Author` | Author username or first name |
| `Finding.Metadata["forward_from"]` | Original channel title (if forwarded) |

### Config reference

Config path: `noctis.sources.telegram`

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | bool | Enable this collector |
| `apiId` | int | Telegram application ID |
| `apiHash` | string | Telegram application hash |
| `phone` | string | Account phone number (logged only, not used for auth) |
| `password` | string | 2FA password (optional) |
| `sessionFile` | string | Path to persist the session file |
| `catchupMessages` | int | Historical messages to fetch per channel on startup |
| `channels` | list | Channels to monitor (see below) |

Each entry under `channels`:

| Key | Type | Description |
|-----|------|-------------|
| `username` | string | Public channel username (without `@`) |
| `id` | int64 | Numeric channel ID (used if `username` is empty) |

---

## Paste Collector

**File:** `internal/collector/paste.go`

Scrapes paste sites for threat intelligence content. Runs a separate polling goroutine for Pastebin and for each generic scraper defined in config, all within the same `Start()` call.

### Pastebin sub-collector

- Polls `https://scrape.pastebin.com/api_scraping.php?limit=50` at a configurable interval (default 60s). This endpoint requires a Pastebin Pro account.
- Parses the JSON response (`pastebinScrapeItem` list) and fetches the raw content for each new paste key via `ScrapeURL`.
- Deduplication is by paste `key` field (in-memory map).
- Emits `title` and `full_url` in finding metadata.

### Generic scraper sub-collector

- Fetches the index page of any paste-like site and extracts links matching the paste URL pattern: `/[A-Za-z0-9]{6,20}$`.
- Links are also matched if they contain `/paste` or `/raw` in the path.
- Deduplication is by full URL.
- Polls at a configurable interval (default 120s).
- Supports per-scraper Tor routing via `tor: true`.

### Config reference

Config path: `noctis.sources.paste`

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | bool | Enable this collector |
| `pastebin.enabled` | bool | Enable the Pastebin sub-collector |
| `pastebin.interval` | duration | Poll interval (default 60s) |
| `scrapers` | list | Generic paste-site scrapers |

Each entry under `scrapers`:

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Human-readable name |
| `url` | string | Index page URL to scrape |
| `interval` | duration | Poll interval (default 120s) |
| `tor` | bool | Route requests through Tor |

---

## Forum Collector

**File:** `internal/collector/forum.go`

CSS-selector-based scraper for underground forums. Runs one polling goroutine per configured site.

### How it works

1. **Auth:** If `auth.loginURL` is set, performs a `POST` to that URL with form fields `usernameField` / `passwordField` (defaults: `username`, `password`). Stores the resulting session cookies in a per-client `cookiejar`.
2. **Thread list crawl:** Fetches the forum's entry URL and applies `threadListSelector` to extract thread links. Follows `paginationSelector` to get more pages, up to `maxPagesPerCrawl` (default 5).
3. **Thread scraping:** Fetches each thread URL, applies `threadContentSelector` and `authorSelector` to extract posts and authors. Author lookup walks up to 5 ancestor elements from the content element to find the author in the same container.
4. **Rate limiting:** Sleeps `requestDelay` (default 3s) between each page request, respecting context cancellation.
5. **Deduplication:** SHA-256 of post content, tracked in an in-memory map (capped at 100,000 entries; map is reset when exceeded, since the archive provides true dedup).
6. **Circuit breaker:** Tracks consecutive HTTP errors per site. After 5 consecutive errors, enters exponential backoff starting at 30s and doubling on each trigger, capped at 1 hour. Resets to initial state on the first successful response.
7. **Tor support:** Per-site opt-in via `tor: true`.
8. **User-Agent rotation:** Round-robin across 4 modern browser strings (Chrome, Safari, Firefox, Edge).

### Metadata emitted

| Field | Value |
|-------|-------|
| `Finding.Source` | `"forum"` |
| `Finding.SourceID` | Thread URL |
| `Finding.SourceName` | Site name from config |
| `Finding.Author` | Extracted author text |
| `Finding.Metadata["thread_url"]` | Thread URL |
| `Finding.Metadata["extracted_links"]` | Comma-separated links found on the thread page |

### Config reference

Config path: `noctis.sources.forums`

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | bool | Enable this collector |
| `sites` | list | Forum sites to scrape |

Each entry under `sites`:

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Human-readable site name |
| `url` | string | Forum entry URL (thread list page) |
| `tor` | bool | Route requests through Tor |
| `interval` | duration | Crawl interval (default 5m) |
| `maxPagesPerCrawl` | int | Max pagination pages per cycle (default 5) |
| `requestDelay` | duration | Delay between page requests (default 3s) |
| `auth.loginURL` | string | POST URL for form-based login |
| `auth.username` | string | Login username |
| `auth.password` | string | Login password |
| `auth.usernameField` | string | Form field name for username (default `username`) |
| `auth.passwordField` | string | Form field name for password (default `password`) |
| `scraper.threadListSelector` | string | CSS selector to extract thread links |
| `scraper.threadContentSelector` | string | CSS selector for post content |
| `scraper.authorSelector` | string | CSS selector for post author |
| `scraper.paginationSelector` | string | CSS selector for the "next page" link |

---

## Web Collector

**File:** `internal/collector/web.go`

Collects from RSS/Atom feeds, scraped web pages, and search engine result pages. Runs one goroutine per feed entry.

### Feed types

**`rss`** — RSS/Atom feed parsing via `github.com/mmcdole/gofeed`. Extracts item description (or content as fallback), author, publication timestamp, and link. Deduplication by SHA-256 of description content.

**`scrape`** — HTML page scraped via `github.com/PuerkitoBio/goquery`. Requires `contentSelector`. Emits one finding per matching element. Deduplication by SHA-256 of text content.

**`search`** — URL template with `{query}` substitution (URL-encoded). For each entry in `queries`, fetches the search results page, extracts all `<a href>` links (capped at 20), fetches each link, and emits the full body text. Deduplication by SHA-256 of the result URL. Default interval is 15 minutes.

All types support Tor routing and User-Agent rotation. Response bodies are capped at 10 MB. The dedup map resets at 100,000 entries.

### Metadata emitted

| Feed type | Metadata fields |
|-----------|-----------------|
| `rss` | `url` (item link), `title` (item title) |
| `scrape` | `url` (feed URL) |
| `search` | `query`, `url` (result URL), `extracted_links` (comma-separated all links from results page) |

### Config reference

Config path: `noctis.sources.web`

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | bool | Enable this collector |
| `feeds` | list | Feed sources to poll |

Each entry under `feeds`:

| Key | Type | Description |
|-----|------|-------------|
| `name` | string | Human-readable feed name |
| `url` | string | Feed URL or URL template (for `search` type, include `{query}`) |
| `type` | string | `rss`, `scrape`, or `search` |
| `contentSelector` | string | CSS selector (required for `scrape` type) |
| `queries` | list | Search terms (required for `search` type) |
| `interval` | duration | Poll interval (default 5m for rss/scrape, 15m for search) |
| `tor` | bool | Route requests through Tor |

---

## Adding a New Collector

1. **Implement the interface.** Create `internal/collector/mytype.go` with a struct that implements `Name() string` and `Start(ctx context.Context, out chan<- models.Finding) error`. Always `defer close(out)` as the first statement in `Start`.

2. **Add configuration.** Add a config struct to `internal/config/config.go` and embed it in `SourcesConfig` with a YAML tag.

3. **Register in serve.go.** In `cmd/noctis/serve.go`, add a block following the existing pattern:
   ```go
   if cfg.Sources.MyType.Enabled {
       mc := collector.NewMyTypeCollector(&cfg.Sources.MyType, &cfg.Sources.Tor)
       collectors = append(collectors, mc)
       slog.Info("mytype collector enabled")
   }
   ```

4. **Add config section.** Add the corresponding YAML block to `deploy/configmap.yaml`.

5. **Write tests.** Add `internal/collector/mytype_test.go`. Use a small internal type to decouple from external dependencies (see `telegramMessage` as a reference pattern).
