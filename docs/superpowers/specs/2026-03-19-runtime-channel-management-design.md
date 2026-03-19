# Runtime Telegram Channel Management — Design Spec

## Goal

Make Telegram channel management work at runtime without pod restarts. Persist the Telegram session across restarts via PVC. Allow adding/approving channels via CLI with the collector picking them up automatically within 5 minutes.

## Architecture

Two changes: (1) replace emptyDir with PVC for session persistence, (2) make the Telegram collector DB-aware so it merges config channels with database sources and polls for new ones.

Config channels are the initial seed. All runtime additions go through the database. The collector merges both. No restart needed to add channels.

---

## 1. PVC for Telegram Session

Replace the `emptyDir` volume in `deploy/noctis.yaml` with a 1Gi PVC using the same StorageClass as PostgreSQL (`nfs-shared`).

**New PVC resource** (in `deploy/noctis.yaml`, before the Deployment):

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: noctis-data
  namespace: noctis
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: nfs-shared
  resources:
    requests:
      storage: 1Gi
```

**Volume change** in the Deployment spec:

```yaml
volumes:
  - name: config
    configMap:
      name: noctis-config
  - name: data
    persistentVolumeClaim:
      claimName: noctis-data
```

The Deployment strategy is already `Recreate`, which is required for RWO PVCs.

---

## 2. `noctis source add` CLI Command

New subcommand: `noctis source add --type <type> --identifier <identifier> -c <config>`

**File:** `cmd/noctis/source.go`

**Flags:**
- `--type` (string, required) — source type (telegram_channel, forum, web, etc.)
- `--identifier` (string, required) — the identifier (username for telegram, URL for others)
- `--config/-c` (string) — config path

**Behavior:**
- Calls `discovery.Engine.AddSource(ctx, sourceType, identifier)` (new method)
- CLI truncates the returned UUID to 8 chars for display (matching `source list` behavior)
- Prints: `source <shortID> added (type=telegram_channel, identifier=channelname, status=active)`

**New method on `discovery.Engine`:**

```go
func (e *Engine) AddSource(ctx context.Context, sourceType, identifier string) (string, error)
```

- Inserts with `status = 'active'`, `name = identifier`, relies on DB column defaults for `metadata`, `collection_interval`, etc.
- Uses `ON CONFLICT (identifier) DO UPDATE SET status = 'active', updated_at = NOW()` so re-adding reactivates
- Returns the full source UUID (CLI handles truncation for display)

Register `newSourceAddCmd()` alongside existing subcommands in `newSourceCmd()`.

---

## 3. Telegram Collector — DB-Aware Channel Merging

### 3a. New Dependency

Change `NewTelegramCollector` to accept `*discovery.Engine`:

```go
func NewTelegramCollector(
    cfg *config.TelegramConfig,
    qrAuth *health.QRAuthState,
    discovery *discovery.Engine,
) *TelegramCollector
```

Store as `tc.discovery`. Can be nil (tests, standalone without DB) — collector falls back to config-only behavior.

**Wire in `serve.go`:** Pass `discoveryEngine` when creating the Telegram collector.

### 3b. Startup: Merge Config + DB Channels

Inside `client.Run`, before catchup:

1. Start with `tc.cfg.Channels` (config seed)
2. If `tc.discovery != nil`, call `tc.discovery.GetApprovedSources(ctx, "telegram_channel")`
3. Convert each DB source to `config.ChannelConfig{Username: extractUsername(source.Identifier)}`
4. Merge: deduplicate by normalized username. Config channels take precedence.
5. Track all subscribed channels in `subscribed map[string]bool` (keyed by normalized username)
6. Run `catchupChannels` with the merged list

The `catchupChannels` method changes from reading `tc.cfg.Channels` to accepting a channels parameter.

**Note:** DB-sourced `ChannelConfig` values have `ID = 0` (zero value). This is fine because `resolveChannelPeer` uses the username path when `ch.Username != ""` and ignores the ID field entirely.

### 3c. `extractUsername` Helper

Normalizes any identifier format to bare username:

| Input | Output |
|-------|--------|
| `"channelname"` | `"channelname"` |
| `"@channelname"` | `"channelname"` |
| `"https://t.me/channelname"` | `"channelname"` |
| `"t.me/channelname"` | `"channelname"` |
| `"http://t.me/channelname"` | `"channelname"` |

Strips scheme, `t.me/` prefix, leading `@`, and any trailing `/`.

### 3d. Poll Loop: Check for New Channels Every 5 Minutes

Replace the current `<-ctx.Done()` block (telegram.go line 238) with a ticker loop:

```go
ticker := time.NewTicker(5 * time.Minute)
defer ticker.Stop()

for {
    select {
    case <-ctx.Done():
        slog.Info("telegram: shutting down")
        return ctx.Err()
    case <-ticker.C:
        if tc.discovery == nil {
            continue
        }
        newChannels := tc.checkForNewChannels(ctx, subscribed)
        for _, ch := range newChannels {
            key := extractUsername(ch.Username)
            subscribed[key] = true
            tc.subscribeChannel(ctx, api, ch, out)
        }
    }
}
```

**`checkForNewChannels`:**
- Queries `tc.discovery.GetApprovedSources(ctx, "telegram_channel")`
- Converts each to `config.ChannelConfig`
- Filters out channels already in `subscribed` map
- Returns only new ones

**`subscribeChannel`:**
- Resolves the peer via `resolveChannelPeer` (which already auto-joins)
- Runs catchup for this single channel: fetches last `tc.cfg.CatchupMessages` messages via `MessagesGetHistory`. If `CatchupMessages` is 0 (catchup disabled), still resolve+join but skip history fetch. The channel will receive new messages going forward via the update handler.
- Messages from catchup go through `tc.processMessage` (which uses the existing `tc.mu` mutex for dedup — thread-safe with the concurrent update handler)
- Logs the subscription

**Thread safety:** The `subscribed` map and poll loop run inside `client.Run`'s callback goroutine. The `OnNewChannelMessage` handler runs in dispatcher goroutines but never touches `subscribed`. No mutex needed for `subscribed`. The existing `tc.mu` mutex protects the `seen` dedup map, which IS accessed from both the poll loop (via catchup's `processMessage`) and the dispatcher (via the message handler's `processMessage`) — this is already safe.

**Key insight:** The `OnNewChannelMessage` handler fires for ALL channels the account has joined. Once we resolve+join a new channel, messages flow automatically. Catchup just fetches historical messages we missed.

---

## 4. End-to-End Flows

### Adding a channel at runtime

1. `kubectl exec deployment/noctis -- /noctis source add --type telegram_channel --identifier "newchannel" -c /etc/noctis/config.yaml`
2. Row inserted into sources table: `type=telegram_channel, identifier=newchannel, status=active`
3. Within 5 minutes: poll loop finds new channel, resolves username, auto-joins, runs catchup
4. Future messages arrive via existing `OnNewChannelMessage` handler

### Approving a discovered channel

1. Discovery engine finds `t.me/somechannel` in content → inserts with `status=discovered`
2. `noctis source approve <id>` → status changes to `approved`
3. Within 5 minutes: poll loop picks it up (`GetApprovedSources` returns approved+active)
4. `extractUsername("t.me/somechannel")` → `"somechannel"` → resolved and subscribed

### Session persistence across restarts

1. Pod restarts — PVC at `/data` persists
2. Telegram session file at `/data/telegram.session` survives
3. Collector starts, `ensureAuthorized` finds valid session → skips QR auth
4. No manual re-scanning needed

---

## 5. Files Changed

| Action | File | What Changes |
|--------|------|-------------|
| Modify | `deploy/noctis.yaml` | Add PVC resource, replace emptyDir with PVC reference |
| Modify | `cmd/noctis/source.go` | Add `newSourceAddCmd()`, register in `newSourceCmd()` |
| Modify | `internal/discovery/engine.go` | Add `AddSource()` method |
| Modify | `internal/collector/telegram.go` | Add discovery field, extractUsername, mergeChannels, poll loop, subscribeChannel, checkForNewChannels. Modify Start/catchupChannels. |
| Modify | `internal/collector/telegram_test.go` | Tests for extractUsername, mergeChannels, checkForNewChannels |
| Modify | `cmd/noctis/serve.go` | Pass discoveryEngine to NewTelegramCollector |

No new files. No schema changes (sources table already has everything needed).

**Note on test breakage:** Adding `*discovery.Engine` to `NewTelegramCollector` breaks all existing test calls. Fix by passing `nil` as the third argument — nil discovery engine means config-only mode (existing behavior).

---

## 6. Design Decisions

- **Normalize on read (Option B):** Discovery stores full URLs, `source add` stores bare usernames. The collector's `extractUsername` normalizes both forms. No migration needed.
- **Config channels as seed:** Config is read-only truth for initial channels. DB is the runtime source. Merge deduplicates by username, config wins on conflict.
- **5-minute poll interval:** Balances responsiveness with DB load. Not configurable initially — can be added later if needed.
- **`discovery.Engine` passed to collector:** Reuses existing `GetApprovedSources` query. No new DB layer needed.
- **`AddSource` uses ON CONFLICT DO UPDATE:** Re-adding an existing source reactivates it (sets status=active). Idempotent.
