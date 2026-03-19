# Runtime Telegram Channel Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable runtime Telegram channel management without pod restarts — persistent session via PVC, `source add` CLI, and a polling collector that merges config + database channels.

**Architecture:** Replace emptyDir with PVC for session persistence. Add `AddSource` to discovery engine + `source add` CLI. Refactor TelegramCollector to accept `*discovery.Engine`, merge config+DB channels on startup, and poll every 5 minutes for new channels.

**Tech Stack:** Go, gotd/td, pgx/v5, cobra, Kubernetes PVC

---

## File Structure

| Action | File | Responsibility |
|--------|------|----------------|
| Modify | `deploy/noctis.yaml` | Add PVC, replace emptyDir volume reference |
| Modify | `internal/discovery/engine.go` | Add `AddSource()` method |
| Modify | `internal/discovery/engine_test.go` | Test for `AddSource()` |
| Modify | `cmd/noctis/source.go` | Add `newSourceAddCmd()`, register it |
| Modify | `internal/collector/telegram.go` | Add discovery field, `extractUsername`, `mergeChannels`, `checkForNewChannels`, `subscribeChannel`, poll loop. Modify `Start`, `catchupChannels`. |
| Modify | `internal/collector/telegram_test.go` | Tests for `extractUsername`, `mergeChannels`. Fix existing constructor calls. |
| Modify | `cmd/noctis/serve.go` | Pass `discoveryEngine` to `NewTelegramCollector` |

---

### Task 1: PVC for Telegram Session Persistence

**Files:**
- Modify: `deploy/noctis.yaml`

- [ ] **Step 1: Add PVC resource and update volume reference**

In `deploy/noctis.yaml`, add a PVC resource block before the `---` Deployment separator, and replace the `emptyDir: {}` volume with a PVC reference.

Add this block at the very top of the file (before the Deployment):

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
---
```

Then change the volumes section (currently at line 64-69) from:

```yaml
      volumes:
        - name: config
          configMap:
            name: noctis-config
        - name: data
          emptyDir: {}
```

to:

```yaml
      volumes:
        - name: config
          configMap:
            name: noctis-config
        - name: data
          persistentVolumeClaim:
            claimName: noctis-data
```

- [ ] **Step 2: Verify YAML is valid**

Run: `kubectl apply --dry-run=client -f deploy/noctis.yaml`
Expected: resources validated successfully (or "configured" dry-run output).

- [ ] **Step 3: Commit**

```bash
git add deploy/noctis.yaml
git commit -m "deploy: replace emptyDir with PVC for Telegram session persistence"
```

---

### Task 2: AddSource Method on Discovery Engine

**Files:**
- Modify: `internal/discovery/engine.go`

- [ ] **Step 1: Add `AddSource` method**

Add this method to `internal/discovery/engine.go`, after the existing `ApproveSource` method (around line 229):

```go
// AddSource explicitly adds a new source with status "active". If a source
// with the same identifier already exists, it is reactivated (status set to
// "active"). Returns the source ID.
func (e *Engine) AddSource(ctx context.Context, sourceType, identifier string) (string, error) {
	var id string
	err := e.pool.QueryRow(ctx, `
INSERT INTO sources (type, identifier, name, status)
VALUES ($1, $2, $2, 'active')
ON CONFLICT (identifier) DO UPDATE SET status = 'active', updated_at = NOW()
RETURNING id`, sourceType, identifier).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("discovery: add source %q: %w", identifier, err)
	}
	return id, nil
}
```

- [ ] **Step 2: Run existing tests to ensure nothing breaks**

Run: `go test ./internal/discovery/ -v -count=1`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add internal/discovery/engine.go
git commit -m "feat: add AddSource method to discovery engine for explicit source registration"
```

---

### Task 3: `noctis source add` CLI Command

**Files:**
- Modify: `cmd/noctis/source.go`

- [ ] **Step 1: Add `newSourceAddCmd` function**

Add this function to `cmd/noctis/source.go`, after `newSourceRemoveCmd` (around line 174):

```go
func newSourceAddCmd() *cobra.Command {
	var configPath string
	var sourceType string
	var identifier string

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new source for collection",
		RunE: func(cmd *cobra.Command, args []string) error {
			if sourceType == "" {
				return fmt.Errorf("--type is required")
			}
			if identifier == "" {
				return fmt.Errorf("--identifier is required")
			}

			eng, cleanup, err := getDiscoveryEngine(configPath)
			if err != nil {
				return err
			}
			defer cleanup()

			ctx := context.Background()
			id, err := eng.AddSource(ctx, sourceType, identifier)
			if err != nil {
				return fmt.Errorf("adding source: %w", err)
			}

			shortID := id
			if len(shortID) > 8 {
				shortID = shortID[:8]
			}

			fmt.Printf("source %s added (type=%s, identifier=%s, status=active)\n", shortID, sourceType, identifier)
			return nil
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "noctis-config.yaml", "path to config file")
	cmd.Flags().StringVar(&sourceType, "type", "", "source type (telegram_channel, telegram_group, forum, paste_site, web, rss)")
	cmd.Flags().StringVar(&identifier, "identifier", "", "source identifier (username for telegram, URL for others)")

	return cmd
}
```

- [ ] **Step 2: Register in `newSourceCmd`**

In `newSourceCmd()` (line 16-28), add the registration alongside the others:

Change:

```go
	cmd.AddCommand(newSourceListCmd())
	cmd.AddCommand(newSourceApproveCmd())
	cmd.AddCommand(newSourcePauseCmd())
	cmd.AddCommand(newSourceRemoveCmd())
```

to:

```go
	cmd.AddCommand(newSourceListCmd())
	cmd.AddCommand(newSourceAddCmd())
	cmd.AddCommand(newSourceApproveCmd())
	cmd.AddCommand(newSourcePauseCmd())
	cmd.AddCommand(newSourceRemoveCmd())
```

- [ ] **Step 3: Build to verify compilation**

Run: `go build ./cmd/noctis/`
Expected: compiles without errors.

- [ ] **Step 4: Commit**

```bash
git add cmd/noctis/source.go
git commit -m "feat: add 'noctis source add' CLI command for runtime source registration"
```

---

### Task 4: extractUsername and mergeChannels Helpers (TDD)

**Files:**
- Modify: `internal/collector/telegram_test.go`
- Modify: `internal/collector/telegram.go`

- [ ] **Step 1: Write failing tests for `extractUsername`**

Add to `internal/collector/telegram_test.go`:

```go
func TestExtractUsername(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"channelname", "channelname"},
		{"@channelname", "channelname"},
		{"https://t.me/channelname", "channelname"},
		{"http://t.me/channelname", "channelname"},
		{"t.me/channelname", "channelname"},
		{"https://t.me/channelname/", "channelname"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractUsername(tt.input)
			if got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/collector/ -run TestExtractUsername -v`
Expected: FAIL — `extractUsername` not defined.

- [ ] **Step 3: Implement `extractUsername`**

Add to `internal/collector/telegram.go`, after `shouldJoinChannel` (line 436):

```go
// extractUsername normalizes a Telegram channel identifier to a bare username.
// Handles: "channelname", "@channelname", "https://t.me/channelname",
// "t.me/channelname", "http://t.me/channelname".
func extractUsername(identifier string) string {
	if identifier == "" {
		return ""
	}
	// Strip scheme
	s := identifier
	for _, prefix := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, prefix)
	}
	// Strip t.me/ prefix
	s = strings.TrimPrefix(s, "t.me/")
	// Strip leading @ and trailing /
	s = strings.TrimPrefix(s, "@")
	s = strings.TrimSuffix(s, "/")
	return s
}
```

Also add `"strings"` to the import block if not already present (it's not currently imported in telegram.go).

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/collector/ -run TestExtractUsername -v`
Expected: PASS

- [ ] **Step 5: Write failing test for `mergeChannels`**

Add to `internal/collector/telegram_test.go`:

```go
func TestMergeChannels(t *testing.T) {
	cfgChannels := []config.ChannelConfig{
		{Username: "alpha"},
		{Username: "beta"},
	}
	dbChannels := []config.ChannelConfig{
		{Username: "beta"},  // duplicate — should be skipped
		{Username: "gamma"}, // new — should be added
	}

	merged := mergeChannels(cfgChannels, dbChannels)

	if len(merged) != 3 {
		t.Fatalf("expected 3 channels, got %d", len(merged))
	}

	names := make(map[string]bool)
	for _, ch := range merged {
		names[ch.Username] = true
	}
	for _, want := range []string{"alpha", "beta", "gamma"} {
		if !names[want] {
			t.Errorf("expected channel %q in merged list", want)
		}
	}
}
```

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/collector/ -run TestMergeChannels -v`
Expected: FAIL — `mergeChannels` not defined.

- [ ] **Step 7: Implement `mergeChannels`**

Add to `internal/collector/telegram.go`, after `extractUsername`:

```go
// mergeChannels combines config channels with database-sourced channels,
// deduplicating by normalized username. Config channels take precedence.
func mergeChannels(cfgChannels, dbChannels []config.ChannelConfig) []config.ChannelConfig {
	seen := make(map[string]bool, len(cfgChannels))
	merged := make([]config.ChannelConfig, 0, len(cfgChannels)+len(dbChannels))

	for _, ch := range cfgChannels {
		key := extractUsername(ch.Username)
		if key == "" {
			key = fmt.Sprintf("id:%d", ch.ID)
		}
		seen[key] = true
		merged = append(merged, ch)
	}

	for _, ch := range dbChannels {
		key := extractUsername(ch.Username)
		if key == "" {
			continue
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, ch)
	}

	return merged
}
```

- [ ] **Step 8: Run all collector tests**

Run: `go test ./internal/collector/ -v -count=1`
Expected: ALL pass (including new tests and existing ones).

- [ ] **Step 9: Commit**

```bash
git add internal/collector/telegram.go internal/collector/telegram_test.go
git commit -m "feat: add extractUsername and mergeChannels helpers for runtime channel management"
```

---

### Task 5: Wire Discovery Engine into TelegramCollector

**Files:**
- Modify: `internal/collector/telegram.go`
- Modify: `internal/collector/telegram_test.go`
- Modify: `cmd/noctis/serve.go`

- [ ] **Step 1: Add discovery field to TelegramCollector struct and update constructor**

In `internal/collector/telegram.go`, modify the struct (line 63-68):

Change:

```go
type TelegramCollector struct {
	cfg    *config.TelegramConfig
	qrAuth *health.QRAuthState
	seen   map[string]bool
	mu     sync.Mutex
}
```

to:

```go
type TelegramCollector struct {
	cfg       *config.TelegramConfig
	qrAuth    *health.QRAuthState
	discovery SourceQuerier
	seen      map[string]bool
	mu        sync.Mutex
}
```

Add a minimal interface for testability (before the struct definition):

```go
// SourceQuerier is the subset of discovery.Engine that the Telegram collector
// needs. Using an interface allows nil checks and test doubles.
type SourceQuerier interface {
	GetApprovedSources(ctx context.Context, sourceType string) ([]discovery.Source, error)
}
```

Add `"github.com/Zyrakk/noctis/internal/discovery"` to the imports.

Modify the constructor (line 71-77):

Change:

```go
func NewTelegramCollector(cfg *config.TelegramConfig, qrAuth *health.QRAuthState) *TelegramCollector {
	return &TelegramCollector{
		cfg:    cfg,
		qrAuth: qrAuth,
		seen:   make(map[string]bool),
	}
}
```

to:

```go
func NewTelegramCollector(cfg *config.TelegramConfig, qrAuth *health.QRAuthState, disc SourceQuerier) *TelegramCollector {
	return &TelegramCollector{
		cfg:       cfg,
		qrAuth:    qrAuth,
		discovery: disc,
		seen:      make(map[string]bool),
	}
}
```

- [ ] **Step 2: Fix existing tests — pass nil as third arg**

In `internal/collector/telegram_test.go`, update ALL calls to `NewTelegramCollector`:

Change every `NewTelegramCollector(&config.TelegramConfig{...}, nil)` to `NewTelegramCollector(&config.TelegramConfig{...}, nil, nil)`.

There should be exactly 2 calls to fix (lines 86 and 93 approximately).

- [ ] **Step 3: Update serve.go to pass discovery engine**

In `cmd/noctis/serve.go`, change line 153:

From:

```go
			tc := collector.NewTelegramCollector(&cfg.Sources.Telegram, qrAuth)
```

to:

```go
			tc := collector.NewTelegramCollector(&cfg.Sources.Telegram, qrAuth, discoveryEngine)
```

- [ ] **Step 4: Build and run tests**

Run: `go build ./cmd/noctis/ && go test ./internal/collector/ -v -count=1`
Expected: compiles and all tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/collector/telegram.go internal/collector/telegram_test.go cmd/noctis/serve.go
git commit -m "refactor: wire discovery engine into TelegramCollector for runtime channel management"
```

---

### Task 6: Startup Merge + Poll Loop + subscribeChannel

**Files:**
- Modify: `internal/collector/telegram.go`

This is the core task. Modify `Start()` to merge config+DB channels on startup, then poll every 5 minutes for new channels.

- [ ] **Step 1: Add `loadDBChannels` helper**

Add after `mergeChannels` in `telegram.go`:

```go
// loadDBChannels queries the sources table for approved/active telegram channels
// and converts them to ChannelConfig entries.
func (tc *TelegramCollector) loadDBChannels(ctx context.Context) []config.ChannelConfig {
	if tc.discovery == nil {
		return nil
	}

	sources, err := tc.discovery.GetApprovedSources(ctx, "telegram_channel")
	if err != nil {
		slog.Error("telegram: failed to load DB channels", "error", err)
		return nil
	}

	channels := make([]config.ChannelConfig, 0, len(sources))
	for _, src := range sources {
		username := extractUsername(src.Identifier)
		if username == "" {
			continue
		}
		channels = append(channels, config.ChannelConfig{Username: username})
	}

	return channels
}
```

- [ ] **Step 2: Add `checkForNewChannels` method**

```go
// checkForNewChannels queries the DB for telegram channels not yet in the
// subscribed set and returns them as ChannelConfig entries.
func (tc *TelegramCollector) checkForNewChannels(ctx context.Context, subscribed map[string]bool) []config.ChannelConfig {
	dbChannels := tc.loadDBChannels(ctx)
	var newChannels []config.ChannelConfig

	for _, ch := range dbChannels {
		key := extractUsername(ch.Username)
		if key == "" || subscribed[key] {
			continue
		}
		newChannels = append(newChannels, ch)
	}

	return newChannels
}
```

- [ ] **Step 3: Add `subscribeChannel` method**

```go
// subscribeChannel resolves, joins, and optionally catches up a single channel
// that was discovered at runtime.
func (tc *TelegramCollector) subscribeChannel(ctx context.Context, api *tg.Client, ch config.ChannelConfig, out chan<- models.Finding) {
	channelName := resolveChannelName(ch)
	slog.Info("telegram: subscribing to new channel", "channel", channelName)

	peer, err := tc.resolveChannelPeer(ctx, api, ch)
	if err != nil {
		slog.Error("telegram: failed to resolve new channel", "channel", channelName, "error", err)
		return
	}

	// Run catchup if configured.
	if tc.cfg.CatchupMessages > 0 {
		history, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
			Peer:  peer,
			Limit: tc.cfg.CatchupMessages,
		})
		if err != nil {
			slog.Error("telegram: failed to get history for new channel", "channel", channelName, "error", err)
			return
		}

		modified, ok := history.AsModified()
		if ok {
			for _, msgClass := range modified.GetMessages() {
				msg, ok := msgClass.(*tg.Message)
				if !ok {
					continue
				}
				tc.processMessage(ctx, telegramMessage{
					ChannelID:   peer.ChannelID,
					ChannelName: channelName,
					Text:        msg.Message,
					Date:        time.Unix(int64(msg.Date), 0),
				}, out)
			}
			slog.Info("telegram: catchup complete for new channel", "channel", channelName, "messages", len(modified.GetMessages()))
		}
	}

	slog.Info("telegram: subscribed to new channel", "channel", channelName)
}
```

- [ ] **Step 4: Modify `catchupChannels` to accept a channels parameter**

Change `catchupChannels` signature from:

```go
func (tc *TelegramCollector) catchupChannels(ctx context.Context, api *tg.Client, out chan<- models.Finding) {
	for _, ch := range tc.cfg.Channels {
```

to:

```go
func (tc *TelegramCollector) catchupChannels(ctx context.Context, api *tg.Client, channels []config.ChannelConfig, out chan<- models.Finding) {
	for _, ch := range channels {
```

- [ ] **Step 5: Modify `Start` — merge channels on startup + poll loop**

Replace the section inside `client.Run` (from after `ensureAuthorized` to the end of the callback). The full replacement for lines 178-241:

```go
		api := client.API()

		// Merge config channels with DB channels.
		channels := tc.cfg.Channels
		dbChannels := tc.loadDBChannels(ctx)
		if len(dbChannels) > 0 {
			channels = mergeChannels(channels, dbChannels)
			slog.Info("telegram: merged channels", "config", len(tc.cfg.Channels), "db", len(dbChannels), "total", len(channels))
		}

		// Track subscribed channels by normalized username.
		subscribed := make(map[string]bool, len(channels))
		for _, ch := range channels {
			key := extractUsername(ch.Username)
			if key == "" {
				key = fmt.Sprintf("id:%d", ch.ID)
			}
			subscribed[key] = true
		}

		// Register handler for new channel messages.
		dispatcher.OnNewChannelMessage(func(ctx context.Context, e tg.Entities, update *tg.UpdateNewChannelMessage) error {
			msg, ok := update.Message.(*tg.Message)
			if !ok {
				return nil
			}

			channelName := "unknown"
			var channelID int64
			if peer, ok := msg.PeerID.(*tg.PeerChannel); ok {
				channelID = peer.ChannelID
				if ch, ok := e.Channels[peer.ChannelID]; ok {
					channelName = ch.Title
				}
			}

			slog.Info("telegram: received message", "channel", channelName, "channelId", channelID)

			author := ""
			if msg.FromID != nil {
				if u, ok := msg.FromID.(*tg.PeerUser); ok {
					if user, ok := e.Users[u.UserID]; ok {
						author = user.Username
						if author == "" {
							author = user.FirstName
						}
					}
				}
			}

			forwardFrom := ""
			if fwd, ok := msg.GetFwdFrom(); ok && fwd.FromID != nil {
				if p, ok := fwd.FromID.(*tg.PeerChannel); ok {
					if ch, ok := e.Channels[p.ChannelID]; ok {
						forwardFrom = ch.Title
					}
				}
			}

			tc.processMessage(ctx, telegramMessage{
				ChannelID:   channelID,
				ChannelName: channelName,
				Text:        msg.Message,
				Author:      author,
				Date:        time.Unix(int64(msg.Date), 0),
				ForwardFrom: forwardFrom,
			}, out)

			return nil
		})

		// Catchup: fetch last N messages from each channel.
		if tc.cfg.CatchupMessages > 0 {
			slog.Info("telegram: starting catchup", "messagesPerChannel", tc.cfg.CatchupMessages)
			tc.catchupChannels(ctx, api, channels, out)
		}

		slog.Info("telegram: listening for updates", "channels", len(channels))

		// Poll for new channels every 5 minutes.
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
				if len(newChannels) > 0 {
					slog.Info("telegram: subscribed to new channels", "count", len(newChannels), "total", len(subscribed))
				}
			}
		}
```

- [ ] **Step 6: Build and run all tests**

Run: `go build ./cmd/noctis/ && go test ./internal/collector/ -v -count=1`
Expected: compiles and all tests pass.

- [ ] **Step 7: Run full test suite**

Run: `make test`
Expected: all packages pass.

- [ ] **Step 8: Commit**

```bash
git add internal/collector/telegram.go
git commit -m "feat: runtime channel management — merge config+DB channels, poll every 5 minutes"
```

---

### Task 7: Update Documentation

**Files:**
- Modify: `docs/deployment.md`
- Modify: `docs/telegram.md`
- Modify: `docs/collectors.md`

- [ ] **Step 1: Update deployment.md**

In `docs/deployment.md`, find the troubleshooting section about "Telegram session lost on restart" and update it to note that the default manifests now use a PVC. Also add a note about `source add` in the Source Management section.

- [ ] **Step 2: Update telegram.md**

In `docs/telegram.md`, update the Session Persistence section to reflect that the default deployment now uses a PVC. Add a section on runtime channel management documenting:
- `noctis source add --type telegram_channel --identifier "channelname" -c config.yaml`
- The 5-minute poll interval
- That approved discovered channels are also picked up automatically
- Config channels are the seed, DB is for runtime additions

- [ ] **Step 3: Update collectors.md**

In `docs/collectors.md`, update the Telegram Collector section to mention the discovery engine integration and runtime channel management.

- [ ] **Step 4: Commit**

```bash
git add docs/deployment.md docs/telegram.md docs/collectors.md
git commit -m "docs: update deployment, telegram, and collectors docs for runtime channel management"
```

---

## Summary

| Task | Description | Files Modified |
|------|-------------|----------------|
| 1 | PVC for session persistence | deploy/noctis.yaml |
| 2 | AddSource on discovery.Engine | internal/discovery/engine.go |
| 3 | `noctis source add` CLI command | cmd/noctis/source.go |
| 4 | extractUsername + mergeChannels (TDD) | telegram.go, telegram_test.go |
| 5 | Wire discovery engine into collector | telegram.go, telegram_test.go, serve.go |
| 6 | Startup merge + poll loop | telegram.go |
| 7 | Documentation updates | docs/*.md |

Total: 7 tasks, 7 files modified, 0 new files.
