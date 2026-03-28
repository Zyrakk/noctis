package collector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/discovery"
	"github.com/Zyrakk/noctis/internal/health"
	"github.com/Zyrakk/noctis/internal/models"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth/qrlogin"
	"github.com/gotd/td/tg"
	"github.com/gotd/td/tgerr"
)

// telegramMessage is an internal type that decouples message processing from
// gotd/td types, making unit testing possible without a live Telegram connection.
type telegramMessage struct {
	ChannelID    int64
	ChannelName  string
	Text         string
	Author       string
	Date         time.Time
	ForwardFrom  string
	MediaCaption string
}

// toFinding converts a telegramMessage into a models.Finding.
// If Text is empty, MediaCaption is used as content instead.
func (m telegramMessage) toFinding() models.Finding {
	content := m.Text
	if content == "" {
		content = m.MediaCaption
	}

	f := models.NewFinding(
		models.SourceTypeTelegram,
		fmt.Sprintf("%d", m.ChannelID),
		m.ChannelName,
		content,
	)
	f.Author = m.Author
	f.Timestamp = m.Date

	if m.ForwardFrom != "" {
		if f.Metadata == nil {
			f.Metadata = make(map[string]string)
		}
		f.Metadata["forward_from"] = m.ForwardFrom
	}

	return *f
}

// SourceQuerier is the subset of discovery.Engine that collectors need for
// loading DB sources and recording collection timestamps. Using an interface
// allows nil checks and test doubles.
type SourceQuerier interface {
	GetApprovedSources(ctx context.Context, sourceType string) ([]discovery.Source, error)
	RecordCollectionByIdentifier(ctx context.Context, identifier string) error
}

// TelegramCollector implements the Collector interface for Telegram channels
// using the MTProto protocol via gotd/td.
type TelegramCollector struct {
	cfg       *config.TelegramConfig
	qrAuth    *health.QRAuthState
	discovery SourceQuerier
	seen      map[string]bool
	mu        sync.Mutex
}

// NewTelegramCollector creates a TelegramCollector from the given configuration.
func NewTelegramCollector(cfg *config.TelegramConfig, qrAuth *health.QRAuthState, disc SourceQuerier) *TelegramCollector {
	return &TelegramCollector{
		cfg:       cfg,
		qrAuth:    qrAuth,
		discovery: disc,
		seen:      make(map[string]bool),
	}
}

// Name returns the collector's identifier.
func (tc *TelegramCollector) Name() string {
	return "telegram"
}

// isDuplicate returns true if a finding with the given content hash has
// already been processed.
func (tc *TelegramCollector) isDuplicate(hash string) bool {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.seen[hash] {
		return true
	}
	tc.seen[hash] = true
	return false
}

// contentHash returns the hex-encoded SHA-256 of the given content string.
func contentHash(content string) string {
	sum := sha256.Sum256([]byte(content))
	return fmt.Sprintf("%x", sum)
}

// processMessage converts a telegramMessage to a Finding, deduplicates it,
// and sends it to the output channel.
func (tc *TelegramCollector) processMessage(ctx context.Context, msg telegramMessage, out chan<- models.Finding) {
	content := msg.Text
	if content == "" {
		content = msg.MediaCaption
	}
	if content == "" {
		return
	}

	hash := contentHash(content)
	if tc.isDuplicate(hash) {
		return
	}

	finding := msg.toFinding()

	select {
	case out <- finding:
	case <-ctx.Done():
	}
}

// Start connects to Telegram via MTProto, registers handlers for new channel
// messages, performs an optional catchup of recent messages, and blocks until
// ctx is cancelled. It closes the out channel on return.
func (tc *TelegramCollector) Start(ctx context.Context, out chan<- models.Finding) error {
	defer close(out)

	if !tc.cfg.Enabled {
		slog.Info("telegram: collector disabled")
		<-ctx.Done()
		return ctx.Err()
	}

	// Log configuration for debugging.
	slog.Info("telegram: starting collector",
		"apiId", tc.cfg.APIId,
		"phone", tc.cfg.Phone,
		"sessionFile", tc.cfg.SessionFile,
		"channels", len(tc.cfg.Channels),
		"catchupMessages", tc.cfg.CatchupMessages,
	)
	for i, ch := range tc.cfg.Channels {
		slog.Info("telegram: configured channel", "index", i, "username", ch.Username, "id", ch.ID)
	}

	// Create update dispatcher — used for both QR login signals and channel messages.
	dispatcher := tg.NewUpdateDispatcher()
	loggedIn := qrlogin.OnLoginToken(dispatcher)

	// Create client with file-based session storage.
	opts := telegram.Options{
		UpdateHandler: dispatcher,
		SessionStorage: &session.FileStorage{
			Path: tc.cfg.SessionFile,
		},
		Device: telegram.DeviceConfig{
			DeviceModel:    "Noctis",
			SystemVersion:  "Linux",
			AppVersion:     "1.0.0",
			SystemLangCode: "en",
			LangCode:       "en",
		},
	}
	client := telegram.NewClient(tc.cfg.APIId, tc.cfg.APIHash, opts)

	slog.Info("telegram: connecting to Telegram")

	return client.Run(ctx, func(ctx context.Context) error {
		// Check if we already have a valid session.
		if err := tc.ensureAuthorized(ctx, client, loggedIn); err != nil {
			return err
		}

		api := client.API()

		// Merge config channels with DB channels.
		channels := tc.cfg.Channels
		dbChannels := tc.loadDBChannels(ctx)
		if len(dbChannels) > 0 {
			channels = mergeChannels(channels, dbChannels)
			slog.Info("telegram: merged channels", "config", len(tc.cfg.Channels), "db", len(dbChannels), "total", len(channels))
		}

		// Track subscribed channels by normalized key.
		subscribed := make(map[string]bool, len(channels))
		for _, ch := range channels {
			subscribed[channelKey(ch)] = true
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

				// Update last_collected for all subscribed channels.
				for key := range subscribed {
					_ = tc.discovery.RecordCollectionByIdentifier(ctx, key)
				}

				newChannels := tc.checkForNewChannels(ctx, subscribed)
				for _, ch := range newChannels {
					subscribed[channelKey(ch)] = true
					tc.subscribeChannel(ctx, api, ch, out)
				}
				if len(newChannels) > 0 {
					slog.Info("telegram: subscribed to new channels", "count", len(newChannels), "total", len(subscribed))
				}
			}
		}
	})
}

// ensureAuthorized checks the session and, if not authorized, runs an inline
// QR login flow so the user can scan the login URL from kubectl logs.
func (tc *TelegramCollector) ensureAuthorized(ctx context.Context, client *telegram.Client, loggedIn qrlogin.LoggedIn) error {
	slog.Info("telegram: checking auth status")

	status, err := client.Auth().Status(ctx)
	if err != nil {
		slog.Warn("telegram: auth status check failed, will attempt QR login", "error", err)
	} else if status.Authorized {
		slog.Info("telegram: session is valid, skipping auth")
		return nil
	} else {
		slog.Info("telegram: session not authorized, starting QR login")
	}

	// Run QR login flow with 5-minute timeout.
	authCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	slog.Info("telegram: starting QR auth — scan the login URL with your Telegram app")
	slog.Info("telegram: open Telegram → Settings → Devices → Link Desktop Device")

	_, err = client.QR().Auth(authCtx, loggedIn, func(ctx context.Context, token qrlogin.Token) error {
		slog.Info("telegram: scan this URL on your phone",
			"url", token.URL(),
			"expires_in", time.Until(token.Expires()).Truncate(time.Second).String(),
		)
		fmt.Printf("\n=== TELEGRAM QR LOGIN ===\nScan this URL on your phone: %s\nExpires in: %s\n=========================\n\n",
			token.URL(),
			time.Until(token.Expires()).Truncate(time.Second),
		)
		if tc.qrAuth != nil {
			tc.qrAuth.SetToken(token.URL(), token.Expires())
		}
		return nil
	})

	if tgerr.Is(err, "SESSION_PASSWORD_NEEDED") {
		slog.Info("telegram: QR scan accepted, 2FA password required")
		password := tc.cfg.Password
		if password == "" {
			if tc.qrAuth != nil {
				tc.qrAuth.Clear()
			}
			slog.Error("telegram: 2FA password required but not configured — set 'password' in telegram config")
			return fmt.Errorf("telegram 2FA password required but not in config")
		}
		slog.Info("telegram: submitting 2FA password from config")
		if _, err := client.Auth().Password(ctx, password); err != nil {
			if tc.qrAuth != nil {
				tc.qrAuth.Clear()
			}
			slog.Error("telegram: 2FA auth failed", "error", err)
			return fmt.Errorf("telegram 2FA: %w", err)
		}
		slog.Info("telegram: 2FA auth successful")
		if tc.qrAuth != nil {
			tc.qrAuth.SetSuccess()
		}
		return nil
	}
	if err != nil {
		if tc.qrAuth != nil {
			tc.qrAuth.Clear()
		}
		slog.Error("telegram: QR auth failed", "error", err)
		return fmt.Errorf("telegram QR auth: %w", err)
	}

	slog.Info("telegram: QR auth successful, session saved")
	if tc.qrAuth != nil {
		tc.qrAuth.SetSuccess()
	}
	return nil
}

// catchupChannels fetches the most recent messages from each configured
// channel and sends them through the processing pipeline.
func (tc *TelegramCollector) catchupChannels(ctx context.Context, api *tg.Client, channels []config.ChannelConfig, out chan<- models.Finding) {
	for _, ch := range channels {
		if ctx.Err() != nil {
			return
		}

		channelName := resolveChannelName(ch)
		slog.Info("telegram: resolving channel", "channel", channelName)

		peer, err := tc.resolveChannelPeer(ctx, api, ch)
		if err != nil {
			slog.Error("telegram: failed to resolve channel", "channel", channelName, "error", err)
			continue
		}

		slog.Info("telegram: channel resolved", "channel", channelName, "channelId", peer.ChannelID)

		history, err := api.MessagesGetHistory(ctx, &tg.MessagesGetHistoryRequest{
			Peer:  peer,
			Limit: tc.cfg.CatchupMessages,
		})
		if err != nil {
			slog.Error("telegram: failed to get history", "channel", channelName, "error", err)
			continue
		}

		modified, ok := history.AsModified()
		if !ok {
			slog.Warn("telegram: unexpected history response type", "channel", channelName)
			continue
		}

		for _, msgClass := range modified.GetMessages() {
			msg, ok := msgClass.(*tg.Message)
			if !ok {
				continue
			}

			tc.processMessage(ctx, telegramMessage{
				ChannelID:   ch.ID,
				ChannelName: channelName,
				Text:        msg.Message,
				Date:        time.Unix(int64(msg.Date), 0),
			}, out)
		}

		slog.Info("telegram: catchup complete", "channel", channelName, "messages", len(modified.GetMessages()))

		// Update last_collected for this channel in the sources table.
		if tc.discovery != nil {
			if err := tc.discovery.RecordCollectionByIdentifier(ctx, channelKey(ch)); err != nil {
				slog.Error("telegram: failed to record collection", "channel", channelName, "error", err)
			}
		}
	}
}

// resolveChannelPeer resolves a channel config entry to an InputPeerChannel.
// It handles three cases: invite hash (private link), username (public channel),
// and raw numeric ID.
func (tc *TelegramCollector) resolveChannelPeer(ctx context.Context, api *tg.Client, ch config.ChannelConfig) (*tg.InputPeerChannel, error) {
	if ch.InviteHash != "" {
		return tc.resolveInviteLink(ctx, api, ch.InviteHash)
	}

	if ch.Username != "" {
		resolved, err := api.ContactsResolveUsername(ctx, &tg.ContactsResolveUsernameRequest{
			Username: ch.Username,
		})
		if err != nil {
			return nil, fmt.Errorf("resolve username %q: %w", ch.Username, err)
		}

		peer, ok := resolved.Peer.(*tg.PeerChannel)
		if !ok {
			return nil, fmt.Errorf("resolved peer for %q is not a channel", ch.Username)
		}

		// Find the access hash from the resolved chats.
		for _, chatClass := range resolved.Chats {
			channel, ok := chatClass.(*tg.Channel)
			if ok && channel.ID == peer.ChannelID {
				// Auto-join public channels so we receive updates without
				// the user having to manually join from the Telegram app.
				if shouldJoinChannel(ch) {
					_, joinErr := api.ChannelsJoinChannel(ctx, &tg.InputChannel{
						ChannelID:  channel.ID,
						AccessHash: channel.AccessHash,
					})
					if joinErr != nil {
						slog.Warn("telegram: auto-join channel failed (may already be joined)",
							"channel", ch.Username, "error", joinErr)
					} else {
						slog.Info("telegram: auto-joined public channel", "channel", ch.Username)
					}
				}

				return &tg.InputPeerChannel{
					ChannelID:  channel.ID,
					AccessHash: channel.AccessHash,
				}, nil
			}
		}

		return &tg.InputPeerChannel{ChannelID: peer.ChannelID}, nil
	}

	return &tg.InputPeerChannel{ChannelID: ch.ID}, nil
}

// resolveInviteLink resolves a private invite hash to an InputPeerChannel.
// It first checks whether the user has already joined (ChatInviteAlready),
// and if not, imports the invite to join the channel/group.
func (tc *TelegramCollector) resolveInviteLink(ctx context.Context, api *tg.Client, hash string) (*tg.InputPeerChannel, error) {
	hash = strings.TrimPrefix(hash, "+")

	invite, err := api.MessagesCheckChatInvite(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("check invite %q: %w", hash, err)
	}

	// Already joined — extract the channel directly.
	if already, ok := invite.(*tg.ChatInviteAlready); ok {
		channel, ok := already.Chat.(*tg.Channel)
		if !ok {
			return nil, fmt.Errorf("invite %q resolved to non-channel chat type", hash)
		}
		slog.Info("telegram: already joined invite link", "hash", hash, "channel", channel.Title)
		return &tg.InputPeerChannel{
			ChannelID:  channel.ID,
			AccessHash: channel.AccessHash,
		}, nil
	}

	// Not yet joined — import the invite to join.
	slog.Info("telegram: joining via invite link", "hash", hash)
	updates, err := api.MessagesImportChatInvite(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("import invite %q: %w", hash, err)
	}

	// Extract channel from the Updates response.
	if u, ok := updates.(*tg.Updates); ok {
		for _, chat := range u.Chats {
			if channel, ok := chat.(*tg.Channel); ok {
				slog.Info("telegram: joined via invite link", "hash", hash, "channel", channel.Title)
				return &tg.InputPeerChannel{
					ChannelID:  channel.ID,
					AccessHash: channel.AccessHash,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("invite %q: no channel found in join response", hash)
}

// resolveChannelName returns a human-readable name for a channel config entry,
// preferring the username over the numeric ID.
func resolveChannelName(ch config.ChannelConfig) string {
	if ch.Username != "" {
		return ch.Username
	}
	if ch.InviteHash != "" {
		return fmt.Sprintf("invite:%s", ch.InviteHash)
	}
	return fmt.Sprintf("channel:%d", ch.ID)
}

// shouldJoinChannel returns true if the channel config uses a username,
// meaning we should attempt to join the public channel before subscribing.
// Channels identified only by numeric ID or invite hash are handled separately.
func shouldJoinChannel(ch config.ChannelConfig) bool {
	return ch.Username != "" && ch.InviteHash == ""
}

// channelKey returns a unique key for a ChannelConfig, used for deduplication
// in the subscribed set. Invite hash channels use "invite:hash", public
// channels use the bare username, and numeric IDs use "id:N".
func channelKey(ch config.ChannelConfig) string {
	if ch.InviteHash != "" {
		return "invite:" + ch.InviteHash
	}
	if key := extractUsername(ch.Username); key != "" {
		return key
	}
	return fmt.Sprintf("id:%d", ch.ID)
}

// extractUsername normalizes a Telegram channel identifier to a bare username.
// Handles: "channelname", "@channelname", "https://t.me/channelname",
// "t.me/channelname", "http://t.me/channelname".
func extractUsername(identifier string) string {
	if identifier == "" {
		return ""
	}
	s := identifier
	for _, prefix := range []string{"https://", "http://"} {
		s = strings.TrimPrefix(s, prefix)
	}
	s = strings.TrimPrefix(s, "t.me/")
	s = strings.TrimPrefix(s, "@")
	s = strings.TrimSuffix(s, "/")
	return s
}

// loadDBChannels queries the sources table for approved/active telegram channels
// and groups, converting them to ChannelConfig entries. Sources with an
// "invite:+hash" identifier are loaded as invite hash channels.
func (tc *TelegramCollector) loadDBChannels(ctx context.Context) []config.ChannelConfig {
	if tc.discovery == nil {
		return nil
	}

	var channels []config.ChannelConfig

	// Load public channels.
	sources, err := tc.discovery.GetApprovedSources(ctx, "telegram_channel")
	if err != nil {
		slog.Error("telegram: failed to load DB channels", "error", err)
	}
	for _, src := range sources {
		// Handle invite hashes stored as telegram_channel type.
		// These arrive as "+hash", "invite:+hash", or full URLs like
		// "https://t.me/+hash" / "https://t.me/joinchat/hash".
		if hash, ok := strings.CutPrefix(src.Identifier, "invite:"); ok {
			channels = append(channels, config.ChannelConfig{InviteHash: hash})
			continue
		}
		username := extractUsername(src.Identifier)
		if username == "" {
			continue
		}
		if strings.HasPrefix(username, "+") {
			channels = append(channels, config.ChannelConfig{InviteHash: username})
			continue
		}
		if hash, ok := strings.CutPrefix(username, "joinchat/"); ok {
			channels = append(channels, config.ChannelConfig{InviteHash: hash})
			continue
		}
		channels = append(channels, config.ChannelConfig{Username: username})
	}

	// Load private groups/channels (invite links).
	groups, err := tc.discovery.GetApprovedSources(ctx, "telegram_group")
	if err != nil {
		slog.Error("telegram: failed to load DB groups", "error", err)
	}
	for _, src := range groups {
		if hash, ok := strings.CutPrefix(src.Identifier, "invite:"); ok {
			channels = append(channels, config.ChannelConfig{InviteHash: hash})
		}
	}

	return channels
}

// checkForNewChannels queries the DB for telegram channels not yet in the
// subscribed set and returns them as ChannelConfig entries.
func (tc *TelegramCollector) checkForNewChannels(ctx context.Context, subscribed map[string]bool) []config.ChannelConfig {
	dbChannels := tc.loadDBChannels(ctx)
	var newChannels []config.ChannelConfig

	for _, ch := range dbChannels {
		key := channelKey(ch)
		if subscribed[key] {
			continue
		}
		newChannels = append(newChannels, ch)
	}

	return newChannels
}

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

	// Update last_collected for this newly subscribed channel.
	if tc.discovery != nil {
		_ = tc.discovery.RecordCollectionByIdentifier(ctx, channelKey(ch))
	}

	slog.Info("telegram: subscribed to new channel", "channel", channelName)
}

// mergeChannels combines config channels with database-sourced channels,
// deduplicating by normalized username. Config channels take precedence.
func mergeChannels(cfgChannels, dbChannels []config.ChannelConfig) []config.ChannelConfig {
	seen := make(map[string]bool, len(cfgChannels))
	merged := make([]config.ChannelConfig, 0, len(cfgChannels)+len(dbChannels))

	for _, ch := range cfgChannels {
		seen[channelKey(ch)] = true
		merged = append(merged, ch)
	}

	for _, ch := range dbChannels {
		key := channelKey(ch)
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, ch)
	}

	return merged
}
