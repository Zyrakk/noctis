package collector

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/models"

	"github.com/gotd/td/session"
	"github.com/gotd/td/telegram"
	"github.com/gotd/td/telegram/auth"
	"github.com/gotd/td/tg"
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

// TelegramCollector implements the Collector interface for Telegram channels
// using the MTProto protocol via gotd/td.
type TelegramCollector struct {
	cfg  *config.TelegramConfig
	seen map[string]bool
	mu   sync.Mutex
}

// NewTelegramCollector creates a TelegramCollector from the given configuration.
func NewTelegramCollector(cfg *config.TelegramConfig) *TelegramCollector {
	return &TelegramCollector{
		cfg:  cfg,
		seen: make(map[string]bool),
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
		slog.Info("telegram collector disabled")
		<-ctx.Done()
		return ctx.Err()
	}

	// Create update dispatcher.
	dispatcher := tg.NewUpdateDispatcher()

	// Create client with file-based session storage.
	opts := telegram.Options{
		UpdateHandler: dispatcher,
		SessionStorage: &session.FileStorage{
			Path: tc.cfg.SessionFile,
		},
	}
	client := telegram.NewClient(tc.cfg.APIId, tc.cfg.APIHash, opts)

	return client.Run(ctx, func(ctx context.Context) error {
		// Build auth flow: use phone + password from config, error on code request
		// (first login must be done interactively; subsequent runs use the session file).
		flow := auth.NewFlow(
			auth.Constant(tc.cfg.Phone, tc.cfg.Password,
				auth.CodeAuthenticatorFunc(func(ctx context.Context, sentCode *tg.AuthSentCode) (string, error) {
					return "", fmt.Errorf("auth code required — run noctis interactively for first login")
				}),
			),
			auth.SendCodeOptions{},
		)

		// Authenticate if the session is not already valid.
		if err := client.Auth().IfNecessary(ctx, flow); err != nil {
			return fmt.Errorf("telegram auth: %w", err)
		}

		api := client.API()

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

		// Catchup: fetch last N messages from each configured channel.
		if tc.cfg.CatchupMessages > 0 {
			tc.catchupChannels(ctx, api, out)
		}

		slog.Info("telegram: listening for updates")
		<-ctx.Done()
		return ctx.Err()
	})
}

// catchupChannels fetches the most recent messages from each configured
// channel and sends them through the processing pipeline.
func (tc *TelegramCollector) catchupChannels(ctx context.Context, api *tg.Client, out chan<- models.Finding) {
	for _, ch := range tc.cfg.Channels {
		if ctx.Err() != nil {
			return
		}

		channelName := resolveChannelName(ch)
		peer, err := tc.resolveChannelPeer(ctx, api, ch)
		if err != nil {
			slog.Error("telegram: failed to resolve channel", "channel", channelName, "error", err)
			continue
		}

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
	}
}

// resolveChannelPeer resolves a channel config entry to an InputPeerChannel.
// If the channel has a username, it is resolved via the API; otherwise the
// raw ID is used (access hash will be zero, which works for channels the user
// has already joined).
func (tc *TelegramCollector) resolveChannelPeer(ctx context.Context, api *tg.Client, ch config.ChannelConfig) (*tg.InputPeerChannel, error) {
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

// resolveChannelName returns a human-readable name for a channel config entry,
// preferring the username over the numeric ID.
func resolveChannelName(ch config.ChannelConfig) string {
	if ch.Username != "" {
		return ch.Username
	}
	return fmt.Sprintf("channel:%d", ch.ID)
}
