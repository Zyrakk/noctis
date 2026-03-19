package collector

import (
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/models"
)

func TestTelegramMessageToFinding(t *testing.T) {
	msg := telegramMessage{
		ChannelID:   12345,
		ChannelName: "threat_intel",
		Text:        "credential dump: admin:hunter2",
		Author:      "darkops",
		Date:        time.Date(2026, 3, 14, 10, 0, 0, 0, time.UTC),
	}

	f := msg.toFinding()

	if f.Source != models.SourceTypeTelegram {
		t.Errorf("expected Source=%q, got %q", models.SourceTypeTelegram, f.Source)
	}
	if f.SourceID != "12345" {
		t.Errorf("expected SourceID=%q, got %q", "12345", f.SourceID)
	}
	if f.SourceName != "threat_intel" {
		t.Errorf("expected SourceName=%q, got %q", "threat_intel", f.SourceName)
	}
	if f.Content != "credential dump: admin:hunter2" {
		t.Errorf("expected Content=%q, got %q", "credential dump: admin:hunter2", f.Content)
	}
	if f.Author != "darkops" {
		t.Errorf("expected Author=%q, got %q", "darkops", f.Author)
	}
	if !f.Timestamp.Equal(msg.Date) {
		t.Errorf("expected Timestamp=%v, got %v", msg.Date, f.Timestamp)
	}
	if f.ContentHash == "" {
		t.Error("ContentHash must not be empty")
	}
	if f.ID == "" {
		t.Error("ID must not be empty")
	}
}

func TestTelegramMessageToFinding_EmptyText(t *testing.T) {
	msg := telegramMessage{
		ChannelID:    99999,
		ChannelName:  "media_channel",
		Text:         "",
		MediaCaption: "screenshot of leaked database",
		Author:       "anon",
		Date:         time.Date(2026, 3, 14, 12, 0, 0, 0, time.UTC),
	}

	f := msg.toFinding()

	if f.Content != "screenshot of leaked database" {
		t.Errorf("expected Content to fall back to MediaCaption, got %q", f.Content)
	}
}

func TestTelegramMessageToFinding_ForwardMetadata(t *testing.T) {
	msg := telegramMessage{
		ChannelID:   55555,
		ChannelName: "aggregator",
		Text:        "forwarded intel about ransomware group",
		Author:      "relay_bot",
		Date:        time.Date(2026, 3, 14, 14, 0, 0, 0, time.UTC),
		ForwardFrom: "original_source_channel",
	}

	f := msg.toFinding()

	if f.Metadata == nil {
		t.Fatal("expected Metadata to be non-nil when ForwardFrom is set")
	}
	if f.Metadata["forward_from"] != "original_source_channel" {
		t.Errorf("expected Metadata[forward_from]=%q, got %q", "original_source_channel", f.Metadata["forward_from"])
	}
}

func TestTelegramCollector_Name(t *testing.T) {
	tc := NewTelegramCollector(&config.TelegramConfig{}, nil)
	if tc.Name() != "telegram" {
		t.Errorf("expected Name()=%q, got %q", "telegram", tc.Name())
	}
}

func TestTelegramCollector_Dedup(t *testing.T) {
	tc := NewTelegramCollector(&config.TelegramConfig{}, nil)

	hash := contentHash("same content twice")

	if tc.isDuplicate(hash) {
		t.Error("first call to isDuplicate should return false")
	}
	if !tc.isDuplicate(hash) {
		t.Error("second call to isDuplicate with same hash should return true")
	}

	// A different hash should not be considered duplicate.
	otherHash := contentHash("different content")
	if tc.isDuplicate(otherHash) {
		t.Error("different hash should not be duplicate")
	}
}

func TestShouldJoinChannel(t *testing.T) {
	tests := []struct {
		name     string
		ch       config.ChannelConfig
		wantJoin bool
	}{
		{
			name:     "username channel should attempt join",
			ch:       config.ChannelConfig{Username: "somechannel"},
			wantJoin: true,
		},
		{
			name:     "id-only channel should not attempt join",
			ch:       config.ChannelConfig{ID: 12345},
			wantJoin: false,
		},
		{
			name:     "empty config should not attempt join",
			ch:       config.ChannelConfig{},
			wantJoin: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldJoinChannel(tt.ch)
			if got != tt.wantJoin {
				t.Errorf("shouldJoinChannel(%+v) = %v, want %v", tt.ch, got, tt.wantJoin)
			}
		})
	}
}

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

func TestMergeChannels(t *testing.T) {
	cfgChannels := []config.ChannelConfig{
		{Username: "alpha"},
		{Username: "beta"},
	}
	dbChannels := []config.ChannelConfig{
		{Username: "beta"},
		{Username: "gamma"},
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
