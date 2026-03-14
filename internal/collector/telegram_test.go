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
	tc := NewTelegramCollector(&config.TelegramConfig{})
	if tc.Name() != "telegram" {
		t.Errorf("expected Name()=%q, got %q", "telegram", tc.Name())
	}
}

func TestTelegramCollector_Dedup(t *testing.T) {
	tc := NewTelegramCollector(&config.TelegramConfig{})

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
