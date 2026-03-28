package processor

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/archive"
)

// TestConcurrencyLimiter_LimitsSlots verifies that the concurrency limiter
// blocks when all slots are taken and unblocks when a slot is released.
func TestConcurrencyLimiter_LimitsSlots(t *testing.T) {
	cl := NewConcurrencyLimiter(2)
	ctx := context.Background()

	// Acquire both slots.
	if err := cl.Acquire(ctx); err != nil {
		t.Fatalf("first Acquire error: %v", err)
	}
	if err := cl.Acquire(ctx); err != nil {
		t.Fatalf("second Acquire error: %v", err)
	}

	// Third acquire should block. Use a short timeout to verify.
	blockCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	err := cl.Acquire(blockCtx)
	if err == nil {
		t.Fatal("third Acquire succeeded; want block/timeout")
	}

	// Release one slot, then acquire should succeed.
	cl.Release()
	if err := cl.Acquire(ctx); err != nil {
		t.Fatalf("Acquire after Release error: %v", err)
	}
}

// TestConcurrencyLimiter_RespectsContext verifies that Acquire returns the
// context error immediately when the context is already cancelled.
func TestConcurrencyLimiter_RespectsContext(t *testing.T) {
	cl := NewConcurrencyLimiter(1)
	ctx := context.Background()

	// Take the only slot.
	if err := cl.Acquire(ctx); err != nil {
		t.Fatalf("first Acquire error: %v", err)
	}

	// Cancel immediately.
	cancelCtx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	err := cl.Acquire(cancelCtx)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("Acquire returned nil; want context error")
	}
	if err != context.Canceled {
		t.Errorf("Acquire error = %v; want context.Canceled", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Errorf("Acquire took %v; should have returned near-immediately on cancelled context", elapsed)
	}
}

// TestTagsFromCategory verifies the tag derivation logic for known and unknown
// categories.
func TestTagsFromCategory(t *testing.T) {
	tests := []struct {
		category  string
		wantLen   int
		wantFirst string
	}{
		{"", 0, ""},
		{"credential_leak", 2, "credential_leak"},
		{"malware_sample", 2, "malware_sample"},
		{"threat_actor_comms", 2, "threat_actor_comms"},
		{"access_broker", 2, "access_broker"},
		{"data_dump", 2, "data_dump"},
		{"vulnerability", 2, "vulnerability"},
		{"canary_hit", 2, "canary_hit"},
		{"irrelevant", 1, "irrelevant"},
		{"unknown_category", 1, "unknown_category"},
	}

	for _, tc := range tests {
		tags := TagsFromCategory(tc.category)
		if len(tags) != tc.wantLen {
			t.Errorf("TagsFromCategory(%q) len = %d; want %d (tags=%v)", tc.category, len(tags), tc.wantLen, tags)
			continue
		}
		if tc.wantLen > 0 && tags[0] != tc.wantFirst {
			t.Errorf("TagsFromCategory(%q)[0] = %q; want %q", tc.category, tags[0], tc.wantFirst)
		}
	}
}

// TestFindingFromRawContent verifies the conversion from archive.RawContent
// back to models.Finding for background worker use.
func TestFindingFromRawContent(t *testing.T) {
	now := time.Now().UTC()
	posted := now.Add(-1 * time.Hour)

	rc := archive.RawContent{
		ID:          "rc-1",
		SourceType:  "telegram",
		SourceID:    "chan-123",
		SourceName:  "threat-intel",
		Content:     "some content",
		ContentHash: "hash-1",
		Author:      "actor1",
		CollectedAt: now,
		PostedAt:    &posted,
	}

	f := FindingFromRawContent(rc)

	if f.ID != "rc-1" {
		t.Errorf("ID = %q; want %q", f.ID, "rc-1")
	}
	if f.Source != "telegram" {
		t.Errorf("Source = %q; want %q", f.Source, "telegram")
	}
	if f.SourceID != "chan-123" {
		t.Errorf("SourceID = %q; want %q", f.SourceID, "chan-123")
	}
	if f.Content != "some content" {
		t.Errorf("Content = %q; want %q", f.Content, "some content")
	}
	if f.Timestamp != posted {
		t.Errorf("Timestamp = %v; want %v", f.Timestamp, posted)
	}
}

func TestFindingFromRawContent_TruncatesContent(t *testing.T) {
	longContent := strings.Repeat("x", 60000)
	rc := archive.RawContent{
		ID:          "rc-trunc",
		SourceType:  "paste",
		SourceName:  "test",
		Content:     longContent,
		CollectedAt: time.Now().UTC(),
	}

	f := FindingFromRawContentWithLimit(rc, 8192)

	if len(f.Content) > 8195 { // 8192 + len("...")
		t.Errorf("Content length = %d; want <= 8195", len(f.Content))
	}
}

func TestFindingFromRawContent_NoTruncateZeroLimit(t *testing.T) {
	content := "short content"
	rc := archive.RawContent{
		ID:          "rc-notrunc",
		SourceType:  "paste",
		SourceName:  "test",
		Content:     content,
		CollectedAt: time.Now().UTC(),
	}

	f := FindingFromRawContentWithLimit(rc, 0)

	if f.Content != content {
		t.Errorf("Content = %q; want %q", f.Content, content)
	}
}
