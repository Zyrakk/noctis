package models_test

import (
	"strings"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/models"
)

// Type aliases to keep test bodies concise.
type (
	Finding  = models.Finding
	Severity = models.Severity
)

const (
	SeverityInfo     = models.SeverityInfo
	SeverityLow      = models.SeverityLow
	SeverityMedium   = models.SeverityMedium
	SeverityHigh     = models.SeverityHigh
	SeverityCritical = models.SeverityCritical
)

func ParseSeverity(s string) (models.Severity, error) { return models.ParseSeverity(s) }
func NewFinding(source, sourceID, sourceName, content string) *models.Finding {
	return models.NewFinding(source, sourceID, sourceName, content)
}

// TestFinding_ComputeContentHash verifies SHA-256 hex output, determinism, and uniqueness.
func TestFinding_ComputeContentHash(t *testing.T) {
	f := &Finding{
		Content: "test content for hashing",
	}

	hash1 := f.ComputeContentHash()

	// Must be a 64-char hex string (SHA-256 = 32 bytes = 64 hex chars)
	if len(hash1) != 64 {
		t.Errorf("expected 64-char hex hash, got len=%d: %q", len(hash1), hash1)
	}

	// Must be lowercase hex
	for _, c := range hash1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hash contains non-hex character: %c in %q", c, hash1)
		}
	}

	// Deterministic: same content -> same hash
	hash2 := f.ComputeContentHash()
	if hash1 != hash2 {
		t.Errorf("ComputeContentHash is not deterministic: %q != %q", hash1, hash2)
	}

	// Unique: different content -> different hash
	f2 := &Finding{Content: "different content"}
	hash3 := f2.ComputeContentHash()
	if hash1 == hash3 {
		t.Errorf("different content produced same hash: %q", hash1)
	}
}

// TestSeverity_String verifies all 5 severity levels map to the correct strings.
func TestSeverity_String(t *testing.T) {
	cases := []struct {
		sev      Severity
		expected string
	}{
		{SeverityInfo, "info"},
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
	}

	for _, tc := range cases {
		got := tc.sev.String()
		if got != tc.expected {
			t.Errorf("Severity(%d).String() = %q, want %q", int(tc.sev), got, tc.expected)
		}
	}
}

// TestParseSeverity verifies round-trip parsing of severity strings.
func TestParseSeverity(t *testing.T) {
	for _, s := range []string{"info", "low", "medium", "high", "critical"} {
		sev, err := ParseSeverity(s)
		if err != nil {
			t.Errorf("ParseSeverity(%q) returned unexpected error: %v", s, err)
		}
		if sev.String() != s {
			t.Errorf("ParseSeverity(%q).String() = %q, want %q", s, sev.String(), s)
		}
	}

	_, err := ParseSeverity("unknown")
	if err == nil {
		t.Error("ParseSeverity(\"unknown\") expected error, got nil")
	}
}

// TestNewFinding verifies auto-generated UUID, hash, and timestamp on construction.
func TestNewFinding(t *testing.T) {
	before := time.Now().UTC().Truncate(time.Second)

	f := NewFinding("telegram", "src-001", "chan-alpha", "alert: leaked creds found")

	after := time.Now().UTC().Add(time.Second)

	// ID must be a non-empty UUID string (36 chars: 8-4-4-4-12)
	if len(f.ID) != 36 {
		t.Errorf("expected UUID of length 36, got len=%d: %q", len(f.ID), f.ID)
	}
	if strings.Count(f.ID, "-") != 4 {
		t.Errorf("UUID should have 4 hyphens, got: %q", f.ID)
	}

	// ContentHash must be set (non-empty, 64 chars)
	if len(f.ContentHash) != 64 {
		t.Errorf("expected 64-char content hash, got len=%d", len(f.ContentHash))
	}

	// CollectedAt must be between before and after
	if f.CollectedAt.Before(before) || f.CollectedAt.After(after) {
		t.Errorf("CollectedAt %v is outside expected window [%v, %v]", f.CollectedAt, before, after)
	}

	// Fields must be stored correctly
	if f.Source != "telegram" {
		t.Errorf("Source = %q, want %q", f.Source, "telegram")
	}
	if f.SourceID != "src-001" {
		t.Errorf("SourceID = %q, want %q", f.SourceID, "src-001")
	}
	if f.SourceName != "chan-alpha" {
		t.Errorf("SourceName = %q, want %q", f.SourceName, "chan-alpha")
	}
	if f.Content != "alert: leaked creds found" {
		t.Errorf("Content = %q, want %q", f.Content, "alert: leaked creds found")
	}

	// Two findings with same content must get different IDs
	f2 := NewFinding("telegram", "src-001", "chan-alpha", "alert: leaked creds found")
	if f.ID == f2.ID {
		t.Errorf("two NewFinding calls returned the same UUID: %q", f.ID)
	}
}
