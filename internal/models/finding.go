package models

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// SourceType constants identify where a finding was collected from.
const (
	SourceTypeTelegram = "telegram"
	SourceTypePaste    = "paste"
	SourceTypeForum    = "forum"
	SourceTypeWeb      = "web"
)

// Severity represents the assessed threat level of a finding.
type Severity int

const (
	SeverityInfo     Severity = iota // 0
	SeverityLow                      // 1
	SeverityMedium                   // 2
	SeverityHigh                     // 3
	SeverityCritical                 // 4
)

// String returns the lowercase string name of the severity level.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// MarshalJSON encodes the severity as its string representation.
func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// ParseSeverity converts a string to a Severity value. Returns an error for
// unrecognised input.
func ParseSeverity(s string) (Severity, error) {
	switch s {
	case "info":
		return SeverityInfo, nil
	case "low":
		return SeverityLow, nil
	case "medium":
		return SeverityMedium, nil
	case "high":
		return SeverityHigh, nil
	case "critical":
		return SeverityCritical, nil
	default:
		return SeverityInfo, fmt.Errorf("unknown severity: %q", s)
	}
}

// Category classifies the kind of threat intelligence a finding represents.
type Category string

const (
	CategoryCredentialLeak    Category = "credential_leak"
	CategoryMalwareSample     Category = "malware_sample"
	CategoryThreatActorComms  Category = "threat_actor_comms"
	CategoryAccessBroker      Category = "access_broker"
	CategoryDataDump          Category = "data_dump"
	CategoryCanaryHit         Category = "canary_hit"
	CategoryIrrelevant        Category = "irrelevant"
)

// Finding is the raw, un-enriched record captured from a source channel.
type Finding struct {
	ID          string            `json:"id"`
	Source      string            `json:"source"`       // e.g. "telegram", "paste"
	SourceID    string            `json:"source_id"`    // channel / paste ID
	SourceName  string            `json:"source_name"`  // human-readable name
	Content     string            `json:"content"`
	ContentHash string            `json:"content_hash"`
	Author      string            `json:"author,omitempty"`
	Timestamp   time.Time         `json:"timestamp,omitempty"` // original post time
	CollectedAt time.Time         `json:"collected_at"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// ComputeContentHash returns the lowercase hex-encoded SHA-256 of f.Content.
func (f *Finding) ComputeContentHash() string {
	sum := sha256.Sum256([]byte(f.Content))
	return fmt.Sprintf("%x", sum)
}

// NewFinding constructs a Finding with an auto-generated UUID, pre-computed
// content hash, and CollectedAt set to the current UTC time.
func NewFinding(source, sourceID, sourceName, content string) *Finding {
	f := &Finding{
		ID:          uuid.New().String(),
		Source:      source,
		SourceID:    sourceID,
		SourceName:  sourceName,
		Content:     content,
		CollectedAt: time.Now().UTC(),
	}
	f.ContentHash = f.ComputeContentHash()
	return f
}

// CanaryHit records a single canary token trigger event embedded in an
// EnrichedFinding.
type CanaryHit struct {
	CanaryID    string    `json:"canary_id"`
	FoundIn     string    `json:"found_in"`
	FoundAt     time.Time `json:"found_at"`
	MatchType   string    `json:"match_type"`
	ContextSnip string    `json:"context_snip,omitempty"`
}

// EnrichedFinding extends a raw Finding with threat-intelligence annotations
// produced by the enrichment pipeline.
type EnrichedFinding struct {
	Finding

	MatchType    string       `json:"match_type,omitempty"`
	MatchedRules []string     `json:"matched_rules,omitempty"`
	Severity     Severity     `json:"severity"`
	Category     Category     `json:"category"`
	IOCs         []IOC        `json:"iocs,omitempty"`
	ActorProfile *ActorProfile `json:"actor_profile,omitempty"`
	CanaryHit    *CanaryHit   `json:"canary_hit,omitempty"`
	LLMAnalysis  string       `json:"llm_analysis,omitempty"`
	Confidence   float64      `json:"confidence"`
}
