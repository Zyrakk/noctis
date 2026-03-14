package models

import "time"

// CadenceProfile captures the posting behaviour patterns of a threat actor.
type CadenceProfile struct {
	HourlyDistribution [24]int `json:"hourly_distribution"` // post counts per UTC hour
	InferredTimezone   string  `json:"inferred_timezone,omitempty"`
	AvgPostsPerDay     float64 `json:"avg_posts_per_day"`
}

// ActorProfile aggregates observed intelligence about a particular threat actor.
type ActorProfile struct {
	ID             string         `json:"id"`
	KnownHandles   []string       `json:"known_handles,omitempty"`
	Platforms      []string       `json:"platforms,omitempty"`
	StyleEmbedding []float64      `json:"style_embedding,omitempty"` // LLM-derived vector
	PostingCadence CadenceProfile `json:"posting_cadence"`
	FirstSeen      time.Time      `json:"first_seen,omitempty"`
	LastSeen       time.Time      `json:"last_seen,omitempty"`
	ThreatLevel    Severity       `json:"threat_level"`
	LinkedFindings []string       `json:"linked_findings,omitempty"` // Finding IDs
}
