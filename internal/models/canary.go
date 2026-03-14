package models

import "time"

// Canary type constants identify the kind of canary token planted.
const (
	CanaryTypeAWSKey       = "aws_key"
	CanaryTypeDBConnstring = "db_connstring"
	CanaryTypeEmailPassword = "email_password"
	CanaryTypeAPIKey       = "api_key"
)

// CanaryToken represents a planted canary credential that, if seen in the wild,
// indicates a breach or data exfiltration.
type CanaryToken struct {
	ID          string     `json:"id"`
	Type        string     `json:"type"`
	Value       string     `json:"value"`
	PlantedAt   time.Time  `json:"planted_at"`
	PlantedIn   string     `json:"planted_in,omitempty"`  // service / file where it was embedded
	Triggered   bool       `json:"triggered"`
	TriggeredAt *time.Time `json:"triggered_at,omitempty"`
	TriggeredIn string     `json:"triggered_in,omitempty"` // Finding ID that caused the trigger
}
