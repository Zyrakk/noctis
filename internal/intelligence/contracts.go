package intelligence

import (
	"github.com/Zyrakk/noctis/internal/evidence"
	"time"
)

type MaterialChange struct {
	ID            string         `json:"id"`
	Reason        string         `json:"reason"`
	PolicyVersion string         `json:"policy_version"`
	Evidence      []evidence.Ref `json:"evidence"`
}
type CaseRevision struct {
	CaseID     string           `json:"case_id"`
	Revision   string           `json:"revision"`
	Supersedes string           `json:"supersedes,omitempty"`
	CreatedAt  time.Time        `json:"created_at"`
	Changes    []MaterialChange `json:"changes"`
}

// DeliveryKey identifies logical delivery across retries, never an attempt.
type DeliveryKey struct {
	CaseID           string `json:"case_id"`
	MaterialChangeID string `json:"material_change_id"`
	DestinationID    string `json:"destination_id"`
	PolicyVersion    string `json:"policy_version"`
}
