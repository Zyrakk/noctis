package jobs

import "time"

type Key struct {
	Stage         string `json:"stage"`
	InputID       string `json:"input_id"`
	InputRevision string `json:"input_revision"`
	PolicyVersion string `json:"policy_version"`
	SchemaVersion string `json:"schema_version"`
}
type Lease struct {
	Owner     string    `json:"owner"`
	ExpiresAt time.Time `json:"expires_at"`
	Fence     int64     `json:"fence"`
}
type State string

const (
	Queued            State = "queued"
	Leased            State = "leased"
	Succeeded         State = "succeeded"
	RetryWait         State = "retry_wait"
	BudgetBlocked     State = "budget_blocked"
	DependencyBlocked State = "dependency_blocked"
	Quarantined       State = "quarantined"
	Cancelled         State = "cancelled"
)
