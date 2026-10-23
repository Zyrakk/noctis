// Package capture defines the collector/storage boundary; receipts exist only after commit.
package capture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"time"
)

type Mode string

const (
	Live         Mode = "live"
	Bootstrap    Mode = "bootstrap"
	LegacyImport Mode = "legacy_import"
)

type Checkpoint struct {
	Version int64           `json:"version"`
	Value   json.RawMessage `json:"value"`
}
type Item struct {
	NativeID       string     `json:"native_id"`
	Revision       string     `json:"revision"`
	Payload        []byte     `json:"payload"`
	Representation string     `json:"representation"`
	Hash           string     `json:"hash"`
	PublishedAt    *time.Time `json:"published_at,omitempty"`
	CollectedAt    time.Time  `json:"collected_at"`
}
type Batch struct {
	BatchID  string     `json:"batch_id"`
	Version  string     `json:"version"`
	SourceID string     `json:"source_id"`
	Epoch    string     `json:"epoch"`
	Mode     Mode       `json:"mode"`
	Items    []Item     `json:"items"`
	Expected Checkpoint `json:"expected_checkpoint"`
	Next     Checkpoint `json:"next_checkpoint"`
}
type Receipt struct {
	BatchID     string     `json:"batch_id"`
	CommittedAt time.Time  `json:"committed_at"`
	Checkpoint  Checkpoint `json:"checkpoint"`
}
type Committer interface {
	CommitBatch(context.Context, Batch) (Receipt, error)
}

func (b Batch) Validate() error {
	if _, err := uuid.Parse(b.BatchID); err != nil {
		return fmt.Errorf("invalid batch UUID")
	}
	if b.Version != "1" {
		return fmt.Errorf("unsupported capture version")
	}
	if _, err := uuid.Parse(b.SourceID); err != nil {
		return fmt.Errorf("invalid source UUID")
	}
	if _, err := uuid.Parse(b.Epoch); err != nil {
		return fmt.Errorf("invalid epoch UUID")
	}
	if b.Mode != Live && b.Mode != Bootstrap && b.Mode != LegacyImport {
		return fmt.Errorf("invalid capture mode")
	}
	if b.Expected.Version < 0 || b.Next.Version != b.Expected.Version+1 || !json.Valid(b.Expected.Value) || !json.Valid(b.Next.Value) {
		return fmt.Errorf("invalid checkpoint CAS")
	}
	if len(b.Items) > 10000 {
		return fmt.Errorf("capture item limit exceeded")
	}
	total := 0
	for _, i := range b.Items {
		total += len(i.Payload)
		if len(i.Payload) > 8<<20 || total > 32<<20 {
			return fmt.Errorf("capture payload limit exceeded")
		}
		if i.Hash != fmt.Sprintf("sha256:%x", sha256.Sum256(i.Payload)) {
			return fmt.Errorf("payload hash mismatch")
		}
		if i.NativeID == "" || i.Revision == "" || i.Representation == "" || i.Hash == "" || i.CollectedAt.IsZero() || i.CollectedAt.Location() != time.UTC || (i.PublishedAt != nil && (i.PublishedAt.IsZero() || i.PublishedAt.Location() != time.UTC)) {
			return fmt.Errorf("invalid item identity or UTC timestamp")
		}
	}
	return nil
}
