// Package collector defines the contract for data source collectors.
package collector

import (
	"context"

	"github.com/Zyrakk/noctis/internal/models"
)

// Collector defines the contract for data source collectors.
// Each collector runs as a long-lived goroutine, sending findings to the output channel.
type Collector interface {
	// Name returns a human-readable identifier for this collector.
	Name() string

	// Start begins collecting data and sending findings to the output channel.
	// It blocks until ctx is cancelled. The collector must close the output channel on return.
	Start(ctx context.Context, out chan<- models.Finding) error
}
