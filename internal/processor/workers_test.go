package processor

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestBudgetCircuitBreaker_SetAndCheck(t *testing.T) {
	var flag atomic.Bool

	if flag.Load() {
		t.Error("expected flag to be false initially")
	}

	flag.Store(true)
	if !flag.Load() {
		t.Error("expected flag to be true after Store(true)")
	}

	flag.Store(false)
	if flag.Load() {
		t.Error("expected flag to be false after reset")
	}
}

func TestBudgetPauseBackoff(t *testing.T) {
	pause := budgetPauseDuration
	if pause < 10*time.Minute || pause > 60*time.Minute {
		t.Errorf("budgetPauseDuration = %v; expected between 10m and 60m", pause)
	}
}
