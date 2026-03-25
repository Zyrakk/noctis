package llm

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// SpendingTracker tracks cumulative token usage and estimated cost for an LLM
// provider. It is goroutine-safe and shared across all callers of a client.
type SpendingTracker struct {
	mu              sync.Mutex
	inputTokens     atomic.Int64
	outputTokens    atomic.Int64
	inputCostPer1M  float64
	outputCostPer1M float64
	budgetLimit     float64 // 0 means unlimited
	resetAtUnix     atomic.Int64
}

// NewSpendingTracker creates a tracker with the given cost rates and budget.
// If budgetLimit is 0, spending is tracked but never rejected.
func NewSpendingTracker(inputCostPer1M, outputCostPer1M, budgetLimit float64) *SpendingTracker {
	s := &SpendingTracker{
		inputCostPer1M:  inputCostPer1M,
		outputCostPer1M: outputCostPer1M,
		budgetLimit:     budgetLimit,
	}
	s.resetAtUnix.Store(startOfNextMonth().Unix())
	return s
}

// Record adds token counts to the running totals. It resets counters if
// the billing period has rolled over.
func (s *SpendingTracker) Record(inputTokens, outputTokens int) {
	s.maybeReset()
	s.inputTokens.Add(int64(inputTokens))
	s.outputTokens.Add(int64(outputTokens))
}

// computeCost returns the estimated USD cost for the given token counts.
func (s *SpendingTracker) computeCost(in, out int64) float64 {
	return (float64(in)/1_000_000)*s.inputCostPer1M + (float64(out)/1_000_000)*s.outputCostPer1M
}

// CheckBudget returns an error if the budget is exhausted.
func (s *SpendingTracker) CheckBudget() error {
	if s.budgetLimit <= 0 {
		return nil
	}
	s.maybeReset()
	in := s.inputTokens.Load()
	out := s.outputTokens.Load()
	spent := s.computeCost(in, out)
	if spent >= s.budgetLimit {
		return fmt.Errorf("llm: budget exhausted (spent $%.2f of $%.2f limit for this billing period)",
			spent, s.budgetLimit)
	}
	return nil
}

// Snapshot returns a point-in-time view of spending for API responses.
// Token counts are read once to ensure internal consistency.
func (s *SpendingTracker) Snapshot() SpendingSnapshot {
	s.maybeReset()
	in := s.inputTokens.Load()
	out := s.outputTokens.Load()
	cost := s.computeCost(in, out)

	remaining := -1.0 // -1 signals unlimited
	if s.budgetLimit > 0 {
		remaining = max(0, s.budgetLimit-cost)
	}

	return SpendingSnapshot{
		InputTokens:        in,
		OutputTokens:       out,
		EstimatedCostUSD:   cost,
		BudgetLimitUSD:     s.budgetLimit,
		BudgetRemainingUSD: remaining,
		ResetsAt:           time.Unix(s.resetAtUnix.Load(), 0).UTC(),
	}
}

// SpendingSnapshot is a serializable point-in-time view of spending.
type SpendingSnapshot struct {
	InputTokens        int64     `json:"input_tokens"`
	OutputTokens       int64     `json:"output_tokens"`
	EstimatedCostUSD   float64   `json:"estimated_cost_usd"`
	BudgetLimitUSD     float64   `json:"budget_limit_usd"`
	BudgetRemainingUSD float64   `json:"budget_remaining_usd"`
	ResetsAt           time.Time `json:"resets_at"`
}

// maybeReset resets counters if the billing period has rolled over.
// The resetAtUnix atomic avoids torn reads on the pre-lock fast path.
func (s *SpendingTracker) maybeReset() {
	if time.Now().Unix() < s.resetAtUnix.Load() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if time.Now().Unix() < s.resetAtUnix.Load() {
		return
	}
	s.inputTokens.Store(0)
	s.outputTokens.Store(0)
	s.resetAtUnix.Store(startOfNextMonth().Unix())
}

func startOfNextMonth() time.Time {
	now := time.Now().UTC()
	y, m, _ := now.Date()
	return time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC)
}
