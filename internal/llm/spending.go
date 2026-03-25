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
	budgetLimit     float64   // 0 means unlimited
	resetAt         time.Time // start of next billing period
}

// NewSpendingTracker creates a tracker with the given cost rates and budget.
// If budgetLimit is 0, spending is tracked but never rejected.
func NewSpendingTracker(inputCostPer1M, outputCostPer1M, budgetLimit float64) *SpendingTracker {
	return &SpendingTracker{
		inputCostPer1M:  inputCostPer1M,
		outputCostPer1M: outputCostPer1M,
		budgetLimit:     budgetLimit,
		resetAt:         startOfNextMonth(),
	}
}

// Record adds token counts to the running totals. It resets counters if
// the billing period has rolled over.
func (s *SpendingTracker) Record(inputTokens, outputTokens int) {
	s.maybeReset()
	s.inputTokens.Add(int64(inputTokens))
	s.outputTokens.Add(int64(outputTokens))
}

// CurrentSpend returns the estimated cost in USD for the current period.
func (s *SpendingTracker) CurrentSpend() float64 {
	s.maybeReset()
	in := float64(s.inputTokens.Load())
	out := float64(s.outputTokens.Load())
	return (in/1_000_000)*s.inputCostPer1M + (out/1_000_000)*s.outputCostPer1M
}

// RemainingBudget returns how much budget is left. Returns a large number
// if no budget limit is set.
func (s *SpendingTracker) RemainingBudget() float64 {
	if s.budgetLimit <= 0 {
		return 1_000_000 // effectively unlimited
	}
	rem := s.budgetLimit - s.CurrentSpend()
	if rem < 0 {
		return 0
	}
	return rem
}

// IsOverBudget returns true if spending has exceeded the configured limit.
// Always returns false if budgetLimit is 0.
func (s *SpendingTracker) IsOverBudget() bool {
	if s.budgetLimit <= 0 {
		return false
	}
	return s.CurrentSpend() >= s.budgetLimit
}

// CheckBudget returns an error if the budget is exhausted.
func (s *SpendingTracker) CheckBudget() error {
	if s.IsOverBudget() {
		return fmt.Errorf("llm: budget exhausted (spent $%.2f of $%.2f limit for this billing period)",
			s.CurrentSpend(), s.budgetLimit)
	}
	return nil
}

// Snapshot returns a point-in-time view of spending for API responses.
func (s *SpendingTracker) Snapshot() SpendingSnapshot {
	s.maybeReset()
	return SpendingSnapshot{
		InputTokens:        s.inputTokens.Load(),
		OutputTokens:       s.outputTokens.Load(),
		EstimatedCostUSD:   s.CurrentSpend(),
		BudgetLimitUSD:     s.budgetLimit,
		BudgetRemainingUSD: s.RemainingBudget(),
		ResetsAt:           s.resetAt,
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
func (s *SpendingTracker) maybeReset() {
	now := time.Now()
	if now.Before(s.resetAt) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Double-check under lock.
	if now.Before(s.resetAt) {
		return
	}
	s.inputTokens.Store(0)
	s.outputTokens.Store(0)
	s.resetAt = startOfNextMonth()
}

func startOfNextMonth() time.Time {
	now := time.Now().UTC()
	y, m, _ := now.Date()
	return time.Date(y, m+1, 1, 0, 0, 0, 0, time.UTC)
}
