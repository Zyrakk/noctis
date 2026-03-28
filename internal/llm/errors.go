package llm

import "errors"

// ErrBudgetExhausted is returned when the provider's spend limit has been
// reached or when our own SpendingTracker budget is exhausted. Callers
// should not retry — all subsequent requests will fail the same way.
var ErrBudgetExhausted = errors.New("llm: budget exhausted")

// IsBudgetExhausted reports whether err (or any error in its chain) signals
// a budget/spend-limit condition.
func IsBudgetExhausted(err error) bool {
	return errors.Is(err, ErrBudgetExhausted)
}
