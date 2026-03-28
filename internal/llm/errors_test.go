package llm_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Zyrakk/noctis/internal/llm"
)

func TestIsBudgetExhausted_DirectMatch(t *testing.T) {
	err := llm.ErrBudgetExhausted
	if !llm.IsBudgetExhausted(err) {
		t.Error("expected IsBudgetExhausted to return true for direct sentinel")
	}
}

func TestIsBudgetExhausted_Wrapped(t *testing.T) {
	wrapped := fmt.Errorf("classify failed: %w", llm.ErrBudgetExhausted)
	if !llm.IsBudgetExhausted(wrapped) {
		t.Error("expected IsBudgetExhausted to return true for wrapped sentinel")
	}
}

func TestIsBudgetExhausted_Unrelated(t *testing.T) {
	err := errors.New("some other error")
	if llm.IsBudgetExhausted(err) {
		t.Error("expected IsBudgetExhausted to return false for unrelated error")
	}
}

func TestIsBudgetExhausted_Nil(t *testing.T) {
	if llm.IsBudgetExhausted(nil) {
		t.Error("expected IsBudgetExhausted to return false for nil")
	}
}
