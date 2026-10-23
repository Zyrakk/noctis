package inference

import (
	"context"
	"errors"
	"testing"
)

func TestAuthorizedWireRejectsInvalidBudgetBeforeDatabaseOrPOST(t *testing.T) {
	for _, budget := range []int{-1, 0, 120001, int(^uint(0) >> 1)} {
		_, err := (Store{DSN: "invalid"}).authorizedWire(context.Background(), execution{Binding: Binding{Limits: Limits{DeadlineMS: budget}}})
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("budget %d reached database or transport: %v", budget, err)
		}
	}
}
