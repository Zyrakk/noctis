package intelligence

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestProjectionIOBudgetRejectsBeforeDatabase(t *testing.T) {
	for _, budget := range []time.Duration{-1, 0, 120*time.Second + 1} {
		called := false
		err := GuardProjectionIOWithBudget(context.Background(), nil, budget, func(context.Context) error { called = true; return nil })
		if err == nil || called {
			t.Fatalf("invalid budget %v admitted", budget)
		}
	}
}

func TestProjectionIOCanceledClosedSessionPreservesMixedErrorsPostgres(t *testing.T) {
	dsn := os.Getenv("NOCTIS_V2_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	for _, mixed := range []bool{false, true} {
		c, err := pgx.Connect(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		unknown := errors.New("unknown cleanup failure")
		ctx, cancel := context.WithCancel(context.Background())
		err = GuardProjectionIOWithBudget(ctx, c, time.Second, func(io context.Context) error {
			if mixed {
				if e := c.Close(context.Background()); e != nil {
					return e
				}
				cancel()
				return errors.Join(context.Canceled, unknown)
			}
			query, done := context.WithTimeout(io, 20*time.Millisecond)
			defer done()
			_, e := c.Exec(query, `SELECT pg_sleep(60)`)
			cancel()
			return e
		})
		cancel()
		if mixed {
			if !errors.Is(err, unknown) || pureIOCancellation(err) {
				t.Fatal("mixed error hidden", err)
			}
		} else if !pureIOCancellation(err) || !c.IsClosed() {
			t.Fatal("canceled session acquired artificial cleanup failure", err)
		}
		c.Close(context.Background())
	}
}
