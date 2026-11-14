package main

import (
	"errors"
	"io"
	"testing"

	"github.com/Zyrakk/noctis/internal/intelligence"
)

func TestDispatchOnceValidatesEndpointBeforeDatabase(t *testing.T) {
	for _, endpoint := range []string{"", "/relative", "https://", "ftp://localhost", "http://localhost:", "http://[::1]:65536"} {
		t.Run(endpoint, func(t *testing.T) {
			cmd := newV2Cmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			// No database secret file: reaching connect would return a config error.
			cmd.SetArgs([]string{"dispatch-once", endpoint})
			if err := cmd.Execute(); !errors.Is(err, intelligence.ErrInvalidDeliveryEndpoint) {
				t.Fatalf("endpoint not rejected before database setup: %v", err)
			}
		})
	}
}
