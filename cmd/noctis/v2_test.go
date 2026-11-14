package main

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/Zyrakk/noctis/internal/intelligence"
)

func TestV2InferenceFlagsDefaultToNoExecution(t *testing.T) {
	cmd, _, err := newV2Cmd().Find([]string{"serve"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"automatic-inference", "manual-inference"} {
		flag := cmd.Flags().Lookup(name)
		if flag == nil || flag.DefValue != "false" {
			t.Fatalf("%s must explicitly default to false", name)
		}
	}
	if !strings.Contains(cmd.Flags().Lookup("manual-inference").Usage, "older eligible requests") {
		t.Fatal("manual inference help must disclose existing backlog")
	}
	if err = cmd.ParseFlags([]string{"--manual-inference"}); err != nil {
		t.Fatal(err)
	}
	manual, err := cmd.Flags().GetBool("manual-inference")
	if err != nil || !manual {
		t.Fatal("manual opt-in unavailable", err)
	}
	automatic, err := cmd.Flags().GetBool("automatic-inference")
	if err != nil || automatic {
		t.Fatal("manual opt-in enabled automatic execution", err)
	}
}

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
