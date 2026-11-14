package main

import (
	"strings"
	"testing"
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
