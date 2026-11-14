package inference

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestConfigRequiresExplicitEnabledPrice(t *testing.T) {
	if err := (Store{}).Validate(DefaultConfig()); err != nil {
		t.Fatal("disabled defaults rejected", err)
	}
	for _, tc := range []struct {
		name    string
		price   Price
		enabled bool
		valid   bool
	}{
		{"default_marker", Price{Version: "unconfigured"}, true, false},
		{"uppercase_marker", Price{Version: "UNCONFIGURED"}, true, false},
		{"padded_marker", Price{Version: " \tUnconfigured\n\u00a0"}, true, false},
		{"empty", Price{}, true, false},
		{"whitespace", Price{Version: " \t\n\u00a0"}, true, false},
		{"disabled_marker", Price{Version: " \tUnconfigured\n"}, false, true},
		{"free_route", Price{Version: "free-local-v1"}, true, true},
		{"explicit", Price{Version: "operator-v1", Input: 1, Output: 2}, true, true},
		{"preserved_version", Price{Version: " \tOperator-V1\n", Input: 1, Output: 2}, true, true},
		{"maximum", Price{Version: strings.Repeat("v", 128), Input: 1e9, Output: 1e9}, true, true},
		{"negative_input", Price{Version: "operator-v1", Input: -1}, true, false},
		{"negative_output", Price{Version: "operator-v1", Output: -1}, true, false},
		{"excess_input", Price{Version: "operator-v1", Input: 1e9 + 1}, true, false},
		{"excess_output", Price{Version: "operator-v1", Output: 1e9 + 1}, true, false},
		{"long_version", Price{Version: strings.Repeat("v", 129)}, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DailyCap, cfg.MonthlyCap = 100, 100
			cfg.Connections = []Connection{{ID: "local", Provider: "synthetic", Adapter: "openai-chat", URL: "https://fixture.invalid", DataClasses: []string{"private-approved"}}}
			b := &cfg.Bindings[0]
			b.Enabled, b.StructuredJSON = tc.enabled, true
			b.ConnectionID, b.Model = "local", "synthetic"
			b.DailyCap, b.MonthlyCap = 100, 100
			b.Price = tc.price
			err := (Store{}).Validate(cfg)
			if (err == nil) != tc.valid || (!tc.valid && !errors.Is(err, ErrInvalid)) {
				t.Fatalf("Validate() = %v, valid = %t", err, tc.valid)
			}
			if b.Price != tc.price {
				t.Fatal("validation rewrote tariff identity or amounts")
			}
			if !tc.valid {
				// No database is available: rejection must precede connecting or encrypting.
				if _, err := (Store{DSN: "invalid-dsn"}).Save(context.Background(), cfg, 0, "fixture"); !errors.Is(err, ErrInvalid) {
					t.Fatal("Save did not reject before database access", err)
				}
			}
		})
	}
}
