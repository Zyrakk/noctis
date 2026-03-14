package config

import (
	"errors"
	"fmt"
	"strings"
)

// Validate checks a parsed Config for required fields and logical consistency.
// It collects all violations and returns them as a single joined error so the
// caller can see every problem at once.
func Validate(cfg *Config) error {
	var errs []string

	// LLM — all three identity fields are required.
	if strings.TrimSpace(cfg.LLM.Provider) == "" {
		errs = append(errs, "llm.provider is required")
	}
	if strings.TrimSpace(cfg.LLM.BaseURL) == "" {
		errs = append(errs, "llm.baseURL is required")
	}
	if strings.TrimSpace(cfg.LLM.Model) == "" {
		errs = append(errs, "llm.model is required")
	}

	// Sources — at least one must be enabled.
	if !cfg.Sources.Telegram.Enabled && !cfg.Sources.Paste.Enabled {
		errs = append(errs, "at least one source (telegram or paste) must be enabled")
	}

	// Telegram — if enabled, must have at least one channel.
	if cfg.Sources.Telegram.Enabled && len(cfg.Sources.Telegram.Channels) == 0 {
		errs = append(errs, "sources.telegram: at least one channel is required when telegram is enabled")
	}

	// Matching rules.
	for i, rule := range cfg.Matching.Rules {
		prefix := fmt.Sprintf("matching.rules[%d]", i)

		if strings.TrimSpace(rule.Name) == "" {
			errs = append(errs, fmt.Sprintf("%s: name is required", prefix))
		}

		if rule.Type != "keyword" && rule.Type != "regex" {
			errs = append(errs, fmt.Sprintf("%s: type must be 'keyword' or 'regex', got %q", prefix, rule.Type))
		}

		if len(rule.Patterns) == 0 {
			errs = append(errs, fmt.Sprintf("%s: patterns must not be empty", prefix))
		}
	}

	if len(errs) == 0 {
		return nil
	}
	return errors.New(strings.Join(errs, "; "))
}
