package config_test

import (
	"os"
	"testing"

	"github.com/Zyrakk/noctis/internal/config"
)

func TestLoad_ValidConfig(t *testing.T) {
	cfg, err := config.Load("../../testdata/valid_config.yaml")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel: want %q, got %q", "debug", cfg.LogLevel)
	}
	if cfg.MetricsPort != 9090 {
		t.Errorf("MetricsPort: want 9090, got %d", cfg.MetricsPort)
	}
	if cfg.HealthPort != 8080 {
		t.Errorf("HealthPort: want 8080, got %d", cfg.HealthPort)
	}

	// Telegram
	if !cfg.Sources.Telegram.Enabled {
		t.Error("expected telegram to be enabled")
	}
	if cfg.Sources.Telegram.APIId != 123456 {
		t.Errorf("APIId: want 123456, got %d", cfg.Sources.Telegram.APIId)
	}
	if len(cfg.Sources.Telegram.Channels) != 2 {
		t.Errorf("expected 2 channels, got %d", len(cfg.Sources.Telegram.Channels))
	}
	if cfg.Sources.Telegram.Channels[0].Username != "examplechannel1" {
		t.Errorf("channel 0 username: want %q, got %q", "examplechannel1", cfg.Sources.Telegram.Channels[0].Username)
	}
	if cfg.Sources.Telegram.Channels[1].ID != 1001234567890 {
		t.Errorf("channel 1 ID: want 1001234567890, got %d", cfg.Sources.Telegram.Channels[1].ID)
	}

	// Matching rules
	if len(cfg.Matching.Rules) != 3 {
		t.Errorf("expected 3 matching rules, got %d", len(cfg.Matching.Rules))
	}
	if cfg.Matching.Rules[0].Type != "keyword" {
		t.Errorf("rule 0 type: want %q, got %q", "keyword", cfg.Matching.Rules[0].Type)
	}
	if cfg.Matching.Rules[1].Type != "regex" {
		t.Errorf("rule 1 type: want %q, got %q", "regex", cfg.Matching.Rules[1].Type)
	}

	// LLM
	if cfg.LLM.Provider != "glm" {
		t.Errorf("LLM provider: want %q, got %q", "glm", cfg.LLM.Provider)
	}
	if cfg.LLM.Model != "glm-4" {
		t.Errorf("LLM model: want %q, got %q", "glm-4", cfg.LLM.Model)
	}
	if cfg.LLM.MaxTokens != 4096 {
		t.Errorf("LLM MaxTokens: want 4096, got %d", cfg.LLM.MaxTokens)
	}
	if cfg.LLM.Temperature != 0.2 {
		t.Errorf("LLM Temperature: want 0.2, got %f", cfg.LLM.Temperature)
	}

	// Database
	if cfg.Database.Driver != "postgres" {
		t.Errorf("Database driver: want %q, got %q", "postgres", cfg.Database.Driver)
	}

	// Graph
	if !cfg.Graph.Enabled {
		t.Error("expected graph to be enabled")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := config.Load("/nonexistent/path/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
}

func TestValidate_MissingLLMProvider(t *testing.T) {
	cfg := &config.Config{
		LLM: config.LLMConfig{
			Provider: "",
			BaseURL:  "http://localhost:11434",
			Model:    "some-model",
		},
		Sources: config.SourcesConfig{
			Telegram: config.TelegramConfig{
				Enabled:  true,
				Channels: []config.ChannelConfig{{Username: "test"}},
			},
		},
	}
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected error for missing LLM provider, got nil")
	}
	if !containsError(err.Error(), "provider") {
		t.Errorf("expected error to mention 'provider', got: %s", err.Error())
	}
}

func TestValidate_MissingLLMBaseURL(t *testing.T) {
	cfg := &config.Config{
		LLM: config.LLMConfig{
			Provider: "glm",
			BaseURL:  "",
			Model:    "some-model",
		},
		Sources: config.SourcesConfig{
			Telegram: config.TelegramConfig{
				Enabled:  true,
				Channels: []config.ChannelConfig{{Username: "test"}},
			},
		},
	}
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected error for missing LLM baseURL, got nil")
	}
	if !containsError(err.Error(), "baseURL") {
		t.Errorf("expected error to mention 'baseURL', got: %s", err.Error())
	}
}

func TestValidate_MissingLLMModel(t *testing.T) {
	cfg := &config.Config{
		LLM: config.LLMConfig{
			Provider: "glm",
			BaseURL:  "http://localhost:11434",
			Model:    "",
		},
		Sources: config.SourcesConfig{
			Telegram: config.TelegramConfig{
				Enabled:  true,
				Channels: []config.ChannelConfig{{Username: "test"}},
			},
		},
	}
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected error for missing LLM model, got nil")
	}
	if !containsError(err.Error(), "model") {
		t.Errorf("expected error to mention 'model', got: %s", err.Error())
	}
}

func TestValidate_NoSourcesEnabled(t *testing.T) {
	cfg := &config.Config{
		LLM: config.LLMConfig{
			Provider: "glm",
			BaseURL:  "http://localhost:11434",
			Model:    "glm-4",
		},
		Sources: config.SourcesConfig{
			Telegram: config.TelegramConfig{Enabled: false},
			Paste:    config.PasteConfig{Enabled: false},
		},
	}
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected error when no sources enabled, got nil")
	}
	if !containsError(err.Error(), "source") {
		t.Errorf("expected error to mention 'source', got: %s", err.Error())
	}
}

func TestValidate_TelegramEnabledNoChannels(t *testing.T) {
	cfg := &config.Config{
		LLM: config.LLMConfig{
			Provider: "glm",
			BaseURL:  "http://localhost:11434",
			Model:    "glm-4",
		},
		Sources: config.SourcesConfig{
			Telegram: config.TelegramConfig{
				Enabled:  true,
				Channels: []config.ChannelConfig{},
			},
		},
	}
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected error for telegram enabled with no channels, got nil")
	}
	if !containsError(err.Error(), "channel") {
		t.Errorf("expected error to mention 'channel', got: %s", err.Error())
	}
}

func TestValidate_RuleInvalidType(t *testing.T) {
	cfg := &config.Config{
		LLM: config.LLMConfig{
			Provider: "glm",
			BaseURL:  "http://localhost:11434",
			Model:    "glm-4",
		},
		Sources: config.SourcesConfig{
			Telegram: config.TelegramConfig{
				Enabled:  true,
				Channels: []config.ChannelConfig{{Username: "test"}},
			},
		},
		Matching: config.MatchingConfig{
			Rules: []config.RuleConfig{
				{Name: "testrule", Type: "invalid", Patterns: []string{"foo"}},
			},
		},
	}
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected error for invalid rule type, got nil")
	}
	if !containsError(err.Error(), "type") {
		t.Errorf("expected error to mention 'type', got: %s", err.Error())
	}
}

func TestValidate_RuleEmptyPatterns(t *testing.T) {
	cfg := &config.Config{
		LLM: config.LLMConfig{
			Provider: "glm",
			BaseURL:  "http://localhost:11434",
			Model:    "glm-4",
		},
		Sources: config.SourcesConfig{
			Telegram: config.TelegramConfig{
				Enabled:  true,
				Channels: []config.ChannelConfig{{Username: "test"}},
			},
		},
		Matching: config.MatchingConfig{
			Rules: []config.RuleConfig{
				{Name: "testrule", Type: "keyword", Patterns: []string{}},
			},
		},
	}
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected error for rule with empty patterns, got nil")
	}
	if !containsError(err.Error(), "pattern") {
		t.Errorf("expected error to mention 'pattern', got: %s", err.Error())
	}
}

func TestValidate_RuleMissingName(t *testing.T) {
	cfg := &config.Config{
		LLM: config.LLMConfig{
			Provider: "glm",
			BaseURL:  "http://localhost:11434",
			Model:    "glm-4",
		},
		Sources: config.SourcesConfig{
			Telegram: config.TelegramConfig{
				Enabled:  true,
				Channels: []config.ChannelConfig{{Username: "test"}},
			},
		},
		Matching: config.MatchingConfig{
			Rules: []config.RuleConfig{
				{Name: "", Type: "keyword", Patterns: []string{"foo"}},
			},
		},
	}
	err := config.Validate(cfg)
	if err == nil {
		t.Fatal("expected error for rule missing name, got nil")
	}
	if !containsError(err.Error(), "name") {
		t.Errorf("expected error to mention 'name', got: %s", err.Error())
	}
}

func TestLoad_EnvSubstitution(t *testing.T) {
	t.Setenv("NOCTIS_LLM_API_KEY", "test-secret-key-12345")

	cfg, err := config.Load("../../testdata/minimal_config.yaml")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if cfg.LLM.APIKey != "test-secret-key-12345" {
		t.Errorf("env substitution failed: want %q, got %q", "test-secret-key-12345", cfg.LLM.APIKey)
	}
}

func TestLoad_EnvSubstitutionMissingVar(t *testing.T) {
	os.Unsetenv("NOCTIS_LLM_API_KEY")

	cfg, err := config.Load("../../testdata/minimal_config.yaml")
	if err != nil {
		t.Fatalf("expected no error loading file (substitution should leave empty string), got: %v", err)
	}
	// When env var is unset, substitution should yield empty string
	if cfg.LLM.APIKey != "" {
		t.Errorf("expected empty string for unset env var, got %q", cfg.LLM.APIKey)
	}
}

// containsError is a helper to check if a string contains a substring (case-insensitive).
func containsError(haystack, needle string) bool {
	lower := func(s string) string {
		b := []byte(s)
		for i, c := range b {
			if c >= 'A' && c <= 'Z' {
				b[i] = c + 32
			}
		}
		return string(b)
	}
	h := lower(haystack)
	n := lower(needle)
	for i := 0; i <= len(h)-len(n); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
