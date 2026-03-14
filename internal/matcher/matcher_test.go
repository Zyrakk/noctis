package matcher

import (
	"testing"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/models"
)

// findingWithContent returns a minimal Finding containing the given content.
func findingWithContent(content string) models.Finding {
	return models.Finding{Content: content}
}

// TestMatcher_KeywordMatch verifies that a keyword rule matches content containing
// the keyword and reports the configured severity.
func TestMatcher_KeywordMatch(t *testing.T) {
	rules := []config.RuleConfig{
		{
			Name:     "domain-watch",
			Type:     "keyword",
			Patterns: []string{"example.com"},
			Severity: "high",
		},
	}

	m, err := New(rules)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	result, ok := m.Match(findingWithContent("leaked creds for example.com found here"))
	if !ok {
		t.Fatal("Match() returned false; expected a match")
	}
	if result.Severity != models.SeverityHigh {
		t.Errorf("Severity = %v; want high", result.Severity)
	}
	if len(result.MatchedRules) != 1 || result.MatchedRules[0] != "domain-watch" {
		t.Errorf("MatchedRules = %v; want [domain-watch]", result.MatchedRules)
	}
}

// TestMatcher_RegexMatch verifies that a regex rule matches content fitting the
// credential pattern and reports critical severity.
func TestMatcher_RegexMatch(t *testing.T) {
	rules := []config.RuleConfig{
		{
			Name:     "cred-pattern",
			Type:     "regex",
			Patterns: []string{`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`},
			Severity: "critical",
		},
	}

	m, err := New(rules)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	result, ok := m.Match(findingWithContent("admin password=hunter2"))
	if !ok {
		t.Fatal("Match() returned false; expected a match")
	}
	if result.Severity != models.SeverityCritical {
		t.Errorf("Severity = %v; want critical", result.Severity)
	}
	if len(result.MatchedRules) != 1 || result.MatchedRules[0] != "cred-pattern" {
		t.Errorf("MatchedRules = %v; want [cred-pattern]", result.MatchedRules)
	}
}

// TestMatcher_NoMatch verifies that unrelated content produces no match.
func TestMatcher_NoMatch(t *testing.T) {
	rules := []config.RuleConfig{
		{
			Name:     "domain-watch",
			Type:     "keyword",
			Patterns: []string{"example.com"},
			Severity: "high",
		},
	}

	m, err := New(rules)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	_, ok := m.Match(findingWithContent("nothing suspicious here at all"))
	if ok {
		t.Fatal("Match() returned true; expected no match")
	}
}

// TestMatcher_MultipleRules_HighestSeverityWins verifies that when two rules both
// match, the result carries the higher severity and includes both rule names.
func TestMatcher_MultipleRules_HighestSeverityWins(t *testing.T) {
	rules := []config.RuleConfig{
		{
			Name:     "domain-watch",
			Type:     "keyword",
			Patterns: []string{"example.com"},
			Severity: "high",
		},
		{
			Name:     "cred-pattern",
			Type:     "regex",
			Patterns: []string{`(?i)(password|passwd|pwd)\s*[:=]\s*\S+`},
			Severity: "critical",
		},
	}

	m, err := New(rules)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	content := "example.com admin password=hunter2"
	result, ok := m.Match(findingWithContent(content))
	if !ok {
		t.Fatal("Match() returned false; expected a match")
	}
	if result.Severity != models.SeverityCritical {
		t.Errorf("Severity = %v; want critical (highest)", result.Severity)
	}

	ruleSet := make(map[string]bool, len(result.MatchedRules))
	for _, r := range result.MatchedRules {
		ruleSet[r] = true
	}
	for _, name := range []string{"domain-watch", "cred-pattern"} {
		if !ruleSet[name] {
			t.Errorf("MatchedRules missing %q; got %v", name, result.MatchedRules)
		}
	}
}

// TestMatcher_InvalidRegex verifies that New() returns an error when a regex
// pattern is syntactically invalid.
func TestMatcher_InvalidRegex(t *testing.T) {
	rules := []config.RuleConfig{
		{
			Name:     "bad-regex",
			Type:     "regex",
			Patterns: []string{`[invalid(`},
			Severity: "low",
		},
	}

	_, err := New(rules)
	if err == nil {
		t.Fatal("New() expected an error for invalid regex; got nil")
	}
}

// TestMatcher_CaseInsensitiveKeyword verifies that keyword matching is
// case-insensitive: the pattern "Example.COM" matches content "EXAMPLE.com".
func TestMatcher_CaseInsensitiveKeyword(t *testing.T) {
	rules := []config.RuleConfig{
		{
			Name:     "domain-watch",
			Type:     "keyword",
			Patterns: []string{"Example.COM"},
			Severity: "medium",
		},
	}

	m, err := New(rules)
	if err != nil {
		t.Fatalf("New() unexpected error: %v", err)
	}

	result, ok := m.Match(findingWithContent("data dump for EXAMPLE.com users"))
	if !ok {
		t.Fatal("Match() returned false; expected a case-insensitive match")
	}
	if result.Severity != models.SeverityMedium {
		t.Errorf("Severity = %v; want medium", result.Severity)
	}
}
