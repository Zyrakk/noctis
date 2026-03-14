package matcher

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/models"
)

// compiledRule holds a pre-compiled matching rule ready for evaluation.
type compiledRule struct {
	name     string
	ruleType string // "keyword" or "regex"
	patterns []*regexp.Regexp
	keywords []string // lowercased for case-insensitive matching
	severity models.Severity
}

// MatchResult carries the outcome of a successful match against one or more rules.
type MatchResult struct {
	MatchedRules []string
	Severity     models.Severity
	MatchType    string
}

// Matcher evaluates findings against a compiled set of rules.
type Matcher struct {
	rules []compiledRule
}

// New constructs a Matcher from the provided rule configurations.
// For keyword rules, all patterns are lowercased for case-insensitive comparison.
// For regex rules, each pattern is compiled with regexp.Compile; an error is
// returned if any pattern is invalid.
func New(ruleConfigs []config.RuleConfig) (*Matcher, error) {
	rules := make([]compiledRule, 0, len(ruleConfigs))

	for _, rc := range ruleConfigs {
		sev, err := models.ParseSeverity(rc.Severity)
		if err != nil {
			return nil, fmt.Errorf("matcher: rule %q: %w", rc.Name, err)
		}

		cr := compiledRule{
			name:     rc.Name,
			ruleType: rc.Type,
			severity: sev,
		}

		switch rc.Type {
		case "keyword":
			cr.keywords = make([]string, len(rc.Patterns))
			for i, p := range rc.Patterns {
				cr.keywords[i] = strings.ToLower(p)
			}
		case "regex":
			cr.patterns = make([]*regexp.Regexp, 0, len(rc.Patterns))
			for _, p := range rc.Patterns {
				compiled, err := regexp.Compile(p)
				if err != nil {
					return nil, fmt.Errorf("matcher: rule %q: invalid regex %q: %w", rc.Name, p, err)
				}
				cr.patterns = append(cr.patterns, compiled)
			}
		default:
			return nil, fmt.Errorf("matcher: rule %q: unknown type %q", rc.Name, rc.Type)
		}

		rules = append(rules, cr)
	}

	return &Matcher{rules: rules}, nil
}

// Match evaluates all rules against the content of f.
// Keywords are matched case-insensitively; regex patterns are matched against
// the original content.
// If any rule matches, Match returns a MatchResult with all matched rule names,
// the highest severity observed, and the match type ("keyword", "regex", or
// "keyword+regex" when both types fired), along with true.
// If no rule matches, Match returns a zero MatchResult and false.
func (m *Matcher) Match(f models.Finding) (MatchResult, bool) {
	lowered := strings.ToLower(f.Content)

	var matchedRules []string
	highestSev := models.SeverityInfo
	sawKeyword := false
	sawRegex := false

	for _, rule := range m.rules {
		matched := false

		switch rule.ruleType {
		case "keyword":
			for _, kw := range rule.keywords {
				if strings.Contains(lowered, kw) {
					matched = true
					sawKeyword = true
					break
				}
			}
		case "regex":
			for _, re := range rule.patterns {
				if re.MatchString(f.Content) {
					matched = true
					sawRegex = true
					break
				}
			}
		}

		if matched {
			matchedRules = append(matchedRules, rule.name)
			if rule.severity > highestSev {
				highestSev = rule.severity
			}
		}
	}

	if len(matchedRules) == 0 {
		return MatchResult{}, false
	}

	matchType := matchTypeString(sawKeyword, sawRegex)

	return MatchResult{
		MatchedRules: matchedRules,
		Severity:     highestSev,
		MatchType:    matchType,
	}, true
}

// matchTypeString returns a human-readable string describing which rule types fired.
func matchTypeString(keyword, regex bool) string {
	switch {
	case keyword && regex:
		return "keyword+regex"
	case regex:
		return "regex"
	default:
		return "keyword"
	}
}
