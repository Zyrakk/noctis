package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// envVarPattern matches ${VAR_NAME} substitution tokens.
var envVarPattern = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// wrapper is used to unmarshal the top-level `noctis:` key.
type wrapper struct {
	Noctis Config `yaml:"noctis"`
}

// Config is the top-level configuration structure.
type Config struct {
	LogLevel    string         `yaml:"logLevel"`
	MetricsPort int            `yaml:"metricsPort"`
	HealthPort  int            `yaml:"healthPort"`
	Sources     SourcesConfig  `yaml:"sources"`
	Matching    MatchingConfig `yaml:"matching"`
	LLM         LLMConfig      `yaml:"llm"`
	Profiling   ProfilingConfig `yaml:"profiling"`
	Canary      CanaryConfig   `yaml:"canary"`
	Dispatch    DispatchConfig  `yaml:"dispatch"`
	Database    DatabaseConfig  `yaml:"database"`
	Graph       GraphConfig     `yaml:"graph"`
}

// SourcesConfig groups all ingest source configurations.
type SourcesConfig struct {
	Telegram TelegramConfig   `yaml:"telegram"`
	Paste    PasteConfig      `yaml:"paste"`
	Forums   ForumsConfig     `yaml:"forums"`
	Web      WebSourcesConfig `yaml:"web"`
	Tor      TorConfig        `yaml:"tor"`
}

// WebSourcesConfig configures web/RSS-based threat intelligence collection.
type WebSourcesConfig struct {
	Enabled bool        `yaml:"enabled"`
	Feeds   []WebConfig `yaml:"feeds"`
}

// WebConfig configures a single web feed source.
type WebConfig struct {
	Name            string        `yaml:"name"`
	URL             string        `yaml:"url"`
	Type            string        `yaml:"type"` // rss, scrape, search
	ContentSelector string        `yaml:"contentSelector"`
	Queries         []string      `yaml:"queries"`
	Interval        time.Duration `yaml:"interval"`
	Tor             bool          `yaml:"tor"`
}

// ForumsConfig configures forum-based threat intelligence collection.
type ForumsConfig struct {
	Enabled bool          `yaml:"enabled"`
	Sites   []ForumConfig `yaml:"sites"`
}

// ForumConfig configures a single forum site to scrape.
type ForumConfig struct {
	Name             string             `yaml:"name"`
	URL              string             `yaml:"url"`
	Tor              bool               `yaml:"tor"`
	Auth             ForumAuthConfig    `yaml:"auth"`
	Scraper          ForumScraperConfig `yaml:"scraper"`
	Interval         time.Duration      `yaml:"interval"`
	MaxPagesPerCrawl int                `yaml:"maxPagesPerCrawl"`
	RequestDelay     time.Duration      `yaml:"requestDelay"`
}

// ForumAuthConfig configures authentication for a forum site.
type ForumAuthConfig struct {
	Username      string `yaml:"username"`
	Password      string `yaml:"password"`
	LoginURL      string `yaml:"loginURL"`
	UsernameField string `yaml:"usernameField"`
	PasswordField string `yaml:"passwordField"`
}

// ForumScraperConfig configures CSS selectors for scraping a forum site.
type ForumScraperConfig struct {
	ThreadListSelector    string `yaml:"threadListSelector"`
	ThreadContentSelector string `yaml:"threadContentSelector"`
	AuthorSelector        string `yaml:"authorSelector"`
	PaginationSelector    string `yaml:"paginationSelector"`
}

// TelegramConfig configures the Telegram MTProto source.
type TelegramConfig struct {
	Enabled         bool            `yaml:"enabled"`
	APIId           int             `yaml:"apiId"`
	APIHash         string          `yaml:"apiHash"`
	Phone           string          `yaml:"phone"`
	Password        string          `yaml:"password"`
	Channels        []ChannelConfig `yaml:"channels"`
	CatchupMessages int             `yaml:"catchupMessages"`
	SessionFile     string          `yaml:"sessionFile"`
}

// ChannelConfig identifies a single Telegram channel.
type ChannelConfig struct {
	Username string `yaml:"username"`
	ID       int64  `yaml:"id"`
}

// PasteConfig configures paste-site scraping.
type PasteConfig struct {
	Enabled  bool            `yaml:"enabled"`
	Pastebin PastebinConfig  `yaml:"pastebin"`
	Scrapers []ScraperConfig `yaml:"scrapers"`
}

// PastebinConfig configures the Pastebin API scraper.
type PastebinConfig struct {
	Enabled  bool          `yaml:"enabled"`
	APIKey   string        `yaml:"apiKey"`
	Interval time.Duration `yaml:"interval"`
}

// ScraperConfig configures a generic HTTP scraper.
type ScraperConfig struct {
	Name     string        `yaml:"name"`
	URL      string        `yaml:"url"`
	Interval time.Duration `yaml:"interval"`
	Tor      bool          `yaml:"tor"`
}

// TorConfig configures the Tor SOCKS proxy used by scrapers.
type TorConfig struct {
	SocksProxy     string        `yaml:"socksProxy"`
	RequestTimeout time.Duration `yaml:"requestTimeout"`
}

// MatchingConfig holds all pattern-matching rules.
type MatchingConfig struct {
	Rules []RuleConfig `yaml:"rules"`
}

// RuleConfig defines a single matching rule.
type RuleConfig struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Patterns []string `yaml:"patterns"`
	Severity string   `yaml:"severity"`
}

// LLMConfig configures the language model client.
type LLMConfig struct {
	Provider         string        `yaml:"provider"`
	BaseURL          string        `yaml:"baseURL"`
	Model            string        `yaml:"model"`
	APIKey           string        `yaml:"apiKey"`
	MaxTokens        int           `yaml:"maxTokens"`
	Temperature      float64       `yaml:"temperature"`
	Timeout          time.Duration `yaml:"timeout"`
	Retries          int           `yaml:"retries"`
	MaxConcurrent    int           `yaml:"maxConcurrent"`
	RequestsPerMinute int          `yaml:"requestsPerMinute"`
}

// ProfilingConfig configures actor profiling behaviour.
type ProfilingConfig struct {
	Enabled             bool    `yaml:"enabled"`
	ActivityThreshold   int     `yaml:"activityThreshold"`
	SimilarityThreshold float64 `yaml:"similarityThreshold"`
	Storage             string  `yaml:"storage"`
}

// CanaryConfig configures canary token monitoring.
type CanaryConfig struct {
	Enabled bool   `yaml:"enabled"`
	Storage string `yaml:"storage"`
}

// DispatchConfig configures all alert dispatch backends.
type DispatchConfig struct {
	Wazuh         WazuhConfig         `yaml:"wazuh"`
	Webhooks      []WebhookConfig     `yaml:"webhooks"`
	CRDs          CRDConfig           `yaml:"crds"`
	NetworkPolicy NetworkPolicyConfig `yaml:"networkPolicy"`
}

// WazuhConfig configures the Wazuh dispatch backend.
type WazuhConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
	Format   string `yaml:"format"`
}

// WebhookConfig configures a single outbound webhook.
type WebhookConfig struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	MinSeverity string `yaml:"minSeverity"`
}

// CRDConfig configures Kubernetes CRD persistence.
type CRDConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Namespace      string `yaml:"namespace"`
	GCStaleAfterDays int  `yaml:"gcStaleAfterDays"`
}

// NetworkPolicyConfig configures automatic NetworkPolicy generation.
type NetworkPolicyConfig struct {
	Enabled        bool     `yaml:"enabled"`
	DryRun         bool     `yaml:"dryRun"`
	Namespace      string   `yaml:"namespace"`
	WhitelistCIDRs []string `yaml:"whitelistCIDRs"`
	MaxPolicies    int      `yaml:"maxPolicies"`
	TTLHours       int      `yaml:"ttlHours"`
}

// DatabaseConfig configures the persistence layer.
type DatabaseConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

// GraphConfig configures the relationship graph store.
type GraphConfig struct {
	Enabled bool `yaml:"enabled"`
}

// Load reads a YAML configuration file, performs ${VAR} environment variable
// substitution, unwraps the top-level `noctis:` key, and returns the parsed Config.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading file %q: %w", path, err)
	}

	substituted := substituteEnvVars(string(raw))

	var w wrapper
	if err := yaml.Unmarshal([]byte(substituted), &w); err != nil {
		return nil, fmt.Errorf("config: parsing YAML: %w", err)
	}

	return &w.Noctis, nil
}

// substituteEnvVars replaces all ${VAR_NAME} tokens with the corresponding
// environment variable value. If the variable is not set, the token is replaced
// with an empty string.
func substituteEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		sub := envVarPattern.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		return os.Getenv(sub[1])
	})
}
