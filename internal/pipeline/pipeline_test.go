package pipeline

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Zyrakk/noctis/internal/collector"
	"github.com/Zyrakk/noctis/internal/config"
	"github.com/Zyrakk/noctis/internal/llm"
	"github.com/Zyrakk/noctis/internal/models"
)

// ---------------------------------------------------------------------------
// fakeCollector emits a fixed list of findings, then blocks until ctx is
// cancelled, then closes out.
// ---------------------------------------------------------------------------

type fakeCollector struct {
	findings []models.Finding
}

func (f *fakeCollector) Name() string { return "fake" }

func (f *fakeCollector) Start(ctx context.Context, out chan<- models.Finding) error {
	defer close(out)
	for _, finding := range f.findings {
		select {
		case out <- finding:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	<-ctx.Done()
	return ctx.Err()
}

// Compile-time check that fakeCollector implements collector.Collector.
var _ collector.Collector = (*fakeCollector)(nil)

// ---------------------------------------------------------------------------
// fakeLLMClient returns canned responses based on the combined prompt prefix.
// ---------------------------------------------------------------------------

type fakeLLMClient struct {
	responses map[string]string
}

func (f *fakeLLMClient) ChatCompletion(_ context.Context, messages []llm.Message, _ ...llm.Option) (*llm.Response, error) {
	var combined strings.Builder
	for _, msg := range messages {
		combined.WriteString(msg.Content)
	}
	prompt := combined.String()

	for key, resp := range f.responses {
		if strings.HasPrefix(prompt, key) {
			return &llm.Response{Content: resp}, nil
		}
	}
	return nil, fmt.Errorf("fakeLLMClient: unrecognized prompt header")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestFakeLLMClient_PromptPrefixRouting(t *testing.T) {
	responses := map[string]string{
		"You are a cyber threat intelligence analyst. Classify": "classification",
		"You are a cyber threat intelligence analyst. Extract":  "indicators",
		"You are a cyber threat intelligence analyst. Assess":   "severity",
		"You are a cyber threat intelligence analyst. Write":    "summary",
	}
	client := &fakeLLMClient{responses: responses}
	var body strings.Builder
	for prefix := range responses {
		body.WriteString("\n")
		body.WriteString(prefix)
	}
	for prefix, want := range responses {
		t.Run(want, func(t *testing.T) {
			response, err := client.ChatCompletion(context.Background(), []llm.Message{{Content: prefix + body.String()}})
			if err != nil {
				t.Fatalf("ChatCompletion() error: %v", err)
			}
			if response.Content != want {
				t.Errorf("Content = %q; want %q", response.Content, want)
			}
		})
	}
	t.Run("unknown header", func(t *testing.T) {
		response, err := client.ChatCompletion(context.Background(), []llm.Message{{Content: "Unknown task" + body.String()}})
		if err == nil || response != nil {
			t.Fatalf("ChatCompletion() = %v, %v; want nil response and error", response, err)
		}
	})
}

func TestPipeline_EndToEnd(t *testing.T) {
	findings := []models.Finding{
		{
			ID:      "match-1",
			Source:  "telegram",
			Content: "leaked creds for example.com admin:hunter2",
		},
		{
			ID:      "no-match-1",
			Source:  "paste",
			Content: "totally unrelated content about cooking recipes",
		},
	}

	rules := []config.RuleConfig{
		{
			Name:     "cred-leak",
			Type:     "keyword",
			Patterns: []string{"example.com"},
			Severity: "high",
		},
	}

	llmClient := &fakeLLMClient{
		responses: map[string]string{
			"You are a cyber threat intelligence analyst. Classify": `{"category":"credential_leak","confidence":0.95,"provenance":"first_party"}`,
			"You are a cyber threat intelligence analyst. Extract":  `[{"type":"hash_sha256","value":"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4","context":"leaked creds","malicious":true}]`,
			"You are a cyber threat intelligence analyst. Assess":   `{"severity":"critical","reasoning":"Active credentials exposed"}`,
			"You are a cyber threat intelligence analyst. Write":    "Credentials for example.com were leaked on Telegram.",
		},
	}

	var mu sync.Mutex
	var dispatched []models.EnrichedFinding

	dispatch := func(ef models.EnrichedFinding) {
		mu.Lock()
		dispatched = append(dispatched, ef)
		mu.Unlock()
	}

	collectors := []collector.Collector{
		&fakeCollector{findings: findings},
	}

	p, err := NewPipeline(collectors, rules, llmClient, "../../prompts", dispatch)
	if err != nil {
		t.Fatalf("NewPipeline() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	p.Run(ctx)

	mu.Lock()
	defer mu.Unlock()

	if len(dispatched) != 1 {
		t.Fatalf("dispatched count = %d; want 1", len(dispatched))
	}

	ef := dispatched[0]
	if ef.Category != models.CategoryCredentialLeak {
		t.Errorf("Category = %q; want %q", ef.Category, models.CategoryCredentialLeak)
	}
	if ef.ID != "match-1" {
		t.Errorf("ID = %q; want %q", ef.ID, "match-1")
	}
	if ef.Confidence != 0.95 {
		t.Errorf("Confidence = %v; want 0.95", ef.Confidence)
	}
	if len(ef.IOCs) != 1 {
		t.Fatalf("IOCs count = %d; want 1", len(ef.IOCs))
	}
	if ef.IOCs[0].Value != "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4" {
		t.Errorf("IOC value = %q; want %q", ef.IOCs[0].Value, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4")
	}
	if ef.LLMAnalysis == "" {
		t.Error("LLMAnalysis is empty; want non-empty summary")
	}
	if ef.Severity != models.SeverityCritical {
		t.Errorf("Severity = %v; want SeverityCritical", ef.Severity)
	}
}

func TestPipeline_NoMatchesNoDispatch(t *testing.T) {
	findings := []models.Finding{
		{
			ID:      "unrelated-1",
			Source:  "paste",
			Content: "nothing interesting here, just a random post",
		},
	}

	rules := []config.RuleConfig{
		{
			Name:     "cred-leak",
			Type:     "keyword",
			Patterns: []string{"example.com"},
			Severity: "high",
		},
	}

	llmClient := &fakeLLMClient{
		responses: map[string]string{},
	}

	var mu sync.Mutex
	var dispatched []models.EnrichedFinding

	dispatch := func(ef models.EnrichedFinding) {
		mu.Lock()
		dispatched = append(dispatched, ef)
		mu.Unlock()
	}

	collectors := []collector.Collector{
		&fakeCollector{findings: findings},
	}

	p, err := NewPipeline(collectors, rules, llmClient, "../../prompts", dispatch)
	if err != nil {
		t.Fatalf("NewPipeline() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	p.Run(ctx)

	mu.Lock()
	defer mu.Unlock()

	if len(dispatched) != 0 {
		t.Fatalf("dispatched count = %d; want 0", len(dispatched))
	}
}
