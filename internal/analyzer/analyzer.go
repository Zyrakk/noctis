package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/Zyrakk/noctis/internal/llm"
	"github.com/Zyrakk/noctis/internal/models"
)

// classifyResponse holds the JSON result from the classify prompt.
type classifyResponse struct {
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
}

// severityResponse holds the JSON result from the severity prompt.
type severityResponse struct {
	Severity  string `json:"severity"`
	Reasoning string `json:"reasoning"`
}

// iocEntry is one element of the JSON array returned by the extract_iocs prompt.
type iocEntry struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Context string `json:"context"`
}

// Analyzer uses an LLM client to classify, enrich, and summarise findings.
type Analyzer struct {
	client    llm.LLMClient
	templates map[string]*template.Template
}

// New constructs an Analyzer that loads all *.tmpl files from promptsDir.
// Missing or unreadable template files produce a warning log rather than an
// error, so the caller can still use the analyzer for the templates that did
// load successfully.
func New(client llm.LLMClient, promptsDir string) *Analyzer {
	a := &Analyzer{
		client:    client,
		templates: make(map[string]*template.Template),
	}

	entries, err := os.ReadDir(promptsDir)
	if err != nil {
		log.Printf("analyzer: cannot read prompts dir %q: %v", promptsDir, err)
		return a
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".tmpl") {
			continue
		}
		name := strings.TrimSuffix(entry.Name(), ".tmpl")
		path := filepath.Join(promptsDir, entry.Name())

		t, err := template.ParseFiles(path)
		if err != nil {
			log.Printf("analyzer: failed to parse template %q: %v", path, err)
			continue
		}
		a.templates[name] = t
	}

	return a
}

// renderTemplate executes the named template with data and returns the result.
func (a *Analyzer) renderTemplate(name string, data any) (string, error) {
	t, ok := a.templates[name]
	if !ok {
		return "", fmt.Errorf("analyzer: template %q not loaded", name)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("analyzer: render template %q: %w", name, err)
	}
	return buf.String(), nil
}

// Classify asks the LLM to assign a category and confidence to the finding.
func (a *Analyzer) Classify(ctx context.Context, finding *models.Finding, matchedRules []string) (*classifyResponse, error) {
	prompt, err := a.renderTemplate("classify", struct {
		Source       string
		SourceName   string
		Content      string
		MatchedRules []string
	}{
		Source:       finding.Source,
		SourceName:   finding.SourceName,
		Content:      finding.Content,
		MatchedRules: matchedRules,
	})
	if err != nil {
		return nil, err
	}

	resp, err := a.client.ChatCompletion(ctx, []llm.Message{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return nil, fmt.Errorf("analyzer: classify LLM call: %w", err)
	}

	var result classifyResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(resp.Content)), &result); err != nil {
		return nil, fmt.Errorf("analyzer: classify parse response: %w", err)
	}
	return &result, nil
}

// ExtractIOCs asks the LLM to extract all indicators of compromise from the
// finding content.
func (a *Analyzer) ExtractIOCs(ctx context.Context, finding *models.Finding) ([]models.IOC, error) {
	prompt, err := a.renderTemplate("extract_iocs", struct {
		Content string
	}{
		Content: finding.Content,
	})
	if err != nil {
		return nil, err
	}

	resp, err := a.client.ChatCompletion(ctx, []llm.Message{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return nil, fmt.Errorf("analyzer: extract_iocs LLM call: %w", err)
	}

	var entries []iocEntry
	if err := json.Unmarshal([]byte(strings.TrimSpace(resp.Content)), &entries); err != nil {
		return nil, fmt.Errorf("analyzer: extract_iocs parse response: %w", err)
	}

	iocs := make([]models.IOC, len(entries))
	for i, e := range entries {
		iocs[i] = models.IOC{
			Type:    e.Type,
			Value:   e.Value,
			Context: e.Context,
		}
	}
	return iocs, nil
}

// AssessSeverity asks the LLM to assign a severity level to the finding.
func (a *Analyzer) AssessSeverity(ctx context.Context, finding *models.Finding, category string, matchedRules []string) (models.Severity, error) {
	prompt, err := a.renderTemplate("severity", struct {
		Source       string
		SourceName   string
		Content      string
		Category     string
		MatchedRules []string
	}{
		Source:       finding.Source,
		SourceName:   finding.SourceName,
		Content:      finding.Content,
		Category:     category,
		MatchedRules: matchedRules,
	})
	if err != nil {
		return models.SeverityInfo, err
	}

	resp, err := a.client.ChatCompletion(ctx, []llm.Message{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return models.SeverityInfo, fmt.Errorf("analyzer: severity LLM call: %w", err)
	}

	var result severityResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(resp.Content)), &result); err != nil {
		return models.SeverityInfo, fmt.Errorf("analyzer: severity parse response: %w", err)
	}

	sev, err := models.ParseSeverity(result.Severity)
	if err != nil {
		return models.SeverityInfo, fmt.Errorf("analyzer: severity unknown value: %w", err)
	}
	return sev, nil
}

// Summarize asks the LLM to write an analyst-readable summary of the finding.
// It returns the raw response text rather than parsed JSON.
func (a *Analyzer) Summarize(ctx context.Context, finding *models.Finding, category string, severity models.Severity) (string, error) {
	prompt, err := a.renderTemplate("summarize", struct {
		Source     string
		SourceName string
		Content    string
		Category   string
		Severity   string
		Author     string
		Timestamp  string
	}{
		Source:     finding.Source,
		SourceName: finding.SourceName,
		Content:    finding.Content,
		Category:   category,
		Severity:   severity.String(),
		Author:     finding.Author,
		Timestamp:  finding.Timestamp.String(),
	})
	if err != nil {
		return "", err
	}

	resp, err := a.client.ChatCompletion(ctx, []llm.Message{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return "", fmt.Errorf("analyzer: summarize LLM call: %w", err)
	}

	return resp.Content, nil
}
