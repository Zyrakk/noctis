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
// Since v3 the classify prompt also returns severity and reasoning.
type classifyResponse struct {
	Category   string  `json:"category"`
	Confidence float64 `json:"confidence"`
	Provenance string  `json:"provenance"`
	Severity   string  `json:"severity"`
	Reasoning  string  `json:"reasoning"`
}

// SubClassifyResult holds the JSON result from the classify_detail prompt.
type SubClassifyResult struct {
	SubCategory string         `json:"sub_category"`
	SubMetadata map[string]any `json:"sub_metadata"`
	Confidence  float64        `json:"confidence"`
	Reasoning   string         `json:"reasoning"`
}

// CorrelationEvalResult holds the JSON result from the evaluate_correlation prompt.
type CorrelationEvalResult struct {
	Decision        string  `json:"decision"`
	Confidence      float64 `json:"confidence"`
	Reasoning       string  `json:"reasoning"`
	MissingEvidence string  `json:"missing_evidence"`
}

// CorrelationPromptData is the data passed to the evaluate_correlation template.
type CorrelationPromptData struct {
	CandidateType string
	SignalCount   int
	Evidence      string
	Findings      []CorrelationFindingSummary
	Entities      []CorrelationEntitySummary
	Notes         []CorrelationNoteSummary
}

// CorrelationFindingSummary is a minimal finding view for the prompt.
type CorrelationFindingSummary struct {
	Category    string
	Severity    string
	Summary     string
	SourceName  string
	CollectedAt string
}

// CorrelationEntitySummary is an entity with its neighbors for the prompt.
type CorrelationEntitySummary struct {
	ID         string
	Type       string
	Properties string
	Neighbors  []CorrelationNeighborSummary
}

// CorrelationNeighborSummary is a neighbor entity for the prompt.
type CorrelationNeighborSummary struct {
	ID           string
	Relationship string
}

// CorrelationNoteSummary is a minimal note view for the prompt.
type CorrelationNoteSummary struct {
	CreatedAt  string
	Title      string
	Content    string
	Confidence float64
}

// severityResponse holds the JSON result from the severity prompt.
type severityResponse struct {
	Severity  string `json:"severity"`
	Reasoning string `json:"reasoning"`
}

// iocEntry is one element of the JSON array returned by the extract_iocs prompt.
type iocEntry struct {
	Type      string `json:"type"`
	Value     string `json:"value"`
	Context   string `json:"context"`
	Malicious bool   `json:"malicious"`
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

// stripCodeFences removes markdown code fences that LLMs (especially GLM)
// wrap around JSON responses. Handles ```json\n...\n```, ```\n...\n```,
// and trailing ```.
func stripCodeFences(s string) string {
	s = strings.TrimSpace(s)
	// Remove opening fence: ```json or ```
	if strings.HasPrefix(s, "```") {
		s = s[3:]
		// Remove optional language tag (e.g., "json")
		if idx := strings.Index(s, "\n"); idx != -1 && idx < 20 {
			s = s[idx+1:]
		}
	}
	// Remove closing fence
	if strings.HasSuffix(s, "```") {
		s = s[:len(s)-3]
	}
	s = strings.TrimSpace(s)

	// Handle thinking model preamble: find first JSON start.
	// Models like Gemini may emit reasoning text before the JSON.
	if len(s) > 0 && s[0] != '{' && s[0] != '[' {
		if idx := strings.IndexAny(s, "{["); idx != -1 {
			s = s[idx:]
		}
	}
	return strings.TrimSpace(s)
}

// truncate returns the first n characters of s, appending "..." if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
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
	if err := json.Unmarshal([]byte(stripCodeFences(resp.Content)), &result); err != nil {
		return nil, fmt.Errorf("analyzer: classify parse response %q: %w", truncate(resp.Content, 200), err)
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
	if err := json.Unmarshal([]byte(stripCodeFences(resp.Content)), &entries); err != nil {
		return nil, fmt.Errorf("analyzer: extract_iocs parse response %q: %w", truncate(resp.Content, 200), err)
	}

	iocs := make([]models.IOC, 0, len(entries))
	for _, e := range entries {
		if !e.Malicious {
			continue
		}
		iocs = append(iocs, models.IOC{
			Type:    e.Type,
			Value:   e.Value,
			Context: e.Context,
		})
	}
	return iocs, nil
}

// EntityEntry is one element of the entities array returned by extract_entities.
type EntityEntry struct {
	Type       string   `json:"type"`
	Name       string   `json:"name"`
	Aliases    []string `json:"aliases"`
	Observed   bool     `json:"observed"`
	Confidence string   `json:"confidence"`
}

// RelationshipEntry is one element of the relationships array returned by extract_entities.
type RelationshipEntry struct {
	Source       string `json:"source"`
	Target       string `json:"target"`
	Relationship string `json:"relationship"`
}

// EntityExtractionResult holds the parsed result of the extract_entities prompt.
type EntityExtractionResult struct {
	Entities      []EntityEntry      `json:"entities"`
	Relationships []RelationshipEntry `json:"relationships"`
}

// ExtractEntities asks the LLM to extract named entities (actors, malware,
// campaigns, TTPs) and their relationships from the finding content.
func (a *Analyzer) ExtractEntities(ctx context.Context, finding *models.Finding, category, sourceName, sourceType, provenance string) (*EntityExtractionResult, error) {
	prompt, err := a.renderTemplate("extract_entities", struct {
		Content    string
		Category   string
		SourceName string
		SourceType string
		Provenance string
	}{
		Content:    finding.Content,
		Category:   category,
		SourceName: sourceName,
		SourceType: sourceType,
		Provenance: provenance,
	})
	if err != nil {
		return nil, err
	}

	resp, err := a.client.ChatCompletion(ctx, []llm.Message{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return nil, fmt.Errorf("analyzer: extract_entities LLM call: %w", err)
	}

	var result EntityExtractionResult
	if err := json.Unmarshal([]byte(stripCodeFences(resp.Content)), &result); err != nil {
		return nil, fmt.Errorf("analyzer: extract_entities parse response %q: %w", truncate(resp.Content, 200), err)
	}
	return &result, nil
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
	if err := json.Unmarshal([]byte(stripCodeFences(resp.Content)), &result); err != nil {
		return models.SeverityInfo, fmt.Errorf("analyzer: severity parse response %q: %w", truncate(resp.Content, 200), err)
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

// SubClassify asks the LLM to determine a fine-grained sub-category and
// structured metadata for an already-classified finding.
func (a *Analyzer) SubClassify(ctx context.Context, finding *models.Finding, category, provenance string, entities, iocs []string) (*SubClassifyResult, error) {
	validSubs := validSubCategories(category)

	prompt, err := a.renderTemplate("classify_detail", struct {
		Content            string
		Category           string
		Source             string
		SourceName         string
		Provenance         string
		Entities           string
		IOCs               string
		ValidSubCategories string
	}{
		Content:            finding.Content,
		Category:           category,
		Source:             finding.Source,
		SourceName:         finding.SourceName,
		Provenance:         provenance,
		Entities:           strings.Join(entities, ", "),
		IOCs:               strings.Join(iocs, ", "),
		ValidSubCategories: strings.Join(validSubs, ", "),
	})
	if err != nil {
		return nil, err
	}

	resp, err := a.client.ChatCompletion(ctx, []llm.Message{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return nil, fmt.Errorf("analyzer: sub_classify LLM call: %w", err)
	}

	var result SubClassifyResult
	if err := json.Unmarshal([]byte(stripCodeFences(resp.Content)), &result); err != nil {
		return nil, fmt.Errorf("analyzer: sub_classify parse response %q: %w", truncate(resp.Content, 200), err)
	}

	if !isValidSubCategory(category, result.SubCategory) {
		return nil, fmt.Errorf("analyzer: sub_classify: invalid sub_category %q for category %q", result.SubCategory, category)
	}

	return &result, nil
}

// validSubCategories returns the allowed sub-categories for a top-level category.
func validSubCategories(category string) []string {
	switch category {
	case "malware_sample":
		return []string{"malware_analysis", "malware_delivery", "c2_infrastructure", "malware_source_code", "malware_config"}
	case "credential_leak":
		return []string{"database_dump", "combo_list", "api_key_leak", "session_token", "stealer_log"}
	case "vulnerability":
		return []string{"vulnerability_disclosure", "exploit_poc", "exploit_weaponized", "patch_advisory", "vulnerability_discussion"}
	case "threat_actor_comms":
		return []string{"campaign_planning", "tool_discussion", "recruitment", "bragging"}
	case "access_broker":
		return []string{"rdp_access", "vpn_access", "shell_access", "database_access", "cloud_access"}
	case "data_dump":
		return []string{"corporate_data", "government_data", "personal_data", "healthcare_data"}
	default:
		return nil
	}
}

// isValidSubCategory checks whether sub is a valid sub-category for the given category.
func isValidSubCategory(category, sub string) bool {
	for _, valid := range validSubCategories(category) {
		if valid == sub {
			return true
		}
	}
	return false
}

// EvaluateCorrelation asks the LLM to evaluate a correlation candidate and
// decide whether to promote, reject, or defer it.
func (a *Analyzer) EvaluateCorrelation(ctx context.Context, data *CorrelationPromptData) (*CorrelationEvalResult, error) {
	prompt, err := a.renderTemplate("evaluate_correlation", data)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.ChatCompletion(ctx, []llm.Message{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return nil, fmt.Errorf("analyzer: evaluate_correlation LLM call: %w", err)
	}

	var result CorrelationEvalResult
	if err := json.Unmarshal([]byte(stripCodeFences(resp.Content)), &result); err != nil {
		return nil, fmt.Errorf("analyzer: evaluate_correlation parse response %q: %w", truncate(resp.Content, 200), err)
	}

	switch result.Decision {
	case "promote", "reject", "defer":
		// valid
	default:
		return nil, fmt.Errorf("analyzer: evaluate_correlation: invalid decision %q", result.Decision)
	}

	return &result, nil
}

// BriefPromptData holds all context for daily brief generation.
type BriefPromptData struct {
	PeriodStart      string
	PeriodEnd        string
	TotalFindings    int64
	CriticalFindings int64
	HighFindings     int64
	TotalIOCs        int64
	NewCorrelations  int64
	AnalystConfirmed int64
	NewNotes         int64
	DeactivatedIOCs  int64
	TopFindings      []BriefFinding
	TrendingEntities []BriefEntity
	SourceActivity   []BriefSource
}

// BriefFinding is a finding summary for brief prompts.
type BriefFinding struct {
	Severity    string
	Category    string
	SubCategory string
	Summary     string
	SourceName  string
}

// BriefEntity is an entity trend for brief prompts.
type BriefEntity struct {
	ID           string
	Type         string
	MentionCount int64
	PrevCount    int64
}

// BriefSource is a source activity summary for brief prompts.
type BriefSource struct {
	Name         string
	FindingCount int64
	ValueScore   float64
}

// BriefResult is the parsed LLM response for a daily brief.
type BriefResult struct {
	Title            string         `json:"title"`
	ExecutiveSummary string         `json:"executive_summary"`
	Sections         map[string]any `json:"sections"`
}

// GenerateBrief asks the LLM to synthesize a daily intelligence brief from metrics.
func (a *Analyzer) GenerateBrief(ctx context.Context, data *BriefPromptData) (*BriefResult, error) {
	prompt, err := a.renderTemplate("daily_brief", data)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.ChatCompletion(ctx, []llm.Message{
		{Role: "user", Content: prompt},
	})
	if err != nil {
		return nil, fmt.Errorf("analyzer: daily_brief LLM call: %w", err)
	}

	var result BriefResult
	if err := json.Unmarshal([]byte(stripCodeFences(resp.Content)), &result); err != nil {
		return nil, fmt.Errorf("analyzer: daily_brief parse response %q: %w", truncate(resp.Content, 200), err)
	}

	if result.Title == "" {
		return nil, fmt.Errorf("analyzer: daily_brief: empty title in response")
	}

	return &result, nil
}
