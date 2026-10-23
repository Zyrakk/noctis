// Package inference implements durable, explicitly configured inference consumers.
package inference

import (
	"encoding/json"
	"github.com/Zyrakk/noctis/internal/evidence"
)

type Function string
type FunctionSpec struct {
	ID          Function `json:"id"`
	InputKind   string   `json:"input_kind"`
	Description string   `json:"description"`
}

var Functions = []FunctionSpec{
	{"semantic.classify", "observation", "Categoría e intención"}, {"semantic.relevance", "observation", "Relevancia explicada"},
	{"semantic.claims", "observation", "Afirmaciones atribuidas a la fuente"}, {"semantic.entities_relations", "observation", "Entidades y relaciones propuestas"},
	{"semantic.observable_roles", "observation", "Roles de observables"}, {"identity.disambiguate", "identity", "Hipótesis de identidad"},
	{"vulnerability.context", "vulnerability", "Contexto CVE; aplicabilidad desconocida"}, {"case.analyze", "case", "Análisis de expediente"},
	{"case.summarize", "case", "Síntesis de expediente"}, {"brief.compose", "brief", "Brief de cambios y cobertura"},
	{"query.plan", "query", "Plan de consulta tipado"}, {"query.explain", "query_result", "Explicación de resultados autorizados"},
	{"evidence.translate", "observation", "Traducción vinculada al original"}, {"source.triage", "source", "Propuesta de evaluación de fuente"},
}

func Spec(id Function) (FunctionSpec, bool) {
	for _, s := range Functions {
		if s.ID == id {
			return s, true
		}
	}
	return FunctionSpec{}, false
}

type Limits struct {
	MaxInputTokens  int `json:"max_input_tokens"`
	MaxOutputTokens int `json:"max_output_tokens"`
	DeadlineMS      int `json:"deadline_ms"`
}
type Price struct {
	Version string `json:"version"`
	Input   int64  `json:"input_units_per_token"`
	Output  int64  `json:"output_units_per_token"`
}
type Connection struct {
	ID            string   `json:"id"`
	Provider      string   `json:"provider"`
	Adapter       string   `json:"adapter"`
	URL           string   `json:"url"`
	DataClasses   []string `json:"data_classes"`
	SecretPresent bool     `json:"secret_present"`
	SecretAction  string   `json:"secret_action,omitempty"`
	APIKey        string   `json:"api_key,omitempty"`
}
type Binding struct {
	Function       Function `json:"function_id"`
	Enabled        bool     `json:"enabled"`
	ConnectionID   string   `json:"connection_id"`
	Model          string   `json:"model"`
	PromptVersion  string   `json:"prompt_version"`
	SchemaVersion  string   `json:"schema_version"`
	PolicyVersion  string   `json:"policy_version"`
	StructuredJSON bool     `json:"structured_json"`
	Limits         Limits   `json:"limits"`
	Price          Price    `json:"price"`
	DailyCap       int64    `json:"daily_cap_units"`
	MonthlyCap     int64    `json:"monthly_cap_units"`
	MaxConcurrent  int      `json:"max_concurrent"`
}
type Config struct {
	Revision      int64        `json:"revision"`
	Connections   []Connection `json:"connections"`
	Bindings      []Binding    `json:"bindings"`
	DailyCap      int64        `json:"daily_cap_units"`
	MonthlyCap    int64        `json:"monthly_cap_units"`
	MaxConcurrent int          `json:"max_concurrent"`
}
type ConfigView struct {
	Config
	Functions           []FunctionSpec `json:"functions"`
	CredentialAvailable bool           `json:"credential_available"`
}
type Input struct {
	Kind      string `json:"kind"`
	ID        string `json:"id,omitempty"`
	Revision  string `json:"revision,omitempty"`
	Text      string `json:"text,omitempty"`
	Period    string `json:"period,omitempty"`
	RightID   string `json:"right_id,omitempty"`
	Language  string `json:"language,omitempty"`
	DataClass string `json:"data_class,omitempty"`
}
type Submit struct {
	Function  Function `json:"function_id"`
	Input     Input    `json:"input"`
	RequestID string   `json:"request_id"`
}
type QueryFilters struct {
	SourceID string `json:"source_id,omitempty"`
	CaseID   string `json:"case_id,omitempty"`
	Kind     string `json:"kind,omitempty"`
}
type QueryPlan struct {
	Version   string       `json:"version"`
	Entity    string       `json:"entity"`
	Operation string       `json:"operation"`
	Mode      string       `json:"mode"`
	Text      string       `json:"text"`
	Filters   QueryFilters `json:"filters"`
	Cursor    string       `json:"cursor,omitempty"`
	Limit     int          `json:"limit"`
}
type QueryResult struct {
	ID         string            `json:"id"`
	Plan       QueryPlan         `json:"plan"`
	Rows       []json.RawMessage `json:"rows"`
	NextCursor string            `json:"next_cursor,omitempty"`
}
type Segment struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	Text  string `json:"text"`
}
type Snapshot struct {
	Input        Input           `json:"input"`
	Documents    []Document      `json:"documents"`
	Context      json.RawMessage `json:"context"`
	Dependencies []Dependency    `json:"dependencies"`
}
type Document struct {
	Ref          evidence.Ref `json:"ref"`
	Segments     []Segment    `json:"segments"`
	SourceID     string       `json:"source_id"`
	SourcePolicy string       `json:"source_policy"`
	Epoch        string       `json:"epoch"`
}
type Dependency struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Revision string `json:"revision"`
}
type Result struct {
	SchemaVersion string         `json:"schema_version"`
	Kind          string         `json:"kind"`
	Text          string         `json:"text"`
	Labels        []string       `json:"labels"`
	Intent        string         `json:"intent"`
	Claims        []Claim        `json:"claims"`
	Entities      []Entity       `json:"entities"`
	Roles         []Role         `json:"roles"`
	Identity      *Identity      `json:"identity"`
	Plan          *QueryPlan     `json:"plan"`
	Refs          []evidence.Ref `json:"refs"`
	Limitations   []string       `json:"limitations"`
}
type Claim struct {
	Subject   string         `json:"subject"`
	Predicate string         `json:"predicate"`
	Object    string         `json:"object"`
	Refs      []evidence.Ref `json:"refs"`
}
type Entity struct {
	Kind     string         `json:"kind"`
	Alias    string         `json:"alias"`
	Scope    string         `json:"scope"`
	Language string         `json:"language"`
	Refs     []evidence.Ref `json:"refs"`
}
type Role struct {
	Type  string         `json:"type"`
	Value string         `json:"value"`
	Role  string         `json:"role"`
	Refs  []evidence.Ref `json:"refs"`
}
type Identity struct {
	Relation string         `json:"relation"`
	Refs     []evidence.Ref `json:"refs"`
}
type JobView struct {
	ID               string         `json:"id"`
	Function         Function       `json:"function_id"`
	State            string         `json:"state"`
	Terminal         bool           `json:"terminal"`
	StatusURL        string         `json:"status_url"`
	Result           *Result        `json:"result,omitempty"`
	Refs             []evidence.Ref `json:"refs"`
	Limitations      []string       `json:"limitations"`
	Error            string         `json:"safe_error,omitempty"`
	ValidationReason string         `json:"validation_reason,omitempty"`
}
