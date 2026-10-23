package inference

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Zyrakk/noctis/internal/evidence"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestResultValidationClosedCategories(t *testing.T) {
	const decoy = "SECRET-DECOY-provider-text-or-id"
	text := "Evidence café 8.8.8.8"
	ref := evidence.Ref{ObservationID: "synthetic", Revision: "1", Hash: "sha256:synthetic", Representation: "text/plain;utf8;v1", End: len(text)}
	x := execution{Function: "case.summarize", Snapshot: Snapshot{Documents: []Document{{Ref: ref, Segments: []Segment{{Text: text, End: len(text)}}}}}}
	base := func() Result {
		return Result{SchemaVersion: "1", Kind: "case.summarize", Text: decoy, Labels: []string{}, Intent: "unknown", Claims: []Claim{}, Entities: []Entity{}, Roles: []Role{}, Refs: []evidence.Ref{ref}, Limitations: []string{}}
	}
	if err := validateResult(x, base()); err != nil {
		t.Fatal("valid baseline rejected", err)
	}
	for _, tc := range []struct {
		name, reason string
		mutate       func(*Result)
	}{
		{"null", "null_collections", func(r *Result) { r.Claims = nil }},
		{"version", "version_kind", func(r *Result) { r.SchemaVersion = decoy }},
		{"kind", "version_kind", func(r *Result) { r.Kind = decoy }},
		{"text_limit", "limits", func(r *Result) { r.Text = strings.Repeat("x", 131073) }},
		{"limitation_limit", "limits", func(r *Result) { r.Limitations = []string{strings.Repeat("x", 4097)} }},
		{"label", "labels_intent", func(r *Result) { r.Labels = []string{decoy} }},
		{"intent", "labels_intent", func(r *Result) { r.Intent = decoy }},
		{"root_ref", "root_refs", func(r *Result) { r.Refs[0].ObservationID = decoy }},
		{"claim", "claim_fields_refs", func(r *Result) {
			r.Claims = []Claim{{Subject: decoy, Predicate: "reports", Object: decoy, Refs: []evidence.Ref{}}}
		}},
		{"entity", "entity_fields_refs", func(r *Result) {
			r.Entities = []Entity{{Kind: "handle", Alias: decoy, Scope: decoy, Language: "und", Refs: []evidence.Ref{}}}
		}},
		{"role", "role_fields_refs", func(r *Result) {
			r.Roles = []Role{{Type: "ip", Value: "8.8.8.8", Role: decoy, Refs: []evidence.Ref{ref}}}
		}},
		{"observable", "observable_extraction", func(r *Result) {
			r.Roles = []Role{{Type: "ip", Value: "8.8.4.4", Role: "reference", Refs: []evidence.Ref{ref}}}
		}},
		{"plan", "plan", func(r *Result) { r.Plan = &QueryPlan{Text: decoy} }},
		{"identity", "identity", func(r *Result) { r.Identity = &Identity{Relation: decoy} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.mutate(&r)
			err := validateResult(x, r)
			var typed *ResultValidationError
			if !errors.Is(err, ErrInvalid) || !errors.As(err, &typed) || typed.Reason != tc.reason || err.Error() != "result_validation_failed:"+tc.reason {
				t.Fatalf("unexpected validation category: %v", err)
			}
			if strings.Contains(err.Error(), decoy) {
				t.Fatal("provider material leaked")
			}
			code, reason := validationCode(err.Error())
			if code != "result_validation_failed" || reason != tc.reason {
				t.Fatal("unsafe API category")
			}
		})
	}
	if code, reason := validationCode("result_validation_failed:" + decoy); code != "result_validation_failed" || reason != "" {
		t.Fatal("unknown reason escaped whitelist")
	}
	if err := (&ResultValidationError{Reason: decoy}).Error(); err != "result_validation_failed" {
		t.Fatal("unknown typed category leaked")
	}
}

func TestResponsesContextOnlyContractThroughWireAndValidator(t *testing.T) {
	snapshot := Snapshot{Input: Input{Kind: "vulnerability", ID: "CVE-2099-12345"}, Documents: []Document{}, Context: json.RawMessage(`{"synthetic":"context only"}`)}
	for _, mutation := range []string{"valid", "claim", "entity", "role"} {
		t.Run(mutation, func(t *testing.T) {
			result := Result{SchemaVersion: "1", Kind: "vulnerability.context", Text: "SYNTHETIC feed context; applicability and exposure unknown", Labels: []string{"unknown"}, Intent: "unknown", Claims: []Claim{}, Entities: []Entity{}, Roles: []Role{}, Refs: []evidence.Ref{}, Limitations: []string{"Context only; no observation citations"}}
			switch mutation {
			case "claim":
				result.Claims = []Claim{{Subject: "secret-decoy", Predicate: "reports", Object: "context", Refs: []evidence.Ref{}}}
			case "entity":
				result.Entities = []Entity{{Kind: "handle", Alias: "secret-decoy", Scope: "context", Language: "und", Refs: []evidence.Ref{}}}
			case "role":
				result.Roles = []Role{{Type: "ip", Value: "8.8.8.8", Role: "reference", Refs: []evidence.Ref{}}}
			}
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				var body struct {
					Instructions string `json:"instructions"`
					Text         struct {
						Format struct {
							Schema map[string]any `json:"schema"`
						} `json:"format"`
					} `json:"text"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("request invalid")
					return
				}
				p := body.Text.Format.Schema["properties"].(map[string]any)
				for _, name := range []string{"refs", "claims", "entities", "roles"} {
					a := p[name].(map[string]any)
					if a["type"] != "array" || a["maxItems"] != float64(0) {
						t.Error("context-only schema allows unsupported evidence", name)
					}
				}
				if !strings.Contains(body.Instructions, "non-null empty arrays []") || !strings.Contains(body.Instructions, "local exposure remain unknown") {
					t.Error("context-only prompt missing")
				}
				raw, _ := json.Marshal(result)
				json.NewEncoder(w).Encode(map[string]any{"status": "completed", "model": "synthetic", "usage": map[string]int{"input_tokens": 10, "output_tokens": 20}, "output": []any{map[string]any{"type": "message", "status": "completed", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": string(raw)}}}}})
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			out, err := (Store{AllowLocal: map[string]bool{u.Host: true}}).wire(context.Background(), Binding{Model: "synthetic", PromptVersion: "2", Limits: Limits{MaxInputTokens: 65536, MaxOutputTokens: 100, DeadlineMS: 1000}}, Connection{URL: srv.URL, Adapter: "openai-responses"}, "synthetic", "synthetic", snapshot, []Function{"vulnerability.context"}, func(context.Context) error { return nil })
			if err != nil || out.Usage == nil || calls != 1 {
				t.Fatal("wire/decoder rejected fixture", err, calls)
			}
			err = validateResult(execution{Function: "vulnerability.context", Snapshot: snapshot}, out.Result)
			if mutation == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrInvalid) {
				t.Fatal("context evidence accepted", err)
			}
		})
	}
	populated := responsesSchemaForSnapshot([]Function{"case.summarize"}, Snapshot{Documents: []Document{{}}})["properties"].(map[string]any)
	if _, exists := populated["refs"].(map[string]any)["maxItems"]; exists {
		t.Fatal("document citations disabled")
	}
}
