package inference

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestResponsesWireOffline(t *testing.T) {
	result := Result{SchemaVersion: "1", Kind: "query.plan", Text: "synthetic", Labels: []string{}, Intent: "unknown", Claims: []Claim{}, Entities: []Entity{}, Roles: []Role{}, Refs: nil, Limitations: []string{}, Plan: &QueryPlan{Version: "1", Entity: "observations", Operation: "search", Mode: "exact", Limit: 1}}
	raw, _ := json.Marshal(result)
	base := func() map[string]any {
		return map[string]any{"status": "completed", "model": "synthetic", "usage": map[string]any{"input_tokens": 12, "output_tokens": 30}, "output": []any{map[string]any{"type": "reasoning"}, map[string]any{"type": "message", "status": "completed", "role": "assistant", "content": []any{map[string]any{"type": "output_text", "text": string(raw)}}}}}
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		code   string
		usage  bool
	}{
		{"completed", func(m map[string]any) {}, "", true},
		{"incomplete", func(m map[string]any) { m["status"] = "incomplete" }, "response_incomplete", true},
		{"model", func(m map[string]any) { m["model"] = "changed" }, "model_changed", true},
		{"missing", func(m map[string]any) { delete(m, "usage") }, "usage_missing", false},
		{"partial", func(m map[string]any) { m["usage"] = map[string]int{"input_tokens": 12} }, "usage_missing", false},
		{"negative", func(m map[string]any) { m["usage"] = map[string]int{"input_tokens": -1, "output_tokens": 2} }, "usage_missing", false},
		{"refusal", func(m map[string]any) {
			m["output"] = []any{map[string]any{"type": "message", "status": "completed", "role": "assistant", "content": []any{map[string]any{"type": "refusal"}}}}
		}, "response_incomplete", true},
		{"tool", func(m map[string]any) { m["output"] = []any{map[string]any{"type": "function_call"}} }, "response_incomplete", true},
		{"ambiguous", func(m map[string]any) { m["output"] = append(m["output"].([]any), m["output"].([]any)[1]) }, "response_invalid", true},
		{"schema", func(m map[string]any) {
			m["output"].([]any)[1].(map[string]any)["content"] = []any{map[string]any{"type": "output_text", "text": "{}"}}
		}, "response_schema_invalid", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/v1/responses" || r.Header.Get("Authorization") != "Bearer synthetic" {
					t.Error("endpoint/auth mismatch")
				}
				var body map[string]json.RawMessage
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("body")
				}
				for _, f := range []string{"model", "instructions", "input", "max_output_tokens", "stream", "store", "text"} {
					if _, ok := body[f]; !ok {
						t.Error("missing", f)
					}
				}
				for _, f := range []string{"messages", "max_tokens", "tools", "previous_response_id", "response_format"} {
					if _, ok := body[f]; ok {
						t.Error("unexpected", f)
					}
				}
				if string(body["stream"]) != "false" || string(body["store"]) != "false" {
					t.Error("stream/store")
				}
				m := base()
				tc.mutate(m)
				json.NewEncoder(w).Encode(m)
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			s := Store{AllowLocal: map[string]bool{u.Host: true}}
			out, err := s.wire(context.Background(), Binding{Model: "synthetic", PromptVersion: "1", Limits: Limits{MaxInputTokens: 65536, MaxOutputTokens: 100, DeadlineMS: 2000}}, Connection{Adapter: "openai-responses", URL: srv.URL + "/v1/responses"}, "synthetic", "test", Snapshot{}, []Function{"query.plan"}, func(context.Context) error { return nil })
			if (err == nil) != (tc.code == "") {
				t.Fatalf("error %v", err)
			}
			if err != nil && err.(*GatewayError).Code != tc.code {
				t.Fatal(err)
			}
			if (out.Usage != nil) != tc.usage || calls.Load() != 1 {
				t.Fatal("usage/calls", out.Usage, calls.Load())
			}
			if err == nil && ValidatePlan(*out.Result.Plan) != nil {
				t.Fatal("real plan validator rejected")
			}
		})
	}
}

func TestResponsesSchemaMatchesValidators(t *testing.T) {
	p := responsesSchema([]Function{"query.plan"})["properties"].(map[string]any)
	plan := p["plan"].(map[string]any)["properties"].(map[string]any)
	if plan["limit"].(map[string]any)["minimum"] != 1 || p["identity"].(map[string]any)["type"] != "null" {
		t.Fatal("plan/null contract")
	}
	if ValidatePlan(QueryPlan{Version: "1", Operation: "search", Entity: "observations", Mode: "exact", Limit: 1}) != nil {
		t.Fatal("validator")
	}
}
