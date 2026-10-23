package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"github.com/Zyrakk/noctis/internal/evidence"
	"github.com/Zyrakk/noctis/internal/inference"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
)

// This fixture accepts only a fixed synthetic key and never contacts a provider.
func setupOfflineResponses(dir, cert, tlsKey string, inputs realAIInputs) (realAIInputs, string, []string, func(), error) {
	fail := func() (realAIInputs, string, []string, func(), error) {
		return inputs, "", nil, nil, errors.New("offline Responses requires exact synthetic key and adapter")
	}
	if inputs.Provider != "synthetic-offline" || inputs.Endpoint != "https://example.invalid/v1/responses" || filepath.Base(inputs.APIKeyFile) != "synthetic.key" {
		return fail()
	}
	key, e := os.ReadFile(inputs.APIKeyFile)
	if e != nil || string(key) != "SYNTHETIC-OFFLINE-RESPONSES" || inputs.Adapter != "openai-responses" {
		return fail()
	}
	pair, e := tls.LoadX509KeyPair(cert, tlsKey)
	if e != nil {
		return fail()
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/responses" || r.Method != "POST" || r.Header.Get("Authorization") != "Bearer SYNTHETIC-OFFLINE-RESPONSES" {
			w.WriteHeader(400)
			return
		}
		var body struct {
			Model string `json:"model"`
			Input string `json:"input"`
			Text  struct {
				Format struct {
					Schema struct {
						Properties struct {
							Kind struct {
								Enum []string `json:"enum"`
							} `json:"kind"`
						} `json:"properties"`
					} `json:"schema"`
				} `json:"format"`
			} `json:"text"`
		}
		var snap inference.Snapshot
		if json.NewDecoder(r.Body).Decode(&body) != nil || json.Unmarshal([]byte(body.Input), &snap) != nil || len(body.Text.Format.Schema.Properties.Kind.Enum) == 0 {
			w.WriteHeader(400)
			return
		}
		kind := body.Text.Format.Schema.Properties.Kind.Enum[0]
		if snap.Input.Kind == "observation" && kind != "evidence.translate" {
			kind = "semantic"
		}
		result := inference.Result{SchemaVersion: "1", Kind: kind, Text: "Resultado sintético offline", Labels: []string{"unknown"}, Intent: "unknown", Claims: []inference.Claim{}, Entities: []inference.Entity{}, Roles: []inference.Role{}, Refs: []evidence.Ref{}, Limitations: []string{"SYNTHETIC offline"}}
		for _, d := range snap.Documents {
			result.Refs = append(result.Refs, d.Ref)
		}
		if kind == "query.plan" {
			result.Plan = &inference.QueryPlan{Version: "1", Entity: "observations", Operation: "search", Mode: "fulltext", Text: "ACME", Limit: 10}
		}
		if kind == "identity.disambiguate" {
			result.Identity = &inference.Identity{Relation: "unknown", Refs: result.Refs}
		}
		raw, _ := json.Marshal(result)
		json.NewEncoder(w).Encode(map[string]any{"model": body.Model, "status": "completed", "usage": map[string]int{"input_tokens": 100, "output_tokens": 20}, "output": []any{map[string]any{"type": "reasoning", "summary": []any{}}, map[string]any{"type": "message", "role": "assistant", "status": "completed", "content": []any{map[string]any{"type": "output_text", "text": string(raw)}}}}})
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	inputs.Endpoint = srv.URL + "/v1/responses"
	path := filepath.Join(dir, "offline-responses-inputs.json")
	raw, _ := json.Marshal(inputs)
	if os.WriteFile(path, raw, 0600) != nil {
		srv.Close()
		return fail()
	}
	u, _ := url.Parse(srv.URL)
	return inputs, path, []string{"--ai-ca-file", cert, "--ai-local-authority", u.Host}, srv.Close, nil
}
