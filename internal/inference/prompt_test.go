package inference

import (
	"context"
	"encoding/json"
	promptsv2 "github.com/Zyrakk/noctis/prompts/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestWirePromptVersionAndUnknownBeforePOST(t *testing.T) {
	for _, version := range []string{"1", "2", "unknown", ""} {
		t.Run("version_"+version, func(t *testing.T) {
			posts, authorized := 0, 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				posts++
				var body struct {
					Instructions string `json:"instructions"`
					Text         struct {
						Format struct {
							Schema map[string]any `json:"schema"`
						} `json:"format"`
					} `json:"text"`
				}
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					t.Error("invalid fixture request")
					return
				}
				instructions, _, err := promptsv2.Resolve(version)
				if err != nil {
					t.Error("unknown reached POST")
					return
				}
				ids, _ := json.Marshal([]Function{"vulnerability.context"})
				if body.Instructions != instructions+string(ids) {
					t.Error("binding version did not select exact registered instructions")
				}
				properties := body.Text.Format.Schema["properties"].(map[string]any)
				for _, name := range []string{"refs", "claims", "entities", "roles"} {
					value, limited := properties[name].(map[string]any)["maxItems"]
					if version == "1" && limited {
						t.Error("v1 generation schema changed", name)
					}
					if version == "2" && (!limited || value != float64(0)) {
						t.Error("v2 no-doc constraint absent", name)
					}
				}
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			u, _ := url.Parse(srv.URL)
			_, err := (Store{AllowLocal: map[string]bool{u.Host: true}}).wire(context.Background(), Binding{PromptVersion: version, Model: "synthetic", Limits: Limits{MaxInputTokens: 65536, MaxOutputTokens: 16, DeadlineMS: 1000}}, Connection{URL: srv.URL, Adapter: "openai-responses"}, "synthetic", "synthetic", Snapshot{}, []Function{"vulnerability.context"}, func(context.Context) error { authorized++; return nil })
			known := version == "1" || version == "2"
			if known {
				if posts != 1 || authorized != 1 {
					t.Fatal("known prompt did not make exactly one call")
				}
			} else {
				if posts != 0 || authorized != 0 || err == nil || err.Error() != "prompt_version_invalid" {
					t.Fatal("unknown prompt reached authorization or POST", posts, authorized, err)
				}
			}
		})
	}
}
func TestPromptVersionsSeparateCacheIdentity(t *testing.T) {
	snapshot := Snapshot{Input: Input{Kind: "query", Text: "same input"}}
	b := Binding{Function: "query.plan", PromptVersion: "1"}
	old := jobCacheKey(1, b, snapshot)
	if old != jobCacheKey(1, b, snapshot) {
		t.Fatal("legacy identity not stable")
	}
	b.PromptVersion = "2"
	if old == jobCacheKey(1, b, snapshot) || old == jobCacheKey(2, b, snapshot) {
		t.Fatal("prompt versions share a cache identity")
	}
}
func TestDefaultConfigUsesPromptV2AndRejectsUnknown(t *testing.T) {
	c := DefaultConfig()
	for _, b := range c.Bindings {
		if b.PromptVersion != "2" {
			t.Fatal("new binding inherits legacy prompt")
		}
	}
	if err := (Store{}).Validate(c); err != nil {
		t.Fatal(err)
	}
	c.Bindings[0].PromptVersion = "1"
	if err := (Store{}).Validate(c); err != nil {
		t.Fatal("persisted v1 unsupported", err)
	}
	c.Bindings[0].PromptVersion = strings.Repeat("unknown", 2)
	if err := (Store{}).Validate(c); err == nil {
		t.Fatal("unknown prompt accepted")
	}
}
