package llm_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Zyrakk/noctis/internal/llm"
)

// fakeResponse builds a minimal OpenAI chat completions response body.
func fakeResponse(content string) string {
	return `{
		"id": "chatcmpl-test",
		"object": "chat.completion",
		"choices": [
			{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": "` + content + `"
				},
				"finish_reason": "stop"
			}
		]
	}`
}

func TestOpenAICompatClient_ChatCompletion(t *testing.T) {
	const wantContent = "Hello, world!"
	const wantModel = "glm-4"
	const wantAPIKey = "test-key"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Validate method
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		// Validate path
		if r.URL.Path != "/chat/completions" {
			t.Errorf("expected path /chat/completions, got %s", r.URL.Path)
		}
		// Validate Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "Bearer "+wantAPIKey {
			t.Errorf("expected Authorization 'Bearer %s', got %s", wantAPIKey, authHeader)
		}
		// Validate model in request body
		var reqBody map[string]interface{}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Fatalf("could not unmarshal request body: %v", err)
		}
		if model, ok := reqBody["model"].(string); !ok || model != wantModel {
			t.Errorf("expected model %q, got %v", wantModel, reqBody["model"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fakeResponse(wantContent)))
	}))
	defer srv.Close()

	client := llm.NewOpenAICompatClient(srv.URL, wantAPIKey, wantModel)

	resp, err := client.ChatCompletion(t.Context(), []llm.Message{
		{Role: "user", Content: "Say hello"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Content != wantContent {
		t.Errorf("expected content %q, got %q", wantContent, resp.Content)
	}
}

func TestOpenAICompatClient_ErrorResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error": "rate limit exceeded"}`))
	}))
	defer srv.Close()

	client := llm.NewOpenAICompatClient(srv.URL, "key", "model")

	_, err := client.ChatCompletion(t.Context(), []llm.Message{
		{Role: "user", Content: "hello"},
	})
	if err == nil {
		t.Fatal("expected error for 429 response, got nil")
	}
}

func TestOpenAICompatClient_WithOptions(t *testing.T) {
	const wantTemp = 0.5
	const wantMaxTokens = 512

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reqBody map[string]interface{}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &reqBody); err != nil {
			t.Fatalf("could not unmarshal request body: %v", err)
		}

		// Validate temperature
		temp, ok := reqBody["temperature"].(float64)
		if !ok || temp != wantTemp {
			t.Errorf("expected temperature %v, got %v", wantTemp, reqBody["temperature"])
		}

		// Validate max_tokens
		maxTokens, ok := reqBody["max_tokens"].(float64) // JSON numbers unmarshal as float64
		if !ok || int(maxTokens) != wantMaxTokens {
			t.Errorf("expected max_tokens %d, got %v", wantMaxTokens, reqBody["max_tokens"])
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fakeResponse("ok")))
	}))
	defer srv.Close()

	client := llm.NewOpenAICompatClient(srv.URL, "key", "model")

	_, err := client.ChatCompletion(t.Context(), []llm.Message{
		{Role: "user", Content: "hello"},
	}, llm.WithTemperature(wantTemp), llm.WithMaxTokens(wantMaxTokens))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
