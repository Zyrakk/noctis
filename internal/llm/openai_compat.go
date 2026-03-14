package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// chatRequest is the JSON body sent to the OpenAI chat completions endpoint.
type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature *float64  `json:"temperature,omitempty"`
	MaxTokens   *int      `json:"max_tokens,omitempty"`
}

// chatResponseChoice is one element in the choices array of the response.
type chatResponseChoice struct {
	Index   int     `json:"index"`
	Message Message `json:"message"`
}

// chatResponse is the JSON body returned by the OpenAI chat completions endpoint.
type chatResponse struct {
	ID      string               `json:"id"`
	Object  string               `json:"object"`
	Choices []chatResponseChoice `json:"choices"`
}

// OpenAICompatClient sends requests to any OpenAI-compatible chat completions
// API (GLM, OpenAI, Ollama, etc.).
type OpenAICompatClient struct {
	baseURL    string
	apiKey     string
	model      string
	httpClient *http.Client
}

// NewOpenAICompatClient constructs an OpenAICompatClient.
func NewOpenAICompatClient(baseURL, apiKey, model string) *OpenAICompatClient {
	return &OpenAICompatClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		model:      model,
		httpClient: &http.Client{},
	}
}

// ChatCompletion sends a chat completion request and returns the assistant reply.
// It implements LLMClient.
func (c *OpenAICompatClient) ChatCompletion(ctx context.Context, messages []Message, opts ...Option) (*Response, error) {
	// Apply functional options.
	options := &Options{}
	for _, o := range opts {
		o(options)
	}

	reqBody := chatRequest{
		Model:       c.model,
		Messages:    messages,
		Temperature: options.Temperature,
		MaxTokens:   options.MaxTokens,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("llm: marshal request: %w", err)
	}

	url := c.baseURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("llm: create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("llm: send request: %w", err)
	}
	defer httpResp.Body.Close()

	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("llm: read response body: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("llm: unexpected status %d: %s", httpResp.StatusCode, string(respBody))
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("llm: unmarshal response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("llm: no choices in response")
	}

	return &Response{Content: chatResp.Choices[0].Message.Content}, nil
}
