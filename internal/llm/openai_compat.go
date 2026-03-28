package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
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
	Usage   *Usage               `json:"usage,omitempty"`
}

const maxRetries = 3

// OpenAICompatClient sends requests to any OpenAI-compatible chat completions
// API (GLM, OpenAI, Ollama, etc.).
type OpenAICompatClient struct {
	baseURL         string
	apiKey          string
	model           string
	httpClient      *http.Client
	rateLimiter     *RateLimiter
	spendingTracker *SpendingTracker
}

// SetRateLimiter attaches a shared rate limiter to this client.
func (c *OpenAICompatClient) SetRateLimiter(rl *RateLimiter) {
	c.rateLimiter = rl
}

// SetSpendingTracker attaches a spending tracker for budget enforcement.
func (c *OpenAICompatClient) SetSpendingTracker(st *SpendingTracker) {
	c.spendingTracker = st
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

// estimateTokens gives a rough token count for rate-limiter budgeting.
func estimateTokens(messages []Message, maxTokens *int) int {
	chars := 0
	for _, m := range messages {
		chars += len(m.Content)
	}
	est := chars/4 + 50 // ~4 chars per token + overhead
	if maxTokens != nil {
		est += *maxTokens
	} else {
		est += 256 // default completion budget
	}
	return est
}

// ChatCompletion sends a chat completion request and returns the assistant reply.
// It implements LLMClient.
func (c *OpenAICompatClient) ChatCompletion(ctx context.Context, messages []Message, opts ...Option) (*Response, error) {
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

	// Check spending budget before sending.
	if c.spendingTracker != nil {
		if err := c.spendingTracker.CheckBudget(); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrBudgetExhausted, err)
		}
	}

	// Wait for rate limiter budget before sending.
	if c.rateLimiter != nil {
		est := estimateTokens(messages, options.MaxTokens)
		if err := c.rateLimiter.Wait(ctx, est); err != nil {
			return nil, fmt.Errorf("llm: rate limiter: %w", err)
		}
	}

	url := c.baseURL + "/chat/completions"

	var lastErr error
	for attempt := range maxRetries {
		resp, err := c.doRequest(ctx, url, payload)
		if err == nil {
			// Record actual usage for spending tracking.
			if c.spendingTracker != nil {
				c.spendingTracker.Record(resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
			}
			return resp, nil
		}

		// Only retry on 429 (rate limited).
		var httpErr *httpStatusError
		if !errors.As(err, &httpErr) || httpErr.statusCode != http.StatusTooManyRequests {
			return nil, err
		}

		lastErr = err
		backoff := retryBackoff(httpErr.retryAfter, attempt)
		slog.Warn("llm: 429 rate limited, backing off",
			"attempt", attempt+1,
			"backoff", backoff,
			"provider", c.baseURL,
		)

		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, fmt.Errorf("llm: retries exhausted: %w", lastErr)
}

// doRequest performs a single HTTP request to the chat completions endpoint.
func (c *OpenAICompatClient) doRequest(ctx context.Context, url string, payload []byte) (*Response, error) {
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

	if httpResp.StatusCode == http.StatusTooManyRequests {
		retryAfter := parseRetryAfter(httpResp.Header.Get("Retry-After"))
		return nil, &httpStatusError{
			statusCode: http.StatusTooManyRequests,
			body:       string(respBody),
			retryAfter: retryAfter,
		}
	}

	if httpResp.StatusCode != http.StatusOK {
		body := string(respBody)
		// Groq returns 400 with "spend_limit_reached" or "spend_alert" when
		// the account's spend cap is hit. Wrap as ErrBudgetExhausted so callers
		// can distinguish budget errors from transient failures.
		if httpResp.StatusCode == http.StatusBadRequest &&
			(strings.Contains(body, "spend_limit_reached") || strings.Contains(body, "spend_alert")) {
			return nil, fmt.Errorf("%w: %s", ErrBudgetExhausted, body)
		}
		return nil, fmt.Errorf("llm: unexpected status %d: %s", httpResp.StatusCode, body)
	}

	var chatResp chatResponse
	if err := json.Unmarshal(respBody, &chatResp); err != nil {
		return nil, fmt.Errorf("llm: unmarshal response: %w", err)
	}

	if len(chatResp.Choices) == 0 {
		return nil, fmt.Errorf("llm: no choices in response")
	}

	resp := &Response{Content: chatResp.Choices[0].Message.Content}
	if chatResp.Usage != nil {
		resp.Usage = *chatResp.Usage
	}
	return resp, nil
}

// httpStatusError captures an HTTP error with optional retry-after duration.
type httpStatusError struct {
	statusCode int
	body       string
	retryAfter time.Duration
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("llm: HTTP %d: %s", e.statusCode, e.body)
}

// parseRetryAfter parses a Retry-After header value (seconds).
func parseRetryAfter(val string) time.Duration {
	if val == "" {
		return 0
	}
	secs, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// retryBackoff returns the backoff duration for a given retry attempt.
// Uses the server's retry-after if available, otherwise exponential backoff.
func retryBackoff(retryAfter time.Duration, attempt int) time.Duration {
	if retryAfter > 0 {
		return retryAfter
	}
	backoff := time.Duration(1<<uint(attempt+1)) * time.Second // 2s, 4s, 8s
	backoff = min(backoff, 30*time.Second)
	return backoff
}
