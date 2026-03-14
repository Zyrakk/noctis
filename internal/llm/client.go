package llm

import "context"

// Message represents a single chat message with a role and content.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Response holds the result from a chat completion call.
type Response struct {
	Content string
}

// Options collects optional overrides for a chat completion request.
type Options struct {
	Temperature *float64
	MaxTokens   *int
}

// Option is a functional option that configures an Options struct.
type Option func(*Options)

// WithTemperature sets the sampling temperature for a request.
func WithTemperature(t float64) Option {
	return func(o *Options) { o.Temperature = &t }
}

// WithMaxTokens sets the maximum number of tokens for a request.
func WithMaxTokens(n int) Option {
	return func(o *Options) { o.MaxTokens = &n }
}

// LLMClient is the interface satisfied by any OpenAI-compatible LLM backend.
type LLMClient interface {
	ChatCompletion(ctx context.Context, messages []Message, opts ...Option) (*Response, error)
}
