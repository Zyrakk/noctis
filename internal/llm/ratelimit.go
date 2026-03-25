package llm

import (
	"context"
	"math"
	"sync"
	"time"
)

// RateLimiter implements a token-bucket rate limiter for LLM API calls.
// It is goroutine-safe and shared across all workers using the same LLM client.
type RateLimiter struct {
	mu         sync.Mutex
	tokens     float64
	maxTokens  float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

// NewRateLimiter creates a rate limiter that allows the given number of tokens
// per minute. If tokensPerMinute is <= 0, it defaults to 30000.
func NewRateLimiter(tokensPerMinute int) *RateLimiter {
	if tokensPerMinute <= 0 {
		tokensPerMinute = 30000
	}
	max := float64(tokensPerMinute)
	return &RateLimiter{
		tokens:     max,
		maxTokens:  max,
		refillRate: max / 60.0,
		lastRefill: time.Now(),
	}
}

// refill adds tokens based on elapsed time since the last refill.
// Must be called with mu held.
func (r *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	if elapsed <= 0 {
		return
	}
	r.tokens = math.Min(r.maxTokens, r.tokens+elapsed*r.refillRate)
	r.lastRefill = now
}

// Wait blocks until estimatedTokens are available, then deducts them.
// It respects context cancellation.
func (r *RateLimiter) Wait(ctx context.Context, estimatedTokens int) error {
	n := float64(estimatedTokens)
	if n <= 0 {
		n = 1
	}
	// Cap the request to bucket size so we never wait forever for an
	// impossibly large deduction.
	if n > r.maxTokens {
		n = r.maxTokens
	}

	for {
		r.mu.Lock()
		r.refill()
		if r.tokens >= n {
			r.tokens -= n
			r.mu.Unlock()
			return nil
		}
		// Calculate how long until enough tokens are available.
		deficit := n - r.tokens
		wait := time.Duration(deficit/r.refillRate*1000) * time.Millisecond
		wait = max(wait, 10*time.Millisecond)
		r.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
