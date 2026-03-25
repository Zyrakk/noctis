package llm

import (
	"context"
	"log"
	"math"
	"sync"
	"time"
)

// RateLimiter implements a token-bucket rate limiter for LLM API calls.
// It is goroutine-safe and shared across all workers using the same LLM client.
type RateLimiter struct {
	mu           sync.Mutex
	tokens       float64
	maxTokens    float64
	refillRate   float64 // tokens per second
	lastRefill   time.Time
	dailyLimit   int64     // 0 = no daily limit
	dailyUsed    int64
	dailyResetAt time.Time // next midnight UTC
}

// NewRateLimiter creates a rate limiter that allows the given number of tokens
// per minute and an optional daily token budget. If tokensPerMinute is <= 0,
// it defaults to 30000. If tokensPerDay is <= 0, the daily limit is disabled.
func NewRateLimiter(tokensPerMinute, tokensPerDay int) *RateLimiter {
	if tokensPerMinute <= 0 {
		tokensPerMinute = 30000
	}
	max := float64(tokensPerMinute)
	rl := &RateLimiter{
		tokens:     max,
		maxTokens:  max,
		refillRate: max / 60.0,
		lastRefill: time.Now(),
		dailyLimit: int64(tokensPerDay),
	}
	if tokensPerDay > 0 {
		rl.dailyResetAt = nextMidnightUTC()
	}
	return rl
}

// nextMidnightUTC returns the next midnight UTC from now.
func nextMidnightUTC() time.Time {
	now := time.Now().UTC()
	return time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC)
}

// resetDailyIfNeeded resets the daily counter if we've passed the reset time.
// Must be called with mu held.
func (r *RateLimiter) resetDailyIfNeeded() {
	if !time.Now().Before(r.dailyResetAt) {
		r.dailyUsed = 0
		r.dailyResetAt = nextMidnightUTC()
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
// It respects context cancellation. When a daily limit is configured and
// exhausted, Wait sleeps until the next midnight UTC reset.
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

		// Check daily limit first.
		if r.dailyLimit > 0 {
			r.resetDailyIfNeeded()
			if r.dailyUsed+int64(n) > r.dailyLimit {
				sleepUntil := r.dailyResetAt
				used := r.dailyUsed
				limit := r.dailyLimit
				r.mu.Unlock()

				wait := time.Until(sleepUntil)
				if wait <= 0 {
					continue // reset just passed, retry
				}
				log.Printf("rate_limiter: daily token limit reached (%d/%d), sleeping until %s",
					used, limit, sleepUntil.UTC().Format("15:04 UTC"))
				timer := time.NewTimer(wait)
				select {
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				case <-timer.C:
					continue
				}
			}
		}

		// Per-minute rate limiting.
		r.refill()
		if r.tokens >= n {
			r.tokens -= n
			if r.dailyLimit > 0 {
				r.dailyUsed += int64(n)
			}
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
