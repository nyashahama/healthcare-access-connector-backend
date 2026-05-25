package middleware

import (
	"context"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
)

const redisRateLimiterTTL = 2 * time.Second

const redisRateLimitScript = `
local key = KEYS[1]
local ratePerSecond = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local rawTokens = redis.call("HGET", key, "tokens")
local rawLastRefill = redis.call("HGET", key, "last_refill")

local tokens = tonumber(rawTokens)
local lastRefill = tonumber(rawLastRefill)

if tokens == nil or lastRefill == nil then
  tokens = burst
  lastRefill = now
end

local elapsed = now - lastRefill
if elapsed > 0 then
  local added = (ratePerSecond * (elapsed / 1000.0))
  tokens = math.min(burst, tokens + added)
  lastRefill = now
end

if tokens < 1 then
  return 0
end

tokens = tokens - 1

redis.call("HSET", key, "tokens", tokens, "last_refill", lastRefill)
redis.call("PEXPIRE", key, ARGV[4])
return 1
`

type rateLimiter interface {
	Allow(ctx context.Context, key string) bool
}

type memoryRateLimiter struct {
	mu      sync.Mutex
	rps     float64
	burst   int
	clients map[string]*memoryLimiterState
}

type memoryLimiterState struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type redisRateLimiter struct {
	client   *redis.Client
	rps      float64
	burst    int
	fallback rateLimiter
	evalFunc func(ctx context.Context, key string, nowMs int64) (int64, error)
}

// extractClientIP returns the client IP from trusted proxy headers or RemoteAddr.
// In production this should be paired with a trusted-proxy allow-list.
func extractClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain (closest to the client)
		if idx := strings.Index(xff, ","); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}
	return r.RemoteAddr
}

// RateLimiter creates an IP-based rate limiter.
// rps = requests per second, burst = max burst size.
func RateLimiter(rps int, burst int) func(next http.Handler) http.Handler {
	if rps <= 0 {
		rps = 1
	}
	if burst <= 0 {
		burst = 1
	}

	var limiter rateLimiter
	limiter = newInMemoryRateLimiter(float64(rps), burst)
	if rl, err := newRedisRateLimiterFromEnv(float64(rps), burst); err == nil && rl != nil {
		limiter = rl
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractClientIP(r)
			if !limiter.Allow(r.Context(), ip) {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func newInMemoryRateLimiter(rps float64, burst int) *memoryRateLimiter {
	limiter := &memoryRateLimiter{
		rps:     rps,
		burst:   burst,
		clients: make(map[string]*memoryLimiterState),
	}

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			limiter.cleanup(3 * time.Minute)
		}
	}()

	return limiter
}

func newRedisRateLimiterFromEnv(rps float64, burst int) (*redisRateLimiter, error) {
	redisURL := strings.TrimSpace(os.Getenv("REDIS_URL"))
	if redisURL == "" {
		return nil, nil
	}

	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &redisRateLimiter{
		client:   client,
		rps:      rps,
		burst:    burst,
		fallback: newInMemoryRateLimiter(rps, burst),
	}, nil
}

func (rls *memoryRateLimiter) Allow(_ context.Context, key string) bool {
	rls.mu.Lock()
	defer rls.mu.Unlock()

	limiter, ok := rls.clients[key]
	if !ok {
		limiter = &memoryLimiterState{
			limiter: rate.NewLimiter(rate.Limit(rls.rps), rls.burst),
		}
		rls.clients[key] = limiter
	}

	limiter.lastSeen = time.Now()
	return limiter.limiter.Allow()
}

func (rls *memoryRateLimiter) cleanup(stale time.Duration) {
	rls.mu.Lock()
	defer rls.mu.Unlock()

	for key, limiter := range rls.clients {
		if time.Since(limiter.lastSeen) > stale {
			delete(rls.clients, key)
		}
	}
}

func (r *redisRateLimiter) Allow(ctx context.Context, key string) bool {
	nowMs := time.Now().UnixNano() / int64(time.Millisecond)
	key = "ratelimit:" + key
	allowed, err := r.eval(ctx, key, nowMs)
	if err != nil {
		if r.fallback != nil {
			return r.fallback.Allow(ctx, key)
		}
		return true
	}
	return allowed == 1
}

func (r *redisRateLimiter) eval(ctx context.Context, key string, nowMs int64) (int64, error) {
	if r.evalFunc != nil {
		return r.evalFunc(ctx, key, nowMs)
	}

	return r.client.Eval(
		ctx,
		redisRateLimitScript,
		[]string{key},
		r.rps,
		r.burst,
		nowMs,
		redisRateLimiterTTL.Milliseconds(),
	).Int64()
}
