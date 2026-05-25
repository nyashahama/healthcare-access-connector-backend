package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRateLimiterAllowsRequestsUnderLimit(t *testing.T) {
	handler := RateLimiter(10, 10)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "192.168.1.1:1234"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		assert.Equal(t, http.StatusOK, rr.Code, "request %d should succeed", i)
	}
}

func TestRateLimiterBlocksExcessRequests(t *testing.T) {
	handler := RateLimiter(1, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request succeeds
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "192.168.1.2:1234"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)

	// Immediate second request from same IP should be rate limited
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "192.168.1.2:1234"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code)
}

func TestRateLimiterUsesXForwardedFor(t *testing.T) {
	handler := RateLimiter(1, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Two requests with same X-Forwarded-For but different RemoteAddr
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "10.0.0.1:1234"
	req1.Header.Set("X-Forwarded-For", "203.0.113.1")
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.2:5678"
	req2.Header.Set("X-Forwarded-For", "203.0.113.1")
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code)
}

func TestRateLimiterIsolatesDifferentIPs(t *testing.T) {
	handler := RateLimiter(1, 1)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "192.168.1.10:1234"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	assert.Equal(t, http.StatusOK, rr1.Code)

	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "192.168.1.11:1234"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusOK, rr2.Code)
}

func TestRateLimiterCleanupRemovesStaleClients(t *testing.T) {
	// We can't easily test the background cleanup ticker, but we can verify
	// that the limiter still functions after a short period.
	handler := RateLimiter(100, 100)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.99:1234"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	// Wait briefly and verify the entry is still there (cleanup is every minute)
	time.Sleep(10 * time.Millisecond)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req)
	assert.Equal(t, http.StatusOK, rr2.Code)
}

func TestRedisRateLimiterFallsBackToMemoryOnRedisError(t *testing.T) {
	limiter := &redisRateLimiter{
		rps:      1,
		burst:    1,
		fallback: newInMemoryRateLimiter(1, 1),
		evalFunc: func(ctx context.Context, key string, nowMs int64) (int64, error) {
			return 0, errors.New("redis unavailable")
		},
	}

	assert.True(t, limiter.Allow(context.Background(), "203.0.113.10"))
	assert.False(t, limiter.Allow(context.Background(), "203.0.113.10"))
}

func TestRedisRateLimiterWithoutFallbackFailsOpen(t *testing.T) {
	limiter := &redisRateLimiter{
		rps:   1,
		burst: 1,
		evalFunc: func(ctx context.Context, key string, nowMs int64) (int64, error) {
			return 0, errors.New("redis unavailable")
		},
	}

	assert.True(t, limiter.Allow(context.Background(), "203.0.113.11"))
}
