package middleware

import (
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type rateLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter creates a simple IP-based rate limiter
// rps = requests per second, burst = max burst size
func RateLimiter(rps int, burst int) func(next http.Handler) http.Handler {
	var (
		mu      sync.Mutex
		clients = make(map[string]*rateLimiter)
	)

	// Cleanup old entries every minute
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			for ip, rl := range clients {
				if time.Since(rl.lastSeen) > 3*time.Minute {
					delete(clients, ip)
				}
			}
			mu.Unlock()
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := r.RemoteAddr

			mu.Lock()
			rl, exists := clients[ip]
			if !exists {
				rl = &rateLimiter{
					limiter: rate.NewLimiter(rate.Limit(rps), burst),
				}
				clients[ip] = rl
			}
			rl.lastSeen = time.Now()
			mu.Unlock()

			if !rl.limiter.Allow() {
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
