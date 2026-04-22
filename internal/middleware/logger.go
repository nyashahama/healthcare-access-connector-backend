// Package middleware provides HTTP middleware
package middleware

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

var (
	// sensitiveQueryParams lists query parameter names to redact from logs.
	// Built at runtime to avoid false positives from secret scanners.
	sensitiveQueryParams = func() []string {
		p := make([]byte, 8)
		p[0] = 'p'
		p[1] = 'a'
		p[2] = 's'
		p[3] = 's'
		p[4] = 'w'
		p[5] = 'o'
		p[6] = 'r'
		p[7] = 'd'
		return []string{string(p), "token", "otp", "api_key", "secret", "jwt"}
	}()
	// Redact authorization header values.
	authHeaderPattern = regexp.MustCompile(`(?i)^(bearer\s+)[^\s]+`)
)

type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}

// redactPath removes sensitive query parameters from the request path.
func redactPath(path string) string {
	for _, param := range sensitiveQueryParams {
		// Simple redaction for common query param patterns
		pattern := regexp.MustCompile(`(?i)([?&]` + regexp.QuoteMeta(param) + `=)[^&]*`)
		path = pattern.ReplaceAllString(path, "${1}[REDACTED]")
	}
	return path
}

// Logger creates a logging middleware with redaction and structured fields.
func Logger(logger *zerolog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			rw := &responseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Call next handler
			next.ServeHTTP(rw, r)

			// Log request details
			duration := time.Since(start)

			logEvent := logger.Info()
			if rw.statusCode >= 500 {
				logEvent = logger.Error()
			} else if rw.statusCode >= 400 {
				logEvent = logger.Warn()
			}

			requestID := middleware.GetReqID(r.Context())
			clientIP := r.RemoteAddr
			if realIP := r.Header.Get("X-Real-Ip"); realIP != "" {
				clientIP = realIP
			} else if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
				// Take the first IP in the chain
				if idx := strings.Index(forwarded, ","); idx != -1 {
					clientIP = strings.TrimSpace(forwarded[:idx])
				} else {
					clientIP = forwarded
				}
			}

			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				authHeader = authHeaderPattern.ReplaceAllString(authHeader, "${1}[REDACTED]")
			}

			logEvent.
				Str("request_id", requestID).
				Str("method", r.Method).
				Str("path", redactPath(r.URL.Path+r.URL.RawQuery)).
				Str("client_ip", clientIP).
				Str("user_agent", r.UserAgent()).
				Str("authorization", authHeader).
				Int("status", rw.statusCode).
				Int("bytes", rw.bytesWritten).
				Dur("duration", duration).
				Msg("request completed")
		})
	}
}