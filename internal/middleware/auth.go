// Package middleware provides authentication middleware
package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"

	"github.com/rs/zerolog"
)

type contextKey string

const (
	UserContextKey contextKey = "user"
)

// AuthMiddleware validates JWT tokens and adds user claims to context
func AuthMiddleware(authService service.AuthService, logger *zerolog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				logger.Warn().Str("path", r.URL.Path).Msg("Missing authorization header")
				respondUnauthorized(w, "Missing authorization token")
				return
			}

			// Parse Bearer token
			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				logger.Warn().Str("header", authHeader).Msg("Invalid authorization header format")
				respondUnauthorized(w, "Invalid authorization header format")
				return
			}

			tokenString := parts[1]

			// Validate token
			claims, err := authService.ValidateToken(r.Context(), tokenString)
			if err != nil {
				logger.Warn().Err(err).Msg("Token validation failed")
				respondUnauthorized(w, "Invalid or expired token")
				return
			}

			// Add claims to context
			ctx := context.WithValue(r.Context(), UserContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole creates middleware that checks for specific roles
func RequireRole(roles ...string) func(next http.Handler) http.Handler {
	roleMap := make(map[string]bool, len(roles))
	for _, role := range roles {
		roleMap[role] = true
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(UserContextKey).(*service.TokenClaims)
			if !ok {
				respondUnauthorized(w, "Unauthorized")
				return
			}

			if !roleMap[claims.Role] {
				respondForbidden(w, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext extracts user claims from context
func GetUserFromContext(ctx context.Context) (*service.TokenClaims, bool) {
	claims, ok := ctx.Value(UserContextKey).(*service.TokenClaims)
	return claims, ok
}

func respondUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func respondForbidden(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}