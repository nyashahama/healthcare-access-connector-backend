// Package handler implements health check handlers
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"

	"github.com/jackc/pgx/v5/pgxpool"
)

type HealthHandler struct {
	pool         *pgxpool.Pool
	cache        cache.Service
	broker       messaging.Broker
	emailService email.Service
}

type HealthResponse struct {
	Status    string            `json:"status"`
	Timestamp string            `json:"timestamp"`
	Services  map[string]string `json:"services"`
	Version   string            `json:"version,omitempty"`
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(pool *pgxpool.Pool, cache cache.Service, broker messaging.Broker, emailService email.Service) *HealthHandler {
	return &HealthHandler{
		pool:         pool,
		cache:        cache,
		broker:       broker,
		emailService: emailService,
	}
}

// Health performs comprehensive health checks
// @Summary Health check
// @Tags system
// @Produce json
// @Success 200 {object} HealthResponse
// @Failure 503 {object} HealthResponse
// @Router /health [get]
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	services := make(map[string]string)
	allHealthy := true

	// Check database
	if err := h.pool.Ping(ctx); err != nil {
		services["database"] = "unhealthy: " + err.Error()
		allHealthy = false
	} else {
		services["database"] = "healthy"
	}

	// Check cache
	if h.cache != nil {
		if err := h.cache.Ping(ctx); err != nil {
			services["cache"] = "degraded"
		} else {
			services["cache"] = "healthy"
		}
	}

	// Check message broker
	if h.broker != nil {
		if h.broker.IsAvailable() {
			services["messaging"] = "healthy"
		} else {
			services["messaging"] = "unavailable"
		}
	}

	if h.emailService != nil {
		if h.emailService.IsAvailable() {
			services["email"] = "healthy"
		} else {
			services["email"] = "degraded"
		}
	}

	status := "healthy"
	statusCode := http.StatusOK
	if !allHealthy {
		status = "unhealthy"
		statusCode = http.StatusServiceUnavailable
	}

	response := HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Services:  services,
		Version:   "1.0.0", // Update with actual version
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// Readiness checks if the service is ready to accept requests
// @Summary Readiness check
// @Tags system
// @Produce json
// @Success 200
// @Failure 503
// @Router /ready [get]
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// Check only critical dependencies for readiness
	if err := h.pool.Ping(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Liveness is a simple liveness check
// @Summary Liveness check
// @Tags system
// @Produce json
// @Success 200
// @Router /live [get]
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
