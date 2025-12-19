// Package server implements the HTTP server
package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

var (
	requestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"path", "method", "status"},
	)

	requestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"path", "method"},
	)
)

type Server struct {
	httpServer    *http.Server
	config        *config.Config
	logger        *zerolog.Logger
	authHandler   *handler.AuthHandler
	healthHandler *handler.HealthHandler
	authService   service.AuthService
}

// NewServer creates a new HTTP server
func NewServer(
	cfg *config.Config,
	logger *zerolog.Logger,
	authHandler *handler.AuthHandler,
	healthHandler *handler.HealthHandler,
	authService service.AuthService,
	txManager repository.TxManager,
) *Server {
	return &Server{
		config:        cfg,
		logger:        logger,
		authHandler:   authHandler,
		healthHandler: healthHandler,
		authService:   authService,
	}
}

// Start starts the HTTP server with graceful shutdown
func (s *Server) Start() error {
	router := s.setupRoutes()

	s.httpServer = &http.Server{
		Addr:         s.config.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	serverErrors := make(chan error, 1)
	go func() {
		s.logger.Info().
			Str("address", s.httpServer.Addr).
			Str("environment", s.config.Environment).
			Msg("Starting HTTP server")

		serverErrors <- s.httpServer.ListenAndServe()
	}()

	// Wait for interrupt signal or server error
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	case sig := <-shutdown:
		s.logger.Info().Str("signal", sig.String()).Msg("Shutdown signal received")

		// Graceful shutdown with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := s.httpServer.Shutdown(ctx); err != nil {
			s.logger.Error().Err(err).Msg("Server forced to shutdown")
			if err := s.httpServer.Close(); err != nil {
				return fmt.Errorf("error closing server: %w", err)
			}
			return fmt.Errorf("graceful shutdown failed: %w", err)
		}

		s.logger.Info().Msg("Server stopped gracefully")
	}

	return nil
}

// setupRoutes configures all routes and middleware
func (s *Server) setupRoutes() http.Handler {
	r := chi.NewRouter()

	// Global middleware (order matters)
	r.Use(middleware.Recovery(s.logger))
	r.Use(middleware.Logger(s.logger))
	r.Use(middleware.CORS(s.config.AllowedOrigins))
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.RateLimiter(s.config.RateLimitRPS, s.config.RateLimitBurst))
	r.Use(s.metricsMiddleware())

	// Health check routes (no auth required)
	r.Get("/health", s.healthHandler.Health)
	r.Get("/ready", s.healthHandler.Readiness)
	r.Get("/live", s.healthHandler.Liveness)
	r.Get("/metrics", promhttp.Handler().ServeHTTP)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public authentication routes
		r.Route("/auth", func(r chi.Router) {
			r.Post("/register", s.authHandler.Register)
			r.Post("/login", s.authHandler.Login)
			r.Get("/verify-email", s.authHandler.VerifyEmail) // ?token=xxx
			r.Post("/password/reset-request", s.authHandler.RequestPasswordReset)
			r.Post("/password/reset", s.authHandler.ResetPassword)
		})

		// Protected routes - require authentication
		r.Group(func(r chi.Router) {
			r.Use(middleware.AuthMiddleware(s.authService, s.logger))

			// Auth management (authenticated)
			r.Route("/auth", func(r chi.Router) {
				r.Post("/refresh", s.authHandler.RefreshToken)
				r.Post("/logout", s.authHandler.Logout)
			})

			// User profile routes
			r.Route("/users/{id}", func(r chi.Router) {
				r.Get("/", s.authHandler.GetProfile)
				r.Put("/password", s.authHandler.UpdatePassword)
				r.Get("/consent", s.authHandler.GetConsent)
			})

			// Admin routes
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireRole("system_admin"))
				// Add admin-only routes here
			})
		})
	})

	// 404 handler
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Route not found"}`))
	})

	return r
}

// metricsMiddleware records Prometheus metrics
func (s *Server) metricsMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			path := r.URL.Path
			method := r.Method

			// Wrap response writer to capture status
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)

			// Call next handler
			next.ServeHTTP(ww, r)

			// Record metrics
			duration := time.Since(start).Seconds()
			status := fmt.Sprintf("%d", ww.Status())

			requestDuration.WithLabelValues(path, method).Observe(duration)
			requestsTotal.WithLabelValues(path, method, status).Inc()
		})
	}
}
