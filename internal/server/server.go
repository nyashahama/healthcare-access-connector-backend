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
	handlercore "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/patients"
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
	httpServer          *http.Server
	config              *config.Config
	logger              *zerolog.Logger
	authHandler         *handlercore.AuthHandler
	userHandler         *handlercore.UserHandler
	otpHandler          *handlercore.OTPHandler
	auditHandler        *handlercore.AuditHandler
	consentHandler      *handlercore.ConsentHandler
	notificationHandler *handlercore.NotificationHandler
	sessionHandler      *handlercore.SessionHandler
	patientHandler      *patients.PatientHandler
	healthHandler       *handler.HealthHandler
	authService         service.AuthService
}

// NewServer creates a new HTTP server
func NewServer(
	cfg *config.Config,
	logger *zerolog.Logger,
	authHandler *handlercore.AuthHandler,
	userHandler *handlercore.UserHandler,
	otpHandler *handlercore.OTPHandler,
	auditHandler *handlercore.AuditHandler,
	consentHandler *handlercore.ConsentHandler,
	notificationHandler *handlercore.NotificationHandler,
	sessionHandler *handlercore.SessionHandler,
	patientHandler *patients.PatientHandler,
	healthHandler *handler.HealthHandler,
	authService service.AuthService,
	txManager repository.TxManager,
) *Server {
	return &Server{
		config:              cfg,
		logger:              logger,
		authHandler:         authHandler,
		userHandler:         userHandler,
		otpHandler:          otpHandler,
		auditHandler:        auditHandler,
		consentHandler:      consentHandler,
		notificationHandler: notificationHandler,
		sessionHandler:      sessionHandler,
		patientHandler:      patientHandler,
		healthHandler:       healthHandler,
		authService:         authService,
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

	// Global middleware
	r.Use(middleware.Recovery(s.logger))
	r.Use(middleware.Logger(s.logger))
	r.Use(middleware.CORS(s.config.AllowedOrigins))
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.RateLimiter(s.config.RateLimitRPS, s.config.RateLimitBurst))
	r.Use(s.metricsMiddleware())

	// Health check routes
	r.Get("/health", s.healthHandler.Health)
	r.Get("/ready", s.healthHandler.Readiness)
	r.Get("/live", s.healthHandler.Liveness)
	r.Get("/metrics", promhttp.Handler().ServeHTTP)

	// API routes
	r.Route("/api/v1", func(r chi.Router) {
		// Public authentication routes
		r.Post("/auth/register", s.authHandler.Register)
		r.Post("/auth/login", s.authHandler.Login)
		r.Get("/auth/verify-email", s.authHandler.VerifyEmail)
		r.Post("/auth/password/reset-request", s.authHandler.RequestPasswordReset)
		r.Post("/auth/password/reset", s.authHandler.ResetPassword)
		r.Post("/auth/resend-verification", s.authHandler.ResendVerificationEmail)

		// Public OTP routes
		r.Post("/auth/otp/generate", s.otpHandler.GenerateOTP)
		r.Post("/auth/otp/verify", s.otpHandler.VerifyOTP)
		r.Post("/auth/password/reset-with-otp", s.otpHandler.ResetPasswordWithOTP)

		// Protected routes - require authentication
		r.Group(func(r chi.Router) {
			r.Use(middleware.AuthMiddleware(s.authService, s.logger))

			// Auth management
			r.Post("/auth/refresh", s.authHandler.RefreshToken)
			r.Post("/auth/logout", s.authHandler.Logout)

			// User profile routes
			r.Route("/users", func(r chi.Router) {
				// User-specific routes
				r.Get("/{id}", s.userHandler.GetUser)
				r.Get("/{id}/profile", s.userHandler.GetProfile)
				r.Put("/{id}/profile", s.userHandler.UpdateProfile)
				r.Delete("/{id}/profile", s.userHandler.DeleteProfile)
				r.Put("/{id}/password", s.authHandler.UpdatePassword)

				// Consent management
				r.Get("/{id}/consent", s.userHandler.GetConsent)
				r.Put("/{id}/consent", s.userHandler.UpdateConsent)

				// User field updates
				r.Put("/{id}/email", s.userHandler.UpdateUserEmail)
				r.Put("/{id}/phone", s.userHandler.UpdateUserPhone)

				// List and search users (may need role restrictions)
				r.Get("/", s.userHandler.ListUsers)
				r.Get("/search", s.userHandler.SearchUsers)
				r.Get("/batch", s.userHandler.GetUsersByIDs)
				r.Get("/count", s.userHandler.CountUsers)
			})

			// Patient profile routes
			r.Route("/patients", func(r chi.Router) {
				// Register patient routes from patient handler
				s.patientHandler.RegisterRoutes(r)
			})

			// Session management routes
			r.Route("/sessions", func(r chi.Router) {
				r.Get("/{token}", s.sessionHandler.GetSession)
				r.Get("/users/{id}", s.sessionHandler.GetUserSessions)
				r.Delete("/users/{id}", s.sessionHandler.RevokeSession)
				r.Delete("/users/{id}/all", s.sessionHandler.RevokeAllSessions)
				r.Delete("/users/{id}/except-current", s.sessionHandler.RevokeAllExceptCurrent)
				r.Delete("/users/{id}/device", s.sessionHandler.InvalidateSessionByDevice)
				r.Put("/{token}/validate", s.sessionHandler.ValidateAndExtendSession)
				r.Get("/users/{id}/count", s.sessionHandler.GetActiveSessionCount)
				r.Put("/{id}/token", s.sessionHandler.UpdateSessionToken)
			})

			// Consent management routes
			r.Route("/consent", func(r chi.Router) {
				r.Route("/users/{id}", func(r chi.Router) {
					r.Get("/privacy", s.consentHandler.GetPrivacyConsent)
					r.Post("/privacy", s.consentHandler.CreatePrivacyConsent)
					r.Put("/privacy", s.consentHandler.UpdatePrivacyConsent)
					r.Post("/withdraw", s.consentHandler.WithdrawConsent)
					r.Put("/health-data", s.consentHandler.UpdateHealthDataConsent)
					r.Put("/research", s.consentHandler.UpdateResearchConsent)
					r.Put("/emergency-access", s.consentHandler.UpdateEmergencyAccessConsent)
					r.Put("/communication", s.consentHandler.UpdateCommunicationConsents)
					r.Get("/history", s.consentHandler.GetConsentHistory)
					r.Get("/export", s.consentHandler.ExportConsentData)
				})
			})

			// Notification preferences routes
			r.Route("/notifications", func(r chi.Router) {
				r.Route("/users/{id}", func(r chi.Router) {
					r.Get("/preferences", s.notificationHandler.GetPreferences)
					r.Post("/preferences", s.notificationHandler.CreatePreferences)
					r.Put("/preferences", s.notificationHandler.UpdatePreferences)
					r.Put("/channels", s.notificationHandler.UpdateChannelSettings)
					r.Put("/appointment-reminders", s.notificationHandler.UpdateAppointmentReminders)
					r.Put("/health-tips", s.notificationHandler.UpdateHealthTips)
					r.Put("/quiet-hours", s.notificationHandler.SetQuietHours)
				})
			})

			// OTP management routes (for testing/admin)
			r.Route("/otp", func(r chi.Router) {
				r.Get("/latest", s.otpHandler.GetLatestActiveOTP)
				r.Delete("/invalidate", s.otpHandler.InvalidateUserOTPs)
				r.Get("/attempts", s.otpHandler.GetOTPAttemptCount)
				r.Get("/recent", s.otpHandler.GetRecentOTPs)
			})

			// Audit trails routes
			r.Route("/audit", func(r chi.Router) {
				// User-specific audit routes
				r.Route("/users/{id}", func(r chi.Router) {
					r.Get("/activities", s.auditHandler.GetUserActivities)
					r.Get("/access-logs", s.auditHandler.GetDataAccessLogs)
					r.Get("/export", s.auditHandler.ExportUserAuditTrail)
					r.Post("/access-report", s.auditHandler.GenerateAccessReport)
				})

				// General audit routes
				r.Get("/activities/{type}", s.auditHandler.GetActivitiesByType)
				r.Get("/emergency-access-logs", s.auditHandler.GetEmergencyAccessLogs)
				r.Get("/suspicious-activities", s.auditHandler.GetSuspiciousActivities)
				r.Get("/failed-login-attempts", s.auditHandler.GetFailedLoginAttempts)
				r.Post("/activity-report", s.auditHandler.GenerateActivityReport)
			})

			// Admin-only routes
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireRole("system_admin"))

				// Admin user management
				r.Put("/users/{id}/role", s.userHandler.UpdateUserRole)
				r.Put("/users/{id}/status", s.userHandler.UpdateUserStatus)
				r.Put("/users/bulk/status", s.userHandler.BulkUpdateStatus)

				// Admin patient management
				r.Get("/patients/demographics", s.patientHandler.GetDemographicsSummary)

				// Admin OTP management
				r.Delete("/otp/expired", s.otpHandler.DeleteExpiredOTPs)

				// Admin session management
				r.Delete("/sessions/expired", s.sessionHandler.CleanupExpiredSessions)

				// Admin consent management
				r.Post("/consent/notify-expirations", s.consentHandler.NotifyConsentExpirations)
				r.Get("/consent/active-by-type", s.consentHandler.GetActiveConsentsByType)
				r.Get("/consent/expired", s.consentHandler.GetExpiredConsents)
				r.Get("/consent/withdrawn", s.consentHandler.GetWithdrawnConsents)

				// Admin notification management
				r.Get("/notifications/can-send", s.notificationHandler.CanSendNotification)
				r.Get("/notifications/disabled-users", s.notificationHandler.GetUsersWithDisabledNotifications)
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

			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			duration := time.Since(start).Seconds()
			status := fmt.Sprintf("%d", ww.Status())

			requestDuration.WithLabelValues(path, method).Observe(duration)
			requestsTotal.WithLabelValues(path, method, status).Inc()
		})
	}
}
