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
	handleradmin "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/admin"
	handlerappointments "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/appointments"
	handlercore "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/providers"
	handlertele "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/telemedicine"
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

// Server holds every handler the application exposes.
type Server struct {
	httpServer *http.Server
	config     *config.Config
	logger     *zerolog.Logger

	// ── Core handlers ──────────────────────────────────────────────────────────
	authHandler         *handlercore.AuthHandler
	userHandler         *handlercore.UserHandler
	otpHandler          *handlercore.OTPHandler
	auditHandler        *handlercore.AuditHandler
	consentHandler      *handlercore.ConsentHandler
	notificationHandler *handlercore.NotificationHandler
	sessionHandler      *handlercore.SessionHandler

	// ── Patient handlers ───────────────────────────────────────────────────────
	patientHandler          *patients.PatientHandler
	allergyHandler          *patients.AllergyHandler
	conditionHandler        *patients.ConditionHandler
	medicationHandler       *patients.MedicationHandler
	surgeryHandler          *patients.SurgeryHandler
	immunizationHandler     *patients.ImmunizationHandler
	familyHistoryHandler    *patients.FamilyHistoryHandler
	medicalInfoHandler      *patients.MedicalInfoHandler
	emergencyContactHandler *patients.EmergencyContactHandler
	dependentHandler        *patients.DependentHandler
	dependentHealthHandler  *patients.DependentHealthRecordHandler

	// ── Provider handlers ──────────────────────────────────────────────────────
	staffHandler      *providers.StaffHandler
	clinicHandler     *providers.ClinicHandler
	serviceHandler    *providers.ServiceHandler
	credentialHandler *providers.CredentialHandler

	// ── Admin handler ──────────────────────────────────────────────────────────
	adminHandler *handleradmin.AdminHandler

	// ── Appointment handler ────────────────────────────────────────────────────
	appointmentHandler *handlerappointments.AppointmentHandler

	// ── Telemedicine handlers ──────────────────────────────────────────────────
	symptomCheckerHandler       *handlertele.SymptomCheckerHandler
	consultationHandler         *handlertele.ConsultationHandler
	consultationMessagesHandler *handlertele.ConsultationMessagesHandler
	consultationNotesHandler    *handlertele.ConsultationNotesHandler
	providerAvailabilityHandler *handlertele.ProviderAvailabilityHandler
	// wsHandler upgrades HTTP connections to WebSocket for real-time chat.
	wsHandler *handlertele.WSHandler

	// ── Misc ───────────────────────────────────────────────────────────────────
	healthHandler *handler.HealthHandler
	authService   service.AuthService
}

// NewServer creates a new HTTP server.
func NewServer(
	cfg *config.Config,
	logger *zerolog.Logger,
	// core
	authHandler *handlercore.AuthHandler,
	userHandler *handlercore.UserHandler,
	otpHandler *handlercore.OTPHandler,
	auditHandler *handlercore.AuditHandler,
	consentHandler *handlercore.ConsentHandler,
	notificationHandler *handlercore.NotificationHandler,
	sessionHandler *handlercore.SessionHandler,
	// patients
	patientHandler *patients.PatientHandler,
	allergyHandler *patients.AllergyHandler,
	conditionHandler *patients.ConditionHandler,
	medicationHandler *patients.MedicationHandler,
	surgeryHandler *patients.SurgeryHandler,
	immunizationHandler *patients.ImmunizationHandler,
	familyHistoryHandler *patients.FamilyHistoryHandler,
	medicalInfoHandler *patients.MedicalInfoHandler,
	emergencyContactHandler *patients.EmergencyContactHandler,
	dependentHandler *patients.DependentHandler,
	dependentHealthHandler *patients.DependentHealthRecordHandler,
	// providers
	staffHandler *providers.StaffHandler,
	clinicHandler *providers.ClinicHandler,
	serviceHandler *providers.ServiceHandler,
	credentialHandler *providers.CredentialHandler,
	// admin
	adminHandler *handleradmin.AdminHandler,
	// appointments
	appointmentHandler *handlerappointments.AppointmentHandler,
	// telemedicine
	symptomCheckerHandler *handlertele.SymptomCheckerHandler,
	consultationHandler *handlertele.ConsultationHandler,
	consultationMessagesHandler *handlertele.ConsultationMessagesHandler,
	consultationNotesHandler *handlertele.ConsultationNotesHandler,
	providerAvailabilityHandler *handlertele.ProviderAvailabilityHandler,
	wsHandler *handlertele.WSHandler,
	// misc
	healthHandler *handler.HealthHandler,
	authService service.AuthService,
	txManager repository.TxManager,
) *Server {
	return &Server{
		config:                      cfg,
		logger:                      logger,
		authHandler:                 authHandler,
		userHandler:                 userHandler,
		otpHandler:                  otpHandler,
		auditHandler:                auditHandler,
		consentHandler:              consentHandler,
		notificationHandler:         notificationHandler,
		sessionHandler:              sessionHandler,
		patientHandler:              patientHandler,
		allergyHandler:              allergyHandler,
		conditionHandler:            conditionHandler,
		medicationHandler:           medicationHandler,
		surgeryHandler:              surgeryHandler,
		immunizationHandler:         immunizationHandler,
		familyHistoryHandler:        familyHistoryHandler,
		medicalInfoHandler:          medicalInfoHandler,
		emergencyContactHandler:     emergencyContactHandler,
		dependentHandler:            dependentHandler,
		dependentHealthHandler:      dependentHealthHandler,
		staffHandler:                staffHandler,
		clinicHandler:               clinicHandler,
		serviceHandler:              serviceHandler,
		credentialHandler:           credentialHandler,
		adminHandler:                adminHandler,
		appointmentHandler:          appointmentHandler,
		symptomCheckerHandler:       symptomCheckerHandler,
		consultationHandler:         consultationHandler,
		consultationMessagesHandler: consultationMessagesHandler,
		consultationNotesHandler:    consultationNotesHandler,
		providerAvailabilityHandler: providerAvailabilityHandler,
		wsHandler:                   wsHandler,
		healthHandler:               healthHandler,
		authService:                 authService,
	}
}

// Start starts the HTTP server with graceful shutdown.
func (s *Server) Start() error {
	router := s.setupRoutes()

	s.httpServer = &http.Server{
		Addr:    s.config.Port,
		Handler: router,
		// WebSocket connections are long-lived; WriteTimeout must be 0 so the
		// server does not forcibly close them after the normal HTTP deadline.
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 0,
		IdleTimeout:  60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		s.logger.Info().
			Str("address", s.httpServer.Addr).
			Str("environment", s.config.Environment).
			Msg("Starting HTTP server")

		serverErrors <- s.httpServer.ListenAndServe()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		if err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("server error: %w", err)
		}
	case sig := <-shutdown:
		s.logger.Info().Str("signal", sig.String()).Msg("Shutdown signal received")

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

// setupRoutes configures all routes and middleware.
func (s *Server) setupRoutes() http.Handler {
	// ── WebSocket router ───────────────────────────────────────────────────────
	// The WS router is intentionally kept separate from the main router so that
	// it is never wrapped by middleware that replaces http.ResponseWriter (e.g.
	// Logger, metricsMiddleware). Those wrappers strip the http.Hijacker
	// interface that gorilla/websocket requires to perform the upgrade, causing
	// a 500 "response does not implement http.Hijacker" error.
	//
	// Only lightweight, non-wrapping middleware is applied here.
	wsRouter := chi.NewRouter()
	wsRouter.Use(middleware.Recovery(s.logger))
	wsRouter.Use(middleware.CORS(s.config.AllowedOrigins))
	wsRouter.Use(middleware.RateLimiter(s.config.RateLimitRPS, s.config.RateLimitBurst))
	// URL: /ws/consultations/{consultationId}
	// JWT passed via Authorization: Bearer <token> header or ?token= query param.
	wsRouter.Get("/ws/consultations/{consultationId}", s.wsHandler.ServeWS)

	r := chi.NewRouter()

	// ── Global middleware ──────────────────────────────────────────────────────
	r.Use(middleware.Recovery(s.logger))
	r.Use(middleware.Logger(s.logger))
	r.Use(middleware.CORS(s.config.AllowedOrigins))
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.RateLimiter(s.config.RateLimitRPS, s.config.RateLimitBurst))
	r.Use(s.metricsMiddleware())

	// ── Infrastructure endpoints ───────────────────────────────────────────────
	r.Get("/health", s.healthHandler.Health)
	r.Get("/ready", s.healthHandler.Readiness)
	r.Get("/live", s.healthHandler.Liveness)
	r.Get("/metrics", promhttp.Handler().ServeHTTP)

	// ── API v1 ─────────────────────────────────────────────────────────────────
	r.Route("/api/v1", func(r chi.Router) {
		// ── Public routes (no auth) ────────────────────────────────────────────
		r.Post("/auth/register", s.authHandler.Register)
		r.Post("/auth/login", s.authHandler.Login)
		r.Get("/auth/verify-email", s.authHandler.VerifyEmail)
		r.Post("/auth/password/reset-request", s.authHandler.RequestPasswordReset)
		r.Post("/auth/password/reset", s.authHandler.ResetPassword)
		r.Post("/auth/resend-verification", s.authHandler.ResendVerificationEmail)
		r.Post("/auth/register/staff", s.authHandler.RegisterInvitedStaff)

		r.Post("/auth/otp/generate", s.otpHandler.GenerateOTP)
		r.Post("/auth/otp/verify", s.otpHandler.VerifyOTP)
		r.Post("/auth/password/reset-with-otp", s.otpHandler.ResetPasswordWithOTP)

		r.Get("/staff/invitations/{token}", s.staffHandler.GetInvitationDetails)
		r.Post("/staff/invitations/{token}/decline", s.staffHandler.DeclineInvitation)

		// ── Protected routes (JWT required) ────────────────────────────────────
		r.Group(func(r chi.Router) {
			r.Use(middleware.AuthMiddleware(s.authService, s.logger))

			// Auth management
			r.Post("/auth/refresh", s.authHandler.RefreshToken)
			r.Post("/auth/logout", s.authHandler.Logout)

			// User profile
			r.Route("/users", func(r chi.Router) {
				r.Get("/{id}", s.userHandler.GetUser)
				r.Get("/{id}/profile", s.userHandler.GetProfile)
				r.Put("/{id}/profile", s.userHandler.UpdateProfile)
				r.Delete("/{id}/profile", s.userHandler.DeleteProfile)
				r.Put("/{id}/password", s.authHandler.UpdatePassword)
				r.Get("/{id}/consent", s.userHandler.GetConsent)
				r.Put("/{id}/consent", s.userHandler.UpdateConsent)
				r.Put("/{id}/email", s.userHandler.UpdateUserEmail)
				r.Put("/{id}/phone", s.userHandler.UpdateUserPhone)
				r.Get("/", s.userHandler.ListUsers)
				r.Get("/search", s.userHandler.SearchUsers)
				r.Get("/batch", s.userHandler.GetUsersByIDs)
				r.Get("/count", s.userHandler.CountUsers)
			})

			// Patient records
			r.Route("/patients", func(r chi.Router) {
				s.patientHandler.RegisterRoutes(r)
				s.allergyHandler.RegisterRoutes(r)
				s.conditionHandler.RegisterRoutes(r)
				s.medicationHandler.RegisterRoutes(r)
				s.surgeryHandler.RegisterRoutes(r)
				s.immunizationHandler.RegisterRoutes(r)
				s.familyHistoryHandler.RegisterRoutes(r)
				s.medicalInfoHandler.RegisterRoutes(r)
				s.emergencyContactHandler.RegisterRoutes(r)
				s.dependentHandler.RegisterRoutes(r)
				s.dependentHealthHandler.RegisterRoutes(r)
			})

			// Appointments
			r.Route("/appointments", func(r chi.Router) {
				s.appointmentHandler.RegisterRoutes(r)
			})

			// ── Telemedicine ───────────────────────────────────────────────────
			r.Route("/telemedicine", func(r chi.Router) {
				// Symptom checker
				s.symptomCheckerHandler.RegisterRoutes(r)

				// Consultations (lifecycle, history, waiting room)
				s.consultationHandler.RegisterRoutes(r)

				// Messages (thread, polling, attachments, read receipts)
				s.consultationMessagesHandler.RegisterRoutes(r)

				// Clinical notes (SOAP, finalise, history)
				s.consultationNotesHandler.RegisterRoutes(r)

				// Provider availability (online/offline, heartbeat, patient list)
				s.providerAvailabilityHandler.RegisterRoutes(r)
			})

			// Provider management
			r.Route("/providers", func(r chi.Router) {
				r.Route("/clinics", func(r chi.Router) {
					r.Post("/", s.clinicHandler.CreateClinic)
					r.Get("/my-clinic", s.clinicHandler.GetMyClinic)
					r.Get("/{id}", s.clinicHandler.GetClinic)
					r.Get("/", s.clinicHandler.ListClinics)
					r.Put("/{id}", s.clinicHandler.UpdateClinic)
					r.Delete("/{id}", s.clinicHandler.DeleteClinic)
					r.Put("/{id}/verify", s.clinicHandler.VerifyClinic)
				})

				r.Route("/staff", func(r chi.Router) {
					r.Post("/", s.staffHandler.CreateStaff)
					r.Get("/user/{user_id}", s.staffHandler.GetStaffByUserID)
					r.Get("/{id}", s.staffHandler.GetStaff)
					r.Put("/{id}", s.staffHandler.UpdateStaff)
					r.Delete("/{id}", s.staffHandler.DeleteStaff)
					r.Get("/{id}/exists", s.staffHandler.CheckStaffExists)
				})

				r.Route("/clinics/{clinic_id}/staff", func(r chi.Router) {
					r.Get("/", s.staffHandler.ListClinicStaff)
					r.Get("/all", s.staffHandler.ListAllClinicStaff)
					r.Get("/active", s.staffHandler.ListActiveClinicStaff)
					r.Post("/invite", s.staffHandler.InviteStaff)
					r.Get("/invitations/pending", s.staffHandler.GetPendingInvitations)
					r.Delete("/invitations/{token}", s.staffHandler.CancelInvitation)
					r.Post("/invitations/{invitation_id}/resend", s.staffHandler.ResendInvitation)
				})

				r.Route("/services", func(r chi.Router) {
					r.Post("/", s.serviceHandler.CreateService)
					r.Get("/{id}", s.serviceHandler.GetService)
					r.Put("/{id}", s.serviceHandler.UpdateService)
					r.Delete("/{id}", s.serviceHandler.DeleteService)
					r.Get("/{id}/exists", s.serviceHandler.CheckServiceExists)
				})

				r.Route("/clinics/{clinic_id}/services", func(r chi.Router) {
					r.Get("/", s.serviceHandler.ListClinicServices)
				})

				r.Route("/credentials", func(r chi.Router) {
					r.Post("/", s.credentialHandler.CreateCredential)
					r.Delete("/{id}", s.credentialHandler.DeleteCredential)
				})

				r.Route("/staff/{staff_id}/credentials", func(r chi.Router) {
					r.Get("/", s.credentialHandler.GetStaffCredentials)
				})
			})
			r.Get("/auth/provider-dashboard", s.authHandler.GetProviderDashboard)

			r.Route("/staff", func(r chi.Router) {
				r.Post("/invitations/{token}/accept", s.staffHandler.AcceptInvitation)
				r.Get("/invitations/my", s.staffHandler.GetMyInvitations)
			})

			// Sessions
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

			// Consent
			r.Route("/consent", func(r chi.Router) {
				r.Route("/users/{id}", func(r chi.Router) {
					r.Get("/privacy", s.consentHandler.GetPrivacyConsent)
					r.Post("/privacy", s.consentHandler.CreatePrivacyConsent)
					r.Put("/privacy", s.consentHandler.UpdatePrivacyConsent)
				})
			})

			// Notifications
			r.Route("/notifications", func(r chi.Router) {
				r.Route("/users/{id}", func(r chi.Router) {
					r.Get("/preferences", s.notificationHandler.GetPreferences)
					r.Put("/preferences", s.notificationHandler.UpdatePreferences)
				})
			})

			// Audit trails
			r.Route("/audit", func(r chi.Router) {
				r.Route("/users/{id}", func(r chi.Router) {
					r.Get("/activities", s.auditHandler.GetUserActivities)
				})
			})

			// Admin-only routes
			r.Group(func(r chi.Router) {
				r.Use(middleware.RequireRole("system_admin"))

				r.Route("/admin", func(r chi.Router) {
					r.Post("/system-admins", s.adminHandler.CreateSystemAdmin)
					r.Get("/system-admins/user/{user_id}", s.adminHandler.GetSystemAdminByUserID)
				})

				r.Put("/users/{id}/role", s.userHandler.UpdateUserRole)
				r.Put("/users/{id}/status", s.userHandler.UpdateUserStatus)
				r.Put("/users/bulk/status", s.userHandler.BulkUpdateStatus)

				r.Get("/patients/demographics", s.patientHandler.GetDemographicsSummary)

				r.Delete("/sessions/expired", s.sessionHandler.CleanupExpiredSessions)
			})
		})
	})

	// 404 handler
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"error": "Route not found"}`))
	})

	// ── Combine routers ────────────────────────────────────────────────────────
	// WS requests are routed before the main handler so they never pass through
	// the response-writer-wrapping middleware on the main router.
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if len(req.URL.Path) >= 4 && req.URL.Path[:4] == "/ws/" {
			wsRouter.ServeHTTP(w, req)
			return
		}
		r.ServeHTTP(w, req)
	})
}

// metricsMiddleware records Prometheus metrics for every request.
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
