// Package app handles application initialization and dependency injection
package app

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/ai"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	handleradmin "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/admin"
	handlerappointments "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/appointments"
	handlercore "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/core"
	handlerpatients "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/patients"
	handlerproviders "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/providers"
	handlertele "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	repoadmin "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/admin"
	repoappointments "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/appointments"
	repocore "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/core"
	repopatients "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/patients"
	repoproviders "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/providers"
	repotele "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/server"
	serviceadmin "github.com/nyashahama/healthcare-access-connector-backend/internal/service/admin"
	serviceappointments "github.com/nyashahama/healthcare-access-connector-backend/internal/service/appointments"
	servicecore "github.com/nyashahama/healthcare-access-connector-backend/internal/service/core"
	servicepatients "github.com/nyashahama/healthcare-access-connector-backend/internal/service/patients"
	serviceproviders "github.com/nyashahama/healthcare-access-connector-backend/internal/service/providers"
	servicetele "github.com/nyashahama/healthcare-access-connector-backend/internal/service/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/ws"
	"github.com/rs/zerolog"
)

// App represents the application with all dependencies
type App struct {
	config       *config.Config
	server       *server.Server
	pool         *pgxpool.Pool
	logger       *zerolog.Logger
	broker       messaging.Broker
	emailService email.Service
	wsCancel     context.CancelFunc
}

// New creates a new application instance
func New(cfg *config.Config) (*App, error) {
	logger := cfg.Logger()

	// Initialize database connection pool
	pool, err := initDatabase(cfg.DBURL, logger, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize cache service
	cacheService := cache.NewRedisCache(cfg.RedisURL, logger, cfg.CacheTTL)

	// Initialize message broker (optional)
	var broker messaging.Broker
	if cfg.NatsURL != "" {
		broker, err = messaging.NewNATSBroker(cfg.NatsURL, logger)
		if err != nil {
			logger.Warn().Err(err).Msg("NATS broker unavailable, async operations disabled")
			broker = nil
		}
	}

	// AI client
	aiCfg := ai.ConfigFromEnv()
	if err := aiCfg.Validate(); err != nil {
		logger.Warn().Err(err).Msg("AI client config invalid, feature disabled")
		aiCfg.Enabled = false
	}
	aiClient := ai.New(aiCfg, logger)

	// ── WebSocket hub ─────────────────────────────────────────────────────────
	wsCfg := ws.ConfigFromEnv()
	if err := wsCfg.Validate(); err != nil {
		return nil, fmt.Errorf("ws config: %w", err)
	}
	wsHub := ws.NewHub(wsCfg, logger)
	wsCtx, wsCancel := context.WithCancel(context.Background())
	go wsHub.Run(wsCtx) // one goroutine for the lifetime of the app

	// Initialize email service
	var emailService email.Service
	frontendURL := os.Getenv("FRONTEND_URL")

	emailService, err = email.NewFromEnv(frontendURL, logger)
	if err != nil {
		logger.Error().Err(err).
			Str("frontend_url", frontendURL).
			Str("EMAIL_PROVIDER", os.Getenv("EMAIL_PROVIDER")).
			Str("EMAIL_FROM_ADDRESS", os.Getenv("EMAIL_FROM_ADDRESS")).
			Msg("Email service initialization failed")
		emailService = nil
	} else {
		logger.Info().
			Bool("service_available", emailService != nil && emailService.IsAvailable()).
			Msg("Email service initialized successfully")
	}

	// ── Repositories ──────────────────────────────────────────────────────────

	/* patients */
	patientRepo := repopatients.NewPatientRepository(pool)
	allergyRepo := repopatients.NewAllergyRepository(pool)
	conditionRepo := repopatients.NewConditionRepository(pool)
	medicationRepo := repopatients.NewMedicationRepository(pool)
	surgeryRepo := repopatients.NewSurgeryRepository(pool)
	immunizationRepo := repopatients.NewImmunizationRepository(pool)
	familyHistoryRepo := repopatients.NewFamilyHistoryRepository(pool)
	medicalInfoRepo := repopatients.NewMedicalInfoRepository(pool)
	emergencyContactRepo := repopatients.NewEmergencyContactRepository(pool)
	dependentRepo := repopatients.NewDependentRepository(pool)
	dependentHealthRepo := repopatients.NewDependentHealthRecordRepository(pool)

	/* core */
	authRepo := repocore.NewAuthRepository(pool)
	userRepo := repocore.NewUserRepository(pool, patientRepo)
	otpRepo := repocore.NewOTPRepository(pool)
	sessionRepo := repocore.NewSessionRepository(pool)
	notificationRepo := repocore.NewNotificationRepository(pool)
	consentRepo := repocore.NewConsentRepository(pool)
	auditRepo := repocore.NewAuditRepository(pool)

	/* admin */
	systemAdminRepo := repoadmin.NewSystemAdminRepository(pool)

	/* providers */
	clinicRepo := repoproviders.NewClinicRepository(pool)
	staffRepo := repoproviders.NewStaffRepository(pool)
	serviceRepo := repoproviders.NewServiceRepository(pool)
	credentialRepo := repoproviders.NewCredentialRepository(pool)

	/* appointments */
	appointmentRepo := repoappointments.NewAppointmentsRepository(pool)

	/* telemedicine */
	symptomCheckerRepo := repotele.NewSymptomCheckerRepository(pool)
	consultationRepo := repotele.NewConsultationRepository(pool)
	consultationMessagesRepo := repotele.NewConsultationMessagesRepository(pool)
	consultationNotesRepo := repotele.NewConsultationNotesRepository(pool)
	providerAvailabilityRepo := repotele.NewProviderAvailabilityRepository(pool)

	// Initialize transaction manager
	txManager := repository.NewTxManager(pool)

	// ── Services ──────────────────────────────────────────────────────────────

	sessionService := servicecore.NewSessionService(
		sessionRepo,
		userRepo,
		cacheService,
		logger,
	)
	staffService := serviceproviders.NewStaffService(
		staffRepo,
		clinicRepo,
		userRepo,
		auditRepo,
		cacheService,
		logger,
	)
	authService := servicecore.NewAuthService(
		authRepo,
		userRepo,
		otpRepo,
		patientRepo,
		sessionService,
		consentRepo,
		staffService,
		cacheService,
		broker,
		emailService,
		logger,
		cfg.JWTSecret,
		cfg.JWTExpiry,
		cfg.SMSEnabled,
		cfg.BcryptCost,
		cfg.LoginMaxAttempts,
		time.Duration(cfg.LoginLockoutMins)*time.Minute,
	)

	userService := servicecore.NewUserService(
		userRepo,
		authRepo,
		patientRepo,
		consentRepo,
		notificationRepo,
		sessionRepo,
		cacheService,
		logger,
	)

	otpService := servicecore.NewOTPService(
		authRepo,
		otpRepo,
		emailService,
		logger,
		cfg.SMSEnabled,
		cfg.BcryptCost,
	)

	consentService := servicecore.NewConsentService(
		consentRepo,
		userRepo,
		auditRepo,
		cacheService,
		logger,
	)

	notificationService := servicecore.NewNotificationService(
		notificationRepo,
		userRepo,
		cacheService,
		logger,
	)

	auditService := servicecore.NewAuditService(
		auditRepo,
		userRepo,
		cacheService,
		logger,
	)

	patientService := servicepatients.NewPatientService(
		patientRepo,
		userRepo,
		notificationRepo,
		cacheService,
		logger,
	)

	allergyService := servicepatients.NewAllergyService(allergyRepo, patientRepo, cacheService, logger)
	conditionService := servicepatients.NewConditionService(conditionRepo, patientRepo, cacheService, logger)
	medicationService := servicepatients.NewMedicationService(medicationRepo, patientRepo, cacheService, logger)
	surgeryService := servicepatients.NewSurgeryService(surgeryRepo, patientRepo, cacheService, logger)
	immunizationService := servicepatients.NewImmunizationService(immunizationRepo, patientRepo, cacheService, logger)
	familyHistoryService := servicepatients.NewFamilyHistoryService(familyHistoryRepo, patientRepo, cacheService, logger)
	medicalInfoService := servicepatients.NewMedicalInfoService(medicalInfoRepo, patientRepo, cacheService, logger)
	emergencyContactService := servicepatients.NewEmergencyContactService(emergencyContactRepo, patientRepo, cacheService, logger)
	dependentService := servicepatients.NewDependentService(dependentRepo, patientRepo, cacheService, logger)
	dependentHealthService := servicepatients.NewDependentHealthRecordService(dependentHealthRepo, dependentRepo, cacheService, logger)

	systemAdminService := serviceadmin.NewSystemAdminService(
		systemAdminRepo, userRepo, auditService, cacheService, logger,
	)

	clinicService := serviceproviders.NewClinicService(
		clinicRepo, auditRepo, userRepo, authRepo, staffRepo, cacheService, logger,
	)
	serviceService := serviceproviders.NewServiceCatalogService(
		serviceRepo, clinicRepo, staffRepo, auditRepo, cacheService, logger,
	)
	credentialService := serviceproviders.NewCredentialService(
		credentialRepo, staffRepo, userRepo, auditRepo, cacheService, logger,
	)

	appointmentService := serviceappointments.NewAppointmentService(
		appointmentRepo, clinicRepo, userRepo, cacheService, logger,
	)

	symptomCheckerService := servicetele.NewSymptomCheckerService(
		symptomCheckerRepo,
		patientRepo,
		aiClient,
		cacheService,
		logger,
	)

	// ── Telemedicine services ──────────────────────────────────────────────────
	providerAvailabilityService := servicetele.NewProviderAvailabilityService(
		providerAvailabilityRepo,
		cacheService,
		logger,
	)

	consultationService := servicetele.NewConsultationService(
		consultationRepo,
		providerAvailabilityRepo,
		symptomCheckerRepo,
		cacheService,
		logger,
	)

	consultationMessagesService := servicetele.NewConsultationMessagesService(
		consultationMessagesRepo,
		consultationRepo,
		cacheService,
		logger,
	)

	consultationNotesService := servicetele.NewConsultationNotesService(
		consultationNotesRepo,
		consultationRepo,
		cacheService,
		logger,
	)

	// ── Wire the WebSocket MessageHandler ─────────────────────────────────────
	//
	// When a client sends a "message" event over WebSocket the hub calls this
	// closure. It:
	//   1. Persists the message to the DB via consultationMessagesService.
	//   2. Broadcasts the persisted message (with its DB-assigned ID and
	//      sent_at timestamp) back to every client in the room.
	//
	// This is the only place where the ws package touches domain logic — the
	// rest of the hub is pure transport.
	wsHub.MessageHandler = func(
		ctx context.Context,
		consultationID, senderUserID, senderRole string,
		payload ws.MessagePayload,
	) error {
		cID, err := uuid.Parse(consultationID)
		if err != nil {
			return fmt.Errorf("invalid consultation_id: %w", err)
		}
		sUID, err := uuid.Parse(senderUserID)
		if err != nil {
			return fmt.Errorf("invalid sender_user_id: %w", err)
		}

		content := payload.Content
		msg := telemedicine.ConsultationMessage{
			ConsultationID: cID,
			SenderUserID:   sUID,
			SenderRole:     telemedicine.SenderRole(senderRole),
			MessageType:    telemedicine.MessageType(payload.MessageType),
			Content:        &content,
			Metadata:       toMetadata(payload.Metadata),
		}

		persisted, err := consultationMessagesService.SendMessage(ctx, msg)
		if err != nil {
			return fmt.Errorf("failed to persist ws message: %w", err)
		}

		// Stamp the DB-assigned ID and broadcast to the room.
		payload.MessageID = persisted.ID.String()
		wsHub.Broadcast(consultationID, ws.OutboundEvent{
			Type:           ws.EventMessage,
			ConsultationID: consultationID,
			SenderUserID:   senderUserID,
			SentAt:         persisted.SentAt,
			Payload:        payload,
		})
		return nil
	}

	// ── Handlers ──────────────────────────────────────────────────────────────

	authHandler := handlercore.NewAuthHandler(authService, userService, logger, cfg.Timeout)
	userHandler := handlercore.NewUserHandler(userService, logger, cfg.Timeout)
	otpHandler := handlercore.NewOTPHandler(otpService, logger, cfg.Timeout)
	auditHandler := handlercore.NewAuditHandler(auditService, logger, cfg.Timeout)
	consentHandler := handlercore.NewConsentHandler(consentService, logger, cfg.Timeout)
	notificationHandler := handlercore.NewNotificationHandler(notificationService, logger, cfg.Timeout)
	sessionHandler := handlercore.NewSessionHandler(sessionService, logger, cfg.Timeout)
	healthHandler := handler.NewHealthHandler(pool, cacheService, broker, emailService, aiClient, wsHub)

	patientHandler := handlerpatients.NewPatientHandler(patientService, logger, cfg.Timeout)
	allergyHandler := handlerpatients.NewAllergyHandler(allergyService, logger, cfg.Timeout)
	conditionHandler := handlerpatients.NewConditionHandler(conditionService, logger, cfg.Timeout)
	medicationHandler := handlerpatients.NewMedicationHandler(medicationService, logger, cfg.Timeout)
	surgeryHandler := handlerpatients.NewSurgeryHandler(surgeryService, logger, cfg.Timeout)
	immunizationHandler := handlerpatients.NewImmunizationHandler(immunizationService, logger, cfg.Timeout)
	familyHistoryHandler := handlerpatients.NewFamilyHistoryHandler(familyHistoryService, logger, cfg.Timeout)
	medicalInfoHandler := handlerpatients.NewMedicalInfoHandler(medicalInfoService, logger, cfg.Timeout)
	emergencyContactHandler := handlerpatients.NewEmergencyContactHandler(emergencyContactService, logger, cfg.Timeout)
	dependentHandler := handlerpatients.NewDependentHandler(dependentService, logger, cfg.Timeout)
	dependentHealthHandler := handlerpatients.NewDependentHealthRecordHandler(dependentHealthService, logger, cfg.Timeout)

	adminHandler := handleradmin.NewAdminHandler(systemAdminService, logger, cfg.Timeout)

	staffHandler := handlerproviders.NewStaffHandler(staffService, userService, logger, cfg.Timeout)
	clinicHandler := handlerproviders.NewClinicHandler(clinicService, logger, cfg.Timeout)
	serviceHandler := handlerproviders.NewServiceHandler(serviceService, logger, cfg.Timeout)
	credentialHandler := handlerproviders.NewCredentialHandler(credentialService, logger, cfg.Timeout)

	appointmentHandler := handlerappointments.NewAppointmentHandler(appointmentService, logger, cfg.Timeout)

	symptomCheckerHandler := handlertele.NewSymptomCheckerHandler(
		symptomCheckerService, patientService, logger, cfg.Timeout,
	)

	// ── Telemedicine handlers ──────────────────────────────────────────────────
	consultationHandler := handlertele.NewConsultationHandler(
		consultationService,
		patientService,
		staffService,
		logger,
		cfg.Timeout,
	)

	consultationMessagesHandler := handlertele.NewConsultationMessagesHandler(
		consultationMessagesService,
		logger,
		cfg.Timeout,
	)

	consultationNotesHandler := handlertele.NewConsultationNotesHandler(
		consultationNotesService,
		patientService,
		staffService,
		logger,
		cfg.Timeout,
	)

	providerAvailabilityHandler := handlertele.NewProviderAvailabilityHandler(
		providerAvailabilityService,
		staffService,
		patientService,
		logger,
		cfg.Timeout,
	)

	// wsHandler wraps the hub's ServeWS into an HTTP handler that can be
	// registered on the chi router.  Authentication is enforced before the
	// upgrade so unauthenticated clients never reach the hub.
	wsHandler := handlertele.NewWSHandler(wsHub, authService, logger)

	// Initialize server with all handlers
	srv := server.NewServer(
		cfg,
		logger,
		authHandler,
		userHandler,
		otpHandler,
		auditHandler,
		consentHandler,
		notificationHandler,
		sessionHandler,
		patientHandler,
		allergyHandler,
		conditionHandler,
		medicationHandler,
		surgeryHandler,
		immunizationHandler,
		familyHistoryHandler,
		medicalInfoHandler,
		emergencyContactHandler,
		dependentHandler,
		dependentHealthHandler,
		staffHandler,
		clinicHandler,
		serviceHandler,
		credentialHandler,
		adminHandler,
		appointmentHandler,
		symptomCheckerHandler,
		consultationHandler,
		consultationMessagesHandler,
		consultationNotesHandler,
		providerAvailabilityHandler,
		wsHandler,
		healthHandler,
		authService,
		txManager,
	)

	return &App{
		config:       cfg,
		server:       srv,
		pool:         pool,
		logger:       logger,
		broker:       broker,
		emailService: emailService,
		wsCancel:     wsCancel,
	}, nil
}

// Run starts the application
func (a *App) Run() error {
	a.logger.Info().
		Str("environment", a.config.Environment).
		Str("port", a.config.Port).
		Msg("Starting healthcare access connector")

	return a.server.Start()
}

// Cleanup performs cleanup operations in reverse initialization order:
// email -> websocket -> broker -> database.
func (a *App) Cleanup() {
	if a.emailService != nil {
		if err := a.emailService.Close(); err != nil {
			a.logger.Warn().Err(err).Msg("Email service close error")
		} else {
			a.logger.Info().Msg("Email service closed")
		}
	}

	if a.wsCancel != nil {
		a.wsCancel()
		a.logger.Info().Msg("WebSocket hub stopped")
	}

	if a.broker != nil {
		if err := a.broker.Close(); err != nil {
			a.logger.Warn().Err(err).Msg("Broker close error")
		} else {
			a.logger.Info().Msg("Message broker closed")
		}
	}

	if a.pool != nil {
		a.pool.Close()
		a.logger.Info().Msg("Database connection closed")
	}
}

func newPoolConfig(dbURL string, cfg *config.Config) (*pgxpool.Config, error) {
	poolCfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, err
	}
	poolCfg.MaxConns = int32(cfg.DBMaxConns)
	poolCfg.MinConns = int32(cfg.DBMinConns)
	poolCfg.MaxConnLifetime = cfg.DBMaxConnLifetime
	poolCfg.MaxConnIdleTime = cfg.DBMaxConnIdleTime
	poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	return poolCfg, nil
}

// initDatabase initializes the database connection pool
func initDatabase(dbURL string, logger *zerolog.Logger, cfg *config.Config) (*pgxpool.Pool, error) {
	poolCfg, err := newPoolConfig(dbURL, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), poolCfg)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info().Msg("Database connection established")
	return pool, nil
}

// toMetadata safely converts a ws payload Metadata interface{} to the
// map[string]interface{} that the domain model expects.
func toMetadata(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	if m, ok := v.(map[string]interface{}); ok {
		return m
	}
	return map[string]interface{}{"raw": v}
}
