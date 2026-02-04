// Package app handles application initialization and dependency injection
package app

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	handleradmin "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/admin"
	handlercore "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/core"
	handlerpatients "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/patients"
	handlerproviders "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	repoadmin "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/admin"
	repocore "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/core"
	repopatients "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/patients"
	repoproviders "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/server"
	serviceadmin "github.com/nyashahama/healthcare-access-connector-backend/internal/service/admin"
	servicecore "github.com/nyashahama/healthcare-access-connector-backend/internal/service/core"
	servicepatients "github.com/nyashahama/healthcare-access-connector-backend/internal/service/patients"
	serviceproviders "github.com/nyashahama/healthcare-access-connector-backend/internal/service/providers"
	"github.com/rs/zerolog"
)

// App represents the application with all dependencies
type App struct {
	config *config.Config
	server *server.Server
	pool   *pgxpool.Pool
	logger *zerolog.Logger
}

// New creates a new application instance
func New(cfg *config.Config) (*App, error) {
	logger := cfg.Logger()

	// Initialize database connection pool
	pool, err := initDatabase(cfg.DBURL, logger)
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

	// Initialize email service
	var emailService email.Service
	frontendURL := os.Getenv("FRONTEND_URL")

	// Always try to initialize email service from environment
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

	// Initialize repositories
	/* patients */
	patientRepo := repopatients.NewPatientRepository(pool)

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

	// Initialize transaction manager
	txManager := repository.NewTxManager(pool)

	sessionService := servicecore.NewSessionService(
		sessionRepo,
		userRepo,
		cacheService,
		logger,
	)
	// Initialize services
	authService := servicecore.NewAuthService(
		authRepo,
		userRepo,
		otpRepo,
		patientRepo,
		sessionService,
		consentRepo,
		cacheService,
		broker,
		emailService,
		logger,
		cfg.JWTSecret,
		cfg.JWTExpiry,
		cfg.SMSEnabled,
		cfg.BcryptCost,
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

	systemAdminService := serviceadmin.NewSystemAdminService(
		systemAdminRepo,
		userRepo,
		auditService,
		cacheService,
		logger,
	)

	clinicService := serviceproviders.NewClinicService(
		clinicRepo,
		auditRepo,
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

	serviceService := serviceproviders.NewServiceCatalogService(
		serviceRepo,
		clinicRepo,
		staffRepo,
		auditRepo,
		cacheService,
		logger,
	)

	credentialService := serviceproviders.NewCredentialService(
		credentialRepo,
		staffRepo,
		userRepo,
		auditRepo,
		cacheService,
		logger,
	)

	// Initialize handlers
	authHandler := handlercore.NewAuthHandler(authService, userService, logger, cfg.Timeout)
	userHandler := handlercore.NewUserHandler(userService, logger, cfg.Timeout)
	otpHandler := handlercore.NewOTPHandler(otpService, logger, cfg.Timeout)
	auditHandler := handlercore.NewAuditHandler(auditService, logger, cfg.Timeout)
	consentHandler := handlercore.NewConsentHandler(consentService, logger, cfg.Timeout)
	notificationHandler := handlercore.NewNotificationHandler(notificationService, logger, cfg.Timeout)
	sessionHandler := handlercore.NewSessionHandler(sessionService, logger, cfg.Timeout)
	healthHandler := handler.NewHealthHandler(pool, cacheService, broker, emailService)

	// Initialize patient handler
	patientHandler := handlerpatients.NewPatientHandler(
		patientService,
		logger,
		cfg.Timeout,
	)

	// Initialize admin handler
	adminHandler := handleradmin.NewAdminHandler(
		systemAdminService,
		logger,
		cfg.Timeout,
	)

	// Initialize provider handlers
	staffHandler := handlerproviders.NewStaffHandler(
		staffService,
		logger,
		cfg.Timeout,
	)

	clinicHandler := handlerproviders.NewClinicHandler(
		clinicService,
		logger,
		cfg.Timeout,
	)

	serviceHandler := handlerproviders.NewServiceHandler(
		serviceService,
		logger,
		cfg.Timeout,
	)

	credentialHandler := handlerproviders.NewCredentialHandler(
		credentialService,
		logger,
		cfg.Timeout,
	)

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
		staffHandler,
		clinicHandler,
		serviceHandler,
		credentialHandler,
		adminHandler,
		healthHandler,
		authService,
		txManager,
	)

	return &App{
		config: cfg,
		server: srv,
		pool:   pool,
		logger: logger,
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

// Cleanup performs cleanup operations
func (a *App) Cleanup() {
	if a.pool != nil {
		a.pool.Close()
		a.logger.Info().Msg("Database connection closed")
	}
}

// initDatabase initializes the database connection pool
func initDatabase(dbURL string, logger *zerolog.Logger) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	pool, err := pgxpool.NewWithConfig(context.Background(), config)
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
