// Package app handles application initialization and dependency injection for health project
package app

import (
	"context"
	"fmt"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/server"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog"
)

// App represents the health project application with all dependencies
type App struct {
	config *config.Config
	server *server.Server
	pool   *pgxpool.Pool
	logger *zerolog.Logger
}

// New creates a new application instance for health project
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

	// Initialize email service (optional)
	var emailService email.Service
	if cfg.EmailFrom != "" && cfg.EmailHost != "" {
		// Create email config from app config
		emailCfg := &email.Config{
			Provider:     "smtp", // Default to SMTP for local development
			FromAddress:  cfg.EmailFrom,
			FromName:     "Healthcare Access Connector", // You might want to make this configurable
			SMTPHost:     cfg.EmailHost,
			SMTPPort:     cfg.EmailPort,
			SMTPUsername: cfg.EmailUser,
			SMTPPassword: cfg.EmailPassword,
			SMTPUseTLS:   cfg.EmailPort == 587 || cfg.EmailPort == 465, // Use TLS for standard email ports
		}

		emailService, err = email.NewEmailService(emailCfg, logger)
		if err != nil {
			logger.Warn().Err(err).Msg("Email service initialization failed, continuing without email")
			emailService = nil
		}
	} else {
		// Try to load email config from environment
		emailService, _ = email.NewFromEnv(logger)
	}

	// Initialize ONLY the repositories that are implemented
	userRepo := repository.NewUserRepository(pool)

	// Initialize stubs for required but not yet implemented repositories
	// These will be replaced with actual implementations later
	patientRepo := &stubPatientRepository{}
	sessionRepo := &stubSessionRepository{}
	consentRepo := &stubConsentRepository{}
	notificationRepo := &stubNotificationRepository{}

	// Initialize transaction manager
	txManager := repository.NewTxManager(pool)

	// Initialize services with stubs where needed
	authService := service.NewAuthService(
		userRepo,
		patientRepo,
		sessionRepo,
		consentRepo,
		cacheService,
		broker,
		emailService,
		logger,
		cfg.JWTSecret,
		cfg.JWTExpiry,
		cfg.SMSEnabled,
	)

	userService := service.NewUserService(
		userRepo,
		patientRepo,
		consentRepo,
		notificationRepo,
		sessionRepo,
		cacheService,
		logger,
	)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService, userService, logger, cfg.Timeout)
	healthHandler := handler.NewHealthHandler(pool, cacheService, broker, emailService)

	// Initialize server with only implemented handlers
	srv := server.NewServer(
		cfg,
		logger,
		authHandler,
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
	// Parse the connection string
	config, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Disable prepared statement caching to avoid conflicts
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	// Create pool with config
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, err
	}

	// Test connection
	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	logger.Info().Msg("Database connection established")
	return pool, nil
}

// =========================================
// STUB REPOSITORY IMPLEMENTATIONS
// These are temporary until actual implementations are ready
// =========================================

type stubPatientRepository struct{}

func (s *stubPatientRepository) CreatePatientProfile(ctx context.Context, profile domain.PatientProfile) (domain.PatientProfile, error) {
	return profile, nil
}

func (s *stubPatientRepository) GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (domain.PatientProfile, error) {
	return domain.PatientProfile{}, nil
}

func (s *stubPatientRepository) GetPatientProfileByID(ctx context.Context, id uuid.UUID) (domain.PatientProfile, error) {
	return domain.PatientProfile{}, nil
}

func (s *stubPatientRepository) UpdatePatientProfile(ctx context.Context, profile domain.PatientProfile) error {
	return nil
}

func (s *stubPatientRepository) SearchPatients(ctx context.Context, query string, province string, limit, offset int) ([]domain.PatientProfile, error) {
	return []domain.PatientProfile{}, nil
}

func (s *stubPatientRepository) CreateMedicalInfo(ctx context.Context, info domain.PatientMedicalInfo) error {
	return nil
}

func (s *stubPatientRepository) GetMedicalInfo(ctx context.Context, patientID uuid.UUID) (domain.PatientMedicalInfo, error) {
	return domain.PatientMedicalInfo{}, nil
}

func (s *stubPatientRepository) UpdateMedicalInfo(ctx context.Context, info domain.PatientMedicalInfo) error {
	return nil
}

func (s *stubPatientRepository) AddAllergy(ctx context.Context, allergy domain.PatientAllergy) (domain.PatientAllergy, error) {
	return domain.PatientAllergy{}, nil
}

func (s *stubPatientRepository) GetAllergies(ctx context.Context, patientID uuid.UUID) ([]domain.PatientAllergy, error) {
	return []domain.PatientAllergy{}, nil
}

func (s *stubPatientRepository) UpdateAllergy(ctx context.Context, allergy domain.PatientAllergy) error {
	return nil
}

func (s *stubPatientRepository) DeleteAllergy(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (s *stubPatientRepository) AddMedication(ctx context.Context, med domain.PatientMedication) (domain.PatientMedication, error) {
	return domain.PatientMedication{}, nil
}

func (s *stubPatientRepository) GetMedications(ctx context.Context, patientID uuid.UUID, status string) ([]domain.PatientMedication, error) {
	return []domain.PatientMedication{}, nil
}

func (s *stubPatientRepository) UpdateMedication(ctx context.Context, med domain.PatientMedication) error {
	return nil
}

func (s *stubPatientRepository) AddCondition(ctx context.Context, condition domain.PatientCondition) (domain.PatientCondition, error) {
	return domain.PatientCondition{}, nil
}

func (s *stubPatientRepository) GetConditions(ctx context.Context, patientID uuid.UUID, status string) ([]domain.PatientCondition, error) {
	return []domain.PatientCondition{}, nil
}

func (s *stubPatientRepository) UpdateCondition(ctx context.Context, condition domain.PatientCondition) error {
	return nil
}

func (s *stubPatientRepository) AddImmunization(ctx context.Context, imm domain.PatientImmunization) (domain.PatientImmunization, error) {
	return domain.PatientImmunization{}, nil
}

func (s *stubPatientRepository) GetImmunizations(ctx context.Context, patientID uuid.UUID) ([]domain.PatientImmunization, error) {
	return []domain.PatientImmunization{}, nil
}

func (s *stubPatientRepository) GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]domain.PatientImmunization, error) {
	return []domain.PatientImmunization{}, nil
}

type stubSessionRepository struct{}

func (s *stubSessionRepository) CreateSession(ctx context.Context, session domain.UserSession) (domain.UserSession, error) {
	return session, nil
}

func (s *stubSessionRepository) GetSession(ctx context.Context, sessionToken string) (domain.UserSession, error) {
	return domain.UserSession{}, nil
}

func (s *stubSessionRepository) DeleteSession(ctx context.Context, sessionToken string) error {
	return nil
}

func (s *stubSessionRepository) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	return nil
}

func (s *stubSessionRepository) DeleteExpiredSessions(ctx context.Context) error {
	return nil
}

type stubConsentRepository struct{}

func (s *stubConsentRepository) CreateConsent(ctx context.Context, consent domain.PrivacyConsent) (domain.PrivacyConsent, error) {
	return consent, nil
}

func (s *stubConsentRepository) GetConsent(ctx context.Context, userID uuid.UUID) (domain.PrivacyConsent, error) {
	return domain.PrivacyConsent{}, nil
}

func (s *stubConsentRepository) UpdateConsent(ctx context.Context, consent domain.PrivacyConsent) error {
	return nil
}

func (s *stubConsentRepository) WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error {
	return nil
}

type stubNotificationRepository struct{}

func (s *stubNotificationRepository) CreatePreferences(ctx context.Context, prefs domain.NotificationPreferences) (domain.NotificationPreferences, error) {
	return prefs, nil
}

func (s *stubNotificationRepository) GetPreferences(ctx context.Context, userID uuid.UUID) (domain.NotificationPreferences, error) {
	return domain.NotificationPreferences{}, nil
}

func (s *stubNotificationRepository) UpdatePreferences(ctx context.Context, prefs domain.NotificationPreferences) error {
	return nil
}
