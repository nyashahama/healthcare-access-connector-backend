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
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/config"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	handlercore "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	repocore "github.com/nyashahama/healthcare-access-connector-backend/internal/repository/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/server"
	servicecore "github.com/nyashahama/healthcare-access-connector-backend/internal/service/core"
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
	authRepo := repocore.NewAuthRepository(pool)
	userRepo := repocore.NewUserRepository(pool)
	otpRepo := repocore.NewOTPRepository(pool)
	sessionRepo := repocore.NewSessionRepository(pool)

	// Initialize stubs for required but not yet implemented repositories
	patientRepo := &stubPatientRepository{}
	consentRepo := &stubConsentRepository{}
	notificationRepo := &stubNotificationRepository{}

	// Initialize transaction manager
	txManager := repository.NewTxManager(pool)

	// Initialize services
	authService := servicecore.NewAuthService(
		authRepo,
		userRepo,
		otpRepo,
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

	// Initialize handlers
	authHandler := handlercore.NewAuthHandler(authService, userService, logger, cfg.Timeout)
	userHandler := handlercore.NewUserHandler(userService, logger, cfg.Timeout)
	otpHandler := handlercore.NewOTPHandler(otpService, logger, cfg.Timeout)
	healthHandler := handler.NewHealthHandler(pool, cacheService, broker, emailService)

	// Initialize server with all handlers
	srv := server.NewServer(
		cfg,
		logger,
		authHandler,
		userHandler,
		otpHandler,
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

// =========================================
// STUB REPOSITORY IMPLEMENTATIONS
// These are temporary until actual implementations are ready
// =========================================

type stubPatientRepository struct{}

func (s *stubPatientRepository) CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error) {
	return profile, nil
}

func (s *stubPatientRepository) GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error) {
	return patients.PatientProfile{}, nil
}

func (s *stubPatientRepository) GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
	return patients.PatientProfile{}, nil
}

func (s *stubPatientRepository) GetPatientsByClinic(ctx context.Context, clinicID uuid.UUID, limit, offset int) ([]patients.PatientProfile, error) {
	return []patients.PatientProfile{}, nil
}

func (s *stubPatientRepository) UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error {
	return nil
}

func (s *stubPatientRepository) DeletePatientProfile(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (s *stubPatientRepository) SearchPatients(ctx context.Context, query string, province string, limit, offset int) ([]patients.PatientProfile, error) {
	return []patients.PatientProfile{}, nil
}

func (s *stubPatientRepository) CreateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error {
	return nil
}

func (s *stubPatientRepository) GetMedicalInfo(ctx context.Context, patientID uuid.UUID) (patients.PatientMedicalInfo, error) {
	return patients.PatientMedicalInfo{}, nil
}

func (s *stubPatientRepository) UpdateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error {
	return nil
}

func (s *stubPatientRepository) DeleteMedicalInfo(ctx context.Context, patientID uuid.UUID) error {
	return nil
}

func (s *stubPatientRepository) AddAllergy(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error) {
	return patients.PatientAllergy{}, nil
}

func (s *stubPatientRepository) GetAllergy(ctx context.Context, id uuid.UUID) (patients.PatientAllergy, error) {
	return patients.PatientAllergy{}, nil
}

func (s *stubPatientRepository) GetAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error) {
	return []patients.PatientAllergy{}, nil
}

func (s *stubPatientRepository) UpdateAllergy(ctx context.Context, allergy patients.PatientAllergy) error {
	return nil
}

func (s *stubPatientRepository) DeleteAllergy(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (s *stubPatientRepository) AddMedication(ctx context.Context, med patients.PatientMedication) (patients.PatientMedication, error) {
	return patients.PatientMedication{}, nil
}

func (s *stubPatientRepository) GetMedication(ctx context.Context, id uuid.UUID) (patients.PatientMedication, error) {
	return patients.PatientMedication{}, nil
}

func (s *stubPatientRepository) GetMedications(ctx context.Context, patientID uuid.UUID, status string) ([]patients.PatientMedication, error) {
	return []patients.PatientMedication{}, nil
}

func (s *stubPatientRepository) UpdateMedication(ctx context.Context, med patients.PatientMedication) error {
	return nil
}

func (s *stubPatientRepository) DeleteMedication(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (s *stubPatientRepository) GetActiveMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error) {
	return []patients.PatientMedication{}, nil
}

func (s *stubPatientRepository) AddCondition(ctx context.Context, condition patients.PatientCondition) (patients.PatientCondition, error) {
	return patients.PatientCondition{}, nil
}

func (s *stubPatientRepository) GetCondition(ctx context.Context, id uuid.UUID) (patients.PatientCondition, error) {
	return patients.PatientCondition{}, nil
}

func (s *stubPatientRepository) GetConditions(ctx context.Context, patientID uuid.UUID, status string) ([]patients.PatientCondition, error) {
	return []patients.PatientCondition{}, nil
}

func (s *stubPatientRepository) UpdateCondition(ctx context.Context, condition patients.PatientCondition) error {
	return nil
}

func (s *stubPatientRepository) DeleteCondition(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (s *stubPatientRepository) GetActiveConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error) {
	return []patients.PatientCondition{}, nil
}

func (s *stubPatientRepository) AddImmunization(ctx context.Context, imm patients.PatientImmunization) (patients.PatientImmunization, error) {
	return patients.PatientImmunization{}, nil
}

func (s *stubPatientRepository) GetImmunization(ctx context.Context, id uuid.UUID) (patients.PatientImmunization, error) {
	return patients.PatientImmunization{}, nil
}

func (s *stubPatientRepository) GetImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error) {
	return []patients.PatientImmunization{}, nil
}

func (s *stubPatientRepository) UpdateImmunization(ctx context.Context, imm patients.PatientImmunization) error {
	return nil
}

func (s *stubPatientRepository) DeleteImmunization(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (s *stubPatientRepository) GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error) {
	return []patients.PatientImmunization{}, nil
}

func (s *stubPatientRepository) GetImmunizationHistory(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error) {
	return []patients.PatientImmunization{}, nil
}

type stubConsentRepository struct{}

func (s *stubConsentRepository) CreateConsent(ctx context.Context, consent core.PrivacyConsent) (core.PrivacyConsent, error) {
	return consent, nil
}

func (s *stubConsentRepository) GetConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error) {
	return core.PrivacyConsent{}, nil
}

func (s *stubConsentRepository) UpdateConsent(ctx context.Context, consent core.PrivacyConsent) error {
	return nil
}

func (s *stubConsentRepository) WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error {
	return nil
}

func (s *stubConsentRepository) GetConsentHistory(ctx context.Context, userID uuid.UUID) ([]core.PrivacyConsent, error) {
	return []core.PrivacyConsent{}, nil
}

func (s *stubConsentRepository) GetActiveConsentsByType(ctx context.Context, consentType string) ([]core.PrivacyConsent, error) {
	return []core.PrivacyConsent{}, nil
}

func (s *stubConsentRepository) GetExpiredConsents(ctx context.Context) ([]core.PrivacyConsent, error) {
	return []core.PrivacyConsent{}, nil
}

func (s *stubConsentRepository) ExportConsentData(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	return []byte{}, nil
}

func (s *stubConsentRepository) NotifyConsentExpirations(ctx context.Context, daysBefore int) ([]uuid.UUID, error) {
	return []uuid.UUID{}, nil
}

type stubNotificationRepository struct{}

func (s *stubNotificationRepository) CreatePreferences(ctx context.Context, prefs core.NotificationPreferences) (core.NotificationPreferences, error) {
	return prefs, nil
}

func (s *stubNotificationRepository) GetPreferences(ctx context.Context, userID uuid.UUID) (core.NotificationPreferences, error) {
	return core.NotificationPreferences{}, nil
}

func (s *stubNotificationRepository) UpdatePreferences(ctx context.Context, prefs core.NotificationPreferences) error {
	return nil
}

func (s *stubNotificationRepository) DeletePreferences(ctx context.Context, userID uuid.UUID) error {
	return nil
}

func (s *stubNotificationRepository) UpdateEmailPreferences(ctx context.Context, userID uuid.UUID, enabled bool, frequency string) error {
	return nil
}

func (s *stubNotificationRepository) UpdateSMSPreferences(ctx context.Context, userID uuid.UUID, enabled bool) error {
	return nil
}

func (s *stubNotificationRepository) UpdatePushPreferences(ctx context.Context, userID uuid.UUID, enabled bool) error {
	return nil
}

func (s *stubNotificationRepository) UpdateAppointmentReminders(ctx context.Context, userID uuid.UUID, enabled bool, hoursBefore int) error {
	return nil
}

func (s *stubNotificationRepository) UpdateMedicationReminders(ctx context.Context, userID uuid.UUID, enabled bool) error {
	return nil
}

func (s *stubNotificationRepository) UpdateHealthTips(ctx context.Context, userID uuid.UUID, enabled bool, frequency string) error {
	return nil
}

func (s *stubNotificationRepository) UpdateEmergencyAlerts(ctx context.Context, userID uuid.UUID, enabled bool) error {
	return nil
}

func (s *stubNotificationRepository) SetQuietHours(ctx context.Context, userID uuid.UUID, startTime, endTime time.Time) error {
	return nil
}

func (s *stubNotificationRepository) UpdateNotificationLanguage(ctx context.Context, userID uuid.UUID, language string) error {
	return nil
}

func (s *stubNotificationRepository) GetUsersWithDisabledNotifications(ctx context.Context, notificationType string) ([]uuid.UUID, error) {
	return []uuid.UUID{}, nil
}
