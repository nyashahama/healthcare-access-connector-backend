// Package service implements business logic
package service

import (
	"context"
	"errors"
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"golang.org/x/crypto/bcrypt"

	"github.com/rs/zerolog"
)

type authService struct {
	userRepo     repository.UserRepository
	patientRepo  repository.PatientRepository
	sessionRepo  repository.SessionRepository
	consentRepo  repository.ConsentRepository
	cache        cache.Service
	broker       messaging.Broker
	emailService email.Service
	logger       *zerolog.Logger
	jwtSecret    string
	jwtExpiry    time.Duration
	smsEnabled   bool
}

// NewAuthService creates a new authentication service
func NewAuthService(
	userRepo repository.UserRepository,
	patientRepo repository.PatientRepository,
	sessionRepo repository.SessionRepository,
	consentRepo repository.ConsentRepository,
	cache cache.Service,
	broker messaging.Broker,
	emailService email.Service,
	logger *zerolog.Logger,
	jwtSecret string,
	jwtExpiry time.Duration,
	smsEnabled bool,
) AuthService {
	return &authService{
		userRepo:     userRepo,
		patientRepo:  patientRepo,
		sessionRepo:  sessionRepo,
		consentRepo:  consentRepo,
		cache:        cache,
		broker:       broker,
		emailService: emailService,
		logger:       logger,
		jwtSecret:    jwtSecret,
		jwtExpiry:    jwtExpiry,
		smsEnabled:   smsEnabled,
	}
}

// Register handles user registration with email or phone
func (s *authService) Register(ctx context.Context, email, phone, password, role string) (domain.User, error) {
	// Validate input
	if email == "" && phone == "" {
		return domain.User{}, domain.NewAppError(domain.ErrValidation, "Email or phone is required", 400)
	}
	if password == "" {
		return domain.User{}, domain.NewAppError(domain.ErrValidation, "Password is required", 400)
	}
	if role == "" {
		role = "patient" // Default role
	}

	// Validate role
	validRoles := map[string]bool{
		"patient":        true,
		"caregiver":      true,
		"provider_staff": true,
		"clinic_admin":   true,
		"system_admin":   true,
		"ngo_partner":    true,
	}
	if !validRoles[role] {
		return domain.User{}, domain.NewAppError(domain.ErrValidation, "Invalid role", 400)
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hash password")
		return domain.User{}, domain.NewAppError(err, "Password hashing failed", 500)
	}

	// Create user domain object
	user := domain.User{
		Email:                &email,
		Phone:                &phone,
		Role:                 role,
		Status:               "pending_verification",
		IsVerified:           false,
		IsSMSOnly:            phone != "" && email == "",
		SMSConsentGiven:      s.smsEnabled && phone != "",
		POPIAConsentGiven:    true, // Default to true, can be updated later
		ConsentDate:          &[]time.Time{time.Now()}[0],
		ProfileCompletionPct: 10, // Basic registration completion
		CreatedAt:            time.Now(),
		UpdatedAt:            time.Now(),
	}

	// Create user in repository
	created, err := s.userRepo.CreateUser(ctx, user, string(hash))
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateEmail) {
			return domain.User{}, domain.NewAppError(err, "Email already exists", 409)
		}
		if errors.Is(err, domain.ErrDuplicatePhone) {
			return domain.User{}, domain.NewAppError(err, "Phone number already exists", 409)
		}
		s.logger.Error().Err(err).Msg("Failed to create user")
		return domain.User{}, domain.NewAppError(err, "User creation failed", 500)
	}

	// Create default consent record
	consent := domain.PrivacyConsent{
		UserID:                     created.ID,
		HealthDataConsent:          true,
		HealthDataConsentDate:      &created.CreatedAt,
		HealthDataConsentVersion:   &[]string{"1.0"}[0],
		ResearchConsent:            false,
		EmergencyAccessConsent:     true,
		EmergencyAccessConsentDate: &created.CreatedAt,
		SMSCommunicationConsent:    s.smsEnabled && phone != "",
		EmailCommunicationConsent:  email != "",
		ConsentWithdrawn:           false,
		CreatedAt:                  created.CreatedAt,
		UpdatedAt:                  created.CreatedAt,
	}

	if _, err := s.consentRepo.CreateConsent(ctx, consent); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to create consent record")
	}

	// For patients, create empty patient profile
	if role == "patient" {
		patientProfile := domain.PatientProfile{
			ID:                           uuid.Generate(),
			UserID:                       created.ID,
			Country:                      "South Africa", // Default
			LanguagePreferences:          []string{"en", "af", "zu"},
			PreferredCommunicationMethod: "sms", // Default for South Africa
			Timezone:                     "Africa/Johannesburg",
			AcceptsMarketingEmails:       false,
			CreatedAt:                    created.CreatedAt,
			UpdatedAt:                    created.CreatedAt,
		}

		if _, err := s.patientRepo.CreatePatientProfile(ctx, patientProfile); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to create patient profile")
		}
	}

	// Send verification email if email provided
	if email != "" && s.emailService != nil && s.emailService.IsAvailable() {
		go func() {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Generate verification token
			verificationToken := uuid.Generate().String()
			tokenExpires := time.Now().Add(24 * time.Hour)

			// Store verification token
			if err := s.userRepo.SetVerificationToken(emailCtx, created.ID, verificationToken, tokenExpires); err != nil {
				s.logger.Error().Err(err).Msg("Failed to set verification token")
				return
			}

			// Send verification email
			if err := s.emailService.SendVerificationEmail(emailCtx, email, verificationToken); err != nil {
				s.logger.Error().Err(err).Msg("Failed to send verification email")
			}
		}()
	}

	// Publish registration event
	if s.broker != nil && s.broker.IsAvailable() {
		event := map[string]interface{}{
			"user_id":   created.ID,
			"email":     email,
			"phone":     phone,
			"role":      role,
			"timestamp": time.Now().UTC(),
		}
		if err := s.broker.PublishJSON("user.registered", event); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to publish registration event")
		}
	}

	s.logger.Info().
		Str("user_id", created.ID.String()).
		Str("role", role).
		Msg("User registered successfully")

	return created, nil
}
