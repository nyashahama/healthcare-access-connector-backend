// Package service implements business logic
package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/golang-jwt/jwt/v5"
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

// Login handles user login with email or phone
func (s *authService) Login(ctx context.Context, identifier, password string) (string, time.Time, error) {
	// Validate input
	if identifier == "" || password == "" {
		return "", time.Time{}, domain.NewAppError(domain.ErrValidation, "Identifier and password are required", 400)
	}

	// Determine if identifier is email or phone
	var user domain.User
	var passwordHash string
	var err error

	if strings.Contains(identifier, "@") {
		// Treat as email
		user, passwordHash, err = s.userRepo.GetUserByEmail(ctx, identifier)
	} else {
		// Treat as phone number
		user, err = s.userRepo.GetUserByPhone(ctx, identifier)
		if err == nil {
			// For phone login, we need to get the password hash
			_, passwordHash, err = s.userRepo.GetUserByEmail(ctx, *user.Email)
		}
	}

	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			s.logger.Warn().Str("identifier", identifier).Msg("User not found")
			return "", time.Time{}, domain.NewAppError(domain.ErrInvalidCredentials, "Invalid credentials", 401)
		}
		s.logger.Error().Err(err).Msg("Failed to get user")
		return "", time.Time{}, domain.NewAppError(err, "Login failed", 500)
	}

	// Check user status
	if user.Status == "inactive" {
		return "", time.Time{}, domain.NewAppError(domain.ErrUserInactive, "Account is inactive", 403)
	}
	if user.Status == "suspended" {
		return "", time.Time{}, domain.NewAppError(domain.ErrUserSuspended, "Account is suspended", 403)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		s.logger.Warn().
			Str("identifier", identifier).
			Str("user_id", user.ID.String()).
			Msg("Invalid password attempt")
		return "", time.Time{}, domain.NewAppError(domain.ErrInvalidCredentials, "Invalid credentials", 401)
	}

	// Check if user is verified (for email users)
	if user.Email != nil && !user.IsVerified && *user.Email != "" {
		return "", time.Time{}, domain.NewAppError(domain.ErrUserNotVerified, "Please verify your email", 403)
	}

	// Generate JWT token
	expiresAt := time.Now().Add(s.jwtExpiry)
	token, err := s.generateToken(user, expiresAt)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to generate token")
		return "", time.Time{}, domain.NewAppError(err, "Token generation failed", 500)
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(ctx, user.ID); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to update last login")
	}

	// Create session record
	session := domain.UserSession{
		ID:           uuid.Generate(),
		UserID:       user.ID,
		SessionToken: token,
		DeviceType:   &[]string{"web"}[0],
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}

	if _, err := s.sessionRepo.CreateSession(ctx, session); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to create session record")
	}

	// Send login alert if email available
	if user.Email != nil && s.emailService != nil && s.emailService.IsAvailable() {
		go func() {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := s.emailService.SendLoginAlertEmail(emailCtx, *user.Email, "User", "Unknown", "Unknown"); err != nil {
				s.logger.Warn().Err(err).Msg("Failed to send login alert email")
			}
		}()
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Str("role", user.Role).
		Msg("User logged in successfully")

	return token, expiresAt, nil
}

// ValidateToken validates JWT token
func (s *authService) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})
	if err != nil {
		return nil, domain.NewAppError(domain.ErrInvalidToken, "Invalid token", 401)
	}

	if !token.Valid {
		return nil, domain.NewAppError(domain.ErrInvalidToken, "Invalid token", 401)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, domain.NewAppError(domain.ErrInvalidToken, "Invalid token claims", 401)
	}

	// Extract user ID (UUID)
	userIDStr, ok := claims["user_id"].(string)
	if !ok {
		return nil, domain.NewAppError(domain.ErrInvalidToken, "Invalid user ID in token", 401)
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, domain.NewAppError(domain.ErrInvalidToken, "Invalid user ID format", 401)
	}

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, domain.NewAppError(domain.ErrExpiredToken, "Token expired", 401)
		}
	}

	// Check if session exists
	session, err := s.sessionRepo.GetSession(ctx, tokenString)
	if err != nil || session.ExpiresAt.Before(time.Now()) {
		return nil, domain.NewAppError(domain.ErrInvalidSession, "Session expired or invalid", 401)
	}

	role, _ := claims["role"].(string)
	email, _ := claims["email"].(string)

	return &TokenClaims{
		UserID: userID,
		Role:   role,
		Email:  email,
	}, nil
}

// RefreshToken refreshes JWT token
func (s *authService) RefreshToken(ctx context.Context, tokenString string) (string, time.Time, error) {
	// Validate existing token
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil && !errors.Is(err, domain.ErrExpiredToken) {
		return "", time.Time{}, err
	}

	// Get user to ensure they still exist
	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return "", time.Time{}, domain.NewAppError(err, "User not found", 404)
	}

	// Generate new token
	expiresAt := time.Now().Add(s.jwtExpiry)
	newToken, err := s.generateToken(user, expiresAt)
	if err != nil {
		return "", time.Time{}, domain.NewAppError(err, "Failed to generate new token", 500)
	}

	// Update session
	session, err := s.sessionRepo.GetSession(ctx, tokenString)
	if err == nil {
		session.SessionToken = newToken
		session.ExpiresAt = expiresAt
		// Update session in repository (you might need to add an UpdateSession method)
	}

	// Delete old session
	if err := s.sessionRepo.DeleteSession(ctx, tokenString); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete old session")
	}

	// Create new session
	newSession := domain.UserSession{
		ID:           uuid.Generate(),
		UserID:       user.ID,
		SessionToken: newToken,
		DeviceType:   &[]string{"web"}[0],
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}

	if _, err := s.sessionRepo.CreateSession(ctx, newSession); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to create new session record")
	}

	return newToken, expiresAt, nil
}
