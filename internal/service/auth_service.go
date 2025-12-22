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
func (s *authService) Login(ctx context.Context, identifier, password string) (string, time.Time, domain.User, error) {
	// Validate input
	if identifier == "" || password == "" {
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrValidation, "Identifier and password are required", 400)
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
		user, passwordHash, err = s.userRepo.GetUserByPhoneWithHash(ctx, identifier)
	}

	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			s.logger.Warn().Str("identifier", identifier).Msg("User not found")
		}
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrInvalidCredentials, "Invalid credentials", 401)
		s.logger.Error().Err(err).Msg("Failed to get user")
		return "", time.Time{}, domain.User{}, domain.NewAppError(err, "Login failed", 500)
	}

	// Check user status
	if user.Status == "inactive" {
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrUserInactive, "Account is inactive", 403)
	}
	if user.Status == "suspended" {
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrUserSuspended, "Account is suspended", 403)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		s.logger.Warn().
			Str("identifier", identifier).
			Str("user_id", user.ID.String()).
			Msg("Invalid password attempt")
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrInvalidCredentials, "Invalid credentials", 401)
	}

	// Check if user is verified (for email users)
	if !user.IsVerified && user.Email != nil && *user.Email != "" {
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrUserNotVerified, "Please verify your email first", 403)
	}

	// Generate JWT token
	expiresAt := time.Now().Add(s.jwtExpiry)
	token, err := s.generateToken(user, expiresAt)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to generate token")
		return "", time.Time{}, domain.User{}, domain.NewAppError(err, "Token generation failed", 500)
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
	if user.Email != nil && *user.Email != "" && s.emailService != nil && s.emailService.IsAvailable() {
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

	return token, expiresAt, user, nil
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
func (s *authService) RefreshToken(ctx context.Context, tokenString string) (string, time.Time, domain.User, error) {
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil && !errors.Is(err, domain.ErrExpiredToken) {
		return "", time.Time{}, domain.User{}, err
	}

	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return "", time.Time{}, domain.User{}, domain.NewAppError(err, "User not found", 404)
	}

	expiresAt := time.Now().Add(s.jwtExpiry)
	newToken, err := s.generateToken(user, expiresAt)
	if err != nil {
		return "", time.Time{}, domain.User{}, domain.NewAppError(err, "Failed to generate new token", 500)
	}

	if err := s.sessionRepo.DeleteSession(ctx, tokenString); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete old session")
	}

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

	return newToken, expiresAt, user, nil
}

// Logout handles user logout
func (s *authService) Logout(ctx context.Context, tokenString string, userID uuid.UUID) error {
	if err := s.sessionRepo.DeleteSession(ctx, tokenString); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete session")
		return domain.NewAppError(err, "Logout failed", 500)
	}

	s.logger.Info().Str("user_id", userID.String()).Msg("User logged out successfully")
	return nil
}

// generateToken creates a JWT token for a user
func (s *authService) generateToken(user domain.User, expiresAt time.Time) (string, error) {
	email := ""
	if user.Email != nil {
		email = *user.Email
	}

	claims := jwt.MapClaims{
		"user_id": user.ID.String(),
		"email":   email,
		"role":    user.Role,
		"exp":     expiresAt.Unix(),
		"iat":     time.Now().Unix(),
		"iss":     "healthcare-access-connector",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// VerifyEmail verifies user email with token
func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	// Get user by verification token
	user, _, err := s.userRepo.GetUserByVerificationToken(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.NewAppError(domain.ErrInvalidToken, "Invalid or expired verification token", 400)
		}
		s.logger.Error().Err(err).Msg("Failed to get user by verification token")
		return domain.NewAppError(err, "Verification failed", 500)
	}

	// Check if token is expired
	if user.VerificationExpires != nil && user.VerificationExpires.Before(time.Now()) {
		return domain.NewAppError(domain.ErrInvalidToken, "Verification token has expired", 400)
	}

	// Check if already verified
	if user.IsVerified {
		return domain.NewAppError(domain.ErrValidation, "Email already verified", 400)
	}

	// Verify user
	if err := s.userRepo.VerifyUser(ctx, user.ID); err != nil {
		s.logger.Error().Err(err).Msg("Failed to verify user")
		return domain.NewAppError(err, "Verification failed", 500)
	}

	// Update user status to active
	if err := s.userRepo.UpdateUserStatus(ctx, user.ID, "active"); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to update user status")
	}

	// Send welcome email
	if user.Email != nil && s.emailService != nil && s.emailService.IsAvailable() {
		go func() {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// Extract username from email or use a default
			username := "User"
			if user.Email != nil && *user.Email != "" {
				parts := strings.Split(*user.Email, "@")
				if len(parts) > 0 && parts[0] != "" {
					username = parts[0]
				}
			}

			if err := s.emailService.SendWelcomeEmail(emailCtx, *user.Email, username); err != nil {
				s.logger.Error().Err(err).Msg("Failed to send welcome email")
			}
		}()
	}

	// Publish email verified event
	if s.broker != nil && s.broker.IsAvailable() {
		event := map[string]interface{}{
			"user_id":   user.ID.String(),
			"email":     user.Email,
			"role":      user.Role,
			"timestamp": time.Now().UTC(),
		}
		if err := s.broker.PublishJSON("user.email_verified", event); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to publish email verified event")
		}
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Str("email", *user.Email).
		Msg("Email verified successfully")

	return nil
}

// RequestPasswordReset requests password reset
func (s *authService) RequestPasswordReset(ctx context.Context, identifier string) error {
	// Find user by email or phone
	var user domain.User
	var err error

	if strings.Contains(identifier, "@") {
		user, _, err = s.userRepo.GetUserByEmail(ctx, identifier)
	} else {
		user, err = s.userRepo.GetUserByPhone(ctx, identifier)
	}

	if err != nil {
		// Don't reveal if user exists for security
		s.logger.Info().Str("identifier", identifier).Msg("Password reset requested for non-existent user")
		return nil // Return success even if user doesn't exist
	}

	// Generate reset token
	resetToken := uuid.Generate().String()
	tokenExpires := time.Now().Add(1 * time.Hour)

	// Store reset token
	if err := s.userRepo.SetPasswordResetToken(ctx, user.ID, resetToken, tokenExpires); err != nil {
		s.logger.Error().Err(err).Msg("Failed to set password reset token")
		return domain.NewAppError(err, "Failed to initiate password reset", 500)
	}

	// Send reset email
	if user.Email != nil && s.emailService != nil && s.emailService.IsAvailable() {
		go func() {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := s.emailService.SendPasswordResetEmail(emailCtx, *user.Email, resetToken); err != nil {
				s.logger.Error().Err(err).Msg("Failed to send password reset email")
			}
		}()
	}

	s.logger.Info().Str("user_id", user.ID.String()).Msg("Password reset requested")

	return nil
}

// ResetPassword resets password with token
func (s *authService) ResetPassword(ctx context.Context, token, newPassword string) error {
	user, _, err := s.userRepo.GetUserByPasswordResetToken(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.NewAppError(domain.ErrInvalidToken, "Invalid or expired reset token", 400)
		}
		s.logger.Error().Err(err).Msg("Failed to get user by reset token")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hash new password")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	// Update password
	if err := s.userRepo.UpdateUserPassword(ctx, user.ID, string(hash)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to update password")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	// Delete all user sessions
	if err := s.sessionRepo.DeleteUserSessions(ctx, user.ID); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete user sessions")
	}

	// Send password changed notification
	if user.Email != nil && s.emailService != nil && s.emailService.IsAvailable() {
		go func() {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// You'll need to implement SendPasswordChangedEmail
			_ = emailCtx
		}()
	}

	s.logger.Info().Str("user_id", user.ID.String()).Msg("Password reset successfully")
	return nil
}

// ResendVerificationEmail resends verification email
func (s *authService) ResendVerificationEmail(ctx context.Context, email string) error {
	// Get user by email
	user, _, err := s.userRepo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// Don't reveal if user exists for security
			s.logger.Info().Str("email", email).Msg("Verification resend requested for non-existent user")
			return nil // Return success even if user doesn't exist
		}
		s.logger.Error().Err(err).Msg("Failed to get user by email")
		return domain.NewAppError(err, "Failed to resend verification", 500)
	}

	// Check if already verified
	if user.IsVerified {
		return domain.NewAppError(domain.ErrValidation, "Email already verified", 400)
	}

	// Generate new verification token
	verificationToken := uuid.Generate().String()
	tokenExpires := time.Now().Add(24 * time.Hour)

	// Store verification token
	if err := s.userRepo.SetVerificationToken(ctx, user.ID, verificationToken, tokenExpires); err != nil {
		s.logger.Error().Err(err).Msg("Failed to set verification token")
		return domain.NewAppError(err, "Failed to resend verification", 500)
	}

	// Send verification email
	if s.emailService != nil && s.emailService.IsAvailable() {
		if err := s.emailService.SendVerificationEmail(ctx, email, verificationToken); err != nil {
			s.logger.Error().Err(err).Msg("Failed to send verification email")
			return domain.NewAppError(err, "Failed to send verification email", 500)
		}
	} else {
		return domain.NewAppError(nil, "Email service unavailable", 503)
	}

	s.logger.Info().Str("user_id", user.ID.String()).Msg("Verification email resent")
	return nil
}
