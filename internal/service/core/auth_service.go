package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"golang.org/x/crypto/bcrypt"

	"github.com/rs/zerolog"
)

type authService struct {
	authRepo     repository.AuthRepository
	userRepo     repository.UserRepository
	otpRepo      repository.OTPRepository
	patientRepo  repository.PatientProfileRepository
	sessionSvc   service.SessionService
	consentRepo  repository.ConsentRepository
	staffService service.StaffService
	cache        cache.Service
	broker       messaging.Broker
	emailService email.Service
	logger       *zerolog.Logger
	jwtSecret    string
	jwtExpiry    time.Duration
	smsEnabled   bool
	bcryptCost   int

	// Token generation pool
	tokenPool sync.Pool

	// Rate limiting for login attempts
	loginAttempts    map[string]loginAttempt
	loginAttemptsMu  sync.RWMutex
	loginMaxAttempts int
	loginLockout     time.Duration
}

type loginAttempt struct {
	attempts    int
	lastFailed  time.Time
	lockedUntil *time.Time
}

// NewAuthService creates a new authentication service
func NewAuthService(
	authRepo repository.AuthRepository,
	userRepo repository.UserRepository,
	otpRepo repository.OTPRepository,
	patientRepo repository.PatientProfileRepository,
	sessionSvc service.SessionService,
	consentRepo repository.ConsentRepository,
	staffService service.StaffService,
	cache cache.Service,
	broker messaging.Broker,
	emailService email.Service,
	logger *zerolog.Logger,
	jwtSecret string,
	jwtExpiry time.Duration,
	smsEnabled bool,
	bcryptCost int,
	loginMaxAttempts int,
	loginLockout time.Duration,
) service.AuthService {
	// Validate bcrypt cost
	if bcryptCost < bcrypt.MinCost {
		logger.Warn().
			Int("provided_cost", bcryptCost).
			Int("min_cost", bcrypt.MinCost).
			Msg("Bcrypt cost too low, using minimum")
		bcryptCost = bcrypt.MinCost
	}
	if bcryptCost > bcrypt.MaxCost {
		logger.Warn().
			Int("provided_cost", bcryptCost).
			Int("max_cost", bcrypt.MaxCost).
			Msg("Bcrypt cost too high, using maximum")
		bcryptCost = bcrypt.MaxCost
	}

	service := &authService{
		authRepo:         authRepo,
		userRepo:         userRepo,
		otpRepo:          otpRepo,
		patientRepo:      patientRepo,
		sessionSvc:       sessionSvc,
		consentRepo:      consentRepo,
		staffService:     staffService,
		cache:            cache,
		broker:           broker,
		emailService:     emailService,
		logger:           logger,
		jwtSecret:        jwtSecret,
		jwtExpiry:        jwtExpiry,
		smsEnabled:       smsEnabled,
		bcryptCost:       bcryptCost,
		loginMaxAttempts: loginMaxAttempts,
		loginLockout:     loginLockout,
		loginAttempts:    make(map[string]loginAttempt),
		tokenPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, 32)
			},
		},
	}

	// Start background cleanup goroutine
	go service.cleanupLoginAttempts()

	return service
}

// Register handles user registration
func (s *authService) Register(ctx context.Context, email, phone, password, role string) (core.User, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("email", email).
			Str("role", role).
			Msg("Registration completed")
	}()

	// Validate input
	if email == "" && phone == "" {
		return core.User{}, domain.NewAppError(domain.ErrValidation, "Email or phone is required", 400)
	}
	if password == "" {
		return core.User{}, domain.NewAppError(domain.ErrValidation, "Password is required", 400)
	}
	if role == "" {
		role = "patient"
	}

	// Validate role
	validRoles := map[string]bool{
		"patient":        true,
		"caregiver":      true,
		"provider_staff": true,
		"clinic_admin":   true,
	}
	if !validRoles[role] {
		return core.User{}, domain.NewAppError(domain.ErrValidation, "Invalid role", 400)
	}
	if role == "system_admin" || role == "ngo_partner" {
		return core.User{}, domain.NewAppError(domain.ErrForbidden, "Privileged roles require invitation or admin action", 403)
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hash password")
		return core.User{}, domain.NewAppError(err, "Password hashing failed", 500)
	}

	// Create user domain object
	now := time.Now()
	user := core.User{
		Email:                stringPtr(email),
		Phone:                stringPtr(phone),
		Role:                 role,
		Status:               "pending_verification",
		IsVerified:           false,
		IsSMSOnly:            phone != "" && email == "",
		SMSConsentGiven:      s.smsEnabled && phone != "",
		POPIAConsentGiven:    true,
		ConsentDate:          &now,
		ProfileCompletionPct: 10,
		PrimaryClinicID:      nil,
		OnboardingCompleted:  false,
		OnboardingStep:       stringPtr(core.OnboardingStepAccountCreated),
		CreatedAt:            now,
		UpdatedAt:            now,
	}

	// TODO:     // Restrict self-selection of admin roles

	// Create user in repository
	created, err := s.authRepo.CreateUser(ctx, user, string(hash))
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateEmail) {
			return core.User{}, domain.NewAppError(err, "Email already exists", 409)
		}
		if errors.Is(err, domain.ErrDuplicatePhone) {
			return core.User{}, domain.NewAppError(err, "Phone number already exists", 409)
		}
		s.logger.Error().Err(err).Msg("Failed to create user")
		return core.User{}, domain.NewAppError(err, "User creation failed", 500)
	}

	// Handle post-registration tasks asynchronously
	go s.handlePostRegistration(created, email, phone, role)

	s.logger.Info().
		Str("user_id", created.ID.String()).
		Str("role", role).
		Dur("duration_ms", time.Since(start)).
		Msg("User registered successfully")

	return created, nil
}

// RegisterInvitedStaff handles staff registration via invitation
func (s *authService) RegisterInvitedStaff(ctx context.Context, token, email, password, phone string) (core.User, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("email", email).
			Msg("Registration completed")
	}()
	// Get invitation
	invitation, err := s.staffService.GetStaffInvitationByToken(ctx, token)
	if err != nil {
		return core.User{}, domain.NewAppError(domain.ErrInvalidToken, "Invalid or expired invitation", 400)
	}

	// Verify email matches
	if strings.ToLower(invitation.WorkEmail) != strings.ToLower(email) {
		return core.User{}, domain.NewAppError(domain.ErrValidation, "Email does not match invitation", 400)
	}

	// Register user (using existing Register method)
	user, err := s.Register(ctx, email, phone, password, "provider_staff")
	if err != nil {
		return core.User{}, err
	}

	// Accept invitation
	_, err = s.staffService.AcceptStaffInvitation(ctx, token, user.ID)
	if err != nil {
		// Rollback user creation if needed
		s.logger.Error().Err(err).Msg("Failed to accept invitation after user creation")
		return core.User{}, domain.NewAppError(err, "Failed to accept invitation", 500)
	}

	// Update user's primary clinic and mark onboarding as complete
	if err := s.authRepo.UpdateUserPrimaryClinic(ctx, user.ID, invitation.ClinicID); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to update user primary clinic")
	}

	if err := s.authRepo.CompleteUserOnboarding(ctx, user.ID); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to complete user onboarding")
	}

	return user, nil
}

// Login handles user login
func (s *authService) Login(ctx context.Context, identifier, password, ipAddress, userAgent string) (string, time.Time, core.User, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("identifier", maskIdentifier(identifier)).
			Msg("Login attempt completed")
	}()

	// Validate input
	if identifier == "" || password == "" {
		return "", time.Time{}, core.User{}, domain.NewAppError(domain.ErrValidation, "Identifier and password are required", 400)
	}

	// Check rate limiting
	if s.isLoginLocked(identifier) {
		return "", time.Time{}, core.User{}, domain.NewAppError(domain.ErrRateLimited, "Too many login attempts. Please try again later", 429)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("user:login:%s", identifier)
	type cachedUserData struct {
		User core.User
		Hash string
	}

	var user core.User
	var passwordHash string
	var err error
	cacheHit := false

	if s.cache != nil && s.cache.IsAvailable() {
		var cached cachedUserData
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			user = cached.User
			passwordHash = cached.Hash
			cacheHit = true
			s.logger.Debug().Str("identifier", maskIdentifier(identifier)).Msg("Cache hit for user lookup")
		}
	}

	// If not in cache, fetch from database
	if !cacheHit {
		if strings.Contains(identifier, "@") {
			user, passwordHash, err = s.authRepo.GetUserByEmail(ctx, strings.ToLower(identifier))
		} else {
			user, passwordHash, err = s.authRepo.GetUserByPhoneWithHash(ctx, identifier)
		}

		if err != nil {
			if errors.Is(err, domain.ErrUserNotFound) {
				s.logger.Warn().Str("identifier", maskIdentifier(identifier)).Msg("User not found")
				s.recordFailedLogin(identifier)
				return "", time.Time{}, core.User{}, domain.NewAppError(domain.ErrInvalidCredentials, "Invalid credentials", 401)
			}
			s.logger.Error().Err(err).Msg("Failed to get user")
			return "", time.Time{}, core.User{}, domain.NewAppError(err, "Login failed", 500)
		}

		// Cache user data
		if s.cache != nil && s.cache.IsAvailable() {
			cached := cachedUserData{User: user, Hash: passwordHash}
			if err := s.cache.Set(ctx, cacheKey, cached, 5*time.Minute); err != nil {
				s.logger.Debug().Err(err).Msg("Failed to cache user data")
			}
		}
	}

	// Check user status
	if user.Status == "inactive" {
		return "", time.Time{}, core.User{}, domain.NewAppError(domain.ErrUserInactive, "Account is inactive", 403)
	}
	if user.Status == "suspended" {
		return "", time.Time{}, core.User{}, domain.NewAppError(domain.ErrUserSuspended, "Account is suspended", 403)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		s.logger.Warn().
			Str("identifier", maskIdentifier(identifier)).
			Str("user_id", user.ID.String()).
			Msg("Invalid password attempt")

		s.recordFailedLogin(identifier)

		// Invalidate cache on failed password
		if s.cache != nil {
			s.cache.Delete(ctx, cacheKey)
		}

		return "", time.Time{}, core.User{}, domain.NewAppError(domain.ErrInvalidCredentials, "Invalid credentials", 401)
	}

	// Check if user is verified
	if !user.IsVerified && user.Email != nil && *user.Email != "" {
		return "", time.Time{}, core.User{}, domain.NewAppError(domain.ErrUserNotVerified, "Please verify your email first", 403)
	}

	// Reset login attempts
	s.resetLoginAttempts(identifier)

	// Generate JWT token
	expiresAt := time.Now().Add(s.jwtExpiry)
	token, err := s.generateToken(user, expiresAt)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to generate token")
		return "", time.Time{}, core.User{}, domain.NewAppError(err, "Token generation failed", 500)
	}

	deviceType := "web"
	if _, err := s.sessionSvc.CreateSession(ctx, user.ID, token, expiresAt, ipAddress, userAgent, deviceType); err != nil {
		s.logger.Error().Err(err).Msg("Failed to create session record")
		return "", time.Time{}, core.User{}, domain.NewAppError(err, "Session creation failed", 500)
	}

	// Update last login asynchronously
	go func(userID uuid.UUID) {
		updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.authRepo.UpdateLastLogin(updateCtx, userID); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to update last login")
		}
	}(user.ID)

	// Send login alert asynchronously
	if user.Email != nil && *user.Email != "" && s.emailService != nil && s.emailService.IsAvailable() {
		go func(email string) {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := s.emailService.SendLoginAlertEmail(emailCtx, email, "User", "Unknown", "Unknown"); err != nil {
				s.logger.Debug().Err(err).Msg("Failed to send login alert email")
			}
		}(*user.Email)
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Str("role", user.Role).
		Bool("cache_hit", cacheHit).
		Dur("duration_ms", time.Since(start)).
		Msg("User logged in successfully")

	return token, expiresAt, user, nil
}

// ValidateToken validates JWT token
func (s *authService) ValidateToken(ctx context.Context, tokenString string) (*service.TokenClaims, error) {
	// Try cache first
	cacheKey := fmt.Sprintf("token:valid:%s", tokenString)

	if s.cache != nil && s.cache.IsAvailable() {
		var claims service.TokenClaims
		if err := s.cache.Get(ctx, cacheKey, &claims); err == nil {
			s.logger.Debug().Msg("Cache hit for token validation")
			return &claims, nil
		}
	}

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

	// Extract user ID
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
	session, err := s.sessionSvc.GetSession(ctx, tokenString)
	if err != nil || session.ExpiresAt.Before(time.Now()) {
		return nil, domain.NewAppError(domain.ErrInvalidSession, "Session expired or invalid", 401)
	}

	role, _ := claims["role"].(string)
	email, _ := claims["email"].(string)

	tokenClaims := &service.TokenClaims{
		UserID: userID,
		Role:   role,
		Email:  email,
	}

	// Cache token validation
	if s.cache != nil && s.cache.IsAvailable() {
		s.cache.Set(ctx, cacheKey, tokenClaims, 1*time.Minute)
	}

	return tokenClaims, nil
}

// RefreshToken refreshes JWT token
func (s *authService) RefreshToken(ctx context.Context, tokenString string, ipAddress, userAgent string) (string, time.Time, core.User, error) {
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil && !errors.Is(err, domain.ErrExpiredToken) {
		return "", time.Time{}, core.User{}, err
	}

	user, err := s.userRepo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return "", time.Time{}, core.User{}, domain.NewAppError(err, "User not found", 404)
	}

	expiresAt := time.Now().Add(s.jwtExpiry)
	newToken, err := s.generateToken(user, expiresAt)
	if err != nil {
		return "", time.Time{}, core.User{}, domain.NewAppError(err, "Failed to generate new token", 500)
	}

	// Delete old session using session service
	if err := s.sessionSvc.RevokeSession(ctx, tokenString, user.ID); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete old session")
	}

	// Create new session using session service
	deviceType := "web"
	if _, err := s.sessionSvc.CreateSession(ctx, user.ID, newToken, expiresAt, ipAddress, userAgent, deviceType); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to create new session record")
	}

	// Invalidate old token cache
	if s.cache != nil {
		s.cache.Delete(ctx, fmt.Sprintf("token:valid:%s", tokenString))
	}

	return newToken, expiresAt, user, nil
}

// Logout handles user logout
func (s *authService) Logout(ctx context.Context, tokenString string, userID uuid.UUID) error {
	if err := s.sessionSvc.RevokeSession(ctx, tokenString, userID); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete session")
		return domain.NewAppError(err, "Logout failed", 500)
	}

	// Invalidate token cache
	if s.cache != nil {
		s.cache.Delete(ctx, fmt.Sprintf("token:valid:%s", tokenString))
	}

	s.logger.Info().Str("user_id", userID.String()).Msg("User logged out successfully")
	return nil
}

// VerifyEmail verifies user email with token
func (s *authService) VerifyEmail(ctx context.Context, token string) error {
	// Get user by verification token
	user, _, err := s.authRepo.GetUserByVerificationToken(ctx, token)
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
	if err := s.authRepo.VerifyUser(ctx, user.ID); err != nil {
		s.logger.Error().Err(err).Msg("Failed to verify user")
		return domain.NewAppError(err, "Verification failed", 500)
	}

	// Update user status to active
	if err := s.userRepo.UpdateUserStatus(ctx, user.ID, "active"); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to update user status")
	}

	// Invalidate login cache
	if s.cache != nil && user.Email != nil {
		s.cache.Delete(ctx, fmt.Sprintf("user:login:%s", *user.Email))
	}

	// Send welcome email asynchronously
	if user.Email != nil && s.emailService != nil && s.emailService.IsAvailable() {
		go func(email string) {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			username := "User"
			if email != "" {
				parts := strings.Split(email, "@")
				if len(parts) > 0 && parts[0] != "" {
					username = parts[0]
				}
			}

			if err := s.emailService.SendWelcomeEmail(emailCtx, email, username); err != nil {
				s.logger.Error().Err(err).Msg("Failed to send welcome email")
			}
		}(*user.Email)
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
	var user core.User
	var err error

	if strings.Contains(identifier, "@") {
		user, _, err = s.authRepo.GetUserByEmail(ctx, strings.ToLower(identifier))
	} else {
		user, err = s.authRepo.GetUserByPhone(ctx, identifier)
	}

	if err != nil {
		// Don't reveal if user exists for security
		s.logger.Info().Str("identifier", maskIdentifier(identifier)).Msg("Password reset requested")
		return nil
	}

	// Generate reset token
	resetToken := s.generateSecureToken()
	tokenExpires := time.Now().Add(1 * time.Hour)

	// Store reset token
	if err := s.authRepo.SetPasswordResetToken(ctx, user.ID, resetToken, tokenExpires); err != nil {
		s.logger.Error().Err(err).Msg("Failed to set password reset token")
		return domain.NewAppError(err, "Failed to initiate password reset", 500)
	}

	// Send reset email asynchronously
	if user.Email != nil && s.emailService != nil && s.emailService.IsAvailable() {
		go func(email, token string) {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := s.emailService.SendPasswordResetEmail(emailCtx, email, token); err != nil {
				s.logger.Error().Err(err).Msg("Failed to send password reset email")
			}
		}(*user.Email, resetToken)
	}

	s.logger.Info().Str("user_id", user.ID.String()).Msg("Password reset requested")
	return nil
}

// ResetPassword resets password with token
func (s *authService) ResetPassword(ctx context.Context, token, newPassword string) error {
	user, _, err := s.authRepo.GetUserByPasswordResetToken(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.NewAppError(domain.ErrInvalidToken, "Invalid or expired reset token", 400)
		}
		s.logger.Error().Err(err).Msg("Failed to get user by reset token")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	// Hash new password
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.bcryptCost)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hash new password")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	// Update password
	if err := s.authRepo.UpdateUserPassword(ctx, user.ID, string(hash)); err != nil {
		s.logger.Error().Err(err).Msg("Failed to update password")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	// Delete all user sessions
	if err := s.sessionSvc.RevokeAllSessions(ctx, user.ID); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete user sessions")
	}

	// Send verification email
	if s.emailService != nil && s.emailService.IsAvailable() {
		if err := s.emailService.SendPasswordChangedEmail(ctx, *user.Email, *user.Email); err != nil {
			s.logger.Error().Err(err).Msg("Failed to send password changed email")
			return domain.NewAppError(err, "Failed to send password changed email", 500)
		}
	} else {
		return domain.NewAppError(nil, "Email service unavailable", 503)
	}

	// Invalidate all caches for this user
	if s.cache != nil {
		if user.Email != nil {
			s.cache.Delete(ctx, fmt.Sprintf("user:login:%s", *user.Email))
		}
		if user.Phone != nil {
			s.cache.Delete(ctx, fmt.Sprintf("user:login:%s", *user.Phone))
		}
	}

	// Reset login attempts
	if user.Email != nil {
		s.resetLoginAttempts(*user.Email)
	}
	if user.Phone != nil {
		s.resetLoginAttempts(*user.Phone)
	}

	s.logger.Info().Str("user_id", user.ID.String()).Msg("Password reset successfully")
	return nil
}

// ResendVerificationEmail resends verification email
func (s *authService) ResendVerificationEmail(ctx context.Context, email string) error {
	// Get user by email
	user, _, err := s.authRepo.GetUserByEmail(ctx, strings.ToLower(email))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// Don't reveal if user exists for security
			s.logger.Info().Str("email", maskIdentifier(email)).Msg("Verification resend requested")
			return nil
		}
		s.logger.Error().Err(err).Msg("Failed to get user by email")
		return domain.NewAppError(err, "Failed to resend verification", 500)
	}

	// Check if already verified
	if user.IsVerified {
		return domain.NewAppError(domain.ErrValidation, "Email already verified", 400)
	}

	// Generate new verification token
	verificationToken := s.generateSecureToken()
	tokenExpires := time.Now().Add(24 * time.Hour)

	// Store verification token
	if err := s.authRepo.SetVerificationToken(ctx, user.ID, verificationToken, tokenExpires); err != nil {
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

// UpdateUserOnboardingStep updates the user's onboarding progress
func (s *authService) UpdateUserOnboardingStep(ctx context.Context, userID uuid.UUID, step string) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Str("step", step).
			Msg("UpdateUserOnboardingStep completed")
	}()

	// Validate step
	validSteps := map[string]bool{
		core.OnboardingStepAccountCreated:   true,
		core.OnboardingStepClinicRegistered: true,
		core.OnboardingStepClinicApproved:   true,
		core.OnboardingStepCompleted:        true,
	}

	if !validSteps[step] {
		return domain.NewAppError(domain.ErrValidation, "Invalid onboarding step", 400)
	}

	// Update onboarding step in repository
	if err := s.authRepo.UpdateUserOnboardingStep(ctx, userID, step); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.NewAppError(domain.ErrUserNotFound, "User not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to update onboarding step")
		return domain.NewAppError(err, "Failed to update onboarding step", 500)
	}

	// Invalidate user cache
	if s.cache != nil && s.cache.IsAvailable() {
		user, err := s.userRepo.GetUserByID(ctx, userID)
		if err == nil {
			if user.Email != nil {
				s.cache.Delete(ctx, fmt.Sprintf("user:login:%s", *user.Email))
			}
			if user.Phone != nil {
				s.cache.Delete(ctx, fmt.Sprintf("user:login:%s", *user.Phone))
			}
		}
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Str("onboarding_step", step).
		Msg("User onboarding step updated successfully")

	return nil
}

// UpdateUserPrimaryClinic links a user to their primary clinic
func (s *authService) UpdateUserPrimaryClinic(ctx context.Context, userID, clinicID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Str("clinic_id", clinicID.String()).
			Msg("UpdateUserPrimaryClinic completed")
	}()

	// Validate IDs
	if userID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}
	if clinicID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}

	// Update primary clinic in repository
	if err := s.authRepo.UpdateUserPrimaryClinic(ctx, userID, clinicID); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.NewAppError(domain.ErrUserNotFound, "User not found", 404)
		}
		s.logger.Error().Err(err).
			Str("user_id", userID.String()).
			Str("clinic_id", clinicID.String()).
			Msg("Failed to update user primary clinic")
		return domain.NewAppError(err, "Failed to update primary clinic", 500)
	}

	// Invalidate user cache
	if s.cache != nil && s.cache.IsAvailable() {
		user, err := s.userRepo.GetUserByID(ctx, userID)
		if err == nil {
			if user.Email != nil {
				s.cache.Delete(ctx, fmt.Sprintf("user:login:%s", *user.Email))
			}
			if user.Phone != nil {
				s.cache.Delete(ctx, fmt.Sprintf("user:login:%s", *user.Phone))
			}
		}
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Str("clinic_id", clinicID.String()).
		Msg("User primary clinic updated successfully")

	return nil
}

// CompleteUserOnboarding marks the user's onboarding as complete
func (s *authService) CompleteUserOnboarding(ctx context.Context, userID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("CompleteUserOnboarding completed")
	}()

	// Validate user ID
	if userID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	// Complete onboarding in repository
	if err := s.authRepo.CompleteUserOnboarding(ctx, userID); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.NewAppError(domain.ErrUserNotFound, "User not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to complete user onboarding")
		return domain.NewAppError(err, "Failed to complete onboarding", 500)
	}

	// Invalidate user cache
	if s.cache != nil && s.cache.IsAvailable() {
		user, err := s.userRepo.GetUserByID(ctx, userID)
		if err == nil {
			if user.Email != nil {
				s.cache.Delete(ctx, fmt.Sprintf("user:login:%s", *user.Email))
			}
			if user.Phone != nil {
				s.cache.Delete(ctx, fmt.Sprintf("user:login:%s", *user.Phone))
			}
		}
	}

	s.logger.Info().
		Str("user_id", userID.String()).
		Msg("User onboarding completed successfully")

	return nil
}

// GetProviderWithClinic retrieves provider user with clinic information
func (s *authService) GetProviderWithClinic(ctx context.Context, userID uuid.UUID) (*core.ProviderWithClinic, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetProviderWithClinic completed")
	}()

	// Validate user ID
	if userID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("provider:with_clinic:%s", userID.String())
	if s.cache != nil && s.cache.IsAvailable() {
		var cached core.ProviderWithClinic
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("user_id", userID.String()).Msg("Provider retrieved from cache")
			return &cached, nil
		}
	}

	// Fetch from repository
	provider, err := s.authRepo.GetProviderWithClinic(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.NewAppError(domain.ErrUserNotFound, "Provider not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get provider with clinic")
		return nil, domain.NewAppError(err, "Failed to get provider information", 500)
	}

	// Cache the result
	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, *provider, 10*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache provider information")
		}
	}

	s.logger.Debug().
		Str("user_id", userID.String()).
		Str("clinic_id", uuidPtrToString(provider.ClinicID)).
		Msg("Provider with clinic retrieved")

	return provider, nil
}

// GetUserClinics retrieves all clinics associated with a user
func (s *authService) GetUserClinics(ctx context.Context, userID uuid.UUID) ([]core.UserClinic, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetUserClinics completed")
	}()

	// Validate user ID
	if userID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("user:clinics:%s", userID.String())
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []core.UserClinic
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("user_id", userID.String()).Msg("User clinics retrieved from cache")
			return cached, nil
		}
	}

	// Fetch from repository
	clinics, err := s.authRepo.GetUserClinics(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user clinics")
		return nil, domain.NewAppError(err, "Failed to get user clinics", 500)
	}

	// Cache the result
	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, clinics, 5*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache user clinics")
		}
	}

	s.logger.Debug().
		Str("user_id", userID.String()).
		Int("clinic_count", len(clinics)).
		Msg("User clinics retrieved")

	return clinics, nil
}

// Helper methods for auth service
func (s *authService) handlePostRegistration(user core.User, email, phone, role string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create default consent record
	consent := core.PrivacyConsent{
		UserID:                     user.ID,
		HealthDataConsent:          true,
		HealthDataConsentDate:      &user.CreatedAt,
		HealthDataConsentVersion:   stringPtr("1.0"),
		ResearchConsent:            false,
		EmergencyAccessConsent:     true,
		EmergencyAccessConsentDate: &user.CreatedAt,
		SMSCommunicationConsent:    s.smsEnabled && phone != "",
		EmailCommunicationConsent:  email != "",
		ConsentWithdrawn:           false,
		CreatedAt:                  user.CreatedAt,
		UpdatedAt:                  user.CreatedAt,
	}

	if _, err := s.consentRepo.CreatePrivacyConsent(ctx, consent); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to create consent record")
	}

	// For patients, create empty patient profile
	if role == "patient" {
		patientProfile := patients.PatientProfile{
			ID:                           uuid.New(),
			UserID:                       user.ID,
			Country:                      "South Africa",
			LanguagePreferences:          []string{"en", "af", "zu"},
			PreferredCommunicationMethod: "sms",
			Timezone:                     "Africa/Johannesburg",
			AcceptsMarketingEmails:       false,
			CreatedAt:                    user.CreatedAt,
			UpdatedAt:                    user.CreatedAt,
		}

		if _, err := s.patientRepo.CreatePatientProfile(ctx, patientProfile); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to create patient profile")
		}
	}

	// Send verification email if email provided
	if email != "" && s.emailService != nil && s.emailService.IsAvailable() {
		verificationToken := s.generateSecureToken()
		tokenExpires := time.Now().Add(24 * time.Hour)

		if err := s.authRepo.SetVerificationToken(ctx, user.ID, verificationToken, tokenExpires); err != nil {
			s.logger.Error().Err(err).Msg("Failed to set verification token")
			return
		}

		if err := s.emailService.SendVerificationEmail(ctx, email, verificationToken); err != nil {
			s.logger.Error().Err(err).Msg("Failed to send verification email")
		}
	}
}

func (s *authService) generateToken(user core.User, expiresAt time.Time) (string, error) {
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

func (s *authService) generateSecureToken() string {
	b := s.tokenPool.Get().([]byte)
	defer s.tokenPool.Put(b)

	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

// Rate limiting helpers
func (s *authService) isLoginLocked(identifier string) bool {
	s.loginAttemptsMu.RLock()
	defer s.loginAttemptsMu.RUnlock()

	attempt, exists := s.loginAttempts[identifier]
	if !exists {
		return false
	}

	if attempt.lockedUntil != nil && time.Now().Before(*attempt.lockedUntil) {
		return true
	}

	return false
}

func (s *authService) recordFailedLogin(identifier string) {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()

	attempt, exists := s.loginAttempts[identifier]
	if !exists {
		attempt = loginAttempt{}
	}

	attempt.attempts++
	attempt.lastFailed = time.Now()

	if attempt.attempts >= s.loginMaxAttempts {
		lockedUntil := time.Now().Add(s.loginLockout)
		attempt.lockedUntil = &lockedUntil
		s.logger.Warn().
			Str("identifier", maskIdentifier(identifier)).
			Int("attempts", attempt.attempts).
			Time("locked_until", lockedUntil).
			Msg("Login locked due to too many failed attempts")
	}

	s.loginAttempts[identifier] = attempt
}

func (s *authService) resetLoginAttempts(identifier string) {
	s.loginAttemptsMu.Lock()
	defer s.loginAttemptsMu.Unlock()
	delete(s.loginAttempts, identifier)
}

func (s *authService) cleanupLoginAttempts() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		s.loginAttemptsMu.Lock()
		now := time.Now()
		for identifier, attempt := range s.loginAttempts {
			// Remove attempts older than 30 minutes
			if now.Sub(attempt.lastFailed) > 30*time.Minute {
				delete(s.loginAttempts, identifier)
			}
			// Remove expired locks
			if attempt.lockedUntil != nil && now.After(*attempt.lockedUntil) {
				delete(s.loginAttempts, identifier)
			}
		}
		s.loginAttemptsMu.Unlock()
	}
}

// Helper functions
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// Helper function to convert UUID pointer to string
func uuidPtrToString(id *uuid.UUID) string {
	if id == nil {
		return "nil"
	}
	return id.String()
}

func maskIdentifier(identifier string) string {
	if len(identifier) <= 3 {
		return "***"
	}
	if strings.Contains(identifier, "@") {
		parts := strings.Split(identifier, "@")
		if len(parts) != 2 {
			return "***"
		}
		local := parts[0]
		if len(local) <= 3 {
			return "***@" + parts[1]
		}
		return local[:3] + "***@" + parts[1]
	}
	// Phone: show last 4 digits only
	if len(identifier) <= 4 {
		return "***"
	}
	return "***" + identifier[len(identifier)-4:]
}

func maskIP(ip string) string {
	if ip == "" {
		return "unknown"
	}
	// Simple IP masking: show only first octet for IPv4
	parts := strings.Split(ip, ".")
	if len(parts) >= 1 {
		return parts[0] + ".***.***.***"
	}
	return "***"
}
