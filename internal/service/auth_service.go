// Package service implements business logic
package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	bcryptCost   int // Configurable bcrypt cost

	// Token generation pool for reduced GC pressure
	tokenPool sync.Pool

	// Rate limiting for login attempts
	loginAttempts   map[string]loginAttempt
	loginAttemptsMu sync.RWMutex
}

type loginAttempt struct {
	attempts    int
	lastFailed  time.Time
	lockedUntil *time.Time
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
	bcryptCost int,
) AuthService {
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

	// Log bcrypt cost for awareness
	if bcryptCost < bcrypt.DefaultCost {
		logger.Warn().
			Int("cost", bcryptCost).
			Msg("Using lower bcrypt cost - suitable for development only")
	}

	service := &authService{
		userRepo:      userRepo,
		patientRepo:   patientRepo,
		sessionRepo:   sessionRepo,
		consentRepo:   consentRepo,
		cache:         cache,
		broker:        broker,
		emailService:  emailService,
		logger:        logger,
		jwtSecret:     jwtSecret,
		jwtExpiry:     jwtExpiry,
		smsEnabled:    smsEnabled,
		bcryptCost:    bcryptCost,
		loginAttempts: make(map[string]loginAttempt),
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

// Register handles user registration with email or phone
func (s *authService) Register(ctx context.Context, email, phone, password, role string) (domain.User, error) {
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

	// Hash password with configured cost
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hash password")
		return domain.User{}, domain.NewAppError(err, "Password hashing failed", 500)
	}

	// Create user domain object
	now := time.Now()
	user := domain.User{
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
		CreatedAt:            now,
		UpdatedAt:            now,
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

	// Handle post-registration tasks asynchronously
	go s.handlePostRegistration(created, email, phone, role)

	s.logger.Info().
		Str("user_id", created.ID.String()).
		Str("role", role).
		Dur("duration_ms", time.Since(start)).
		Msg("User registered successfully")

	return created, nil
}

// handlePostRegistration handles all async post-registration tasks
func (s *authService) handlePostRegistration(user domain.User, email, phone, role string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create default consent record
	consent := domain.PrivacyConsent{
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

	if _, err := s.consentRepo.CreateConsent(ctx, consent); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to create consent record")
	}

	// For patients, create empty patient profile
	if role == "patient" {
		patientProfile := domain.PatientProfile{
			ID:                           uuid.Generate(),
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

		if err := s.userRepo.SetVerificationToken(ctx, user.ID, verificationToken, tokenExpires); err != nil {
			s.logger.Error().Err(err).Msg("Failed to set verification token")
			return
		}

		if err := s.emailService.SendVerificationEmail(ctx, email, verificationToken); err != nil {
			s.logger.Error().Err(err).Msg("Failed to send verification email")
		}
	}

	// Publish registration event
	if s.broker != nil && s.broker.IsAvailable() {
		event := map[string]interface{}{
			"user_id":   user.ID,
			"email":     email,
			"phone":     phone,
			"role":      role,
			"timestamp": time.Now().UTC(),
		}
		if err := s.broker.PublishJSON("user.registered", event); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to publish registration event")
		}
	}
}

// Login handles user login with email or phone
func (s *authService) Login(ctx context.Context, identifier, password string) (string, time.Time, domain.User, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("identifier", maskIdentifier(identifier)).
			Msg("Login attempt completed")
	}()

	// Validate input
	if identifier == "" || password == "" {
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrValidation, "Identifier and password are required", 400)
	}

	// Check rate limiting
	if s.isLoginLocked(identifier) {
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrRateLimited, "Too many login attempts. Please try again later", 429)
	}

	// Try cache first for user lookup
	cacheKey := fmt.Sprintf("user:login:%s", identifier)

	type cachedUserData struct {
		User domain.User
		Hash string
	}

	var user domain.User
	var passwordHash string
	var err error
	cacheHit := false

	// Check cache if available
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
			user, passwordHash, err = s.userRepo.GetUserByEmail(ctx, strings.ToLower(identifier))
		} else {
			user, passwordHash, err = s.userRepo.GetUserByPhoneWithHash(ctx, identifier)
		}

		if err != nil {
			if errors.Is(err, domain.ErrUserNotFound) {
				s.logger.Warn().Str("identifier", maskIdentifier(identifier)).Msg("User not found")
				s.recordFailedLogin(identifier)
				return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrInvalidCredentials, "Invalid credentials", 401)
			}
			s.logger.Error().Err(err).Msg("Failed to get user")
			return "", time.Time{}, domain.User{}, domain.NewAppError(err, "Login failed", 500)
		}

		// Cache user data for subsequent logins (short TTL)
		if s.cache != nil && s.cache.IsAvailable() {
			cached := cachedUserData{User: user, Hash: passwordHash}
			if err := s.cache.Set(ctx, cacheKey, cached, 5*time.Minute); err != nil {
				s.logger.Debug().Err(err).Msg("Failed to cache user data")
			}
		}
	}

	// Check user status BEFORE expensive password verification
	if user.Status == "inactive" {
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrUserInactive, "Account is inactive", 403)
	}
	if user.Status == "suspended" {
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrUserSuspended, "Account is suspended", 403)
	}

	// Verify password (expensive operation)
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

		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrInvalidCredentials, "Invalid credentials", 401)
	}

	// Check if user is verified (for email users)
	if !user.IsVerified && user.Email != nil && *user.Email != "" {
		return "", time.Time{}, domain.User{}, domain.NewAppError(domain.ErrUserNotVerified, "Please verify your email first", 403)
	}

	// Reset login attempts on successful login
	s.resetLoginAttempts(identifier)

	// Generate JWT token
	expiresAt := time.Now().Add(s.jwtExpiry)
	token, err := s.generateToken(user, expiresAt)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to generate token")
		return "", time.Time{}, domain.User{}, domain.NewAppError(err, "Token generation failed", 500)
	}

	// CRITICAL: Create session SYNCHRONOUSLY before returning
	session := domain.UserSession{
		ID:           uuid.Generate(),
		UserID:       user.ID,
		SessionToken: token,
		DeviceType:   stringPtr("web"),
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}

	if _, err := s.sessionRepo.CreateSession(ctx, session); err != nil {
		s.logger.Error().Err(err).Msg("Failed to create session record")
		return "", time.Time{}, domain.User{}, domain.NewAppError(err, "Session creation failed", 500)
	}

	// OPTIMIZATION: Update last login asynchronously (don't block response)
	go func(userID uuid.UUID) {
		updateCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.userRepo.UpdateLastLogin(updateCtx, userID); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to update last login")
		}
	}(user.ID)

	// OPTIMIZATION: Send login alert asynchronously
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

	// Lock for 5 minutes after 5 failed attempts
	if attempt.attempts >= 5 {
		lockedUntil := time.Now().Add(5 * time.Minute)
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

// ValidateToken validates JWT token
func (s *authService) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	// Try cache first for token validation
	cacheKey := fmt.Sprintf("token:valid:%s", tokenString)

	if s.cache != nil && s.cache.IsAvailable() {
		var claims TokenClaims
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

	tokenClaims := &TokenClaims{
		UserID: userID,
		Role:   role,
		Email:  email,
	}

	// Cache token validation result (short TTL)
	if s.cache != nil && s.cache.IsAvailable() {
		s.cache.Set(ctx, cacheKey, tokenClaims, 1*time.Minute)
	}

	return tokenClaims, nil
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

	// Delete old session
	if err := s.sessionRepo.DeleteSession(ctx, tokenString); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete old session")
	}

	// Create new session
	newSession := domain.UserSession{
		ID:           uuid.Generate(),
		UserID:       user.ID,
		SessionToken: newToken,
		DeviceType:   stringPtr("web"),
		ExpiresAt:    expiresAt,
		CreatedAt:    time.Now(),
	}

	if _, err := s.sessionRepo.CreateSession(ctx, newSession); err != nil {
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
	if err := s.sessionRepo.DeleteSession(ctx, tokenString); err != nil {
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

// generateSecureToken generates a secure token using crypto/rand
func (s *authService) generateSecureToken() string {
	b := s.tokenPool.Get().([]byte)
	defer s.tokenPool.Put(b)

	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
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

	// Invalidate login cache if exists
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

	// Publish email verified event asynchronously
	if s.broker != nil && s.broker.IsAvailable() {
		go func() {
			event := map[string]interface{}{
				"user_id":   user.ID.String(),
				"email":     user.Email,
				"role":      user.Role,
				"timestamp": time.Now().UTC(),
			}
			if err := s.broker.PublishJSON("user.email_verified", event); err != nil {
				s.logger.Warn().Err(err).Msg("Failed to publish email verified event")
			}
		}()
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
		user, _, err = s.userRepo.GetUserByEmail(ctx, strings.ToLower(identifier))
	} else {
		user, err = s.userRepo.GetUserByPhone(ctx, identifier)
	}

	if err != nil {
		// Don't reveal if user exists for security
		s.logger.Info().Str("identifier", maskIdentifier(identifier)).Msg("Password reset requested")
		return nil // Return success even if user doesn't exist
	}

	// Generate reset token
	resetToken := s.generateSecureToken()
	tokenExpires := time.Now().Add(1 * time.Hour)

	// Store reset token
	if err := s.userRepo.SetPasswordResetToken(ctx, user.ID, resetToken, tokenExpires); err != nil {
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
	user, _, err := s.userRepo.GetUserByPasswordResetToken(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.NewAppError(domain.ErrInvalidToken, "Invalid or expired reset token", 400)
		}
		s.logger.Error().Err(err).Msg("Failed to get user by reset token")
		return domain.NewAppError(err, "Password reset failed", 500)
	}

	// Hash new password with configured cost
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), s.bcryptCost)
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
	user, _, err := s.userRepo.GetUserByEmail(ctx, strings.ToLower(email))
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// Don't reveal if user exists for security
			s.logger.Info().Str("email", maskIdentifier(email)).Msg("Verification resend requested")
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
	verificationToken := s.generateSecureToken()
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

// GenerateOTP generates and sends OTP to user
func (s *authService) GenerateOTP(ctx context.Context, identifier string) error {
	// Find user by email or phone
	var user domain.User
	var err error
	channel := "email"

	if strings.Contains(identifier, "@") {
		user, _, err = s.userRepo.GetUserByEmail(ctx, strings.ToLower(identifier))
	} else {
		user, err = s.userRepo.GetUserByPhone(ctx, identifier)
		channel = "sms"
	}

	if err != nil {
		// Don't reveal if user exists for security
		s.logger.Info().Str("identifier", maskIdentifier(identifier)).Msg("OTP requested for non-existent user")
		return nil // Return success even if user doesn't exist
	}

	// Check OTP attempt count (rate limiting)
	attempts, err := s.userRepo.GetOTPAttemptCount(ctx, user.ID, "password_reset")
	if err != nil {
		s.logger.Warn().Err(err).Msg("Failed to get OTP attempt count")
	}
	if attempts >= 5 {
		return domain.NewAppError(domain.ErrOTPRateLimited, "Too many OTP requests. Please try again later.", 429)
	}

	// Check if user can receive OTP
	if channel == "email" && (user.Email == nil || !user.EmailCommunicationConsent) {
		s.logger.Warn().Str("user_id", user.ID.String()).Msg("User cannot receive email OTP")
		return nil
	}
	if channel == "sms" && (user.Phone == nil || !user.SMSConsentGiven) {
		s.logger.Warn().Str("user_id", user.ID.String()).Msg("User cannot receive SMS OTP")
		return nil
	}

	// Generate 6-digit OTP
	otp := s.generateNumericOTP(6)
	expiresAt := time.Now().Add(10 * time.Minute)

	// Delete any existing unused OTPs for this user
	if err := s.userRepo.DeleteUserOTPs(ctx, user.ID, "password_reset"); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to delete old OTPs")
	}

	// Create OTP record
	otpRecord := domain.OTPVerification{
		ID:        uuid.Generate(),
		UserID:    user.ID,
		OTP:       otp,
		Type:      "password_reset",
		Channel:   channel,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}

	// Save OTP to repository
	if err := s.userRepo.SaveOTP(ctx, otpRecord); err != nil {
		s.logger.Error().Err(err).Msg("Failed to save OTP")
		return domain.NewAppError(err, "Failed to generate OTP", 500)
	}

	// Send OTP via email or SMS
	if channel == "email" && user.Email != nil && s.emailService != nil && s.emailService.IsAvailable() {
		go s.sendOTPEmail(context.Background(), *user.Email, otp, user.ID.String())
	} else if channel == "sms" && user.Phone != nil && s.smsEnabled {
		// TODO: Implement SMS sending for OTP
		s.logger.Info().
			Str("phone", maskIdentifier(*user.Phone)).
			Str("otp", otp).
			Msg("OTP generated for SMS (SMS service not implemented)")
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Str("channel", channel).
		Msg("OTP generated and sent")

	return nil
}

// VerifyOTP verifies OTP and returns reset token
func (s *authService) VerifyOTP(ctx context.Context, identifier, otp string) (string, error) {
	// Find user
	var user domain.User
	var err error

	if strings.Contains(identifier, "@") {
		user, _, err = s.userRepo.GetUserByEmail(ctx, strings.ToLower(identifier))
	} else {
		user, err = s.userRepo.GetUserByPhone(ctx, identifier)
	}

	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", domain.NewAppError(domain.ErrInvalidOTP, "Invalid OTP code", 400)
		}
		return "", domain.NewAppError(err, "OTP verification failed", 500)
	}

	// Get OTP record
	otpRecord, err := s.userRepo.GetOTP(ctx, user.ID, otp, "password_reset")
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			s.logger.Warn().
				Str("user_id", user.ID.String()).
				Str("identifier", maskIdentifier(identifier)).
				Msg("Invalid OTP attempt")
			return "", domain.NewAppError(domain.ErrInvalidOTP, "Invalid OTP code", 400)
		}
		s.logger.Error().Err(err).Msg("Failed to get OTP")
		return "", domain.NewAppError(err, "OTP verification failed", 500)
	}

	// Check if OTP is expired (redundant but explicit)
	if time.Now().After(otpRecord.ExpiresAt) {
		return "", domain.NewAppError(domain.ErrOTPExpired, "OTP has expired", 400)
	}

	// Check if OTP already used
	if otpRecord.UsedAt != nil {
		return "", domain.NewAppError(domain.ErrOTPAlreadyUsed, "OTP has already been used", 400)
	}

	// Mark OTP as used
	now := time.Now()
	if err := s.userRepo.MarkOTPUsed(ctx, otpRecord.ID, &now); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to mark OTP as used")
	}

	// Generate password reset token (for backward compatibility with existing flow)
	resetToken := s.generateSecureToken()
	tokenExpires := time.Now().Add(1 * time.Hour)

	// Store reset token
	if err := s.userRepo.SetPasswordResetToken(ctx, user.ID, resetToken, tokenExpires); err != nil {
		s.logger.Error().Err(err).Msg("Failed to set password reset token")
		return "", domain.NewAppError(err, "Failed to process reset", 500)
	}

	s.logger.Info().
		Str("user_id", user.ID.String()).
		Msg("OTP verified successfully")

	return resetToken, nil
}

// RequestPasswordResetWithOTP combines OTP generation and sending
func (s *authService) RequestPasswordResetWithOTP(ctx context.Context, identifier string) error {
	return s.GenerateOTP(ctx, identifier)
}

// ResetPasswordWithOTP combines OTP verification and password reset in one call
func (s *authService) ResetPasswordWithOTP(ctx context.Context, identifier, otp, newPassword string) error {
	// Verify OTP first
	resetToken, err := s.VerifyOTP(ctx, identifier, otp)
	if err != nil {
		return err
	}

	// Now reset password using the token
	return s.ResetPassword(ctx, resetToken, newPassword)
}

// generateNumericOTP generates a secure numeric OTP
func (s *authService) generateNumericOTP(length int) string {
	const digits = "0123456789"
	b := make([]byte, length)
	rand.Read(b)

	for i := range b {
		b[i] = digits[int(b[i])%len(digits)]
	}

	return string(b)
}

// Helper functions
func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func maskIdentifier(identifier string) string {
	if len(identifier) <= 3 {
		return "***"
	}
	if strings.Contains(identifier, "@") {
		// Email: show first 3 chars, then ***, then domain
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

// generateNumericOTP generates a 6-digit OTP
func (s *authService) generateNumericOTP(length int) string {
	const digits = "0123456789"
	b := make([]byte, length)
	rand.Read(b) // fill with random bytes
	for i := range b {
		b[i] = digits[int(b[i])%len(digits)]
	}
	return string(b)
}

// sendOTPEmail sends OTP via email (helper function)
func (s *authService) sendOTPEmail(ctx context.Context, email, otp, userID string) {
	emailCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	subject := "Your Password Reset Code"
	body := fmt.Sprintf(`
Hello,

Your password reset verification code is: %s

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email or contact support immediately.

Best regards,
Healthcare Access Connector Team
    `, otp)

	msg := &email.Message{
		To:      []string{email},
		Subject: subject,
		Body:    body,
	}

	if err := s.emailService.SendEmail(emailCtx, msg); err != nil {
		s.logger.Error().
			Err(err).
			Str("user_id", userID).
			Msg("Failed to send OTP email")
	}
}
