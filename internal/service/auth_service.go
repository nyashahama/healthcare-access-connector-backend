// Package service implements business logic
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/email"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/messaging"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
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

func (s *authService) Register(ctx context.Context, username, email, password, role string) (domain.User, error) {
	// Validate password
	if password == "" {
		return domain.User{}, domain.ErrValidation
	}

	// Default role
	if role == "" {
		role = "user"
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hash password")
		return domain.User{}, fmt.Errorf("password hashing failed: %w", err)
	}

	// Create user
	user := domain.User{
		Username: username,
		Email:    email,
		Role:     role,
	}

	created, err := s.repo.CreateUser(ctx, user, string(hash))
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateEmail) {
			return domain.User{}, domain.ErrDuplicateEmail
		}
		s.logger.Error().Err(err).Msg("Failed to create user")
		return domain.User{}, fmt.Errorf("user creation failed: %w", err)
	}

	// Send welcome email asynchronously
	if s.emailService != nil && s.emailService.IsAvailable() {
		go func() {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := s.emailService.SendWelcomeEmail(emailCtx, created.Email, created.Username); err != nil {
				s.logger.Error().Err(err).Str("email", created.Email).Msg("Failed to send welcome email")
			} else {
				s.logger.Info().Str("email", created.Email).Msg("Welcome email sent")
			}
		}()
	}

	// Publish user registration event
	if s.broker != nil && s.broker.IsAvailable() {
		event := map[string]interface{}{
			"user_id":   created.ID,
			"email":     created.Email,
			"username":  created.Username,
			"timestamp": time.Now().UTC(),
		}
		if err := s.broker.PublishJSON("user.registered", event); err != nil {
			s.logger.Error().Err(err).Msg("Failed to publish registration event")
		}
	}

	s.logger.Info().
		Int32("user_id", created.ID).
		Str("email", email).
		Msg("User registered successfully")

	return created, nil
}

func (s *authService) Login(ctx context.Context, email, password string) (string, time.Time, error) {
	// Get user by email
	user, hash, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return "", time.Time{}, domain.ErrInvalidCredentials
		}
		s.logger.Error().Err(err).Msg("Failed to get user")
		return "", time.Time{}, fmt.Errorf("login failed: %w", err)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		s.logger.Warn().
			Str("email", email).
			Msg("Invalid password attempt")
		return "", time.Time{}, domain.ErrInvalidCredentials
	}

	// Generate JWT token
	expiresAt := time.Now().Add(s.jwtExpiry)
	token, err := s.generateToken(user, expiresAt)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to generate token")
		return "", time.Time{}, fmt.Errorf("token generation failed: %w", err)
	}

	// Send login alert email asynchronously (optional security feature)
	if s.emailService != nil && s.emailService.IsAvailable() {
		go func() {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			// You could extract IP and location from context if available
			ipAddress := "Unknown"
			location := "Unknown"

			if err := s.emailService.SendLoginAlertEmail(emailCtx, user.Email, user.Username, ipAddress, location); err != nil {
				s.logger.Warn().Err(err).Msg("Failed to send login alert email")
			}
		}()
	}

	s.logger.Info().
		Int32("user_id", user.ID).
		Str("email", email).
		Msg("User logged in successfully")

	return token, expiresAt, nil
}

func (s *authService) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.jwtSecret), nil
	})
	if err != nil {
		return nil, domain.ErrInvalidToken
	}

	if !token.Valid {
		return nil, domain.ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, domain.ErrInvalidToken
	}

	// Extract claims
	userID, ok := claims["user_id"].(float64)
	if !ok {
		return nil, domain.ErrInvalidToken
	}

	role, _ := claims["role"].(string)
	email, _ := claims["email"].(string)

	// Check expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, domain.ErrExpiredToken
		}
	}

	return &TokenClaims{
		UserID: int32(userID),
		Role:   role,
		Email:  email,
	}, nil
}

func (s *authService) RefreshToken(ctx context.Context, tokenString string) (string, time.Time, error) {
	// Validate existing token
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil && !errors.Is(err, domain.ErrExpiredToken) {
		return "", time.Time{}, err
	}

	// Get user to ensure they still exist
	user, err := s.repo.GetUserByID(ctx, claims.UserID)
	if err != nil {
		return "", time.Time{}, err
	}

	// Generate new token
	expiresAt := time.Now().Add(s.jwtExpiry)
	newToken, err := s.generateToken(user, expiresAt)
	if err != nil {
		return "", time.Time{}, err
	}

	return newToken, expiresAt, nil
}

// generateToken creates a JWT token for a user
func (s *authService) generateToken(user domain.User, expiresAt time.Time) (string, error) {
	claims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"role":    user.Role,
		"exp":     expiresAt.Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(s.jwtSecret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}
