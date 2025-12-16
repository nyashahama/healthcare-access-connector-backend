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
	repo         repository.UserRepository
	cache        cache.Service
	broker       messaging.Broker
	emailService email.Service
	logger       *zerolog.Logger
	jwtSecret    string
	jwtExpiry    time.Duration
	bcryptCost   int // Make bcrypt cost configurable
}

// NewAuthService creates a new authentication service
func NewAuthService(
	repo repository.UserRepository,
	cache cache.Service,
	broker messaging.Broker,
	emailService email.Service,
	logger *zerolog.Logger,
	jwtSecret string,
	jwtExpiry time.Duration,
) AuthService {
	// Use bcrypt.DefaultCost (10) for production
	// Consider bcrypt.MinCost (4) for development/testing
	// Each +1 to cost doubles the time
	bcryptCost := bcrypt.DefaultCost
	if jwtExpiry < 24*time.Hour { // Quick heuristic for dev environment
		bcryptCost = 10 // Balanced for dev
	}

	return &authService{
		repo:         repo,
		cache:        cache,
		broker:       broker,
		emailService: emailService,
		logger:       logger,
		jwtSecret:    jwtSecret,
		jwtExpiry:    jwtExpiry,
		bcryptCost:   bcryptCost,
	}
}

func (s *authService) Register(ctx context.Context, username, email, password, role string) (domain.User, error) {
	start := time.Now()

	// Validate password
	if password == "" {
		return domain.User{}, domain.ErrValidation
	}

	// Default role
	if role == "" {
		role = "user"
	}

	// Hash password with configured cost
	hashStart := time.Now()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.bcryptCost)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to hash password")
		return domain.User{}, fmt.Errorf("password hashing failed: %w", err)
	}
	s.logger.Debug().
		Dur("hash_duration_ms", time.Since(hashStart)).
		Int("bcrypt_cost", s.bcryptCost).
		Msg("Password hashed")

	// Create user
	user := domain.User{
		Username: username,
		Email:    email,
		Role:     role,
	}

	dbStart := time.Now()
	created, err := s.repo.CreateUser(ctx, user, string(hash))
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateEmail) {
			return domain.User{}, domain.ErrDuplicateEmail
		}
		s.logger.Error().Err(err).Msg("Failed to create user")
		return domain.User{}, fmt.Errorf("user creation failed: %w", err)
	}
	s.logger.Debug().
		Dur("db_duration_ms", time.Since(dbStart)).
		Msg("User created in database")

	// Send welcome email asynchronously (non-blocking)
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

	// Publish user registration event (non-blocking)
	if s.broker != nil && s.broker.IsAvailable() {
		go func() {
			event := map[string]interface{}{
				"user_id":   created.ID,
				"email":     created.Email,
				"username":  created.Username,
				"timestamp": time.Now().UTC(),
			}
			if err := s.broker.PublishJSON("user.registered", event); err != nil {
				s.logger.Error().Err(err).Msg("Failed to publish registration event")
			}
		}()
	}

	s.logger.Info().
		Int32("user_id", created.ID).
		Str("email", email).
		Dur("total_duration_ms", time.Since(start)).
		Msg("User registered successfully")

	return created, nil
}

func (s *authService) Login(ctx context.Context, email, password string) (string, time.Time, error) {
	start := time.Now()

	// Try to get cached failed login attempts to prevent brute force
	cacheKey := fmt.Sprintf("login_attempts:%s", email)
	var attempts int
	if err := s.cache.Get(ctx, cacheKey, &attempts); err == nil {
		if attempts >= 5 {
			s.logger.Warn().Str("email", email).Msg("Too many login attempts")
			return "", time.Time{}, fmt.Errorf("too many login attempts, try again later")
		}
	}

	// Get user by email
	dbStart := time.Now()
	user, hash, err := s.repo.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			// Increment failed attempts
			s.cache.Set(ctx, cacheKey, attempts+1, 15*time.Minute)
			return "", time.Time{}, domain.ErrInvalidCredentials
		}
		s.logger.Error().Err(err).Msg("Failed to get user")
		return "", time.Time{}, fmt.Errorf("login failed: %w", err)
	}
	s.logger.Debug().
		Dur("db_duration_ms", time.Since(dbStart)).
		Msg("User fetched from database")

	// Verify password
	bcryptStart := time.Now()
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		s.logger.Warn().
			Str("email", email).
			Dur("bcrypt_duration_ms", time.Since(bcryptStart)).
			Msg("Invalid password attempt")

		// Increment failed attempts
		s.cache.Set(ctx, cacheKey, attempts+1, 15*time.Minute)
		return "", time.Time{}, domain.ErrInvalidCredentials
	}
	s.logger.Debug().
		Dur("bcrypt_duration_ms", time.Since(bcryptStart)).
		Msg("Password verified")

	// Clear failed attempts on successful login
	s.cache.Delete(ctx, cacheKey)

	// Generate JWT token
	tokenStart := time.Now()
	expiresAt := time.Now().Add(s.jwtExpiry)
	token, err := s.generateToken(user, expiresAt)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to generate token")
		return "", time.Time{}, fmt.Errorf("token generation failed: %w", err)
	}
	s.logger.Debug().
		Dur("token_duration_ms", time.Since(tokenStart)).
		Msg("JWT token generated")

	// Send login alert email asynchronously (non-blocking)
	if s.emailService != nil && s.emailService.IsAvailable() {
		go func() {
			emailCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

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
		Dur("total_duration_ms", time.Since(start)).
		Msg("User logged in successfully")

	return token, expiresAt, nil
}

func (s *authService) ValidateToken(ctx context.Context, tokenString string) (*TokenClaims, error) {
	// Try cache first
	cacheKey := fmt.Sprintf("token:%s", tokenString)
	var cached TokenClaims
	if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
		return &cached, nil
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
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

	userID, ok := claims["user_id"].(float64)
	if !ok {
		return nil, domain.ErrInvalidToken
	}

	role, _ := claims["role"].(string)
	email, _ := claims["email"].(string)

	// Check expiration
	var exp int64
	if expFloat, ok := claims["exp"].(float64); ok {
		exp = int64(expFloat)
		if time.Now().Unix() > exp {
			return nil, domain.ErrExpiredToken
		}
	}

	result := &TokenClaims{
		UserID: int32(userID),
		Role:   role,
		Email:  email,
	}

	// Cache valid token (cache for remaining lifetime or max 5 minutes)
	ttl := time.Until(time.Unix(exp, 0))
	if ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	if ttl > 0 {
		s.cache.Set(ctx, cacheKey, result, ttl)
	}

	return result, nil
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
