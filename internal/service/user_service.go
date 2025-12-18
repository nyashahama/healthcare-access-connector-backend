// Package service implements user business logic
package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/rs/zerolog"
)

type userService struct {
	userRepo         repository.UserRepository
	patientRepo      repository.PatientRepository
	consentRepo      repository.ConsentRepository
	notificationRepo repository.NotificationRepository
	cache            cache.Service
	logger           *zerolog.Logger
}

// NewUserService creates a new user service for health project
func NewUserService(
	userRepo repository.UserRepository,
	patientRepo repository.PatientRepository,
	consentRepo repository.ConsentRepository,
	notificationRepo repository.NotificationRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) UserService {
	return &userService{
		userRepo:         userRepo,
		patientRepo:      patientRepo,
		consentRepo:      consentRepo,
		notificationRepo: notificationRepo,
		cache:            cache,
		logger:           logger,
	}
}

// GetProfile gets user profile with additional info
func (s *userService) GetProfile(ctx context.Context, userID uuid.UUID) (domain.User, domain.PatientProfile, error) {
	cacheKey := fmt.Sprintf("user:profile:%s", userID.String())

	// Try cache first
	type CachedProfile struct {
		User    domain.User           `json:"user"`
		Profile domain.PatientProfile `json:"profile"`
	}
	var cached CachedProfile
	if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
		s.logger.Debug().Str("user_id", userID.String()).Msg("Profile retrieved from cache")
		return cached.User, cached.Profile, nil
	}

	// Get user
	user, err := s.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user")
		return domain.User{}, domain.PatientProfile{}, domain.NewAppError(err, "User not found", 404)
	}

	// Get patient profile if user is a patient
	var patientProfile domain.PatientProfile
	if user.Role == "patient" {
		patientProfile, err = s.patientRepo.GetPatientProfileByUserID(ctx, userID)
		if err != nil && !errors.Is(err, domain.ErrPatientNotFound) {
			s.logger.Warn().Err(err).Str("user_id", userID.String()).Msg("Failed to get patient profile")
		}
	}

	// Cache the result
	cached = CachedProfile{
		User:    user,
		Profile: patientProfile,
	}
	if err := s.cache.Set(ctx, cacheKey, cached, 5*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache user profile")
	}

	return user, patientProfile, nil
}
