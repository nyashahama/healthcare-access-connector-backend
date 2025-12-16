// Package service implements user business logic
package service

import (
	"context"
	"fmt"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/rs/zerolog"
)

type userService struct {
	repo   repository.UserRepository
	cache  cache.Service
	logger *zerolog.Logger
}

// NewUserService creates a new user service
func NewUserService(
	repo repository.UserRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) UserService {
	return &userService{
		repo:   repo,
		cache:  cache,
		logger: logger,
	}
}

func (s *userService) GetProfile(ctx context.Context, userID int32) (domain.User, error) {
	return s.GetUserByID(ctx, userID)
}

func (s *userService) GetUserByID(ctx context.Context, userID int32) (domain.User, error) {
	cacheKey := fmt.Sprintf("user:%d", userID)

	// Try cache first
	var user domain.User
	if err := s.cache.Get(ctx, cacheKey, &user); err == nil {
		s.logger.Debug().Int32("user_id", userID).Msg("User retrieved from cache")
		return user, nil
	}

	// Fetch from database
	user, err := s.repo.GetUserByID(ctx, userID)
	if err != nil {
		s.logger.Error().Err(err).Int32("user_id", userID).Msg("Failed to get user")
		return domain.User{}, err
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, user, 0); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache user")
		// Don't fail the request if caching fails
	}

	return user, nil
}

func (s *userService) UpdateProfile(ctx context.Context, userID int32, updates map[string]interface{}) error {
	// Invalidate cache
	cacheKey := fmt.Sprintf("user:%d", userID)
	if err := s.cache.Delete(ctx, cacheKey); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to invalidate cache")
	}

	// Implementation depends on your update requirements
	return fmt.Errorf("not implemented")
}

func (s *userService) DeleteProfile(ctx context.Context, userID int32) error {
	// Invalidate cache
	cacheKey := fmt.Sprintf("user:%d", userID)
	if err := s.cache.Delete(ctx, cacheKey); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to invalidate cache")
	}

	if err := s.repo.DeleteUser(ctx, userID); err != nil {
		s.logger.Error().Err(err).Int32("user_id", userID).Msg("Failed to delete user")
		return err
	}

	s.logger.Info().Int32("user_id", userID).Msg("User deleted")
	return nil
}

func (s *userService) ListUsers(ctx context.Context, limit, offset int) ([]domain.User, error) {
	users, err := s.repo.ListUsers(ctx, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to list users")
		return nil, err
	}

	return users, nil
}