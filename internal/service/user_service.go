// Package service implements user business logic
package service

import (
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
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
