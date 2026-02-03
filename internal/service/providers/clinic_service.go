package providers

import (
	"context"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type clinicService struct {
	clinicRepo repository.ClinicRepository
	auditRepo  repository.AuditRepository
	cache      cache.Service
	logger     *zerolog.Logger
}

func NewClinicService(clinicRepo repository.ClinicRepository, auditRepo repository.AuditRepository, cache cache.Service, logger *zerolog.Logger) service.ClinicService {
	return &clinicService{
		clinicRepo: clinicRepo,
		auditRepo:  auditRepo,
		cache:      cache,
		logger:     logger,
	}
}

func (c *clinicService) CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error) {
	return providers.Clinic{}, nil
}
