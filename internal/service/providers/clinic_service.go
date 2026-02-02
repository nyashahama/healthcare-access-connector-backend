package providers

import (
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
)

type clinicService struct {
	clinicRepo repository.ClinicRepository
	cache      cache.Service
	logger     *zerolog.Logger
}
