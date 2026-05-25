package providers

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type serviceCatalogService struct {
	serviceRepo repository.ServiceRepository
	clinicRepo  repository.ClinicRepository
	staffRepo   repository.StaffRepository
	auditRepo   repository.AuditRepository
	cache       cache.Service
	logger      *zerolog.Logger
}

func (s *serviceCatalogService) cacheAvailable() bool {
	return s != nil && s.cache != nil && s.cache.IsAvailable()
}

func NewServiceCatalogService(
	serviceRepo repository.ServiceRepository,
	clinicRepo repository.ClinicRepository,
	staffRepo repository.StaffRepository,
	auditRepo repository.AuditRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ServiceCatalogService {
	return &serviceCatalogService{
		serviceRepo: serviceRepo,
		clinicRepo:  clinicRepo,
		staffRepo:   staffRepo,
		auditRepo:   auditRepo,
		cache:       cache,
		logger:      logger,
	}
}

func (s *serviceCatalogService) CreateClinicService(ctx context.Context, service providers.ClinicService) (providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("service_name", service.ServiceName).
			Msg("CreateClinicService completed")
	}()

	// Validate required fields
	if service.ClinicID == uuid.Nil {
		return providers.ClinicService{}, domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}
	if service.ServiceName == "" {
		return providers.ClinicService{}, domain.NewAppError(domain.ErrValidation, "Service name is required", 400)
	}
	if service.CostCurrency == "" {
		service.CostCurrency = "ZAR" // Default currency
	}

	// Verify clinic exists
	if _, err := s.clinicRepo.GetClinicByID(ctx, service.ClinicID); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return providers.ClinicService{}, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		s.logger.Error().Err(err).Str("clinic_id", service.ClinicID.String()).Msg("Failed to get clinic")
		return providers.ClinicService{}, domain.NewAppError(err, "Failed to verify clinic", 500)
	}

	// Verify staff members exist if provided
	for _, staffID := range service.ProvidedByStaffIDs {
		exists, err := s.staffRepo.StaffExists(ctx, staffID)
		if err != nil {
			s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to check staff existence")
			return providers.ClinicService{}, domain.NewAppError(err, "Failed to verify staff member", 500)
		}
		if !exists {
			return providers.ClinicService{}, domain.NewAppError(domain.ErrStaffNotFound,
				fmt.Sprintf("Staff member %s not found", staffID.String()), 404)
		}
	}

	// Check for duplicate service name in same clinic
	exists, err := s.serviceRepo.CheckServiceNameExists(ctx, service.ClinicID, service.ServiceName, nil)
	if err != nil {
		s.logger.Error().Err(err).
			Str("clinic_id", service.ClinicID.String()).
			Str("service_name", service.ServiceName).
			Msg("Failed to check service name uniqueness")
		return providers.ClinicService{}, domain.NewAppError(err, "Failed to check service name", 500)
	}
	if exists {
		return providers.ClinicService{}, domain.NewAppError(domain.ErrDuplicate,
			"Service name already exists for this clinic", 409)
	}

	// Set timestamps and defaults
	now := time.Now()
	service.ID = uuid.New()
	if !service.IsActive {
		service.IsActive = true
	}
	service.CreatedAt = now
	service.UpdatedAt = now

	// Create service
	createdService, err := s.serviceRepo.CreateClinicService(ctx, service)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicate) {
			return providers.ClinicService{}, domain.NewAppError(err, "Service with this name already exists", 409)
		}
		s.logger.Error().Err(err).
			Str("clinic_id", service.ClinicID.String()).
			Str("service_name", service.ServiceName).
			Msg("Failed to create clinic service")
		return providers.ClinicService{}, domain.NewAppError(err, "Failed to create clinic service", 500)
	}

	// Invalidate cache
	s.invalidateServiceCache(ctx, createdService.ID, createdService.ClinicID)

	// Log audit activity
	s.logServiceActivity(ctx, "service_created", createdService.ID, nil, map[string]interface{}{
		"clinic_id":    createdService.ClinicID,
		"service_name": createdService.ServiceName,
		"category":     stringPtrToString(createdService.ServiceCategory),
	})

	s.logger.Info().
		Str("service_id", createdService.ID.String()).
		Str("clinic_id", createdService.ClinicID.String()).
		Str("service_name", createdService.ServiceName).
		Msg("Clinic service created successfully")

	return createdService, nil
}

func (s *serviceCatalogService) GetServiceByID(ctx context.Context, id uuid.UUID) (providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("service_id", id.String()).
			Msg("GetServiceByID completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("service:%s", id.String())
	var svc providers.ClinicService
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &svc); err == nil {
			s.logger.Debug().Str("service_id", id.String()).Msg("Service retrieved from cache")
			return svc, nil
		}
	}

	// Fetch from database
	svc, err := s.serviceRepo.GetServiceByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrServiceNotFound) {
			return providers.ClinicService{}, domain.NewAppError(domain.ErrServiceNotFound, "Service not found", 404)
		}
		s.logger.Error().Err(err).Str("service_id", id.String()).Msg("Failed to get service")
		return providers.ClinicService{}, domain.NewAppError(err, "Failed to get service", 500)
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, svc, 10*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache service")
		}
	}

	return svc, nil
}

func (s *serviceCatalogService) UpdateClinicService(ctx context.Context, svc providers.ClinicService) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("service_id", svc.ID.String()).
			Msg("UpdateClinicService completed")
	}()

	// Validate required fields
	if svc.ServiceName == "" {
		return domain.NewAppError(domain.ErrValidation, "Service name is required", 400)
	}

	// Get existing service to compare changes
	existing, err := s.serviceRepo.GetServiceByID(ctx, svc.ID)
	if err != nil {
		if errors.Is(err, domain.ErrServiceNotFound) {
			return domain.NewAppError(domain.ErrServiceNotFound, "Service not found", 404)
		}
		return domain.NewAppError(err, "Failed to get service", 500)
	}

	// Check for duplicate service name (excluding current service)
	exists, err := s.serviceRepo.CheckServiceNameExists(ctx, svc.ClinicID, svc.ServiceName, &svc.ID)
	if err != nil {
		s.logger.Error().Err(err).
			Str("clinic_id", svc.ClinicID.String()).
			Str("service_name", svc.ServiceName).
			Msg("Failed to check service name uniqueness")
		return domain.NewAppError(err, "Failed to check service name", 500)
	}
	if exists {
		return domain.NewAppError(domain.ErrDuplicate,
			"Service name already exists for this clinic", 409)
	}

	// Update service
	if err := s.serviceRepo.UpdateClinicService(ctx, svc); err != nil {
		s.logger.Error().Err(err).Str("service_id", svc.ID.String()).Msg("Failed to update service")
		return domain.NewAppError(err, "Failed to update service", 500)
	}

	// Invalidate cache
	s.invalidateServiceCache(ctx, svc.ID, svc.ClinicID)

	// Log audit activity
	s.logServiceActivity(ctx, "service_updated", svc.ID, nil, map[string]interface{}{
		"clinic_id":    svc.ClinicID,
		"service_name": svc.ServiceName,
		"changes":      s.compareServiceChanges(existing, svc),
	})

	s.logger.Info().
		Str("service_id", svc.ID.String()).
		Str("service_name", svc.ServiceName).
		Msg("Service updated successfully")

	return nil
}

func (s *serviceCatalogService) DeleteClinicService(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("service_id", id.String()).
			Msg("DeleteClinicService completed")
	}()

	// Get service first for audit logging
	svc, err := s.serviceRepo.GetServiceByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrServiceNotFound) {
		s.logger.Error().Err(err).Str("service_id", id.String()).Msg("Failed to get service for deletion")
		return domain.NewAppError(err, "Failed to get service", 500)
	}

	// Delete service
	if err := s.serviceRepo.DeleteClinicService(ctx, id); err != nil {
		if errors.Is(err, domain.ErrServiceNotFound) {
			return domain.NewAppError(domain.ErrServiceNotFound, "Service not found", 404)
		}
		s.logger.Error().Err(err).Str("service_id", id.String()).Msg("Failed to delete service")
		return domain.NewAppError(err, "Failed to delete service", 500)
	}

	// Invalidate cache
	if svc.ID != uuid.Nil {
		s.invalidateServiceCache(ctx, svc.ID, svc.ClinicID)
	}

	// Log audit activity
	if svc.ID != uuid.Nil {
		s.logServiceActivity(ctx, "service_deleted", id, nil, map[string]interface{}{
			"clinic_id":    svc.ClinicID,
			"service_name": svc.ServiceName,
		})
	}

	s.logger.Info().
		Str("service_id", id.String()).
		Msg("Service deleted successfully")

	return nil
}

func (s *serviceCatalogService) GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Msg("GetClinicServices completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("services:clinic:%s", clinicID.String())
	var services []providers.ClinicService
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &services); err == nil {
			s.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Clinic services retrieved from cache")
			return services, nil
		}
	}

	// Get clinic services
	services, err := s.serviceRepo.GetClinicServices(ctx, clinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get clinic services")
		return nil, domain.NewAppError(err, "Failed to get clinic services", 500)
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, services, 5*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache clinic services")
		}
	}

	s.logger.Debug().
		Str("clinic_id", clinicID.String()).
		Int("service_count", len(services)).
		Msg("Clinic services retrieved")

	return services, nil
}

func (s *serviceCatalogService) GetActiveClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Msg("GetActiveClinicServices completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("services:clinic:%s:active", clinicID.String())
	var services []providers.ClinicService
	if s.cacheAvailable() {
		if err := s.cache.Get(ctx, cacheKey, &services); err == nil {
			s.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Active clinic services retrieved from cache")
			return services, nil
		}
	}

	// Get active clinic services
	services, err := s.serviceRepo.GetActiveClinicServices(ctx, clinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get active clinic services")
		return nil, domain.NewAppError(err, "Failed to get active clinic services", 500)
	}

	// Cache the result
	if s.cacheAvailable() {
		if err := s.cache.Set(ctx, cacheKey, services, 5*time.Minute); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache active clinic services")
		}
	}

	s.logger.Debug().
		Str("clinic_id", clinicID.String()).
		Int("active_service_count", len(services)).
		Msg("Active clinic services retrieved")

	return services, nil
}

func (s *serviceCatalogService) ServiceExists(ctx context.Context, id uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("service_id", id.String()).
			Msg("ServiceExists completed")
	}()

	exists, err := s.serviceRepo.ServiceExists(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("service_id", id.String()).Msg("Failed to check if service exists")
		return false, domain.NewAppError(err, "Failed to check service existence", 500)
	}

	return exists, nil
}

func (s *serviceCatalogService) CheckServiceNameExists(ctx context.Context, clinicID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Str("service_name", name).
			Msg("CheckServiceNameExists completed")
	}()

	exists, err := s.serviceRepo.CheckServiceNameExists(ctx, clinicID, name, excludeID)
	if err != nil {
		s.logger.Error().Err(err).
			Str("clinic_id", clinicID.String()).
			Str("service_name", name).
			Msg("Failed to check service name existence")
		return false, domain.NewAppError(err, "Failed to check service name", 500)
	}

	return exists, nil
}

// Helper methods
func (s *serviceCatalogService) invalidateServiceCache(ctx context.Context, serviceID, clinicID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("service:%s", serviceID.String()),
		fmt.Sprintf("services:clinic:%s", clinicID.String()),
		fmt.Sprintf("services:clinic:%s:active", clinicID.String()),
	}

	for _, key := range cacheKeys {
		if s.cacheAvailable() {
			if err := s.cache.Delete(ctx, key); err != nil {
				s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate service cache")
			}
		}
	}
}

func (s *serviceCatalogService) logServiceActivity(ctx context.Context, activityType string, serviceID uuid.UUID, userID *uuid.UUID, details map[string]interface{}) {
	// Create activity log
	activity := core.UserActivity{
		UserID:          userID,
		ActivityType:    activityType,
		ActivityDetails: details,
		ResourceType:    stringPtr("service"),
		ResourceID:      &serviceID,
		PerformedAt:     time.Now(),
	}

	// Log activity asynchronously
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.auditRepo.LogUserActivity(activityCtx, activity); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to log service activity")
		}
	}()
}

func (s *serviceCatalogService) compareServiceChanges(oldService, newService providers.ClinicService) map[string]interface{} {
	changes := make(map[string]interface{})

	if oldService.ServiceName != newService.ServiceName {
		changes["service_name"] = map[string]string{
			"old": oldService.ServiceName,
			"new": newService.ServiceName,
		}
	}
	if stringPtrToString(oldService.ServiceCategory) != stringPtrToString(newService.ServiceCategory) {
		changes["service_category"] = map[string]string{
			"old": stringPtrToString(oldService.ServiceCategory),
			"new": stringPtrToString(newService.ServiceCategory),
		}
	}
	if oldService.Cost != nil && newService.Cost != nil && *oldService.Cost != *newService.Cost {
		changes["cost"] = map[string]float64{
			"old": *oldService.Cost,
			"new": *newService.Cost,
		}
	}
	// Add more field comparisons as needed

	return changes
}
