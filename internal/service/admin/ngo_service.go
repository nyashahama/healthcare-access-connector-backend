package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

type ngoPartnerService struct {
	ngoRepo      repository.NGOPartnerRepository
	userRepo     repository.UserRepository
	auditService service.AuditService
	cache        cache.Service
	logger       *zerolog.Logger
}

// NewNGOPartnerService creates a new NGO partner service.
func NewNGOPartnerService(
	ngoRepo repository.NGOPartnerRepository,
	userRepo repository.UserRepository,
	auditService service.AuditService,
	cache cache.Service,
	logger *zerolog.Logger,
) service.NGOPartnerService {
	return &ngoPartnerService{
		ngoRepo:      ngoRepo,
		userRepo:     userRepo,
		auditService: auditService,
		cache:        cache,
		logger:       logger,
	}
}

// CreateNGOPartner creates a new NGO partner profile.
func (s *ngoPartnerService) CreateNGOPartner(ctx context.Context, partner admin.NGOPartner) (admin.NGOPartner, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", partner.UserID.String()).
			Msg("CreateNGOPartner completed")
	}()

	if partner.UserID == uuid.Nil {
		return admin.NGOPartner{}, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}
	if partner.OrganizationName == "" {
		return admin.NGOPartner{}, domain.NewAppError(domain.ErrValidation, "Organization name is required", 400)
	}
	if partner.PartnershipStatus == "" {
		return admin.NGOPartner{}, domain.NewAppError(domain.ErrValidation, "Partnership status is required", 400)
	}

	validStatuses := map[string]bool{
		"active":       true,
		"suspended":    true,
		"terminated":   true,
		"inactive":     true,
		"under_review": true,
		"pending":      true,
	}
	if !validStatuses[partner.PartnershipStatus] {
		return admin.NGOPartner{}, domain.NewAppError(domain.ErrValidation, "Invalid partnership status", 400)
	}

	user, err := s.userRepo.GetUserByID(ctx, partner.UserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return admin.NGOPartner{}, domain.NewAppError(domain.ErrUserNotFound, "User not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", partner.UserID.String()).Msg("Failed to get user")
		return admin.NGOPartner{}, domain.NewAppError(err, "Failed to verify user", 500)
	}

	if user.Role != "ngo_partner" && user.Role != "system_admin" {
		s.logger.Warn().
			Str("user_id", partner.UserID.String()).
			Str("role", user.Role).
			Msg("Invalid role for NGO partner profile")
		return admin.NGOPartner{}, domain.NewAppError(domain.ErrValidation, "User must have ngo_partner role", 400)
	}

	now := time.Now()
	partner.CreatedAt = now
	partner.UpdatedAt = now

	created, err := s.ngoRepo.CreateNGOPartner(ctx, partner)
	if err != nil {
		s.logger.Error().Err(err).
			Str("user_id", partner.UserID.String()).
			Msg("Failed to create NGO partner")
		return admin.NGOPartner{}, domain.NewAppError(err, "Failed to create NGO partner", 500)
	}

	s.invalidateNGOPartnerCache(ctx, created.UserID)
	s.logNGOActivity(ctx, &created.UserID, "ngo_partner_created", map[string]interface{}{
		"user_id":            created.UserID.String(),
		"organization_name":  created.OrganizationName,
		"partnership_status": created.PartnershipStatus,
		"partnership_type":   created.PartnershipType,
		"organization_type":  stringFromPtr(created.OrganizationType),
	})

	return created, nil
}

// GetNGOPartnerByUserID returns the NGO partner profile by user ID.
func (s *ngoPartnerService) GetNGOPartnerByUserID(ctx context.Context, userID uuid.UUID) (admin.NGOPartner, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetNGOPartnerByUserID completed")
	}()

	if userID == uuid.Nil {
		return admin.NGOPartner{}, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	cacheKey := fmt.Sprintf("ngo_partner:user:%s", userID.String())
	if s.cache == nil {
		partner, err := s.ngoRepo.GetNGOPartnerByUserID(ctx, userID)
		if err != nil {
			if errors.Is(err, domain.ErrNotFound) {
				return admin.NGOPartner{}, domain.NewAppError(domain.ErrNotFound, "NGO partner not found", 404)
			}
			s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get NGO partner")
			return admin.NGOPartner{}, domain.NewAppError(err, "Failed to get NGO partner", 500)
		}
		return partner, nil
	}

	var cached admin.NGOPartner
	if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
		s.logger.Debug().Str("user_id", userID.String()).Msg("NGO partner fetched from cache")
		return cached, nil
	}

	partner, err := s.ngoRepo.GetNGOPartnerByUserID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return admin.NGOPartner{}, domain.NewAppError(domain.ErrNotFound, "NGO partner not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get NGO partner")
		return admin.NGOPartner{}, domain.NewAppError(err, "Failed to get NGO partner", 500)
	}

	if err := s.cache.Set(ctx, cacheKey, partner, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Str("user_id", userID.String()).Msg("Failed to cache NGO partner")
	}

	return partner, nil
}

func (s *ngoPartnerService) invalidateNGOPartnerCache(ctx context.Context, userID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}

	keys := []string{
		fmt.Sprintf("ngo_partner:user:%s", userID.String()),
		fmt.Sprintf("ngo_partner:profile:%s", userID.String()),
	}

	for _, key := range keys {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate NGO partner cache")
		}
	}
}

func (s *ngoPartnerService) logNGOActivity(
	ctx context.Context,
	userID *uuid.UUID,
	activityType string,
	details map[string]interface{},
) {
	if s.auditService == nil {
		return
	}

	go func() {
		auditCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resourceType := "ngo_partner"
		var resourceID *uuid.UUID
		if userID != nil {
			id := *userID
			resourceID = &id
		}

		activity := core.UserActivity{
			UserID:          userID,
			ActivityType:    activityType,
			ActivityDetails: details,
			ResourceType:    &resourceType,
			ResourceID:      resourceID,
			PerformedAt:     time.Now(),
		}
		if err := s.auditService.LogUserActivity(auditCtx, activity); err != nil {
			s.logger.Warn().Err(err).
				Str("activity_type", activityType).
				Str("user_id", ctxUserID(userID)).
				Msg("Failed to log NGO partner activity")
		}
	}()
}

// Helper to safely deference string pointers in logs.
func stringFromPtr(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func ctxUserID(userID *uuid.UUID) string {
	if userID == nil {
		return ""
	}
	return userID.String()
}
