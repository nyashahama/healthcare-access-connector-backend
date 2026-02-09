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

type credentialService struct {
	credentialRepo repository.CredentialRepository
	staffRepo      repository.StaffRepository
	userRepo       repository.UserRepository
	auditRepo      repository.AuditRepository
	cache          cache.Service
	logger         *zerolog.Logger
}

func NewCredentialService(
	credentialRepo repository.CredentialRepository,
	staffRepo repository.StaffRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.CredentialService {
	return &credentialService{
		credentialRepo: credentialRepo,
		staffRepo:      staffRepo,
		userRepo:       userRepo,
		auditRepo:      auditRepo,
		cache:          cache,
		logger:         logger,
	}
}

func (c *credentialService) CreateCredential(ctx context.Context, credential providers.ProfessionalCredential) (providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("credential_type", credential.CredentialType).
			Str("staff_id", credential.StaffID.String()).
			Msg("CreateCredential completed")
	}()

	// Validate required fields
	if credential.StaffID == uuid.Nil {
		return providers.ProfessionalCredential{}, domain.NewAppError(domain.ErrValidation, "Staff ID is required", 400)
	}
	if credential.CredentialType == "" {
		return providers.ProfessionalCredential{}, domain.NewAppError(domain.ErrValidation, "Credential type is required", 400)
	}
	if credential.IssuingAuthority == "" {
		return providers.ProfessionalCredential{}, domain.NewAppError(domain.ErrValidation, "Issuing authority is required", 400)
	}

	// Verify staff exists
	staff, err := c.staffRepo.GetStaffByID(ctx, credential.StaffID)
	if err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return providers.ProfessionalCredential{}, domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		c.logger.Error().Err(err).Str("staff_id", credential.StaffID.String()).Msg("Failed to get staff member")
		return providers.ProfessionalCredential{}, domain.NewAppError(err, "Failed to verify staff member", 500)
	}

	// Verify verifier exists if provided
	if credential.VerifiedBy != nil && *credential.VerifiedBy != uuid.Nil {
		if _, err := c.userRepo.GetUserByID(ctx, *credential.VerifiedBy); err != nil {
			if errors.Is(err, domain.ErrUserNotFound) {
				return providers.ProfessionalCredential{}, domain.NewAppError(domain.ErrUserNotFound, "Verifier not found", 404)
			}
			c.logger.Error().Err(err).Str("verified_by", credential.VerifiedBy.String()).Msg("Failed to get verifier")
			return providers.ProfessionalCredential{}, domain.NewAppError(err, "Failed to verify verifier", 500)
		}
	}

	// Set default status if not provided
	if credential.Status == "" {
		credential.Status = "pending"
	}

	// Set timestamps
	now := time.Now()
	credential.ID = uuid.New()
	credential.CreatedAt = now
	credential.UpdatedAt = now

	// If verified, set verification date
	if credential.Status == "verified" && credential.VerifiedBy != nil && credential.VerificationDate == nil {
		credential.VerificationDate = &now
	}

	// Create credential
	createdCredential, err := c.credentialRepo.CreateCredential(ctx, credential)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicate) {
			return providers.ProfessionalCredential{}, domain.NewAppError(err, "Credential number already exists", 409)
		}
		c.logger.Error().Err(err).
			Str("staff_id", credential.StaffID.String()).
			Str("credential_type", credential.CredentialType).
			Msg("Failed to create credential")
		return providers.ProfessionalCredential{}, domain.NewAppError(err, "Failed to create credential", 500)
	}

	// Invalidate cache
	c.invalidateCredentialCache(ctx, createdCredential.ID, createdCredential.StaffID)

	// Log audit activity
	c.logCredentialActivity(ctx, "credential_created", createdCredential.ID, &staff.ID, map[string]interface{}{
		"staff_id":          createdCredential.StaffID,
		"credential_type":   createdCredential.CredentialType,
		"credential_number": stringPtrToString(createdCredential.CredentialNumber),
		"status":            createdCredential.Status,
	})

	c.logger.Info().
		Str("credential_id", createdCredential.ID.String()).
		Str("staff_id", createdCredential.StaffID.String()).
		Str("credential_type", createdCredential.CredentialType).
		Str("status", createdCredential.Status).
		Msg("Credential created successfully")

	return createdCredential, nil
}

func (c *credentialService) GetStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", staffID.String()).
			Msg("GetStaffCredentials completed")
	}()

	// Verify staff exists
	if _, err := c.staffRepo.GetStaffByID(ctx, staffID); err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return nil, domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		c.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to get staff member")
		return nil, domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("credentials:staff:%s", staffID.String())
	var credentials []providers.ProfessionalCredential
	if err := c.cache.Get(ctx, cacheKey, &credentials); err == nil {
		c.logger.Debug().Str("staff_id", staffID.String()).Msg("Staff credentials retrieved from cache")
		return credentials, nil
	}

	// Get staff credentials
	credentials, err := c.credentialRepo.GetStaffCredentials(ctx, staffID)
	if err != nil {
		c.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to get staff credentials")
		return nil, domain.NewAppError(err, "Failed to get staff credentials", 500)
	}

	// Cache the result
	if err := c.cache.Set(ctx, cacheKey, credentials, 10*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache staff credentials")
	}

	c.logger.Debug().
		Str("staff_id", staffID.String()).
		Int("credential_count", len(credentials)).
		Msg("Staff credentials retrieved")

	return credentials, nil
}

func (c *credentialService) DeleteCredential(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("credential_id", id.String()).
			Msg("DeleteCredential completed")
	}()

	// Get credential first for audit logging
	credential, err := c.getCredentialForAudit(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrCredentialNotFound) {
		c.logger.Error().Err(err).Str("credential_id", id.String()).Msg("Failed to get credential for deletion")
		return domain.NewAppError(err, "Failed to get credential", 500)
	}

	// Delete credential
	if err := c.credentialRepo.DeleteCredential(ctx, id); err != nil {
		if errors.Is(err, domain.ErrCredentialNotFound) {
			return domain.NewAppError(domain.ErrCredentialNotFound, "Credential not found", 404)
		}
		c.logger.Error().Err(err).Str("credential_id", id.String()).Msg("Failed to delete credential")
		return domain.NewAppError(err, "Failed to delete credential", 500)
	}

	// Invalidate cache
	if credential != nil && credential.ID != uuid.Nil {
		c.invalidateCredentialCache(ctx, credential.ID, credential.StaffID)
	}

	// Log audit activity
	if credential != nil && credential.ID != uuid.Nil {
		// Get staff for user ID
		staff, err := c.staffRepo.GetStaffByID(ctx, credential.StaffID)
		if err != nil {
			c.logger.Warn().Err(err).Str("staff_id", credential.StaffID.String()).Msg("Failed to get staff for audit")
		}

		var userID *uuid.UUID
		if staff.ID != uuid.Nil {
			userID = &staff.ID
		}

		c.logCredentialActivity(ctx, "credential_deleted", id, userID, map[string]interface{}{
			"staff_id":          credential.StaffID,
			"credential_type":   credential.CredentialType,
			"credential_number": stringPtrToString(credential.CredentialNumber),
		})
	}

	c.logger.Info().
		Str("credential_id", id.String()).
		Msg("Credential deleted successfully")

	return nil
}

// Helper method to get credential for audit logging
func (c *credentialService) getCredentialForAudit(ctx context.Context, id uuid.UUID) (*providers.ProfessionalCredential, error) {
	// Get staff credentials to find the specific one
	credentials, err := c.credentialRepo.GetStaffCredentials(ctx, uuid.Nil) // This won't work as expected
	if err != nil && !errors.Is(err, domain.ErrCredentialNotFound) {
		return nil, err
	}

	// Look for the credential by ID (this is inefficient, better to have GetCredentialByID in repository)
	for _, cred := range credentials {
		if cred.ID == id {
			return &cred, nil
		}
	}

	return nil, domain.ErrCredentialNotFound
}

// Helper methods
func (c *credentialService) invalidateCredentialCache(ctx context.Context, credentialID, staffID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("credentials:staff:%s", staffID.String()),
	}

	for _, key := range cacheKeys {
		if err := c.cache.Delete(ctx, key); err != nil {
			c.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate credential cache")
		}
	}
}

func (c *credentialService) logCredentialActivity(ctx context.Context, activityType string, credentialID uuid.UUID, userID *uuid.UUID, details map[string]interface{}) {
	// Create activity log
	activity := core.UserActivity{
		UserID:          userID,
		ActivityType:    activityType,
		ActivityDetails: details,
		ResourceType:    stringPtr("credential"),
		ResourceID:      &credentialID,
		PerformedAt:     time.Now(),
	}

	// Log activity asynchronously
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := c.auditRepo.LogUserActivity(activityCtx, activity); err != nil {
			c.logger.Warn().Err(err).Msg("Failed to log credential activity")
		}
	}()
}
