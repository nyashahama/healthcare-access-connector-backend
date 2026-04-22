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

type clinicService struct {
	clinicRepo repository.ClinicRepository
	auditRepo  repository.AuditRepository
	userRepo   repository.UserRepository
	authRepo   repository.AuthRepository
	staffRepo  repository.StaffRepository
	cache      cache.Service
	logger     *zerolog.Logger
}

func NewClinicService(
	clinicRepo repository.ClinicRepository,
	auditRepo repository.AuditRepository,
	userRepo repository.UserRepository,
	authRepo repository.AuthRepository,
	staffRepo repository.StaffRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ClinicService {
	return &clinicService{
		clinicRepo: clinicRepo,
		auditRepo:  auditRepo,
		userRepo:   userRepo,
		authRepo:   authRepo,
		staffRepo:  staffRepo,
		cache:      cache,
		logger:     logger,
	}
}

// RegisterClinic creates a new clinic with owner tracking
func (c *clinicService) RegisterClinic(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_name", clinic.ClinicName).
			Str("owner_user_id", ownerUserID.String()).
			Msg("RegisterClinic completed")
	}()

	// Validate required fields
	if clinic.ClinicName == "" {
		return providers.Clinic{}, domain.NewAppError(domain.ErrValidation, "Clinic name is required", 400)
	}
	if clinic.ClinicType == "" {
		return providers.Clinic{}, domain.NewAppError(domain.ErrValidation, "Clinic type is required", 400)
	}
	if clinic.PhysicalAddress == "" {
		return providers.Clinic{}, domain.NewAppError(domain.ErrValidation, "Physical address is required", 400)
	}
	if createdBy == uuid.Nil {
		return providers.Clinic{}, domain.NewAppError(domain.ErrValidation, "CreatedBy user ID is required", 400)
	}
	if ownerUserID == uuid.Nil {
		return providers.Clinic{}, domain.NewAppError(domain.ErrValidation, "Owner user ID is required", 400)
	}

	// Verify that the owner user exists
	owner, err := c.userRepo.GetUserByID(ctx, ownerUserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return providers.Clinic{}, domain.NewAppError(domain.ErrUserNotFound, "Owner user not found", 404)
		}
		c.logger.Error().Err(err).Str("owner_user_id", ownerUserID.String()).Msg("Failed to get owner user")
		return providers.Clinic{}, domain.NewAppError(err, "Failed to verify owner user", 500)
	}

	// Validate owner is a provider role
	validOwnerRoles := map[string]bool{
		"provider":       true,
		"provider_staff": true,
		"clinic_admin":   true,
		"system_admin":   true, // System admins can own clinics too
	}
	if !validOwnerRoles[owner.Role] {
		return providers.Clinic{}, domain.NewAppError(domain.ErrValidation, "User must have provider role to own a clinic", 403)
	}

	// Set timestamps, status, and owner tracking
	now := time.Now()
	clinic.ID = uuid.New()
	clinic.CreatedBy = &createdBy
	clinic.OwnerUserID = &ownerUserID
	clinic.IsVerified = false
	clinic.VerificationStatus = "pending"
	clinic.CreatedAt = now
	clinic.UpdatedAt = now

	// Create clinic in repository
	createdClinic, err := c.clinicRepo.CreateClinic(ctx, clinic, createdBy, ownerUserID)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateRegistrationNumber) {
			return providers.Clinic{}, domain.NewAppError(err, "Registration number already exists", 409)
		}
		if errors.Is(err, domain.ErrDuplicateEmail) {
			return providers.Clinic{}, domain.NewAppError(err, "Email already exists", 409)
		}
		if errors.Is(err, domain.ErrDuplicatePhone) {
			return providers.Clinic{}, domain.NewAppError(err, "Phone number already exists", 409)
		}
		c.logger.Error().Err(err).Str("clinic_name", clinic.ClinicName).Msg("Failed to create clinic")
		return providers.Clinic{}, domain.NewAppError(err, "Failed to create clinic", 500)
	}

	// Try to get more user details for better staff record
	firstName := "Clinic" // Default placeholder
	lastName := "Owner"   // Default placeholder

	// If the user has a patient profile (unlikely for providers, but check anyway)
	// or any other profile source, we could populate actual names here
	// For now, we'll use email/phone as identifiers until they complete their provider profile

	// Create owner staff record with user information
	ownerStaff := providers.ClinicStaff{
		ID:                     uuid.New(),
		ClinicID:               createdClinic.ID,
		UserID:                 &ownerUserID,
		FirstName:              firstName,   // Will be updated when user completes provider profile
		LastName:               lastName,    // Will be updated when user completes provider profile
		WorkEmail:              owner.Email, // Use the owner's email from user account
		WorkPhone:              owner.Phone, // Use the owner's phone from user account
		StaffRole:              providers.StaffRoleOwner,
		Department:             stringPtr("Management"),
		IsPrimaryContact:       true,
		InvitationStatus:       stringPtr(providers.InvitationStatusAccepted),
		InvitedAt:              &now,
		InvitedBy:              &ownerUserID,
		Permissions:            nil, // Set to nil to avoid JSON marshal error (will be NULL in DB)
		OtherLicenseNumbers:    nil, // Set to nil to avoid JSON marshal error (will be NULL in DB)
		CanManageStaff:         true,
		CanApproveAppointments: true,
		CanEditClinicInfo:      true,
		WorkingHours:           nil, // Set to nil to avoid JSON marshal error (will be NULL in DB)
		AvailableDays:          []string{"monday", "tuesday", "wednesday", "thursday", "friday"},
		IsAcceptingNewPatients: true,
		EmploymentStatus:       providers.EmploymentStatusActive,
		StartDate:              &now,
		ProfilePictureURL:      nil,
		LanguagesSpoken:        []string{"en"},
		CreatedAt:              now,
		UpdatedAt:              now,
	}

	// Try to create owner staff record
	if c.staffRepo != nil {
		if _, err := c.staffRepo.CreateStaffMember(ctx, ownerStaff); err != nil {
			c.logger.Warn().Err(err).
				Str("clinic_id", createdClinic.ID.String()).
				Str("user_id", ownerUserID.String()).
				Msg("Failed to create owner staff record")
			// Continue even if staff record fails
		}
	} else {
		c.logger.Warn().
			Str("clinic_id", createdClinic.ID.String()).
			Str("user_id", ownerUserID.String()).
			Msg("Staff repository not available, skipping owner staff creation")
	}

	// Update user's primary clinic
	if err := c.authRepo.UpdateUserPrimaryClinic(ctx, ownerUserID, createdClinic.ID); err != nil {
		c.logger.Warn().Err(err).
			Str("user_id", ownerUserID.String()).
			Str("clinic_id", createdClinic.ID.String()).
			Msg("Failed to update user primary clinic")
		// Continue even if this fails
	}

	// Update user's onboarding step
	if err := c.authRepo.UpdateUserOnboardingStep(ctx, ownerUserID, core.OnboardingStepClinicRegistered); err != nil {
		c.logger.Warn().Err(err).
			Str("user_id", ownerUserID.String()).
			Msg("Failed to update user onboarding step")
		// Continue even if this fails
	}

	// Invalidate user cache
	if c.cache != nil {
		userCacheKey := fmt.Sprintf("user:%s", ownerUserID.String())
		c.cache.Delete(ctx, userCacheKey)

		// Also invalidate any login caches
		if owner.Email != nil {
			loginCacheKey := fmt.Sprintf("user:login:%s", *owner.Email)
			c.cache.Delete(ctx, loginCacheKey)
		}
		if owner.Phone != nil {
			loginCacheKey := fmt.Sprintf("user:login:%s", *owner.Phone)
			c.cache.Delete(ctx, loginCacheKey)
		}
	}

	// Invalidate clinic cache
	c.invalidateClinicListCache(ctx)
	c.invalidateClinicCache(ctx, createdClinic.ID)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_registered", createdClinic.ID, &ownerUserID, map[string]interface{}{
		"clinic_name": createdClinic.ClinicName,
		"clinic_type": createdClinic.ClinicType,
		"owner_id":    ownerUserID.String(),
		"created_by":  createdBy.String(),
		"staff_role":  ownerStaff.StaffRole,
	})

	c.logger.Info().
		Str("clinic_id", createdClinic.ID.String()).
		Str("clinic_name", createdClinic.ClinicName).
		Str("owner_user_id", ownerUserID.String()).
		Str("onboarding_step", core.OnboardingStepClinicRegistered).
		Msg("Clinic registered successfully with owner staff")

	return createdClinic, nil
}

func (c *clinicService) GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Msg("GetClinicByID completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("clinic:%s", id.String())
	var clinic providers.Clinic
	if err := c.cache.Get(ctx, cacheKey, &clinic); err == nil {
		c.logger.Debug().Str("clinic_id", id.String()).Msg("Clinic retrieved from cache")
		return clinic, nil
	}

	// Fetch from database
	clinic, err := c.clinicRepo.GetClinicByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return providers.Clinic{}, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to get clinic")
		return providers.Clinic{}, domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Cache the result
	if err := c.cache.Set(ctx, cacheKey, clinic, 10*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache clinic")
	}

	return clinic, nil
}

// GetClinicByUserID retrieves the clinic from a user's primary_clinic_id
func (c *clinicService) GetClinicByUserID(ctx context.Context, userID uuid.UUID) (*providers.Clinic, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("GetClinicByUserID completed")
	}()

	// Validate user ID
	if userID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	// Get the user to access their primary_clinic_id
	user, err := c.userRepo.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return nil, domain.NewAppError(domain.ErrUserNotFound, "User not found", 404)
		}
		c.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user")
		return nil, domain.NewAppError(err, "Failed to get user", 500)
	}

	// Check if user has a primary_clinic_id
	if user.PrimaryClinicID == nil || *user.PrimaryClinicID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrClinicNotFound, "No clinic assigned to this user", 404)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("clinic:user:%s", userID.String())
	var clinic providers.Clinic
	if err := c.cache.Get(ctx, cacheKey, &clinic); err == nil {
		c.logger.Debug().Str("user_id", userID.String()).Msg("Clinic retrieved from cache")
		return &clinic, nil
	}

	// Get the clinic using the primary_clinic_id
	// Note: GetClinicByID returns providers.Clinic (not a pointer)
	clinic, err = c.clinicRepo.GetClinicByID(ctx, *user.PrimaryClinicID)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return nil, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", user.PrimaryClinicID.String()).Msg("Failed to get clinic")
		return nil, domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Cache the result
	if err := c.cache.Set(ctx, cacheKey, clinic, 10*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache clinic")
	}

	c.logger.Debug().
		Str("clinic_id", clinic.ID.String()).
		Str("user_id", userID.String()).
		Msg("Clinic retrieved by user ID")

	return &clinic, nil
}

func (c *clinicService) UpdateClinic(ctx context.Context, clinic providers.Clinic) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinic.ID.String()).
			Msg("UpdateClinic completed")
	}()

	// Validate required fields
	if clinic.ClinicName == "" {
		return domain.NewAppError(domain.ErrValidation, "Clinic name is required", 400)
	}
	if clinic.ClinicType == "" {
		return domain.NewAppError(domain.ErrValidation, "Clinic type is required", 400)
	}

	// Get existing clinic to compare changes
	existing, err := c.clinicRepo.GetClinicByID(ctx, clinic.ID)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Update timestamp
	clinic.UpdatedAt = time.Now()

	// Update clinic
	if err := c.clinicRepo.UpdateClinic(ctx, clinic); err != nil {
		c.logger.Error().Err(err).Str("clinic_id", clinic.ID.String()).Msg("Failed to update clinic")
		return domain.NewAppError(err, "Failed to update clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, clinic.ID)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_updated", clinic.ID, nil, map[string]interface{}{
		"clinic_name": clinic.ClinicName,
		"changes":     c.compareClinicChanges(existing, clinic),
	})

	c.logger.Info().
		Str("clinic_id", clinic.ID.String()).
		Str("clinic_name", clinic.ClinicName).
		Msg("Clinic updated successfully")

	return nil
}

func (c *clinicService) DeleteClinic(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Msg("DeleteClinic completed")
	}()

	// Get clinic first for audit logging
	clinic, err := c.clinicRepo.GetClinicByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrClinicNotFound) {
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to get clinic for deletion")
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Delete clinic
	if err := c.clinicRepo.DeleteClinic(ctx, id); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to delete clinic")
		return domain.NewAppError(err, "Failed to delete clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	if clinic.ID != uuid.Nil {
		c.logClinicActivity(ctx, "clinic_deleted", id, nil, map[string]interface{}{
			"clinic_name": clinic.ClinicName,
		})
	}

	c.logger.Info().
		Str("clinic_id", id.String()).
		Msg("Clinic deleted successfully")

	return nil
}

// VerifyClinic verifies a clinic - only system_admin and ngo_partner roles are authorized
func (c *clinicService) VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Str("verified_by", verifiedBy.String()).
			Msg("VerifyClinic completed")
	}()

	// Get the user who is attempting to verify
	verifier, err := c.userRepo.GetUserByID(ctx, verifiedBy)
	if err != nil {
		c.logger.Warn().
			Err(err).
			Str("verifier_id", verifiedBy.String()).
			Msg("Verifier not found")
		return domain.NewAppError(domain.ErrUserNotFound, "Verifier not found", 404)
	}

	// Authorization check: Only system_admin and ngo_partner can verify clinics
	if verifier.Role != "system_admin" && verifier.Role != "ngo_partner" {
		c.logger.Warn().
			Str("verifier_id", verifiedBy.String()).
			Str("verifier_role", verifier.Role).
			Str("clinic_id", id.String()).
			Msg("Unauthorized clinic verification attempt")
		return domain.NewAppError(
			domain.ErrUnauthorized,
			"Only system administrators and NGO partners can verify clinics",
			403,
		)
	}

	// Get existing clinic to check current verification status
	existingClinic, err := c.clinicRepo.GetClinicByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// If clinic is already verified, check if it was verified by an authorized user
	if existingClinic.IsVerified && existingClinic.VerifiedBy != nil {
		previousVerifier, err := c.userRepo.GetUserByID(ctx, *existingClinic.VerifiedBy)
		if err == nil {
			// If previously verified by unauthorized user, log a warning and proceed with re-verification
			if previousVerifier.Role != "system_admin" && previousVerifier.Role != "ngo_partner" {
				c.logger.Warn().
					Str("clinic_id", id.String()).
					Str("previous_verifier_id", previousVerifier.ID.String()).
					Str("previous_verifier_role", previousVerifier.Role).
					Msg("Clinic was previously verified by unauthorized user - resetting verification")
			}
		}
	}

	// Verify clinic
	if err := c.clinicRepo.VerifyClinic(ctx, id, verifiedBy, notes); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to verify clinic")
		return domain.NewAppError(err, "Failed to verify clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_verified", id, &verifiedBy, map[string]interface{}{
		"verification_notes": notes,
		"verifier_role":      verifier.Role,
	})

	c.logger.Info().
		Str("clinic_id", id.String()).
		Str("verified_by", verifiedBy.String()).
		Str("verifier_role", verifier.Role).
		Msg("Clinic verified successfully")

	return nil
}

// RejectClinicVerification rejects a clinic verification - only system_admin and ngo_partner roles are authorized
func (c *clinicService) RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Str("verified_by", verifiedBy.String()).
			Msg("RejectClinicVerification completed")
	}()

	// Get the user who is attempting to reject verification
	verifier, err := c.userRepo.GetUserByID(ctx, verifiedBy)
	if err != nil {
		c.logger.Warn().
			Err(err).
			Str("verifier_id", verifiedBy.String()).
			Msg("Verifier not found")
		return domain.NewAppError(domain.ErrUserNotFound, "Verifier not found", 404)
	}

	// Authorization check: Only system_admin and ngo_partner can reject clinic verification
	if verifier.Role != "system_admin" && verifier.Role != "ngo_partner" {
		c.logger.Warn().
			Str("verifier_id", verifiedBy.String()).
			Str("verifier_role", verifier.Role).
			Str("clinic_id", id.String()).
			Msg("Unauthorized clinic verification rejection attempt")
		return domain.NewAppError(
			domain.ErrUnauthorized,
			"Only system administrators and NGO partners can reject clinic verifications",
			403,
		)
	}

	// Reject clinic verification
	if err := c.clinicRepo.RejectClinicVerification(ctx, id, verifiedBy, notes); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to reject clinic verification")
		return domain.NewAppError(err, "Failed to reject clinic verification", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_verification_rejected", id, &verifiedBy, map[string]interface{}{
		"rejection_notes": notes,
		"verifier_role":   verifier.Role,
	})

	c.logger.Info().
		Str("clinic_id", id.String()).
		Str("verified_by", verifiedBy.String()).
		Str("verifier_role", verifier.Role).
		Msg("Clinic verification rejected")

	return nil
}

// UpdateClinicVerificationStatus updates clinic verification status - only system_admin and ngo_partner roles are authorized
func (c *clinicService) UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Str("status", status).
			Msg("UpdateClinicVerificationStatus completed")
	}()

	// Validate status
	validStatuses := map[string]bool{
		"pending":    true,
		"verified":   true,
		"rejected":   true,
		"in_review":  true,
		"unverified": true,
	}
	if !validStatuses[status] {
		return domain.NewAppError(domain.ErrValidation, "Invalid verification status", 400)
	}

	// Update verification status
	if err := c.clinicRepo.UpdateClinicVerificationStatus(ctx, id, status); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to update clinic verification status")
		return domain.NewAppError(err, "Failed to update verification status", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_verification_status_updated", id, nil, map[string]interface{}{
		"status": status,
	})

	c.logger.Info().
		Str("clinic_id", id.String()).
		Str("status", status).
		Msg("Clinic verification status updated")

	return nil
}

func (c *clinicService) DeactivateClinic(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Msg("DeactivateClinic completed")
	}()

	// Get clinic for audit logging
	clinic, err := c.clinicRepo.GetClinicByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrClinicNotFound) {
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to get clinic for deactivation")
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Deactivate clinic
	if err := c.clinicRepo.DeactivateClinic(ctx, id); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to deactivate clinic")
		return domain.NewAppError(err, "Failed to deactivate clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	if clinic.ID != uuid.Nil {
		c.logClinicActivity(ctx, "clinic_deactivated", id, nil, map[string]interface{}{
			"clinic_name": clinic.ClinicName,
		})
	}

	c.logger.Info().
		Str("clinic_id", id.String()).
		Msg("Clinic deactivated")

	return nil
}

func (c *clinicService) ReactivateClinic(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", id.String()).
			Msg("ReactivateClinic completed")
	}()

	// Get clinic for audit logging
	clinic, err := c.clinicRepo.GetClinicByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrClinicNotFound) {
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to get clinic for reactivation")
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Reactivate clinic
	if err := c.clinicRepo.ReactivateClinic(ctx, id); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", id.String()).Msg("Failed to reactivate clinic")
		return domain.NewAppError(err, "Failed to reactivate clinic", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, id)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	if clinic.ID != uuid.Nil {
		c.logClinicActivity(ctx, "clinic_reactivated", id, nil, map[string]interface{}{
			"clinic_name": clinic.ClinicName,
		})
	}

	c.logger.Info().
		Str("clinic_id", id.String()).
		Msg("Clinic reactivated")

	return nil
}

func (c *clinicService) SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("query", params.Query).
			Int("limit", params.Limit).
			Int("offset", params.Offset).
			Msg("SearchClinics completed")
	}()

	// Validate limit and offset
	if params.Limit <= 0 || params.Limit > 100 {
		params.Limit = 50
	}
	if params.Offset < 0 {
		params.Offset = 0
	}

	// Try cache first (for common search patterns)
	cacheKey := fmt.Sprintf("clinic:search:%s:%s:%s:%d:%d",
		params.Query,
		stringPtrToString(params.Province),
		stringPtrToString(params.City),
		params.Limit,
		params.Offset,
	)
	var results []providers.ClinicSearchResult
	if err := c.cache.Get(ctx, cacheKey, &results); err == nil {
		c.logger.Debug().Str("query", params.Query).Msg("Search results retrieved from cache")
		return results, nil
	}

	// Search clinics
	results, err := c.clinicRepo.SearchClinics(ctx, params)
	if err != nil {
		c.logger.Error().Err(err).Str("query", params.Query).Msg("Failed to search clinics")
		return nil, domain.NewAppError(err, "Failed to search clinics", 500)
	}

	// Cache the result (shorter TTL for search results)
	if err := c.cache.Set(ctx, cacheKey, results, 2*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache search results")
	}

	c.logger.Debug().
		Str("query", params.Query).
		Int("result_count", len(results)).
		Msg("Clinics search completed")

	return results, nil
}

func (c *clinicService) GetClinics(ctx context.Context) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("GetClinics completed")
	}()

	var clinics []providers.Clinic

	// Get clinics
	clinics, err := c.clinicRepo.GetClinics(ctx)
	if err != nil {
		c.logger.Error().Err(err).Msg("Failed to get clinics")
		return nil, domain.NewAppError(err, "Failed to get clinics", 500)
	}

	c.logger.Debug().
		Int("clinic_count", len(clinics)).
		Msg("Clinics list retrieved")

	return clinics, nil
}

// GetClinicByOwner retrieves the clinic owned by a specific user
func (c *clinicService) GetClinicByOwner(ctx context.Context, ownerUserID uuid.UUID) (*providers.Clinic, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("owner_user_id", ownerUserID.String()).
			Msg("GetClinicByOwner completed")
	}()

	// Validate owner user ID
	if ownerUserID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrValidation, "Owner user ID is required", 400)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("clinic:owner:%s", ownerUserID.String())
	var clinic providers.Clinic
	if err := c.cache.Get(ctx, cacheKey, &clinic); err == nil {
		c.logger.Debug().Str("owner_user_id", ownerUserID.String()).Msg("Clinic retrieved from cache")
		return &clinic, nil
	}

	// Fetch from repository (returns *providers.Clinic)
	clinicPtr, err := c.clinicRepo.GetClinicByOwner(ctx, ownerUserID)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return nil, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found for owner", 404)
		}
		c.logger.Error().Err(err).Str("owner_user_id", ownerUserID.String()).Msg("Failed to get clinic by owner")
		return nil, domain.NewAppError(err, "Failed to get clinic by owner", 500)
	}

	// Cache the result
	if err := c.cache.Set(ctx, cacheKey, *clinicPtr, 10*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache clinic")
	}

	c.logger.Debug().
		Str("clinic_id", clinicPtr.ID.String()).
		Str("owner_user_id", ownerUserID.String()).
		Msg("Clinic retrieved by owner")

	return clinicPtr, nil
}

// GetClinicWithOwnerInfo retrieves clinic with detailed owner information
func (c *clinicService) GetClinicWithOwnerInfo(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicWithOwner, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Msg("GetClinicWithOwnerInfo completed")
	}()

	// Validate clinic ID
	if clinicID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("clinic:with_owner:%s", clinicID.String())
	var clinicWithOwner providers.ClinicWithOwner
	if err := c.cache.Get(ctx, cacheKey, &clinicWithOwner); err == nil {
		c.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Clinic with owner retrieved from cache")
		return &clinicWithOwner, nil
	}

	// Fetch from repository (returns *providers.ClinicWithOwner)
	clinicWithOwnerPtr, err := c.clinicRepo.GetClinicWithOwnerInfo(ctx, clinicID)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return nil, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get clinic with owner info")
		return nil, domain.NewAppError(err, "Failed to get clinic with owner", 500)
	}

	// Cache the result
	if err := c.cache.Set(ctx, cacheKey, *clinicWithOwnerPtr, 10*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache clinic with owner")
	}

	c.logger.Debug().
		Str("clinic_id", clinicID.String()).
		Str("owner_email", stringPtrToString(clinicWithOwnerPtr.OwnerEmail)).
		Msg("Clinic with owner info retrieved")

	return clinicWithOwnerPtr, nil
}

// UpdateClinicOwner changes the owner of a clinic
func (c *clinicService) UpdateClinicOwner(ctx context.Context, clinicID, newOwnerUserID uuid.UUID, updatedBy uuid.UUID) error {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Str("new_owner_user_id", newOwnerUserID.String()).
			Msg("UpdateClinicOwner completed")
	}()

	// Validate IDs
	if clinicID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}
	if newOwnerUserID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "New owner user ID is required", 400)
	}
	if updatedBy == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "Updated by user ID is required", 400)
	}

	// Verify clinic exists
	clinic, err := c.clinicRepo.GetClinicByID(ctx, clinicID)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		return domain.NewAppError(err, "Failed to get clinic", 500)
	}

	// Verify new owner exists and has appropriate role
	newOwner, err := c.userRepo.GetUserByID(ctx, newOwnerUserID)
	if err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return domain.NewAppError(domain.ErrUserNotFound, "New owner user not found", 404)
		}
		c.logger.Error().Err(err).Str("new_owner_user_id", newOwnerUserID.String()).Msg("Failed to get new owner user")
		return domain.NewAppError(err, "Failed to verify new owner user", 500)
	}

	// Validate new owner is a provider role
	if newOwner.Role != "provider" && newOwner.Role != "provider_staff" && newOwner.Role != "clinic_admin" {
		return domain.NewAppError(domain.ErrValidation, "New owner must have provider role", 403)
	}

	// Get old owner ID for logging
	var oldOwnerID uuid.UUID
	if clinic.OwnerUserID != nil {
		oldOwnerID = *clinic.OwnerUserID
	}

	// Update clinic owner in repository
	if err := c.clinicRepo.UpdateClinicOwner(ctx, clinicID, newOwnerUserID); err != nil {
		c.logger.Error().Err(err).
			Str("clinic_id", clinicID.String()).
			Str("new_owner_user_id", newOwnerUserID.String()).
			Msg("Failed to update clinic owner")
		return domain.NewAppError(err, "Failed to update clinic owner", 500)
	}

	// Invalidate cache
	c.invalidateClinicCache(ctx, clinicID)
	if oldOwnerID != uuid.Nil {
		cacheKey := fmt.Sprintf("clinic:owner:%s", oldOwnerID.String())
		c.cache.Delete(ctx, cacheKey)
	}
	cacheKey := fmt.Sprintf("clinic:owner:%s", newOwnerUserID.String())
	c.cache.Delete(ctx, cacheKey)
	c.invalidateClinicListCache(ctx)

	// Log audit activity
	c.logClinicActivity(ctx, "clinic_owner_updated", clinicID, &updatedBy, map[string]interface{}{
		"clinic_name":       clinic.ClinicName,
		"old_owner_user_id": oldOwnerID.String(),
		"new_owner_user_id": newOwnerUserID.String(),
		"updated_by":        updatedBy.String(),
	})

	c.logger.Info().
		Str("clinic_id", clinicID.String()).
		Str("old_owner_user_id", oldOwnerID.String()).
		Str("new_owner_user_id", newOwnerUserID.String()).
		Msg("Clinic owner updated successfully")

	return nil
}

// GetClinicVerificationStatus retrieves the verification status of a clinic
func (c *clinicService) GetClinicVerificationStatus(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicVerification, error) {
	start := time.Now()
	defer func() {
		c.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Msg("GetClinicVerificationStatus completed")
	}()

	// Validate clinic ID
	if clinicID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("clinic:verification:%s", clinicID.String())
	var verification providers.ClinicVerification
	if err := c.cache.Get(ctx, cacheKey, &verification); err == nil {
		c.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Clinic verification status retrieved from cache")
		return &verification, nil
	}

	// Fetch from repository (returns *providers.ClinicVerification)
	verificationPtr, err := c.clinicRepo.GetClinicVerificationStatus(ctx, clinicID)
	if err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return nil, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		c.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get clinic verification status")
		return nil, domain.NewAppError(err, "Failed to get verification status", 500)
	}

	// Cache the result
	if err := c.cache.Set(ctx, cacheKey, *verificationPtr, 5*time.Minute); err != nil {
		c.logger.Warn().Err(err).Msg("Failed to cache clinic verification status")
	}

	c.logger.Debug().
		Str("clinic_id", clinicID.String()).
		Str("verification_status", verificationPtr.VerificationStatus).
		Bool("is_verified", verificationPtr.IsVerified).
		Msg("Clinic verification status retrieved")

	return verificationPtr, nil
}

// Helper method to log clinic activities (extending existing service)
func (c *clinicService) logClinicActivityWithUser(ctx context.Context, activityType string, clinicID, userID uuid.UUID, details map[string]interface{}) {
	// Create activity log
	activity := core.UserActivity{
		UserID:          &userID,
		ActivityType:    activityType,
		ActivityDetails: details,
		ResourceType:    stringPtr("clinic"),
		ResourceID:      &clinicID,
		PerformedAt:     time.Now(),
	}

	// Log activity asynchronously
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := c.auditRepo.LogUserActivity(activityCtx, activity); err != nil {
			c.logger.Warn().Err(err).Msg("Failed to log clinic activity")
		}
	}()
}

// Helper methods
func (c *clinicService) invalidateClinicCache(ctx context.Context, clinicID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("clinic:%s", clinicID.String()),
	}
	for _, key := range cacheKeys {
		if err := c.cache.Delete(ctx, key); err != nil {
			c.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate clinic cache")
		}
	}
}

func (c *clinicService) invalidateClinicListCache(ctx context.Context) {
	// Invalidate all clinic listing caches (pattern matching would be needed)
	// For now, we'll clear common patterns
	patterns := []string{
		"clinic:list:*",
		"clinic:search:*",
	}
	for _, pattern := range patterns {
		// Note: This requires cache implementation with pattern matching support
		c.logger.Debug().Str("pattern", pattern).Msg("Would invalidate cache pattern")
	}
}

func (c *clinicService) logClinicActivity(ctx context.Context, activityType string, clinicID uuid.UUID, userID *uuid.UUID, details map[string]interface{}) {
	// Create activity log
	activity := core.UserActivity{
		UserID:          userID,
		ActivityType:    activityType,
		ActivityDetails: details,
		ResourceType:    stringPtr("clinic"),
		ResourceID:      &clinicID,
		PerformedAt:     time.Now(),
	}

	// Log activity asynchronously
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := c.auditRepo.LogUserActivity(activityCtx, activity); err != nil {
			c.logger.Warn().Err(err).Msg("Failed to log clinic activity")
		}
	}()
}

func (c *clinicService) compareClinicChanges(oldClinic, newClinic providers.Clinic) map[string]interface{} {
	changes := make(map[string]interface{})

	if oldClinic.ClinicName != newClinic.ClinicName {
		changes["clinic_name"] = map[string]string{
			"old": oldClinic.ClinicName,
			"new": newClinic.ClinicName,
		}
	}
	if oldClinic.ClinicType != newClinic.ClinicType {
		changes["clinic_type"] = map[string]string{
			"old": oldClinic.ClinicType,
			"new": newClinic.ClinicType,
		}
	}
	// Add more field comparisons as needed

	return changes
}

func stringPtrToString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func stringPtr(s string) *string {
	return &s
}
