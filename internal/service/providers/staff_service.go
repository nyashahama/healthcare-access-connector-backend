package providers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

type staffService struct {
	staffRepo  repository.StaffRepository
	clinicRepo repository.ClinicRepository
	userRepo   repository.UserRepository
	auditRepo  repository.AuditRepository
	cache      cache.Service
	logger     *zerolog.Logger
}

func NewStaffService(
	staffRepo repository.StaffRepository,
	clinicRepo repository.ClinicRepository,
	userRepo repository.UserRepository,
	auditRepo repository.AuditRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.StaffService {
	return &staffService{
		staffRepo:  staffRepo,
		clinicRepo: clinicRepo,
		userRepo:   userRepo,
		auditRepo:  auditRepo,
		cache:      cache,
		logger:     logger,
	}
}

func (s *staffService) CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("first_name", staff.FirstName).
			Str("last_name", staff.LastName).
			Msg("CreateStaffMember completed")
	}()

	// Validate required fields
	if staff.ClinicID == uuid.Nil {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}
	if *staff.UserID == uuid.Nil {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}
	if staff.FirstName == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "First name is required", 400)
	}
	if staff.LastName == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Last name is required", 400)
	}
	if staff.StaffRole == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Staff role is required", 400)
	}

	// Verify clinic exists
	if _, err := s.clinicRepo.GetClinicByID(ctx, staff.ClinicID); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		s.logger.Error().Err(err).Str("clinic_id", staff.ClinicID.String()).Msg("Failed to get clinic")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to verify clinic", 500)
	}

	// Verify user exists
	if _, err := s.userRepo.GetUserByID(ctx, *staff.UserID); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrUserNotFound, "User not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", staff.UserID.String()).Msg("Failed to get user")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to verify user", 500)
	}

	// Set timestamps and status
	now := time.Now()
	staff.ID = uuid.New()
	staff.EmploymentStatus = "active"
	staff.CreatedAt = now
	staff.UpdatedAt = now

	// Create staff member
	createdStaff, err := s.staffRepo.CreateStaffMember(ctx, staff)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateUserStaff) {
			return providers.ClinicStaff{}, domain.NewAppError(err, "User is already a staff member", 409)
		}
		if errors.Is(err, domain.ErrDuplicateStaffEmail) {
			return providers.ClinicStaff{}, domain.NewAppError(err, "Work email already exists", 409)
		}
		if errors.Is(err, domain.ErrDuplicateHPCSNumber) {
			return providers.ClinicStaff{}, domain.NewAppError(err, "HPCS number already exists", 409)
		}
		s.logger.Error().Err(err).
			Str("user_id", staff.UserID.String()).
			Str("clinic_id", staff.ClinicID.String()).
			Msg("Failed to create staff member")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to create staff member", 500)
	}

	// Invalidate cache
	s.invalidateStaffCache(ctx, createdStaff.ID, createdStaff.ClinicID)

	// Log audit activity
	s.logStaffActivity(ctx, "staff_created", createdStaff.ID, createdStaff.ClinicID, map[string]interface{}{
		"clinic_id":  createdStaff.ClinicID,
		"staff_role": createdStaff.StaffRole,
		"first_name": createdStaff.FirstName,
		"last_name":  createdStaff.LastName,
	})

	s.logger.Info().
		Str("staff_id", createdStaff.ID.String()).
		Str("user_id", createdStaff.UserID.String()).
		Str("clinic_id", createdStaff.ClinicID.String()).
		Str("role", createdStaff.StaffRole).
		Msg("Staff member created successfully")

	return createdStaff, nil
}

// CreateStaffInvitation creates a pending staff invitation
func (s *staffService) CreateStaffInvitation(ctx context.Context, invitation providers.StaffInvitation) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("work_email", invitation.WorkEmail).
			Str("clinic_id", invitation.ClinicID.String()).
			Msg("CreateStaffInvitation completed")
	}()

	// Validate required fields
	if invitation.ClinicID == uuid.Nil {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}
	if invitation.WorkEmail == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Work email is required", 400)
	}
	if invitation.FirstName == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "First name is required", 400)
	}
	if invitation.LastName == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Last name is required", 400)
	}
	if invitation.StaffRole == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Staff role is required", 400)
	}
	if invitation.InvitedBy == uuid.Nil {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "InvitedBy user ID is required", 400)
	}

	// Verify clinic exists
	if _, err := s.clinicRepo.GetClinicByID(ctx, invitation.ClinicID); err != nil {
		if errors.Is(err, domain.ErrClinicNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrClinicNotFound, "Clinic not found", 404)
		}
		s.logger.Error().Err(err).Str("clinic_id", invitation.ClinicID.String()).Msg("Failed to get clinic")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to verify clinic", 500)
	}

	// Verify inviter exists
	if _, err := s.userRepo.GetUserByID(ctx, invitation.InvitedBy); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrUserNotFound, "Inviter not found", 404)
		}
		s.logger.Error().Err(err).Str("invited_by", invitation.InvitedBy.String()).Msg("Failed to get inviter")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to verify inviter", 500)
	}

	// Check if email already exists for this clinic
	exists, err := s.staffRepo.CheckStaffEmailExists(ctx, invitation.ClinicID, invitation.WorkEmail)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to check staff email existence")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to check email", 500)
	}
	if exists {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrDuplicateStaffEmail, "Staff member with this email already exists", 409)
	}

	// Generate invitation token if not provided
	if invitation.InvitationToken == "" {
		invitation.InvitationToken = s.generateInvitationToken()
	}

	// Set invitation expiry if not provided (7 days default)
	if invitation.InvitationExpires.IsZero() {
		invitation.InvitationExpires = time.Now().Add(7 * 24 * time.Hour)
	}

	// Create staff invitation in repository
	staff, err := s.staffRepo.CreateStaffInvitation(ctx, invitation)
	if err != nil {
		if errors.Is(err, domain.ErrDuplicateStaffEmail) {
			return providers.ClinicStaff{}, domain.NewAppError(err, "Work email already exists", 409)
		}
		s.logger.Error().Err(err).
			Str("work_email", invitation.WorkEmail).
			Str("clinic_id", invitation.ClinicID.String()).
			Msg("Failed to create staff invitation")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to create invitation", 500)
	}

	// Invalidate cache
	s.invalidateStaffCache(ctx, staff.ID, staff.ClinicID)

	// Log audit activity
	s.logStaffActivity(ctx, "staff_invitation_created", staff.ID, invitation.InvitedBy, map[string]interface{}{
		"clinic_id":  staff.ClinicID,
		"work_email": invitation.WorkEmail,
		"staff_role": staff.StaffRole,
		"invited_by": invitation.InvitedBy.String(),
		"expires_at": invitation.InvitationExpires,
	})

	s.logger.Info().
		Str("staff_id", staff.ID.String()).
		Str("work_email", invitation.WorkEmail).
		Str("clinic_id", staff.ClinicID.String()).
		Msg("Staff invitation created successfully")

	return staff, nil
}

// GetStaffInvitationByToken retrieves invitation details by token
func (s *staffService) GetStaffInvitationByToken(ctx context.Context, token string) (*providers.StaffInvitationDetails, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("GetStaffInvitationByToken completed")
	}()

	// Validate token
	if token == "" {
		return nil, domain.NewAppError(domain.ErrValidation, "Invitation token is required", 400)
	}

	// Fetch invitation from repository (returns *providers.StaffInvitationDetails)
	invitation, err := s.staffRepo.GetStaffInvitationByToken(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrInvitationNotFound) {
			return nil, domain.NewAppError(domain.ErrInvitationNotFound, "Invitation not found", 404)
		}
		s.logger.Error().Err(err).Msg("Failed to get staff invitation by token")
		return nil, domain.NewAppError(err, "Failed to get invitation", 500)
	}

	s.logger.Debug().
		Str("clinic_id", invitation.ClinicID.String()).
		Str("work_email", invitation.WorkEmail).
		Msg("Staff invitation retrieved by token")

	return invitation, nil
}

// AcceptStaffInvitation links a user account to an accepted invitation
func (s *staffService) AcceptStaffInvitation(ctx context.Context, token string, userID uuid.UUID) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Msg("AcceptStaffInvitation completed")
	}()

	// Validate inputs
	if token == "" {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "Invitation token is required", 400)
	}
	if userID == uuid.Nil {
		return providers.ClinicStaff{}, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}

	// Verify user exists
	if _, err := s.userRepo.GetUserByID(ctx, userID); err != nil {
		if errors.Is(err, domain.ErrUserNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrUserNotFound, "User not found", 404)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to get user")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to verify user", 500)
	}

	// Get invitation details first to return the staff member
	invitationDetails, err := s.staffRepo.GetStaffInvitationByToken(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrInvitationNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrInvitationNotFound, "Invitation not found", 404)
		}
		s.logger.Error().Err(err).Msg("Failed to get invitation details")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to get invitation", 500)
	}

	// Accept invitation in repository (returns error only)
	if err := s.staffRepo.AcceptStaffInvitation(ctx, token, userID); err != nil {
		if errors.Is(err, domain.ErrInvitationNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrInvitationNotFound, "Invitation not found", 404)
		}
		if errors.Is(err, domain.ErrInvitationExpired) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrInvitationExpired, "Invitation has expired", 410)
		}
		if errors.Is(err, domain.ErrInvitationAlreadyAccepted) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrInvitationAlreadyAccepted, "Invitation already accepted", 409)
		}
		s.logger.Error().Err(err).Str("user_id", userID.String()).Msg("Failed to accept staff invitation")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to accept invitation", 500)
	}

	// Get the updated staff member
	staff, err := s.staffRepo.GetStaffByUserAndClinic(ctx, userID, invitationDetails.ClinicID)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get staff after accepting invitation")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Invalidate cache
	s.invalidateStaffCache(ctx, staff.ID, staff.ClinicID)

	// Log audit activity
	s.logStaffActivity(ctx, "staff_invitation_accepted", staff.ID, userID, map[string]interface{}{
		"clinic_id":  staff.ClinicID,
		"staff_role": staff.StaffRole,
		"user_id":    userID.String(),
	})

	s.logger.Info().
		Str("staff_id", staff.ID.String()).
		Str("user_id", userID.String()).
		Str("clinic_id", staff.ClinicID.String()).
		Msg("Staff invitation accepted successfully")

	return *staff, nil
}

// DeclineStaffInvitation marks an invitation as declined
func (s *staffService) DeclineStaffInvitation(ctx context.Context, token string) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("DeclineStaffInvitation completed")
	}()

	// Validate token
	if token == "" {
		return domain.NewAppError(domain.ErrValidation, "Invitation token is required", 400)
	}

	// Decline invitation in repository
	if err := s.staffRepo.DeclineStaffInvitation(ctx, token); err != nil {
		if errors.Is(err, domain.ErrInvitationNotFound) {
			return domain.NewAppError(domain.ErrInvitationNotFound, "Invitation not found", 404)
		}
		s.logger.Error().Err(err).Msg("Failed to decline staff invitation")
		return domain.NewAppError(err, "Failed to decline invitation", 500)
	}

	s.logger.Info().Msg("Staff invitation declined successfully")
	return nil
}

// GetPendingInvitationsByClinic retrieves all pending invitations for a clinic
func (s *staffService) GetPendingInvitationsByClinic(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Msg("GetPendingInvitationsByClinic completed")
	}()

	// Validate clinic ID
	if clinicID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("staff:clinic:%s:invitations:pending", clinicID.String())
	var invitations []providers.ClinicStaff
	if err := s.cache.Get(ctx, cacheKey, &invitations); err == nil {
		s.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Pending invitations retrieved from cache")
		return invitations, nil
	}

	// Fetch from repository
	invitations, err := s.staffRepo.GetPendingInvitationsByClinic(ctx, clinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get pending invitations")
		return nil, domain.NewAppError(err, "Failed to get pending invitations", 500)
	}

	// Cache the result (shorter TTL for invitations)
	if err := s.cache.Set(ctx, cacheKey, invitations, 2*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache pending invitations")
	}

	s.logger.Debug().
		Str("clinic_id", clinicID.String()).
		Int("invitation_count", len(invitations)).
		Msg("Pending invitations retrieved")

	return invitations, nil
}

// GetStaffInvitationsByEmail retrieves all invitations for a specific email
func (s *staffService) GetStaffInvitationsByEmail(ctx context.Context, email string) ([]providers.StaffInvitationDetails, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("email", email).
			Msg("GetStaffInvitationsByEmail completed")
	}()

	// Validate email
	if email == "" {
		return nil, domain.NewAppError(domain.ErrValidation, "Email is required", 400)
	}

	// Fetch from repository
	invitations, err := s.staffRepo.GetStaffInvitationsByEmail(ctx, email)
	if err != nil {
		s.logger.Error().Err(err).Str("email", email).Msg("Failed to get staff invitations by email")
		return nil, domain.NewAppError(err, "Failed to get invitations", 500)
	}

	s.logger.Debug().
		Str("email", email).
		Int("invitation_count", len(invitations)).
		Msg("Staff invitations retrieved by email")

	return invitations, nil
}

// CancelStaffInvitation cancels a pending invitation using token
func (s *staffService) CancelStaffInvitation(ctx context.Context, token string, cancelledBy uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("CancelStaffInvitation completed")
	}()

	// Validate inputs
	if token == "" {
		return domain.NewAppError(domain.ErrValidation, "Invitation token is required", 400)
	}
	if cancelledBy == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "CancelledBy user ID is required", 400)
	}

	// Get invitation details for audit logging
	invitationDetails, err := s.staffRepo.GetStaffInvitationByToken(ctx, token)
	if err != nil {
		if errors.Is(err, domain.ErrInvitationNotFound) {
			return domain.NewAppError(domain.ErrInvitationNotFound, "Staff invitation not found", 404)
		}
		return domain.NewAppError(err, "Failed to get staff invitation", 500)
	}

	// Cancel invitation in repository (uses token instead of staffID)
	if err := s.staffRepo.CancelStaffInvitation(ctx, token); err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return domain.NewAppError(domain.ErrStaffNotFound, "Staff invitation not found", 404)
		}
		s.logger.Error().Err(err).Msg("Failed to cancel staff invitation")
		return domain.NewAppError(err, "Failed to cancel invitation", 500)
	}

	// Log audit activity
	s.logStaffActivity(ctx, "staff_invitation_cancelled", invitationDetails.ClinicID, cancelledBy, map[string]interface{}{
		"clinic_id":    invitationDetails.ClinicID,
		"work_email":   invitationDetails.WorkEmail,
		"cancelled_by": cancelledBy.String(),
	})

	s.logger.Info().
		Str("cancelled_by", cancelledBy.String()).
		Str("work_email", invitationDetails.WorkEmail).
		Msg("Staff invitation cancelled successfully")

	return nil
}

// ResendStaffInvitation generates a new token and extends expiry for an invitation
func (s *staffService) ResendStaffInvitation(ctx context.Context, invitationID uuid.UUID, resentBy uuid.UUID) (string, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("invitation_id", invitationID.String()).
			Msg("ResendStaffInvitation completed")
	}()

	// Validate IDs
	if invitationID == uuid.Nil {
		return "", domain.NewAppError(domain.ErrValidation, "Invitation ID is required", 400)
	}
	if resentBy == uuid.Nil {
		return "", domain.NewAppError(domain.ErrValidation, "ResentBy user ID is required", 400)
	}

	// Get staff for validation
	staff, err := s.staffRepo.GetStaffByID(ctx, invitationID)
	if err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return "", domain.NewAppError(domain.ErrStaffNotFound, "Staff invitation not found", 404)
		}
		return "", domain.NewAppError(err, "Failed to get staff invitation", 500)
	}

	// Verify it's still a pending invitation
	if staff.InvitationStatus == nil || *staff.InvitationStatus != providers.InvitationStatusPending {
		return "", domain.NewAppError(domain.ErrValidation, "Only pending invitations can be resent", 400)
	}

	// Resend invitation in repository (generates new token internally)
	newToken, err := s.staffRepo.ResendStaffInvitation(ctx, invitationID)
	if err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return "", domain.NewAppError(domain.ErrStaffNotFound, "Staff invitation not found", 404)
		}
		s.logger.Error().Err(err).Str("invitation_id", invitationID.String()).Msg("Failed to resend staff invitation")
		return "", domain.NewAppError(err, "Failed to resend invitation", 500)
	}

	// Invalidate cache
	s.invalidateStaffCache(ctx, invitationID, staff.ClinicID)

	// Log audit activity
	s.logStaffActivity(ctx, "staff_invitation_resent", invitationID, resentBy, map[string]interface{}{
		"clinic_id":  staff.ClinicID,
		"work_email": stringPtrToString(staff.WorkEmail),
		"resent_by":  resentBy.String(),
	})

	s.logger.Info().
		Str("invitation_id", invitationID.String()).
		Str("resent_by", resentBy.String()).
		Msg("Staff invitation resent successfully")

	return newToken, nil
}

// GetStaffByUserAndClinic retrieves a staff record by user ID and clinic ID
func (s *staffService) GetStaffByUserAndClinic(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("user_id", userID.String()).
			Str("clinic_id", clinicID.String()).
			Msg("GetStaffByUserAndClinic completed")
	}()

	// Validate IDs
	if userID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrValidation, "User ID is required", 400)
	}
	if clinicID == uuid.Nil {
		return nil, domain.NewAppError(domain.ErrValidation, "Clinic ID is required", 400)
	}

	// Try cache first
	cacheKey := fmt.Sprintf("staff:user:%s:clinic:%s", userID.String(), clinicID.String())
	var staff providers.ClinicStaff
	if err := s.cache.Get(ctx, cacheKey, &staff); err == nil {
		s.logger.Debug().
			Str("user_id", userID.String()).
			Str("clinic_id", clinicID.String()).
			Msg("Staff retrieved from cache")
		return &staff, nil
	}

	// Fetch from repository (returns *providers.ClinicStaff)
	staffPtr, err := s.staffRepo.GetStaffByUserAndClinic(ctx, userID, clinicID)
	if err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return nil, domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		s.logger.Error().Err(err).
			Str("user_id", userID.String()).
			Str("clinic_id", clinicID.String()).
			Msg("Failed to get staff by user and clinic")
		return nil, domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, *staffPtr, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache staff")
	}

	s.logger.Debug().
		Str("staff_id", staffPtr.ID.String()).
		Str("user_id", userID.String()).
		Str("clinic_id", clinicID.String()).
		Msg("Staff retrieved by user and clinic")

	return staffPtr, nil
}

// UpdateStaffPermissions updates permissions for a staff member
func (s *staffService) UpdateStaffPermissions(ctx context.Context, staffID uuid.UUID, permissions providers.StaffPermissions, updatedBy uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", staffID.String()).
			Msg("UpdateStaffPermissions completed")
	}()

	// Validate IDs
	if staffID == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "Staff ID is required", 400)
	}
	if updatedBy == uuid.Nil {
		return domain.NewAppError(domain.ErrValidation, "UpdatedBy user ID is required", 400)
	}

	// Get existing staff for audit logging
	staff, err := s.staffRepo.GetStaffByID(ctx, staffID)
	if err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		return domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Update permissions in repository
	if err := s.staffRepo.UpdateStaffPermissions(ctx, staffID, permissions); err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to update staff permissions")
		return domain.NewAppError(err, "Failed to update permissions", 500)
	}

	// Invalidate cache
	s.invalidateStaffCache(ctx, staffID, staff.ClinicID)

	// Log audit activity
	s.logStaffActivity(ctx, "staff_permissions_updated", staffID, updatedBy, map[string]interface{}{
		"clinic_id":                staff.ClinicID,
		"can_manage_staff":         permissions.CanManageStaff,
		"can_approve_appointments": permissions.CanApproveAppointments,
		"can_edit_clinic_info":     permissions.CanEditClinicInfo,
		"updated_by":               updatedBy.String(),
	})

	s.logger.Info().
		Str("staff_id", staffID.String()).
		Str("updated_by", updatedBy.String()).
		Msg("Staff permissions updated successfully")

	return nil
}

// ExpireStaffInvitations marks expired invitations (typically run as a background job)
func (s *staffService) ExpireStaffInvitations(ctx context.Context) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("ExpireStaffInvitations completed")
	}()

	// Expire invitations in repository (returns error only, not count)
	if err := s.staffRepo.ExpireStaffInvitations(ctx); err != nil {
		s.logger.Error().Err(err).Msg("Failed to expire staff invitations")
		return domain.NewAppError(err, "Failed to expire invitations", 500)
	}

	s.logger.Info().Msg("Staff invitations expired successfully")
	return nil
}

func (s *staffService) GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", id.String()).
			Msg("GetStaffByID completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("staff:%s", id.String())
	var staff providers.ClinicStaff
	if err := s.cache.Get(ctx, cacheKey, &staff); err == nil {
		s.logger.Debug().Str("staff_id", id.String()).Msg("Staff retrieved from cache")
		return staff, nil
	}

	// Fetch from database
	staff, err := s.staffRepo.GetStaffByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return providers.ClinicStaff{}, domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		s.logger.Error().Err(err).Str("staff_id", id.String()).Msg("Failed to get staff member")
		return providers.ClinicStaff{}, domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, staff, 10*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache staff")
	}

	return staff, nil
}

func (s *staffService) UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", staff.ID.String()).
			Msg("UpdateStaffMember completed")
	}()

	// Validate required fields
	if staff.FirstName == "" {
		return domain.NewAppError(domain.ErrValidation, "First name is required", 400)
	}
	if staff.LastName == "" {
		return domain.NewAppError(domain.ErrValidation, "Last name is required", 400)
	}

	// Get existing staff to compare changes
	existing, err := s.staffRepo.GetStaffByID(ctx, staff.ID)
	if err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		return domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Update staff member
	if err := s.staffRepo.UpdateStaffMember(ctx, staff); err != nil {
		s.logger.Error().Err(err).Str("staff_id", staff.ID.String()).Msg("Failed to update staff member")
		return domain.NewAppError(err, "Failed to update staff member", 500)
	}

	// Invalidate cache
	s.invalidateStaffCache(ctx, staff.ID, staff.ClinicID)

	// Log audit activity
	s.logStaffActivity(ctx, "staff_updated", staff.ID, staff.ID, map[string]interface{}{
		"clinic_id": staff.ClinicID,
		"changes":   s.compareStaffChanges(existing, staff),
	})

	s.logger.Info().
		Str("staff_id", staff.ID.String()).
		Str("first_name", staff.FirstName).
		Str("last_name", staff.LastName).
		Msg("Staff member updated successfully")

	return nil
}

func (s *staffService) DeleteStaffMember(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", id.String()).
			Msg("DeleteStaffMember completed")
	}()

	// Get staff first for audit logging
	staff, err := s.staffRepo.GetStaffByID(ctx, id)
	if err != nil && !errors.Is(err, domain.ErrStaffNotFound) {
		s.logger.Error().Err(err).Str("staff_id", id.String()).Msg("Failed to get staff member for deletion")
		return domain.NewAppError(err, "Failed to get staff member", 500)
	}

	// Delete staff member
	if err := s.staffRepo.DeleteStaffMember(ctx, id); err != nil {
		if errors.Is(err, domain.ErrStaffNotFound) {
			return domain.NewAppError(domain.ErrStaffNotFound, "Staff member not found", 404)
		}
		s.logger.Error().Err(err).Str("staff_id", id.String()).Msg("Failed to delete staff member")
		return domain.NewAppError(err, "Failed to delete staff member", 500)
	}

	// Invalidate cache
	if staff.ID != uuid.Nil {
		s.invalidateStaffCache(ctx, staff.ID, staff.ClinicID)
	}

	// Log audit activity
	if staff.ID != uuid.Nil {
		s.logStaffActivity(ctx, "staff_deleted", id, staff.ID, map[string]interface{}{
			"clinic_id":  staff.ClinicID,
			"first_name": staff.FirstName,
			"last_name":  staff.LastName,
		})
	}

	s.logger.Info().
		Str("staff_id", id.String()).
		Msg("Staff member deleted successfully")

	return nil
}

func (s *staffService) GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Str("role", stringPtrToString(role)).
			Msg("GetClinicStaff completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("staff:clinic:%s:role:%s", clinicID.String(), stringPtrToString(role))
	var staff []providers.ClinicStaff
	if err := s.cache.Get(ctx, cacheKey, &staff); err == nil {
		s.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Clinic staff retrieved from cache")
		return staff, nil
	}

	// Get clinic staff
	staff, err := s.staffRepo.GetClinicStaff(ctx, clinicID, role)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get clinic staff")
		return nil, domain.NewAppError(err, "Failed to get clinic staff", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, staff, 5*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache clinic staff")
	}

	s.logger.Debug().
		Str("clinic_id", clinicID.String()).
		Int("staff_count", len(staff)).
		Msg("Clinic staff retrieved")

	return staff, nil
}

func (s *staffService) GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("clinic_id", clinicID.String()).
			Msg("GetActiveClinicStaff completed")
	}()

	// Try cache first
	cacheKey := fmt.Sprintf("staff:clinic:%s:active", clinicID.String())
	var staff []providers.ClinicStaff
	if err := s.cache.Get(ctx, cacheKey, &staff); err == nil {
		s.logger.Debug().Str("clinic_id", clinicID.String()).Msg("Active clinic staff retrieved from cache")
		return staff, nil
	}

	// Get active clinic staff
	staff, err := s.staffRepo.GetActiveClinicStaff(ctx, clinicID)
	if err != nil {
		s.logger.Error().Err(err).Str("clinic_id", clinicID.String()).Msg("Failed to get active clinic staff")
		return nil, domain.NewAppError(err, "Failed to get active clinic staff", 500)
	}

	// Cache the result
	if err := s.cache.Set(ctx, cacheKey, staff, 5*time.Minute); err != nil {
		s.logger.Warn().Err(err).Msg("Failed to cache active clinic staff")
	}

	s.logger.Debug().
		Str("clinic_id", clinicID.String()).
		Int("active_staff_count", len(staff)).
		Msg("Active clinic staff retrieved")

	return staff, nil
}

func (s *staffService) StaffExists(ctx context.Context, id uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("staff_id", id.String()).
			Msg("StaffExists completed")
	}()

	exists, err := s.staffRepo.StaffExists(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("staff_id", id.String()).Msg("Failed to check if staff exists")
		return false, domain.NewAppError(err, "Failed to check staff existence", 500)
	}

	return exists, nil
}

// Helper methods
func (s *staffService) invalidateStaffCache(ctx context.Context, staffID, clinicID uuid.UUID) {
	cacheKeys := []string{
		fmt.Sprintf("staff:%s", staffID.String()),
		fmt.Sprintf("staff:user:*"), // Need user ID to be more specific
		fmt.Sprintf("staff:clinic:%s:*", clinicID.String()),
	}

	for _, pattern := range cacheKeys {
		// Note: This requires cache implementation with pattern matching support
		s.logger.Debug().Str("pattern", pattern).Msg("Would invalidate staff cache pattern")
	}
}

func (s *staffService) logStaffActivity(ctx context.Context, activityType string, staffID, userID uuid.UUID, details map[string]interface{}) {
	// Create activity log
	activity := core.UserActivity{
		UserID:          &userID,
		ActivityType:    activityType,
		ActivityDetails: details,
		ResourceType:    stringPtr("staff"),
		ResourceID:      &staffID,
		PerformedAt:     time.Now(),
	}

	// Log activity asynchronously
	go func() {
		activityCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.auditRepo.LogUserActivity(activityCtx, activity); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to log staff activity")
		}
	}()
}

func (s *staffService) compareStaffChanges(oldStaff, newStaff providers.ClinicStaff) map[string]interface{} {
	changes := make(map[string]interface{})

	if oldStaff.FirstName != newStaff.FirstName {
		changes["first_name"] = map[string]string{
			"old": oldStaff.FirstName,
			"new": newStaff.FirstName,
		}
	}
	if oldStaff.LastName != newStaff.LastName {
		changes["last_name"] = map[string]string{
			"old": oldStaff.LastName,
			"new": newStaff.LastName,
		}
	}
	if stringPtrToString(oldStaff.ProfessionalTitle) != stringPtrToString(newStaff.ProfessionalTitle) {
		changes["professional_title"] = map[string]string{
			"old": stringPtrToString(oldStaff.ProfessionalTitle),
			"new": stringPtrToString(newStaff.ProfessionalTitle),
		}
	}
	// Add more field comparisons as needed

	return changes
}

// Helper function to generate secure invitation token
func (s *staffService) generateInvitationToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}
