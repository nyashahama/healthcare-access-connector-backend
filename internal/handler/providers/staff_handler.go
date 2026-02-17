package providers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	dproviders "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type StaffHandler struct {
	staffService service.StaffService
	userService  service.UserService
	logger       *zerolog.Logger
	timeout      time.Duration
}

// NewStaffHandler creates a new staff handler
func NewStaffHandler(
	staffService service.StaffService,
	userService service.UserService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *StaffHandler {
	return &StaffHandler{
		staffService: staffService,
		userService:  userService,
		logger:       logger,
		timeout:      timeout,
	}
}

// InviteStaff handles sending staff invitations
// POST /api/v1/clinics/{clinic_id}/staff/invite
func (h *StaffHandler) InviteStaff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Get clinic ID from URL
	clinicIDStr := chi.URLParam(r, "clinic_id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	// Get authenticated user from context
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, providers.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	var req providers.InviteStaffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("work_email", req.WorkEmail)
	v.ValidateEmail("work_email", req.WorkEmail)
	v.ValidateRequired("first_name", req.FirstName)
	v.ValidateMinLength("first_name", req.FirstName, 1)
	v.ValidateRequired("last_name", req.LastName)
	v.ValidateMinLength("last_name", req.LastName, 1)
	v.ValidateRequired("staff_role", req.StaffRole)
	v.ValidateEnum("staff_role", req.StaffRole, []string{
		"doctor",
		"nurse",
		"administrator",
		"receptionist",
		"manager",
	})

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Generate invitation token and expiry
	token := generateSecureToken()
	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days

	// Create staff invitation
	invitation := providers.ToStaffInvitation(clinicID, claims.UserID, req, token, expiresAt)

	staff, err := h.staffService.CreateStaffInvitation(ctx, invitation)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Send invitation email asynchronously
	go h.sendInvitationEmail(staff, req.WorkEmail, token)

	response := map[string]interface{}{
		"message":            "Staff invitation sent successfully",
		"invitation_token":   staff.InvitationToken,
		"invitation_expires": staff.InvitationExpires,
		"staff": providers.StaffResponse{
			ID:                     staff.ID,
			ClinicID:               staff.ClinicID,
			FirstName:              staff.FirstName,
			LastName:               staff.LastName,
			WorkEmail:              staff.WorkEmail,
			StaffRole:              staff.StaffRole,
			ProfessionalTitle:      staff.ProfessionalTitle,
			InvitationStatus:       staff.InvitationStatus,
			InvitedBy:              staff.InvitedBy,
			InvitedAt:              staff.InvitedAt,
			InvitationExpires:      staff.InvitationExpires,
			CanManageStaff:         staff.CanManageStaff,
			CanApproveAppointments: staff.CanApproveAppointments,
			CanEditClinicInfo:      staff.CanEditClinicInfo,
		},
	}

	handler.RespondJSON(w, http.StatusCreated, response)
}

// GetInvitationDetails gets staff invitation details by token
// GET /api/v1/staff/invitations/{token}
func (h *StaffHandler) GetInvitationDetails(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	token := chi.URLParam(r, "token")
	if token == "" {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invitation token is required",
		})
		return
	}

	invitationDetails, err := h.staffService.GetStaffInvitationByToken(ctx, token)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	if invitationDetails == nil {
		handler.RespondJSON(w, http.StatusNotFound, providers.ErrorResponse{
			Error: "Invitation not found or expired",
		})
		return
	}

	handler.RespondJSON(w, http.StatusOK, providers.ToStaffInvitationResponse(*invitationDetails))
}

// AcceptInvitation handles accepting a staff invitation
// POST /api/v1/staff/invitations/{token}/accept
func (h *StaffHandler) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	token := chi.URLParam(r, "token")
	if token == "" {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invitation token is required",
		})
		return
	}

	// Get authenticated user from context
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, providers.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	// Accept the invitation
	staff, err := h.staffService.AcceptStaffInvitation(ctx, token, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := map[string]interface{}{
		"message": "Invitation accepted successfully",
		"staff":   providers.ToStaffResponse(staff),
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// DeclineInvitation handles declining a staff invitation
// POST /api/v1/staff/invitations/{token}/decline
func (h *StaffHandler) DeclineInvitation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	token := chi.URLParam(r, "token")
	if token == "" {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invitation token is required",
		})
		return
	}

	if err := h.staffService.DeclineStaffInvitation(ctx, token); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Invitation declined successfully",
	})
}

// GetPendingInvitations lists all pending invitations for a clinic
// GET /api/v1/clinics/{clinic_id}/staff/invitations/pending
func (h *StaffHandler) GetPendingInvitations(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "clinic_id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	invitations, err := h.staffService.GetPendingInvitationsByClinic(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := providers.StaffListResponse{
		Staff: make([]providers.StaffResponse, len(invitations)),
		Total: len(invitations),
	}

	for i, inv := range invitations {
		response.Staff[i] = providers.ToStaffResponse(inv)
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// GetMyInvitations gets all invitations for the authenticated user's email
// GET /api/v1/staff/invitations/my
func (h *StaffHandler) GetMyInvitations(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Get authenticated user from context
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, providers.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	// Get user's email
	user, err := h.userService.GetUserByID(ctx, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	if user.Email == nil || *user.Email == "" {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "User does not have an email address",
		})
		return
	}

	// Get invitations by email
	invitations, err := h.staffService.GetStaffInvitationsByEmail(ctx, *user.Email)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	responses := make([]providers.StaffInvitationResponse, len(invitations))
	for i, inv := range invitations {
		responses[i] = providers.ToStaffInvitationResponse(inv)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"invitations": responses,
		"total":       len(responses),
	})
}

// CancelInvitation cancels a pending staff invitation
// DELETE /api/v1/clinics/{clinic_id}/staff/invitations/{token}
func (h *StaffHandler) CancelInvitation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	token := chi.URLParam(r, "token")
	if token == "" {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invitation token is required",
		})
		return
	}

	// Get authenticated user from context
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, providers.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	if err := h.staffService.CancelStaffInvitation(ctx, token, claims.UserID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Invitation cancelled successfully",
	})
}

// ResendInvitation resends a staff invitation email
// POST /api/v1/clinics/{clinic_id}/staff/invitations/{invitation_id}/resend
func (h *StaffHandler) ResendInvitation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	invitationIDStr := chi.URLParam(r, "invitation_id")
	invitationID, err := uuid.Parse(invitationIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid invitation ID format",
		})
		return
	}

	// Get authenticated user from context
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, providers.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	// Resend invitation
	newToken, err := h.staffService.ResendStaffInvitation(ctx, invitationID, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Get staff details for email
	staff, err := h.staffService.GetStaffByID(ctx, invitationID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Send new invitation email
	go h.sendInvitationEmail(staff, *staff.WorkEmail, newToken)

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message":            "Invitation resent successfully",
		"new_token":          newToken,
		"invitation_expires": staff.InvitationExpires,
	})
}

// CreateStaff handles staff member creation (for backward compatibility)
func (h *StaffHandler) CreateStaff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req providers.CreateStaffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("first_name", req.FirstName)
	v.ValidateMinLength("first_name", req.FirstName, 1)
	v.ValidateRequired("last_name", req.LastName)
	v.ValidateMinLength("last_name", req.LastName, 1)
	v.ValidateRequired("staff_role", req.StaffRole)
	v.ValidateEnum("staff_role", req.StaffRole, []string{
		"doctor",
		"nurse",
		"administrator",
		"receptionist",
		"manager",
	})
	v.ValidateEnum("employment_status", req.EmploymentStatus, []string{
		"active",
		"on_leave",
		"terminated",
	})

	if req.WorkEmail != nil && *req.WorkEmail != "" {
		v.ValidateEmail("work_email", *req.WorkEmail)
	}
	if req.WorkPhone != nil && *req.WorkPhone != "" {
		v.ValidatePhone("work_phone", *req.WorkPhone)
	}
	if req.PersonalPhone != nil && *req.PersonalPhone != "" {
		v.ValidatePhone("personal_phone", *req.PersonalPhone)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Convert DTO to domain model
	staff := providers.ToDomainStaff(req)

	// Create staff member
	createdStaff, err := h.staffService.CreateStaffMember(ctx, staff)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, providers.ToStaffResponse(createdStaff))
}

// GetStaffByUserID handles getting a staff member by their user ID
// GET /api/v1/providers/staff/user/{user_id}
func (h *StaffHandler) GetStaffByUserID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	staff, err := h.staffService.GetStaffByUserID(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, providers.ToStaffResponse(staff))
}

// ListAllClinicStaff handles listing ALL staff for a clinic regardless of status
// GET /api/v1/providers/clinics/{clinic_id}/staff/all
func (h *StaffHandler) ListAllClinicStaff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "clinic_id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	staff, err := h.staffService.GetAllClinicStaff(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := providers.StaffListResponse{
		Staff: make([]providers.StaffResponse, len(staff)),
		Total: len(staff),
	}

	for i, s := range staff {
		response.Staff[i] = providers.ToStaffResponse(s)
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// GetStaff handles getting a staff member by ID
func (h *StaffHandler) GetStaff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffIDStr := chi.URLParam(r, "id")
	staffID, err := uuid.Parse(staffIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid staff ID format",
		})
		return
	}

	staff, err := h.staffService.GetStaffByID(ctx, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, providers.ToStaffResponse(staff))
}

// UpdateStaff handles staff member updates
func (h *StaffHandler) UpdateStaff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffIDStr := chi.URLParam(r, "id")
	staffID, err := uuid.Parse(staffIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid staff ID format",
		})
		return
	}

	var req providers.UpdateStaffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("first_name", req.FirstName)
	v.ValidateMinLength("first_name", req.FirstName, 1)
	v.ValidateRequired("last_name", req.LastName)
	v.ValidateMinLength("last_name", req.LastName, 1)
	v.ValidateEnum("staff_role", req.StaffRole, []string{
		"doctor",
		"nurse",
		"administrator",
		"receptionist",
		"manager",
	})
	v.ValidateEnum("employment_status", req.EmploymentStatus, []string{
		"active",
		"on_leave",
		"terminated",
	})

	if req.WorkEmail != nil && *req.WorkEmail != "" {
		v.ValidateEmail("work_email", *req.WorkEmail)
	}
	if req.WorkPhone != nil && *req.WorkPhone != "" {
		v.ValidatePhone("work_phone", *req.WorkPhone)
	}
	if req.PersonalPhone != nil && *req.PersonalPhone != "" {
		v.ValidatePhone("personal_phone", *req.PersonalPhone)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Get existing staff to preserve clinic_id and user_id
	existingStaff, err := h.staffService.GetStaffByID(ctx, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Update staff with new data
	updated := providers.UpdateToDomainStaff(existingStaff, req)

	// Update staff member
	if err := h.staffService.UpdateStaffMember(ctx, updated); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Fetch updated staff
	updatedStaff, err := h.staffService.GetStaffByID(ctx, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, providers.ToStaffResponse(updatedStaff))
}

// DeleteStaff handles staff member deletion
func (h *StaffHandler) DeleteStaff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffIDStr := chi.URLParam(r, "id")
	staffID, err := uuid.Parse(staffIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid staff ID format",
		})
		return
	}

	if err := h.staffService.DeleteStaffMember(ctx, staffID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Staff member deleted successfully",
	})
}

// ListClinicStaff handles listing staff members for a clinic
func (h *StaffHandler) ListClinicStaff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "clinic_id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	// Get optional role filter
	role := r.URL.Query().Get("role")
	var rolePtr *string
	if role != "" {
		rolePtr = &role
	}

	staff, err := h.staffService.GetClinicStaff(ctx, clinicID, rolePtr)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := providers.StaffListResponse{
		Staff: make([]providers.StaffResponse, len(staff)),
		Total: len(staff),
	}

	for i, s := range staff {
		response.Staff[i] = providers.ToStaffResponse(s)
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// ListActiveClinicStaff handles listing active staff members for a clinic
func (h *StaffHandler) ListActiveClinicStaff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	clinicIDStr := chi.URLParam(r, "clinic_id")
	clinicID, err := uuid.Parse(clinicIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid clinic ID format",
		})
		return
	}

	staff, err := h.staffService.GetActiveClinicStaff(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := providers.StaffListResponse{
		Staff: make([]providers.StaffResponse, len(staff)),
		Total: len(staff),
	}

	for i, s := range staff {
		response.Staff[i] = providers.ToStaffResponse(s)
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// CheckStaffExists handles checking if staff member exists
func (h *StaffHandler) CheckStaffExists(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffIDStr := chi.URLParam(r, "id")
	staffID, err := uuid.Parse(staffIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, providers.ErrorResponse{
			Error: "Invalid staff ID format",
		})
		return
	}

	exists, err := h.staffService.StaffExists(ctx, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]bool{
		"exists": exists,
	})
}

// Helper functions

func generateSecureToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.URLEncoding.EncodeToString(b)
}

func (h *StaffHandler) sendInvitationEmail(staff dproviders.ClinicStaff, email, token string) {
	// TODO: Implement actual email sending using your email service
	// This is a placeholder that should be replaced with actual email service call
	h.logger.Info().
		Str("email", email).
		Str("token", token).
		Str("staff_name", staff.FirstName+" "+staff.LastName).
		Msg("Sending staff invitation email")

	// Example of what the email should contain:
	// - Clinic name
	// - Inviter name
	// - Staff role
	// - Link to accept invitation (e.g., https://your-app.com/staff/invitations/accept?token=TOKEN)
	// - Link to decline invitation
	// - Expiration date
}
