package providers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type StaffHandler struct {
	staffService service.StaffService
	logger       *zerolog.Logger
	timeout      time.Duration
}

// NewStaffHandler creates a new staff handler
func NewStaffHandler(
	staffService service.StaffService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *StaffHandler {
	return &StaffHandler{
		staffService: staffService,
		logger:       logger,
		timeout:      timeout,
	}
}

// CreateStaff handles staff member creation
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
