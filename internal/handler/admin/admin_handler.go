package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	adminDomain "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type AdminHandler struct {
	adminService service.SystemAdminService
	logger       *zerolog.Logger
	timeout      time.Duration
}

// NewAdminHandler creates a new admin handler
func NewAdminHandler(
	adminService service.SystemAdminService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *AdminHandler {
	return &AdminHandler{
		adminService: adminService,
		logger:       logger,
		timeout:      timeout,
	}
}

// CreateSystemAdmin creates a new system admin profile
func (h *AdminHandler) CreateSystemAdmin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, admin.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	if claims.Role != "system_admin" {
		handler.RespondJSON(w, http.StatusForbidden, admin.ErrorResponse{
			Error: "Insufficient permissions",
		})
		return
	}

	var req admin.CreateSystemAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, admin.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("user_id", req.UserID.String())
	v.ValidateRequired("admin_level", req.AdminLevel)

	// Validate admin level
	validLevels := map[string]bool{
		"super_admin":  true,
		"regional":     true,
		"departmental": true,
		"support":      true,
	}
	if !validLevels[req.AdminLevel] {
		v.AddError("admin_level", "must be one of: super_admin, regional, departmental, support")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Convert request to domain model
	sysAdmin := req.ToDomain()

	// Create system admin
	created, err := h.adminService.CreateSystemAdmin(ctx, sysAdmin)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, admin.ToSystemAdminResponse(created))
}

// GetSystemAdminByUserID retrieves a system admin profile by user ID
// GET /api/v1/admin/system-admins/user/{user_id}
func (h *AdminHandler) GetSystemAdminByUserID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, admin.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	if claims.Role != "system_admin" {
		handler.RespondJSON(w, http.StatusForbidden, admin.ErrorResponse{
			Error: "Insufficient permissions",
		})
		return
	}

	userIDStr := chi.URLParam(r, "user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, admin.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	sysAdmin, err := h.adminService.GetSystemAdminByUserID(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, admin.ToSystemAdminResponse(sysAdmin))
}

// GetSystemAdmin retrieves a system admin profile by system admin ID
// GET /api/v1/admin/system-admins/{id}
func (h *AdminHandler) GetSystemAdmin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, admin.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	if claims.Role != "system_admin" {
		handler.RespondJSON(w, http.StatusForbidden, admin.ErrorResponse{
			Error: "Insufficient permissions",
		})
		return
	}

	adminIDStr := chi.URLParam(r, "id")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, admin.ErrorResponse{
			Error: "Invalid system admin ID format",
		})
		return
	}

	sysAdmin, err := h.adminService.GetSystemAdmin(ctx, adminID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, admin.ToSystemAdminResponse(sysAdmin))
}

// UpdateSystemAdmin updates a system admin profile
// PUT /api/v1/admin/system-admins/{id}
func (h *AdminHandler) UpdateSystemAdmin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, admin.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	if claims.Role != "system_admin" {
		handler.RespondJSON(w, http.StatusForbidden, admin.ErrorResponse{
			Error: "Insufficient permissions",
		})
		return
	}

	adminIDStr := chi.URLParam(r, "id")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, admin.ErrorResponse{
			Error: "Invalid system admin ID format",
		})
		return
	}

	var req admin.UpdateSystemAdminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, admin.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	if errs := validateAdminUpdateRequest(req); len(errs) > 0 {
		handler.RespondValidationError(w, errs)
		return
	}

	existing, err := h.adminService.GetSystemAdmin(ctx, adminID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	update := existing
	update.ID = adminID
	update.UpdatedAt = existing.UpdatedAt

	if req.AdminLevel != nil {
		if !isValidAdminLevel(*req.AdminLevel) {
			handler.RespondJSON(w, http.StatusBadRequest, admin.ErrorResponse{
				Error: "admin_level must be one of: super_admin, regional, departmental, support",
			})
			return
		}
		update.AdminLevel = *req.AdminLevel
	}
	if req.AssignedRegions != nil {
		update.AssignedRegions = req.AssignedRegions
	}
	if req.Department != nil {
		update.Department = req.Department
	}
	if req.Permissions != nil {
		update.Permissions = req.Permissions
	}
	if req.CanManageUsers != nil {
		update.CanManageUsers = *req.CanManageUsers
	}
	if req.CanManageClinics != nil {
		update.CanManageClinics = *req.CanManageClinics
	}
	if req.CanManageContent != nil {
		update.CanManageContent = *req.CanManageContent
	}
	if req.CanViewAnalytics != nil {
		update.CanViewAnalytics = *req.CanViewAnalytics
	}
	if req.CanManageSystem != nil {
		update.CanManageSystem = *req.CanManageSystem
	}
	if req.WorkPhone != nil {
		update.WorkPhone = req.WorkPhone
	}
	if req.Extension != nil {
		update.Extension = req.Extension
	}

	updated, err := h.adminService.UpdateSystemAdmin(ctx, update)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, admin.ToSystemAdminResponse(updated))
}

// DeleteSystemAdmin deletes a system admin profile by system admin ID
// DELETE /api/v1/admin/system-admins/{id}
func (h *AdminHandler) DeleteSystemAdmin(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, admin.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	if claims.Role != "system_admin" {
		handler.RespondJSON(w, http.StatusForbidden, admin.ErrorResponse{
			Error: "Insufficient permissions",
		})
		return
	}

	adminIDStr := chi.URLParam(r, "id")
	adminID, err := uuid.Parse(adminIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, admin.ErrorResponse{
			Error: "Invalid system admin ID format",
		})
		return
	}

	if err := h.adminService.DeleteSystemAdmin(ctx, adminID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "System admin deleted successfully",
	})
}

// DeleteSystemAdminByUserID deletes a system admin profile by user ID
// DELETE /api/v1/admin/system-admins/user/{user_id}
func (h *AdminHandler) DeleteSystemAdminByUserID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, admin.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	if claims.Role != "system_admin" {
		handler.RespondJSON(w, http.StatusForbidden, admin.ErrorResponse{
			Error: "Insufficient permissions",
		})
		return
	}

	userIDStr := chi.URLParam(r, "user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, admin.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	if err := h.adminService.DeleteSystemAdminByUserID(ctx, userID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "System admin deleted successfully",
	})
}

// SearchSystemAdmins searches for system admins using filters
// GET /api/v1/admin/system-admins/search
func (h *AdminHandler) SearchSystemAdmins(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, admin.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	if claims.Role != "system_admin" {
		handler.RespondJSON(w, http.StatusForbidden, admin.ErrorResponse{
			Error: "Insufficient permissions",
		})
		return
	}

	limitStr := strings.TrimSpace(r.URL.Query().Get("limit"))
	limit := 50
	if limitStr != "" {
		parsed, err := strconv.Atoi(limitStr)
		if err == nil && parsed > 0 {
			limit = parsed
		}
	}

	offsetStr := strings.TrimSpace(r.URL.Query().Get("offset"))
	offset := 0
	if offsetStr != "" {
		parsed, err := strconv.Atoi(offsetStr)
		if err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	params := adminDomain.SystemAdminSearchParams{
		AdminLevel: strings.TrimSpace(r.URL.Query().Get("admin_level")),
		Region:     strings.TrimSpace(r.URL.Query().Get("region")),
		Department: strings.TrimSpace(r.URL.Query().Get("department")),
		Query:      strings.TrimSpace(r.URL.Query().Get("query")),
		Limit:      limit,
		Offset:     offset,
	}

	if params.AdminLevel != "" && !isValidAdminLevel(params.AdminLevel) {
		handler.RespondJSON(w, http.StatusBadRequest, admin.ErrorResponse{
			Error: "admin_level must be one of: super_admin, regional, departmental, support",
		})
		return
	}

	results, err := h.adminService.SearchSystemAdmins(ctx, params)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := make([]admin.SystemAdminResponse, 0, len(results))
	for _, sysAdmin := range results {
		response = append(response, admin.ToSystemAdminResponse(sysAdmin))
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

func validateAdminUpdateRequest(req admin.UpdateSystemAdminRequest) []validator.ValidationError {
	errors := []validator.ValidationError{}
	hasField := false
	if req.AdminLevel != nil {
		hasField = true
		if !isValidAdminLevel(*req.AdminLevel) {
			errors = append(errors, validator.ValidationError{
				Field: "admin_level",
				Message: "must be one of: super_admin, regional, departmental, support",
			})
		}
	}
	if req.AssignedRegions != nil {
		hasField = true
	}
	if req.Department != nil {
		hasField = true
	}
	if req.Permissions != nil {
		hasField = true
	}
	if req.CanManageUsers != nil {
		hasField = true
	}
	if req.CanManageClinics != nil {
		hasField = true
	}
	if req.CanManageContent != nil {
		hasField = true
	}
	if req.CanViewAnalytics != nil {
		hasField = true
	}
	if req.CanManageSystem != nil {
		hasField = true
	}
	if req.WorkPhone != nil {
		hasField = true
	}
	if req.Extension != nil {
		hasField = true
	}

	if !hasField {
		errors = append(errors, validator.ValidationError{
			Field: "_form",
			Message: "No updatable fields provided",
		})
	}
	return errors
}

func isValidAdminLevel(level string) bool {
	validLevels := map[string]bool{
		"super_admin":  true,
		"regional":     true,
		"departmental": true,
		"support":      true,
	}
	return validLevels[level]
}
