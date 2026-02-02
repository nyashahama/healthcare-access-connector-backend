package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/admin"
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
