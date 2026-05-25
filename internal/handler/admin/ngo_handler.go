package admin

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	dtoadmin "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
)

// CreateNGOPartner creates a new NGO partner profile.
// POST /api/v1/admin/ngo-partners
func (h *AdminHandler) CreateNGOPartner(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, dtoadmin.ErrorResponse{Error: "User not authenticated"})
		return
	}
	if claims.Role != "system_admin" {
		handler.RespondJSON(w, http.StatusForbidden, dtoadmin.ErrorResponse{Error: "Insufficient permissions"})
		return
	}

	var req dtoadmin.CreateNGOPartnerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dtoadmin.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	v.ValidateRequired("user_id", req.UserID.String())
	v.ValidateRequired("organization_name", req.OrganizationName)
	v.ValidateRequired("partnership_status", req.PartnershipStatus)
	if req.OrganizationEmail != nil && *req.OrganizationEmail != "" {
		v.ValidateEmail("organization_email", *req.OrganizationEmail)
	}
	if req.ContactPersonEmail != nil && *req.ContactPersonEmail != "" {
		v.ValidateEmail("contact_person_email", *req.ContactPersonEmail)
	}

	validStatuses := map[string]bool{
		"active":       true,
		"suspended":    true,
		"terminated":   true,
		"inactive":     true,
		"under_review": true,
		"pending":      true,
	}
	if !validStatuses[req.PartnershipStatus] {
		v.AddError("partnership_status", "must be one of: active, suspended, terminated, inactive, under_review, pending")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	created, err := h.ngoService.CreateNGOPartner(ctx, req.ToDomain())
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, dtoadmin.ToNGOPartnerResponse(created))
}

// GetNGOPartnerByUserID retrieves an NGO partner profile by user ID.
// GET /api/v1/admin/ngo-partners/user/{user_id}
func (h *AdminHandler) GetNGOPartnerByUserID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, dtoadmin.ErrorResponse{Error: "User not authenticated"})
		return
	}
	if claims.Role != "system_admin" {
		handler.RespondJSON(w, http.StatusForbidden, dtoadmin.ErrorResponse{Error: "Insufficient permissions"})
		return
	}

	userIDStr := chi.URLParam(r, "user_id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, dtoadmin.ErrorResponse{Error: "Invalid user ID format"})
		return
	}

	partner, err := h.ngoService.GetNGOPartnerByUserID(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, dtoadmin.ToNGOPartnerResponse(partner))
}
