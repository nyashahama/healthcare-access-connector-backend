package telemedicine

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	telemeddto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

// ProviderAvailabilityHandler handles all provider availability HTTP endpoints.
type ProviderAvailabilityHandler struct {
	availabilityService service.ProviderAvailabilityService
	// staffService resolves the authenticated user's staff profile.
	staffService service.StaffService
	// patientService resolves the authenticated patient profile for patient-facing routes.
	patientService service.PatientService
	logger         *zerolog.Logger
	timeout        time.Duration
}

// NewProviderAvailabilityHandler creates a new provider availability handler.
func NewProviderAvailabilityHandler(
	availabilityService service.ProviderAvailabilityService,
	staffService service.StaffService,
	patientService service.PatientService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *ProviderAvailabilityHandler {
	return &ProviderAvailabilityHandler{
		availabilityService: availabilityService,
		staffService:        staffService,
		patientService:      patientService,
		logger:              logger,
		timeout:             timeout,
	}
}

// RegisterRoutes registers all provider availability routes onto the provided router.
func (h *ProviderAvailabilityHandler) RegisterRoutes(router chi.Router) {
	router.Route("/providers", func(r chi.Router) {
		// ── Patient-facing ─────────────────────────────────────────────────────
		r.Get("/available", h.GetAvailableProviders)
		r.Get("/available/specialization", h.GetAvailableProvidersBySpecialization)

		// ── Provider self-management (identity from JWT) ────────────────────────
		r.Put("/me/online", h.GoOnline)
		r.Put("/me/offline", h.GoOffline)
		r.Put("/me/accepting", h.SetAccepting)
		r.Put("/me/status", h.UpdateStatus)
		r.Put("/me/wait-time", h.UpdateWaitTime)
		r.Post("/me/heartbeat", h.UpdateHeartbeat)
		r.Get("/me/availability", h.GetMyAvailability)

		// ── Admin / background job ─────────────────────────────────────────────
		r.Get("/stale", h.GetStaleProviders)
		r.Put("/stale/offline", h.SetStaleProvidersOffline)
	})
}

// ─── Patient-facing handlers ───────────────────────────────────────────────────

// GetAvailableProviders handles GET /providers/available.
// Returns all currently accepting providers. Optionally scoped by ?clinic_id=<uuid>.
func (h *ProviderAvailabilityHandler) GetAvailableProviders(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var clinicID *uuid.UUID
	if raw := r.URL.Query().Get("clinic_id"); raw != "" {
		parsed, err := uuid.Parse(raw)
		if err != nil {
			handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{
				Error: "Invalid clinic_id format",
			})
			return
		}
		clinicID = &parsed
	}

	providers, err := h.availabilityService.GetAvailableProviders(ctx, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]telemeddto.AvailableProviderResponse, len(providers))
	for i, p := range providers {
		items[i] = telemeddto.ToAvailableProviderResponse(p)
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.AvailableProvidersResponse{
		Providers: items,
		Count:     len(items),
	})
}

// GetAvailableProvidersBySpecialization handles GET /providers/available/specialization.
// Query param: specialization (required).
func (h *ProviderAvailabilityHandler) GetAvailableProvidersBySpecialization(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	specialization := r.URL.Query().Get("specialization")

	v := validator.New()
	v.ValidateRequired("specialization", specialization)
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	providers, err := h.availabilityService.GetAvailableProvidersBySpecialization(ctx, specialization)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]telemeddto.AvailableProviderBySpecializationResponse, len(providers))
	for i, p := range providers {
		items[i] = telemeddto.ToAvailableProviderBySpecializationResponse(p)
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.AvailableProvidersBySpecializationResponse{
		Providers: items,
		Count:     len(items),
	})
}

// ─── Provider self-management handlers ────────────────────────────────────────

// GoOnline handles PUT /providers/me/online.
// Marks the authenticated provider as online and records their shift start.
func (h *ProviderAvailabilityHandler) GoOnline(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	avail, err := h.availabilityService.GoOnline(ctx, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToProviderAvailabilityResponse(avail))
}

// GoOffline handles PUT /providers/me/offline.
// Marks the authenticated provider as offline and clears their shift.
func (h *ProviderAvailabilityHandler) GoOffline(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	if err := h.availabilityService.GoOffline(ctx, staffID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "You are now offline",
	})
}

// SetAccepting handles PUT /providers/me/accepting.
// Toggles the provider's accepting state and optionally updates fee override and
// estimated wait minutes. Provider must be online to accept consultations.
func (h *ProviderAvailabilityHandler) SetAccepting(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	var req telemeddto.UpsertAvailabilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	if req.ConsultationFeeOverride != nil && *req.ConsultationFeeOverride < 0 {
		v.AddError("consultation_fee_override", "must be non-negative")
	}
	if req.EstimatedWaitMinutes != nil && *req.EstimatedWaitMinutes < 0 {
		v.AddError("estimated_wait_minutes", "must be non-negative")
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	avail, err := h.availabilityService.SetAccepting(ctx, staffID, req.IsAccepting, req.ConsultationFeeOverride, req.EstimatedWaitMinutes)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToProviderAvailabilityResponse(avail))
}

// UpdateStatus handles PUT /providers/me/status.
// Sets the provider's status enum (available, busy, away) and optional status message.
// Providers cannot set themselves to "offline" via this route — use GoOffline instead.
func (h *ProviderAvailabilityHandler) UpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	var req telemeddto.UpdateAvailabilityStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	validStatuses := map[string]bool{"available": true, "busy": true, "away": true}
	if string(req.Status) == "" {
		v.AddError("status", "required")
	} else if !validStatuses[string(req.Status)] {
		v.AddError("status", "must be one of: available, busy, away (use the offline endpoint to go offline)")
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.availabilityService.UpdateStatus(ctx, staffID, req.Status, req.StatusMessage); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Status updated",
	})
}

// UpdateWaitTime handles PUT /providers/me/wait-time.
// Updates the estimated wait minutes displayed to patients.
// Query param: minutes (int, 0–480).
func (h *ProviderAvailabilityHandler) UpdateWaitTime(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	minutes := parseIntQuery(r, "minutes", -1)

	v := validator.New()
	if minutes < 0 {
		v.AddError("minutes", "required and must be non-negative")
	}
	if minutes > 480 {
		v.AddError("minutes", "cannot exceed 480 minutes")
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.availabilityService.UpdateWaitTime(ctx, staffID, minutes); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Wait time updated",
	})
}

// UpdateHeartbeat handles POST /providers/me/heartbeat.
// Refreshes last_seen_at to prevent the stale-provider background job from
// marking this provider offline. Should be called every ~30 seconds.
func (h *ProviderAvailabilityHandler) UpdateHeartbeat(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	if err := h.availabilityService.UpdateHeartbeat(ctx, staffID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Return 204 for heartbeats — no body needed.
	w.WriteHeader(http.StatusNoContent)
}

// GetMyAvailability handles GET /providers/me/availability.
// Returns the authenticated provider's full availability record.
func (h *ProviderAvailabilityHandler) GetMyAvailability(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	avail, err := h.availabilityService.GetAvailabilityByStaffID(ctx, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToProviderAvailabilityResponse(avail))
}

// ─── Admin / background job handlers ──────────────────────────────────────────

// GetStaleProviders handles GET /providers/stale.
// Returns providers whose heartbeat is older than 2 minutes. Admin/internal use.
func (h *ProviderAvailabilityHandler) GetStaleProviders(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	providers, err := h.availabilityService.GetStaleProviders(ctx)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// StaleProvider only carries a staff_id — return the raw slice as-is.
	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
		"count":     len(providers),
	})
}

// SetStaleProvidersOffline handles PUT /providers/stale/offline.
// Bulk-marks heartbeat-stale providers as offline. Intended for a background
// scheduler (e.g. cron every 2 minutes). Admin/internal use.
func (h *ProviderAvailabilityHandler) SetStaleProvidersOffline(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	if err := h.availabilityService.SetStaleProvidersOffline(ctx); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Stale providers set offline",
	})
}

// ─── Private helpers ───────────────────────────────────────────────────────────

// resolveStaffID extracts the authenticated user's ID from JWT claims, then
// looks up their staff profile to get the canonical staff UUID and clinic UUID.
func (h *ProviderAvailabilityHandler) resolveStaffID(ctx context.Context, w http.ResponseWriter) (staffID uuid.UUID, clinicID uuid.UUID, ok bool) {
	claims, found := middleware.GetUserFromContext(ctx)
	if !found {
		handler.RespondJSON(w, http.StatusUnauthorized, telemeddto.ErrorResponse{
			Error: "User not authenticated",
		})
		return uuid.Nil, uuid.Nil, false
	}

	staff, err := h.staffService.GetStaffByUserID(ctx, claims.UserID)
	if err != nil {
		handler.RespondJSON(w, http.StatusUnauthorized, telemeddto.ErrorResponse{
			Error: "No staff profile found for authenticated user",
		})
		return uuid.Nil, uuid.Nil, false
	}

	return staff.ID, staff.ClinicID, true
}
