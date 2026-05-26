package telemedicine

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	telemeddto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

// ConsultationHandler handles all consultation lifecycle HTTP endpoints.
type ConsultationHandler struct {
	consultationService service.ConsultationService
	// patientService resolves the authenticated user's patient profile.
	// Patient identity is always derived from the JWT — never from the request body.
	patientService service.PatientService
	// staffService resolves the authenticated user's staff profile for provider routes.
	staffService service.StaffService
	logger       *zerolog.Logger
	timeout      time.Duration
}

// NewConsultationHandler creates a new consultation handler.
func NewConsultationHandler(
	consultationService service.ConsultationService,
	patientService service.PatientService,
	staffService service.StaffService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *ConsultationHandler {
	return &ConsultationHandler{
		consultationService: consultationService,
		patientService:      patientService,
		staffService:        staffService,
		logger:              logger,
		timeout:             timeout,
	}
}

// RegisterRoutes registers all consultation routes onto the provided router.
func (h *ConsultationHandler) RegisterRoutes(router chi.Router) {
	router.Route("/consultations", func(r chi.Router) {
		// ── Patient-facing ────────────────────────────────────────────────────
		r.Post("/", h.RequestConsultation)
		r.Get("/me/active", h.GetPatientActiveConsultation)
		r.Get("/me/history", h.GetPatientConsultations)
		r.Put("/{id}/cancel", h.CancelConsultation)
		r.Post("/{id}/rating", h.SubmitPatientRating)

		// ── Shared (patient + provider) ────────────────────────────────────────
		r.Get("/{id}", h.GetConsultationByID)
		r.Get("/{id}/details", h.GetConsultationWithDetails)
		r.Put("/{id}/channel", h.UpdateConsultationChannel)

		// ── Provider-facing ────────────────────────────────────────────────────
		r.Get("/provider/active", h.GetProviderActiveConsultations)
		r.Get("/provider/history", h.GetProviderConsultationHistory)
		r.Get("/waiting-room", h.GetWaitingRoom)
		r.Put("/{id}/accept", h.AcceptConsultation)
		r.Put("/{id}/start", h.StartConsultation)
		r.Put("/{id}/complete", h.CompleteConsultation)
		r.Put("/{id}/escalate", h.EscalateConsultation)
		r.Put("/{id}/decline", h.DeclineConsultation)
		r.Put("/{id}/no-show", h.MarkNoShow)

		// ── Billing & admin ────────────────────────────────────────────────────
		r.Put("/{id}/payment", h.UpdatePaymentStatus)
		r.Put("/{id}/follow-up", h.LinkFollowUpAppointment)
	})
}

// ─── Patient-facing handlers ───────────────────────────────────────────────────

// RequestConsultation handles POST /consultations.
//
// The patient_id is always resolved from the JWT — clients must not supply it
// in the body. The symptom_session_id and channel must be provided.
func (h *ConsultationHandler) RequestConsultation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, _, ok := h.resolvePatientID(ctx, w)
	if !ok {
		return
	}

	var req telemeddto.RequestConsultationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Stamp the verified identity — ignore any client-supplied patient_id.
	req.PatientID = patientID

	v := validator.New()
	if req.SymptomSessionID == uuid.Nil {
		v.AddError("symptom_session_id", "required")
	}
	if req.Channel == "" {
		v.AddError("channel", "required")
	} else {
		validChannels := map[string]bool{"chat": true, "video": true, "phone": true}
		if !validChannels[string(req.Channel)] {
			v.AddError("channel", "must be one of: chat, video, phone")
		}
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	consultation := telemeddto.ToDomainConsultation(req)
	created, err := h.consultationService.RequestConsultation(ctx, consultation)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, telemeddto.ToConsultationResponse(created))
}

// GetConsultationByID handles GET /consultations/{id}.
func (h *ConsultationHandler) GetConsultationByID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, telemeddto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	consultation, err := h.consultationService.GetConsultationByIDForActor(ctx, consultationID, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationResponse(consultation))
}

// GetConsultationWithDetails handles GET /consultations/{id}/details.
// Returns the rich hydrated view used by the patient and provider chat screen.
func (h *ConsultationHandler) GetConsultationWithDetails(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, telemeddto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	result, err := h.consultationService.GetConsultationWithDetailsForActor(ctx, consultationID, claims.UserID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationWithDetailsResponse(result))
}

// GetPatientConsultations handles GET /consultations/me/history.
// Supports ?limit=20&offset=0. Patient ID is resolved from the JWT.
func (h *ConsultationHandler) GetPatientConsultations(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, _, ok := h.resolvePatientID(ctx, w)
	if !ok {
		return
	}

	limit := parseIntQuery(r, "limit", 20)
	offset := parseIntQuery(r, "offset", 0)

	consultations, err := h.consultationService.GetPatientConsultations(ctx, patientID, limit, offset)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]telemeddto.PatientConsultationSummaryResponse, len(consultations))
	for i, c := range consultations {
		items[i] = telemeddto.ToPatientConsultationSummaryResponse(c)
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.PatientConsultationsResponse{
		Consultations: items,
		Count:         len(items),
		Limit:         limit,
		Offset:        offset,
	})
}

// GetPatientActiveConsultation handles GET /consultations/me/active.
// Returns 404 when no active consultation exists — the client treats that as "no session".
func (h *ConsultationHandler) GetPatientActiveConsultation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, _, ok := h.resolvePatientID(ctx, w)
	if !ok {
		return
	}

	result, err := h.consultationService.GetPatientActiveConsultation(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToActiveConsultationCheckResponse(result))
}

// CancelConsultation handles PUT /consultations/{id}/cancel.
// Patient ID is resolved from the JWT — the service enforces ownership.
func (h *ConsultationHandler) CancelConsultation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	patientID, _, ok := h.resolvePatientID(ctx, w)
	if !ok {
		return
	}

	updated, err := h.consultationService.CancelConsultation(ctx, consultationID, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationResponse(updated))
}

// SubmitPatientRating handles POST /consultations/{id}/rating.
// Patient ID is resolved from the JWT — the service enforces ownership.
func (h *ConsultationHandler) SubmitPatientRating(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	patientID, _, ok := h.resolvePatientID(ctx, w)
	if !ok {
		return
	}

	var req telemeddto.SubmitRatingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	if req.Rating < 1 || req.Rating > 5 {
		v.AddError("rating", "must be between 1 and 5")
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.consultationService.SubmitPatientRating(ctx, consultationID, patientID, req.Rating, req.Feedback); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Rating submitted successfully",
	})
}

// ─── Provider-facing handlers ──────────────────────────────────────────────────

// AcceptConsultation handles PUT /consultations/{id}/accept.
// The provider's staff ID and clinic ID are resolved from the JWT.
func (h *ConsultationHandler) AcceptConsultation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	staffID, clinicID, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	updated, err := h.consultationService.AcceptConsultation(ctx, consultationID, staffID, clinicID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationResponse(updated))
}

// StartConsultation handles PUT /consultations/{id}/start.
// Transitions an accepted consultation to in_progress on first provider interaction.
func (h *ConsultationHandler) StartConsultation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	if _, _, ok := h.resolveStaffID(ctx, w); !ok {
		return
	}

	updated, err := h.consultationService.StartConsultation(ctx, consultationID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationResponse(updated))
}

// CompleteConsultation handles PUT /consultations/{id}/complete.
// The provider's ID from the JWT is used as the ended_by actor.
func (h *ConsultationHandler) CompleteConsultation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	updated, err := h.consultationService.CompleteConsultation(ctx, consultationID, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationResponse(updated))
}

// EscalateConsultation handles PUT /consultations/{id}/escalate.
func (h *ConsultationHandler) EscalateConsultation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	updated, err := h.consultationService.EscalateConsultation(ctx, consultationID, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationResponse(updated))
}

// DeclineConsultation handles PUT /consultations/{id}/decline.
// Moves a pending consultation back to declined so the patient can re-select a provider.
func (h *ConsultationHandler) DeclineConsultation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	if _, _, ok := h.resolveStaffID(ctx, w); !ok {
		return
	}

	if err := h.consultationService.DeclineConsultation(ctx, consultationID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Consultation declined",
	})
}

// MarkNoShow handles PUT /consultations/{id}/no-show.
func (h *ConsultationHandler) MarkNoShow(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	if _, _, ok := h.resolveStaffID(ctx, w); !ok {
		return
	}

	if err := h.consultationService.MarkNoShow(ctx, consultationID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Consultation marked as no-show",
	})
}

// GetProviderActiveConsultations handles GET /consultations/provider/active.
// Staff ID is resolved from the JWT.
func (h *ConsultationHandler) GetProviderActiveConsultations(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	consultations, err := h.consultationService.GetProviderActiveConsultations(ctx, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]telemeddto.ProviderActiveConsultationResponse, len(consultations))
	for i, c := range consultations {
		items[i] = telemeddto.ToProviderActiveConsultationResponse(c)
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ProviderActiveConsultationsResponse{
		Consultations: items,
		Count:         len(items),
	})
}

// GetProviderConsultationHistory handles GET /consultations/provider/history.
// Supports ?limit=20&offset=0. Staff ID is resolved from the JWT.
func (h *ConsultationHandler) GetProviderConsultationHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	limit := parseIntQuery(r, "limit", 20)
	offset := parseIntQuery(r, "offset", 0)

	consultations, err := h.consultationService.GetProviderConsultationHistory(ctx, staffID, limit, offset)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]telemeddto.ProviderConsultationHistoryEntryResponse, len(consultations))
	for i, c := range consultations {
		items[i] = telemeddto.ToProviderConsultationHistoryEntryResponse(c)
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ProviderConsultationHistoryResponse{
		Consultations: items,
		Count:         len(items),
		Limit:         limit,
		Offset:        offset,
	})
}

// GetWaitingRoom handles GET /consultations/waiting-room.
// Returns all pending_acceptance consultations ordered by triage priority.
func (h *ConsultationHandler) GetWaitingRoom(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	if _, _, ok := h.resolveStaffID(ctx, w); !ok {
		return
	}

	entries, err := h.consultationService.GetWaitingRoom(ctx)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]telemeddto.WaitingRoomEntryResponse, len(entries))
	for i, e := range entries {
		items[i] = telemeddto.ToWaitingRoomEntryResponse(e)
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.WaitingRoomResponse{
		Entries: items,
		Count:   len(items),
	})
}

// ─── Billing & admin handlers ─────────────────────────────────────────────────

// UpdatePaymentStatus handles PUT /consultations/{id}/payment.
func (h *ConsultationHandler) UpdatePaymentStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	if _, _, ok := h.resolveStaffID(ctx, w); !ok {
		return
	}

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	var req telemeddto.UpdatePaymentStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	validStatuses := map[string]bool{"pending": true, "paid": true, "waived": true, "failed": true}
	if !validStatuses[string(req.Status)] {
		v.AddError("status", "must be one of: pending, paid, waived, failed")
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.consultationService.UpdatePaymentStatus(ctx, consultationID, req.Status, req.Reference); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Payment status updated",
	})
}

// UpdateConsultationChannel handles PUT /consultations/{id}/channel.
func (h *ConsultationHandler) UpdateConsultationChannel(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	if _, ok := middleware.GetUserFromContext(ctx); !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, telemeddto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	consultation, err := h.consultationService.GetConsultationByID(ctx, consultationID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	if !h.authorizeConsultationActor(ctx, w, consultation) {
		return
	}

	var req telemeddto.UpdateConsultationChannelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	validChannels := map[string]bool{"chat": true, "video": true, "phone": true}
	if !validChannels[string(req.Channel)] {
		v.AddError("channel", "must be one of: chat, video, phone")
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.consultationService.UpdateConsultationChannel(ctx, consultationID, req.Channel); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Channel updated",
	})
}

// LinkFollowUpAppointment handles PUT /consultations/{id}/follow-up.
func (h *ConsultationHandler) LinkFollowUpAppointment(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	if _, _, ok := h.resolveStaffID(ctx, w); !ok {
		return
	}

	consultationID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	var req telemeddto.LinkFollowUpAppointmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	if req.AppointmentID == uuid.Nil {
		v.AddError("appointment_id", "required")
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.consultationService.LinkFollowUpAppointment(ctx, consultationID, req.AppointmentID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Follow-up appointment linked",
	})
}

// ─── Private helpers ───────────────────────────────────────────────────────────

// resolvePatientID extracts the authenticated user's ID from the JWT claims,
// then looks up their patient profile to get the canonical patient UUID.
func (h *ConsultationHandler) resolvePatientID(ctx context.Context, w http.ResponseWriter) (patientID uuid.UUID, userID uuid.UUID, ok bool) {
	claims, found := middleware.GetUserFromContext(ctx)
	if !found {
		handler.RespondJSON(w, http.StatusUnauthorized, telemeddto.ErrorResponse{
			Error: "User not authenticated",
		})
		return uuid.Nil, uuid.Nil, false
	}

	patient, err := h.patientService.GetPatientProfile(ctx, claims.UserID)
	if err != nil {
		handler.RespondJSON(w, http.StatusUnauthorized, telemeddto.ErrorResponse{
			Error: "No patient profile found for authenticated user",
		})
		return uuid.Nil, uuid.Nil, false
	}

	return patient.ID, claims.UserID, true
}

// resolveStaffID extracts the authenticated user's ID from JWT claims,
// then looks up their staff profile to get the canonical staff UUID and clinic UUID.
func (h *ConsultationHandler) resolveStaffID(ctx context.Context, w http.ResponseWriter) (staffID uuid.UUID, clinicID uuid.UUID, ok bool) {
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

// authorizeConsultationActor checks if the authenticated user is either the owning
// patient of the consultation or the assigned provider staff member.
func (h *ConsultationHandler) authorizeConsultationActor(ctx context.Context, w http.ResponseWriter, consultation telemedicine.Consultation) bool {
	claims, found := middleware.GetUserFromContext(ctx)
	if !found {
		handler.RespondJSON(w, http.StatusUnauthorized, telemeddto.ErrorResponse{
			Error: "User not authenticated",
		})
		return false
	}

	if patient, err := h.patientService.GetPatientProfile(ctx, claims.UserID); err == nil && patient.ID == consultation.PatientID {
		return true
	}

	if staff, err := h.staffService.GetStaffByUserID(ctx, claims.UserID); err == nil &&
		consultation.ProviderStaffID != nil && *consultation.ProviderStaffID == staff.ID {
		return true
	}

	handler.RespondJSON(w, http.StatusForbidden, telemeddto.ErrorResponse{
		Error: "Access denied",
	})
	return false
}
