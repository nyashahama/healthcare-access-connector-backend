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
	"github.com/rs/zerolog"
)

// ConsultationNotesHandler handles all consultation notes HTTP endpoints.
type ConsultationNotesHandler struct {
	notesService service.ConsultationNotesService
	// patientService resolves the authenticated user's patient profile.
	patientService service.PatientService
	// staffService resolves the authenticated user's staff profile for provider routes.
	staffService service.StaffService
	logger       *zerolog.Logger
	timeout      time.Duration
}

// NewConsultationNotesHandler creates a new consultation notes handler.
func NewConsultationNotesHandler(
	notesService service.ConsultationNotesService,
	patientService service.PatientService,
	staffService service.StaffService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *ConsultationNotesHandler {
	return &ConsultationNotesHandler{
		notesService:   notesService,
		patientService: patientService,
		staffService:   staffService,
		logger:         logger,
		timeout:        timeout,
	}
}

// RegisterRoutes registers all consultation notes routes onto the provided router.
func (h *ConsultationNotesHandler) RegisterRoutes(router chi.Router) {
	router.Route("/consultations/{consultationId}/notes", func(r chi.Router) {
		// ── CRUD on the draft note ─────────────────────────────────────────────
		r.Post("/", h.CreateNote)
		r.Get("/", h.GetNoteByConsultationID)
		r.Put("/{noteId}", h.UpdateNote)
		r.Put("/{noteId}/finalise", h.FinaliseNote)
		r.Put("/finalise", h.FinaliseNoteByConsultation)

		// ── Hydrated view (with provider info) ─────────────────────────────────
		r.Get("/with-provider", h.GetNoteWithProviderInfo)
	})

	// Standalone note GET by note ID
	router.Get("/notes/{noteId}", h.GetNoteByID)

	// History routes
	router.Route("/notes/history", func(r chi.Router) {
		r.Get("/provider/me", h.GetProviderNoteHistory)
		r.Get("/patient/me", h.GetPatientNoteHistory)
	})
}

// ─── Write handlers ────────────────────────────────────────────────────────────

// CreateNote handles POST /consultations/{consultationId}/notes.
//
// Opens a new draft SOAP note for the consultation. The authored_by_staff_id is
// resolved from the JWT — the client must not supply it in the body.
func (h *ConsultationNotesHandler) CreateNote(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	note, err := h.notesService.CreateNote(ctx, consultationID, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, telemeddto.ToConsultationNoteResponse(note))
}

// UpdateNote handles PUT /consultations/{consultationId}/notes/{noteId}.
//
// Auto-saves SOAP fields as the provider types. The requesting staff ID is
// resolved from the JWT; the service layer enforces authorship.
func (h *ConsultationNotesHandler) UpdateNote(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	noteID, err := parseUUIDParam(r, "noteId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid note ID"})
		return
	}

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	var req telemeddto.UpdateNoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	// Map UpdateNoteRequest fields onto a partial domain note.
	// The service layer performs field-level merging against the existing record.
	update := telemeddto.ToDomainNoteUpdate(req)

	updated, err := h.notesService.UpdateNote(ctx, noteID, update, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationNoteResponse(updated))
}

// FinaliseNote handles PUT /consultations/{consultationId}/notes/{noteId}/finalise.
//
// Locks the note by note ID. Typically called from the "End Consultation" button.
// The requesting staff ID is resolved from the JWT.
func (h *ConsultationNotesHandler) FinaliseNote(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	noteID, err := parseUUIDParam(r, "noteId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid note ID"})
		return
	}

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	finalised, err := h.notesService.FinaliseNote(ctx, noteID, staffID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationNoteResponse(finalised))
}

// FinaliseNoteByConsultation handles PUT /consultations/{consultationId}/notes/finalise.
//
// Locks the note by consultation ID — more natural to call from the consultation
// service when the consultation itself is completed.
func (h *ConsultationNotesHandler) FinaliseNoteByConsultation(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	finalised, err := h.notesService.FinaliseNoteByConsultation(ctx, consultationID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationNoteResponse(finalised))
}

// ─── Read handlers ─────────────────────────────────────────────────────────────

// GetNoteByID handles GET /notes/{noteId}.
func (h *ConsultationNotesHandler) GetNoteByID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	noteID, err := parseUUIDParam(r, "noteId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid note ID"})
		return
	}

	note, err := h.notesService.GetNoteByID(ctx, noteID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationNoteResponse(note))
}

// GetNoteByConsultationID handles GET /consultations/{consultationId}/notes.
// Returns the active (draft or finalised) note for a given consultation.
func (h *ConsultationNotesHandler) GetNoteByConsultationID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	note, err := h.notesService.GetNoteByConsultationID(ctx, consultationID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationNoteResponse(note))
}

// GetNoteWithProviderInfo handles GET /consultations/{consultationId}/notes/with-provider.
// Returns the note joined with the authoring provider's profile — used in patient
// records and admin audits.
func (h *ConsultationNotesHandler) GetNoteWithProviderInfo(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, telemeddto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	result, err := h.notesService.GetNoteWithProviderInfo(ctx, consultationID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ToConsultationNoteWithProviderInfoResponse(result))
}

// ─── History handlers ─────────────────────────────────────────────────────────

// GetProviderNoteHistory handles GET /notes/history/provider/me.
// Returns paginated finalised notes written by the authenticated provider.
// Supports ?limit=20&offset=0.
func (h *ConsultationNotesHandler) GetProviderNoteHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	staffID, _, ok := h.resolveStaffID(ctx, w)
	if !ok {
		return
	}

	limit := parseIntQuery(r, "limit", 20)
	offset := parseIntQuery(r, "offset", 0)

	notes, err := h.notesService.GetProviderNoteHistory(ctx, staffID, limit, offset)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]telemeddto.ProviderNoteHistoryEntryResponse, len(notes))
	for i, n := range notes {
		items[i] = telemeddto.ToProviderNoteHistoryEntryResponse(n)
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.ProviderNoteHistoryResponse{
		Notes:  items,
		Count:  len(items),
		Limit:  limit,
		Offset: offset,
	})
}

// GetPatientNoteHistory handles GET /notes/history/patient/me.
// Returns all finalised notes across the authenticated patient's consultations.
// Patient ID is always resolved from the JWT.
func (h *ConsultationNotesHandler) GetPatientNoteHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, _, ok := h.resolvePatientID(ctx, w)
	if !ok {
		return
	}

	notes, err := h.notesService.GetPatientNoteHistory(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]telemeddto.PatientNoteHistoryEntryResponse, len(notes))
	for i, n := range notes {
		items[i] = telemeddto.ToPatientNoteHistoryEntryResponse(n)
	}

	handler.RespondJSON(w, http.StatusOK, telemeddto.PatientNoteHistoryResponse{
		Notes:  items,
		Count:  len(items),
		Limit:  0, // GetPatientNoteHistory returns all; no server-side pagination
		Offset: 0,
	})
}

// ─── Private helpers ───────────────────────────────────────────────────────────

// resolvePatientID extracts the authenticated user's ID from the JWT claims,
// then looks up their patient profile to get the canonical patient UUID.
func (h *ConsultationNotesHandler) resolvePatientID(ctx context.Context, w http.ResponseWriter) (patientID uuid.UUID, userID uuid.UUID, ok bool) {
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

// resolveStaffID extracts the authenticated user's ID from JWT claims, then
// looks up their staff profile to get the canonical staff UUID and clinic UUID.
func (h *ConsultationNotesHandler) resolveStaffID(ctx context.Context, w http.ResponseWriter) (staffID uuid.UUID, clinicID uuid.UUID, ok bool) {
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
