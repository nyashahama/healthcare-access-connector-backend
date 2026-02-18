package telemedicine

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	sc_dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type SymptomCheckerHandler struct {
	symptomService service.SymptomCheckerService
	logger         *zerolog.Logger
	timeout        time.Duration
}

// NewSymptomCheckerHandler creates a new symptom checker handler.
func NewSymptomCheckerHandler(
	symptomService service.SymptomCheckerService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *SymptomCheckerHandler {
	return &SymptomCheckerHandler{
		symptomService: symptomService,
		logger:         logger,
		timeout:        timeout,
	}
}

// RegisterRoutes registers all symptom checker routes onto the provided router.
func (h *SymptomCheckerHandler) RegisterRoutes(router chi.Router) {
	router.Route("/symptom-checker", func(r chi.Router) {
		// Patient-facing
		r.Post("/sessions", h.SubmitSession)
		r.Get("/sessions/{id}", h.GetSessionByID)
		r.Put("/sessions/{id}/abandon", h.AbandonSession)
		r.Put("/sessions/{id}/convert", h.MarkSessionConverted)

		// Patient history
		r.Get("/patients/{patientId}/sessions", h.GetPatientSessions)
		r.Get("/patients/{patientId}/eligible-session", h.GetLatestEligibleSession)

		// Dependent history
		r.Get("/patients/{patientId}/dependents/{dependentId}/sessions", h.GetDependentSessions)

		// Provider-facing
		r.Get("/sessions/{id}/patient-context", h.GetSessionWithPatientContext)

		// Admin / analytics
		r.Get("/admin/sessions/triage", h.GetSessionsByTriageLevel)
		r.Get("/admin/sessions/outcome-counts", h.CountSessionsByOutcome)
	})
}

// ─── Patient-facing handlers ───────────────────────────────────────────────────

// SubmitSession handles POST /symptom-checker/sessions
func (h *SymptomCheckerHandler) SubmitSession(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Get authenticated user from context
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, sc_dto.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	var req sc_dto.SubmitSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Always stamp the user ID from the JWT — never trust the body
	req.UserID = claims.UserID

	// Validate input
	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())
	v.ValidateRequired("chief_complaint", req.ChiefComplaint)
	v.ValidateMinLength("chief_complaint", req.ChiefComplaint, 5)

	if len(req.SymptomsReported) == 0 {
		v.AddError("symptoms_reported", "at least one symptom is required")
	}
	if req.SeverityScore != nil && (*req.SeverityScore < 1 || *req.SeverityScore > 10) {
		v.AddError("severity_score", "must be between 1 and 10")
	}
	if req.IsForDependent && req.DependentID == nil {
		v.AddError("dependent_id", "required when is_for_dependent is true")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	session := sc_dto.ToDomainSession(req)

	created, err := h.symptomService.SubmitSession(ctx, session)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, sc_dto.ToSessionResponse(created))
}

// GetSessionByID handles GET /symptom-checker/sessions/{id}
func (h *SymptomCheckerHandler) GetSessionByID(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	id, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid session ID",
		})
		return
	}

	session, err := h.symptomService.GetSessionByID(ctx, id)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, sc_dto.ToSessionResponse(session))
}

// GetPatientSessions handles GET /symptom-checker/patients/{patientId}/sessions
// Supports ?limit=20&offset=0 query params for pagination.
func (h *SymptomCheckerHandler) GetPatientSessions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := parseUUIDParam(r, "patientId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid patient ID",
		})
		return
	}

	limit := parseIntQuery(r, "limit", 20)
	offset := parseIntQuery(r, "offset", 0)

	sessions, err := h.symptomService.GetPatientSessions(ctx, patientID, limit, offset)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]sc_dto.SymptomSessionSummaryResponse, len(sessions))
	for i, s := range sessions {
		items[i] = sc_dto.ToSessionSummaryResponse(s)
	}

	handler.RespondJSON(w, http.StatusOK, sc_dto.PatientSessionsResponse{
		Sessions: items,
		Count:    len(items),
		Limit:    limit,
		Offset:   offset,
	})
}

// GetDependentSessions handles GET /symptom-checker/patients/{patientId}/dependents/{dependentId}/sessions
func (h *SymptomCheckerHandler) GetDependentSessions(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := parseUUIDParam(r, "patientId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid patient ID",
		})
		return
	}

	dependentID, err := parseUUIDParam(r, "dependentId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid dependent ID",
		})
		return
	}

	sessions, err := h.symptomService.GetDependentSessions(ctx, patientID, dependentID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]sc_dto.DependentSessionSummaryResponse, len(sessions))
	for i, s := range sessions {
		items[i] = sc_dto.ToDependentSessionSummaryResponse(s)
	}

	handler.RespondJSON(w, http.StatusOK, sc_dto.DependentSessionsResponse{
		Sessions: items,
		Count:    len(items),
	})
}

// GetLatestEligibleSession handles GET /symptom-checker/patients/{patientId}/eligible-session
// This is the preflight check before the patient sees the provider list.
func (h *SymptomCheckerHandler) GetLatestEligibleSession(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	patientID, err := parseUUIDParam(r, "patientId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid patient ID",
		})
		return
	}

	session, err := h.symptomService.GetLatestEligibleSession(ctx, patientID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, sc_dto.ToEligibleSessionResponse(session))
}

// AbandonSession handles PUT /symptom-checker/sessions/{id}/abandon
func (h *SymptomCheckerHandler) AbandonSession(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	sessionID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid session ID",
		})
		return
	}

	var req sc_dto.AbandonSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	v := validator.New()
	v.ValidateRequired("patient_id", req.PatientID.String())
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.symptomService.AbandonSession(ctx, sessionID, req.PatientID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Session abandoned successfully",
	})
}

// MarkSessionConverted handles PUT /symptom-checker/sessions/{id}/convert
// Called by the consultation service when a consultation is created.
func (h *SymptomCheckerHandler) MarkSessionConverted(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	sessionID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid session ID",
		})
		return
	}

	if err := h.symptomService.MarkSessionConverted(ctx, sessionID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Session converted to consultation successfully",
	})
}

// ─── Provider-facing handlers ──────────────────────────────────────────────────

// GetSessionWithPatientContext handles GET /symptom-checker/sessions/{id}/patient-context
// Returns the rich provider view joining session with patient demographics and medical info.
func (h *SymptomCheckerHandler) GetSessionWithPatientContext(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	sessionID, err := parseUUIDParam(r, "id")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid session ID",
		})
		return
	}

	contextData, err := h.symptomService.GetSessionWithPatientContext(ctx, sessionID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, sc_dto.ToSessionWithPatientContextResponse(contextData))
}

// ─── Admin / analytics handlers ───────────────────────────────────────────────

// GetSessionsByTriageLevel handles GET /symptom-checker/admin/sessions/triage
// Query params: triage_level, from (YYYY-MM-DD), to (YYYY-MM-DD), limit, offset
func (h *SymptomCheckerHandler) GetSessionsByTriageLevel(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	triageLevelStr := r.URL.Query().Get("triage_level")
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")

	v := validator.New()
	v.ValidateRequired("triage_level", triageLevelStr)
	v.ValidateRequired("from", fromStr)
	v.ValidateRequired("to", toStr)

	validLevels := map[string]bool{
		string(telemedicine.TriageLow):       true,
		string(telemedicine.TriageMedium):    true,
		string(telemedicine.TriageHigh):      true,
		string(telemedicine.TriageEmergency): true,
	}
	if triageLevelStr != "" && !validLevels[triageLevelStr] {
		v.AddError("triage_level", "must be one of: low, medium, high, emergency")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid 'from' date format. Use YYYY-MM-DD",
		})
		return
	}

	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid 'to' date format. Use YYYY-MM-DD",
		})
		return
	}

	// Set to end of day so the range is inclusive
	to = to.Add(24*time.Hour - time.Second)

	limit := parseIntQuery(r, "limit", 20)
	offset := parseIntQuery(r, "offset", 0)

	sessions, err := h.symptomService.GetSessionsByTriageLevel(
		ctx,
		telemedicine.TriageLevel(triageLevelStr),
		from, to,
		limit, offset,
	)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]sc_dto.AdminSessionSummaryResponse, len(sessions))
	for i, s := range sessions {
		items[i] = sc_dto.ToAdminSessionSummaryResponse(s)
	}

	handler.RespondJSON(w, http.StatusOK, sc_dto.AdminSessionsResponse{
		Sessions: items,
		Count:    len(items),
		Limit:    limit,
		Offset:   offset,
	})
}

// CountSessionsByOutcome handles GET /symptom-checker/admin/sessions/outcome-counts
// Query params: from (YYYY-MM-DD), to (YYYY-MM-DD)
func (h *SymptomCheckerHandler) CountSessionsByOutcome(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")

	v := validator.New()
	v.ValidateRequired("from", fromStr)
	v.ValidateRequired("to", toStr)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid 'from' date format. Use YYYY-MM-DD",
		})
		return
	}

	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid 'to' date format. Use YYYY-MM-DD",
		})
		return
	}

	to = to.Add(24*time.Hour - time.Second)

	counts, err := h.symptomService.CountSessionsByOutcome(ctx, from, to)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]sc_dto.SessionOutcomeCountResponse, len(counts))
	for i, c := range counts {
		items[i] = sc_dto.ToOutcomeCountResponse(c)
	}

	handler.RespondJSON(w, http.StatusOK, sc_dto.OutcomeCountsResponse{
		Counts: items,
	})
}

// ─── Private helpers ───────────────────────────────────────────────────────────

func parseUUIDParam(r *http.Request, param string) (uuid.UUID, error) {
	return uuid.Parse(chi.URLParam(r, param))
}

func parseIntQuery(r *http.Request, key string, defaultVal int) int {
	if s := r.URL.Query().Get(key); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
	}
	return defaultVal
}
