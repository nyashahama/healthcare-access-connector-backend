package telemedicine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	symptomDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "symptom_checker_db_query_duration_seconds",
			Help:    "Symptom checker database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	symptomDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "symptom_checker_db_query_total",
			Help: "Total number of symptom checker database queries",
		},
		[]string{"operation", "status"},
	)
)

type symptomCheckerRepository struct {
	querier sqlc.Querier
}

func NewSymptomCheckerRepository(pool *pgxpool.Pool) repository.SymptomCheckerRepository {
	return NewSymptomCheckerRepositoryWithQuerier(sqlc.New(pool))
}

func NewSymptomCheckerRepositoryWithQuerier(querier sqlc.Querier) repository.SymptomCheckerRepository {
	return &symptomCheckerRepository{
		querier: querier,
	}
}

// ─── Core CRUD ───────────────────────────────────────────────────────────────

// CreateSession persists a new symptom checker session.
func (r *symptomCheckerRepository) CreateSession(ctx context.Context, session telemedicine.SymptomCheckerSession) (telemedicine.SymptomCheckerSession, error) {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	symptomsJSON := interfaceToJSONRawMessage(session.SymptomsReported)
	rawAnswersJSON := interfaceToJSONRawMessage(session.RawAnswers)

	row, err := r.querier.CreateSymptomSession(ctx, sqlc.CreateSymptomSessionParams{
		PatientID:           uuidToPgtypeUUID(session.PatientID),
		UserID:              uuidToPgtypeUUID(session.UserID),
		DependentID:         uuidPtrToPgtypeUUID(session.DependentID),
		ChiefComplaint:      session.ChiefComplaint,
		SymptomDuration:     pgtypeTextFromStringPtr(session.SymptomDuration),
		Column6:             symptomsJSON,
		BodySystemsAffected: stringSliceToArray(session.BodySystemsAffected),
		SeverityScore:       intPtrToPgtypeInt4(session.SeverityScore),
		TriageLevel:         string(session.TriageLevel),
		IsForDependent:      session.IsForDependent,
		AiSummary:           pgtypeTextFromStringPtr(session.AISummary),
		RecommendedAction:   pgtypeTextFromString(string(session.RecommendedAction)),
		Status:              string(session.Status),
		Column14:            rawAnswersJSON,
	})
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("create_session", "error").Inc()
		return telemedicine.SymptomCheckerSession{}, r.handleError(err, "create session")
	}

	symptomDBQueryTotal.WithLabelValues("create_session", "success").Inc()
	return r.mapToSession(row), nil
}

// GetSessionByID retrieves a full session by its primary key.
func (r *symptomCheckerRepository) GetSessionByID(ctx context.Context, id uuid.UUID) (telemedicine.SymptomCheckerSession, error) {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetSymptomSessionByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("get_session_by_id", "error").Inc()
		return telemedicine.SymptomCheckerSession{}, r.handleError(err, "get session by id")
	}

	symptomDBQueryTotal.WithLabelValues("get_session_by_id", "success").Inc()
	return r.mapToSession(row), nil
}

// UpdateSessionStatus updates the lifecycle status of a session.
func (r *symptomCheckerRepository) UpdateSessionStatus(ctx context.Context, id uuid.UUID, status telemedicine.SessionStatus) error {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateSessionStatus(ctx, sqlc.UpdateSessionStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: string(status),
	})
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("update_session_status", "error").Inc()
		return r.handleError(err, "update session status")
	}

	symptomDBQueryTotal.WithLabelValues("update_session_status", "success").Inc()
	return nil
}

// MarkSessionConverted transitions a completed session to converted_to_consult.
func (r *symptomCheckerRepository) MarkSessionConverted(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.MarkSessionConverted(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("mark_session_converted", "error").Inc()
		return r.handleError(err, "mark session converted")
	}

	symptomDBQueryTotal.WithLabelValues("mark_session_converted", "success").Inc()
	return nil
}

// ─── Patient-Facing ──────────────────────────────────────────────────────────

// GetLatestEligibleSession returns the most recent telemedicine-eligible session
// created in the past 24 hours. Returns domain.ErrNotFound when none qualifies.
func (r *symptomCheckerRepository) GetLatestEligibleSession(ctx context.Context, patientID uuid.UUID) (telemedicine.EligibleSession, error) {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetLatestEligibleSession(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("get_latest_eligible_session", "error").Inc()
		return telemedicine.EligibleSession{}, r.handleError(err, "get latest eligible session")
	}

	symptomDBQueryTotal.WithLabelValues("get_latest_eligible_session", "success").Inc()
	return r.mapToEligibleSession(row), nil
}

// GetPatientSessions returns a paginated summary list of sessions for a patient.
func (r *symptomCheckerRepository) GetPatientSessions(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.SymptomSessionSummary, error) {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientSessions(ctx, sqlc.GetPatientSessionsParams{
		PatientID: uuidToPgtypeUUID(patientID),
		Limit:     int32(limit),
		Offset:    int32(offset),
	})
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("get_patient_sessions", "error").Inc()
		return nil, r.handleError(err, "get patient sessions")
	}

	symptomDBQueryTotal.WithLabelValues("get_patient_sessions", "success").Inc()
	return r.mapToSessionSummaries(rows), nil
}

// GetDependentSessions returns all sessions filed for a specific dependent.
func (r *symptomCheckerRepository) GetDependentSessions(ctx context.Context, patientID uuid.UUID, dependentID uuid.UUID) ([]telemedicine.DependentSessionSummary, error) {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetDependentSessions(ctx, sqlc.GetDependentSessionsParams{
		PatientID:   uuidToPgtypeUUID(patientID),
		DependentID: uuidToPgtypeUUID(dependentID),
	})
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("get_dependent_sessions", "error").Inc()
		return nil, r.handleError(err, "get dependent sessions")
	}

	symptomDBQueryTotal.WithLabelValues("get_dependent_sessions", "success").Inc()
	return r.mapToDependentSessionSummaries(rows), nil
}

// ─── Provider-Facing ─────────────────────────────────────────────────────────

// GetSessionWithPatientContext returns the session joined with patient profile and
// medical info. Called when a provider accepts a consultation.
func (r *symptomCheckerRepository) GetSessionWithPatientContext(ctx context.Context, sessionID uuid.UUID) (telemedicine.SessionWithPatientContext, error) {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetSessionWithPatientContext(ctx, uuidToPgtypeUUID(sessionID))
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("get_session_with_patient_context", "error").Inc()
		return telemedicine.SessionWithPatientContext{}, r.handleError(err, "get session with patient context")
	}

	symptomDBQueryTotal.WithLabelValues("get_session_with_patient_context", "success").Inc()
	return r.mapToSessionWithPatientContext(row), nil
}

// ─── Admin / Analytics ───────────────────────────────────────────────────────

// GetSessionsByTriageLevel returns a paginated list of sessions for a given triage level
// and time window, ordered newest first.
func (r *symptomCheckerRepository) GetSessionsByTriageLevel(ctx context.Context, triageLevel telemedicine.TriageLevel, from, to time.Time, limit, offset int) ([]telemedicine.AdminSessionSummary, error) {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetSessionsByTriageLevel(ctx, sqlc.GetSessionsByTriageLevelParams{
		TriageLevel: string(triageLevel),
		CreatedAt:   pgtype.Timestamp{Time: from, Valid: true},
		CreatedAt_2: pgtype.Timestamp{Time: to, Valid: true},
		Limit:       int32(limit),
		Offset:      int32(offset),
	})
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("get_sessions_by_triage_level", "error").Inc()
		return nil, r.handleError(err, "get sessions by triage level")
	}

	symptomDBQueryTotal.WithLabelValues("get_sessions_by_triage_level", "success").Inc()
	return r.mapToAdminSessionSummaries(rows), nil
}

// CountSessionsByOutcome returns per-action session counts within a time window.
func (r *symptomCheckerRepository) CountSessionsByOutcome(ctx context.Context, from, to time.Time) ([]telemedicine.SessionOutcomeCount, error) {
	start := time.Now()
	defer func() {
		symptomDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.CountSessionsByOutcome(ctx, sqlc.CountSessionsByOutcomeParams{
		CreatedAt:   pgtype.Timestamp{Time: from, Valid: true},
		CreatedAt_2: pgtype.Timestamp{Time: to, Valid: true},
	})
	if err != nil {
		symptomDBQueryTotal.WithLabelValues("count_sessions_by_outcome", "error").Inc()
		return nil, r.handleError(err, "count sessions by outcome")
	}

	symptomDBQueryTotal.WithLabelValues("count_sessions_by_outcome", "success").Inc()
	return r.mapToOutcomeCounts(rows), nil
}

// ─── Mapping helpers ─────────────────────────────────────────────────────────

func (r *symptomCheckerRepository) mapToSession(row sqlc.SymptomCheckerSession) telemedicine.SymptomCheckerSession {
	return telemedicine.SymptomCheckerSession{
		ID:                  pgtypeUUIDToUUID(row.ID),
		PatientID:           pgtypeUUIDToUUID(row.PatientID),
		UserID:              pgtypeUUIDToUUID(row.UserID),
		DependentID:         uuidPtrToUUID(row.DependentID),
		ChiefComplaint:      row.ChiefComplaint,
		SymptomDuration:     pgtypeTextToStringPtr(row.SymptomDuration),
		SymptomsReported:    stringSliceFromJSONB(row.SymptomsReported),
		BodySystemsAffected: row.BodySystemsAffected,
		SeverityScore:       pgtypeInt4ToIntPtr(row.SeverityScore),
		IsForDependent:      row.IsForDependent,
		TriageLevel:         telemedicine.TriageLevel(row.TriageLevel),
		AISummary:           pgtypeTextToStringPtr(row.AiSummary),
		RecommendedAction:   telemedicine.RecommendedAction(pgtypeTextToString(row.RecommendedAction)),
		Status:              telemedicine.SessionStatus(row.Status),
		RawAnswers:          mapFromJSONB(row.RawAnswers),
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.UpdatedAt.Time,
	}
}

func (r *symptomCheckerRepository) mapToEligibleSession(row sqlc.GetLatestEligibleSessionRow) telemedicine.EligibleSession {
	return telemedicine.EligibleSession{
		ID:                  pgtypeUUIDToUUID(row.ID),
		TriageLevel:         telemedicine.TriageLevel(row.TriageLevel),
		AISummary:           pgtypeTextToStringPtr(row.AiSummary),
		RecommendedAction:   telemedicine.RecommendedAction(pgtypeTextToString(row.RecommendedAction)),
		ChiefComplaint:      row.ChiefComplaint,
		SymptomsReported:    stringSliceFromJSONB(row.SymptomsReported),
		BodySystemsAffected: row.BodySystemsAffected,
		SeverityScore:       pgtypeInt4ToIntPtr(row.SeverityScore),
		IsForDependent:      row.IsForDependent,
		DependentID:         uuidPtrToUUID(row.DependentID),
		CreatedAt:           row.CreatedAt.Time,
	}
}

func (r *symptomCheckerRepository) mapToSessionSummary(row sqlc.GetPatientSessionsRow) telemedicine.SymptomSessionSummary {
	return telemedicine.SymptomSessionSummary{
		ID:                pgtypeUUIDToUUID(row.ID),
		ChiefComplaint:    row.ChiefComplaint,
		TriageLevel:       telemedicine.TriageLevel(row.TriageLevel),
		RecommendedAction: telemedicine.RecommendedAction(pgtypeTextToString(row.RecommendedAction)),
		SeverityScore:     pgtypeInt4ToIntPtr(row.SeverityScore),
		Status:            telemedicine.SessionStatus(row.Status),
		IsForDependent:    row.IsForDependent,
		DependentID:       uuidPtrToUUID(row.DependentID),
		CreatedAt:         row.CreatedAt.Time,
	}
}

func (r *symptomCheckerRepository) mapToSessionSummaries(rows []sqlc.GetPatientSessionsRow) []telemedicine.SymptomSessionSummary {
	result := make([]telemedicine.SymptomSessionSummary, len(rows))
	for i, row := range rows {
		result[i] = r.mapToSessionSummary(row)
	}
	return result
}

func (r *symptomCheckerRepository) mapToDependentSessionSummary(row sqlc.GetDependentSessionsRow) telemedicine.DependentSessionSummary {
	return telemedicine.DependentSessionSummary{
		ID:                pgtypeUUIDToUUID(row.ID),
		ChiefComplaint:    row.ChiefComplaint,
		TriageLevel:       telemedicine.TriageLevel(row.TriageLevel),
		RecommendedAction: telemedicine.RecommendedAction(pgtypeTextToString(row.RecommendedAction)),
		SeverityScore:     pgtypeInt4ToIntPtr(row.SeverityScore),
		Status:            telemedicine.SessionStatus(row.Status),
		CreatedAt:         row.CreatedAt.Time,
	}
}

func (r *symptomCheckerRepository) mapToDependentSessionSummaries(rows []sqlc.GetDependentSessionsRow) []telemedicine.DependentSessionSummary {
	result := make([]telemedicine.DependentSessionSummary, len(rows))
	for i, row := range rows {
		result[i] = r.mapToDependentSessionSummary(row)
	}
	return result
}

func (r *symptomCheckerRepository) mapToSessionWithPatientContext(row sqlc.GetSessionWithPatientContextRow) telemedicine.SessionWithPatientContext {
	return telemedicine.SessionWithPatientContext{
		// Session fields
		SessionID:           pgtypeUUIDToUUID(row.SessionID),
		ChiefComplaint:      row.ChiefComplaint,
		SymptomDuration:     pgtypeTextToStringPtr(row.SymptomDuration),
		SymptomsReported:    stringSliceFromJSONB(row.SymptomsReported),
		BodySystemsAffected: row.BodySystemsAffected,
		SeverityScore:       pgtypeInt4ToIntPtr(row.SeverityScore),
		TriageLevel:         telemedicine.TriageLevel(row.TriageLevel),
		AISummary:           pgtypeTextToStringPtr(row.AiSummary),
		RecommendedAction:   telemedicine.RecommendedAction(pgtypeTextToString(row.RecommendedAction)),
		IsForDependent:      row.IsForDependent,
		DependentID:         uuidPtrToUUID(row.DependentID),

		// Patient demographics
		PatientID:                    pgtypeUUIDToUUID(row.PatientID),
		FirstName:                    row.FirstName,
		LastName:                     row.LastName,
		DateOfBirth:                  pgtypeDateToTimePtr(row.DateOfBirth),
		Gender:                       pgtypeTextToStringPtr(row.Gender),
		PreferredCommunicationMethod: pgtypeTextToStringPtr(row.PreferredCommunicationMethod),
		LanguagePreferences:          row.LanguagePreferences,
		RequiresInterpreter:          pgtypeBoolToBool(row.RequiresInterpreter),

		// Medical summary (left-joined, may be empty)
		BloodType:           pgtypeTextToStringPtr(row.BloodType),
		OverallHealthStatus: pgtypeTextToStringPtr(row.OverallHealthStatus),
		HealthSummary:       pgtypeTextToStringPtr(row.HealthSummary),
	}
}

func (r *symptomCheckerRepository) mapToAdminSessionSummary(row sqlc.GetSessionsByTriageLevelRow) telemedicine.AdminSessionSummary {
	return telemedicine.AdminSessionSummary{
		ID:                pgtypeUUIDToUUID(row.ID),
		PatientID:         pgtypeUUIDToUUID(row.PatientID),
		TriageLevel:       telemedicine.TriageLevel(row.TriageLevel),
		RecommendedAction: telemedicine.RecommendedAction(pgtypeTextToString(row.RecommendedAction)),
		SeverityScore:     pgtypeInt4ToIntPtr(row.SeverityScore),
		Status:            telemedicine.SessionStatus(row.Status),
		CreatedAt:         row.CreatedAt.Time,
	}
}

func (r *symptomCheckerRepository) mapToAdminSessionSummaries(rows []sqlc.GetSessionsByTriageLevelRow) []telemedicine.AdminSessionSummary {
	result := make([]telemedicine.AdminSessionSummary, len(rows))
	for i, row := range rows {
		result[i] = r.mapToAdminSessionSummary(row)
	}
	return result
}

func (r *symptomCheckerRepository) mapToOutcomeCount(row sqlc.CountSessionsByOutcomeRow) telemedicine.SessionOutcomeCount {
	return telemedicine.SessionOutcomeCount{
		RecommendedAction: telemedicine.RecommendedAction(pgtypeTextToString(row.RecommendedAction)),
		Total:             row.Total,
	}
}

func (r *symptomCheckerRepository) mapToOutcomeCounts(rows []sqlc.CountSessionsByOutcomeRow) []telemedicine.SessionOutcomeCount {
	result := make([]telemedicine.SessionOutcomeCount, len(rows))
	for i, row := range rows {
		result[i] = r.mapToOutcomeCount(row)
	}
	return result
}

// ─── Error handling ───────────────────────────────────────────────────────────

func (r *symptomCheckerRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
