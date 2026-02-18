// Package telemedicine implements the symptom checker service
package telemedicine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/ai"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

// cache TTLs
const (
	sessionCacheTTL         = 10 * time.Minute
	patientSessionsCacheTTL = 5 * time.Minute
	eligibleSessionCacheTTL = 2 * time.Minute // short TTL — eligibility window is time-sensitive
	adminSessionsCacheTTL   = 5 * time.Minute
)

type symptomCheckerService struct {
	sessionRepo repository.SymptomCheckerRepository
	patientRepo repository.PatientProfileRepository
	aiClient    ai.Client
	cache       cache.Service
	logger      *zerolog.Logger
}

// NewSymptomCheckerService creates a new symptom checker service.
func NewSymptomCheckerService(
	sessionRepo repository.SymptomCheckerRepository,
	patientRepo repository.PatientProfileRepository,
	aiClient ai.Client,
	cache cache.Service,
	logger *zerolog.Logger,
) service.SymptomCheckerService {
	return &symptomCheckerService{
		sessionRepo: sessionRepo,
		patientRepo: patientRepo,
		aiClient:    aiClient,
		cache:       cache,
		logger:      logger,
	}
}

// ─── Patient-facing operations ─────────────────────────────────────────────────

// SubmitSession is the primary entry point: validates input, calls the AI for
// a clinical summary and triage level, then persists and returns the session.
func (s *symptomCheckerService) SubmitSession(ctx context.Context, session telemedicine.SymptomCheckerSession) (telemedicine.SymptomCheckerSession, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("patient_id", session.PatientID.String()).
			Msg("SubmitSession completed")
	}()

	// ── Validate required fields ──────────────────────────────────────────────
	if session.PatientID == uuid.Nil {
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(domain.ErrValidation, "patient_id is required", 400)
	}
	if session.UserID == uuid.Nil {
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(domain.ErrValidation, "user_id is required", 400)
	}
	if session.ChiefComplaint == "" {
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(domain.ErrValidation, "chief_complaint is required", 400)
	}
	if len(session.SymptomsReported) == 0 {
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(domain.ErrValidation, "at least one symptom must be reported", 400)
	}
	if session.SeverityScore != nil && (*session.SeverityScore < 1 || *session.SeverityScore > 10) {
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(domain.ErrValidation, "severity_score must be between 1 and 10", 400)
	}

	// ── Validate patient profile exists ──────────────────────────────────────
	if _, err := s.patientRepo.GetPatientProfileByID(ctx, session.PatientID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.SymptomCheckerSession{}, domain.NewAppError(err, "patient profile not found", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", session.PatientID.String()).Msg("Failed to fetch patient profile")
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(err, "failed to validate patient", 500)
	}

	// ── Validate dependent belongs to patient (when session is for a dependent) ─
	if session.IsForDependent {
		if session.DependentID == nil {
			return telemedicine.SymptomCheckerSession{}, domain.NewAppError(domain.ErrValidation, "dependent_id is required when is_for_dependent is true", 400)
		}
		if err := s.validateDependent(ctx, session.PatientID, *session.DependentID); err != nil {
			return telemedicine.SymptomCheckerSession{}, err
		}
	}

	// ── Call AI for clinical summary and triage ───────────────────────────────
	session = s.enrichWithAISummary(ctx, session)

	// ── Set defaults ─────────────────────────────────────────────────────────
	session.Status = telemedicine.StatusCompleted

	// ── Persist ──────────────────────────────────────────────────────────────
	created, err := s.sessionRepo.CreateSession(ctx, session)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", session.PatientID.String()).Msg("Failed to create symptom session")
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(err, "failed to save symptom session", 500)
	}

	// Cache the new session
	s.setSessionCache(ctx, created)

	// Bust the patient's session-list cache so the new entry appears immediately
	s.invalidatePatientSessionCache(ctx, session.PatientID)

	s.logger.Info().
		Str("session_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("triage_level", string(created.TriageLevel)).
		Str("recommended_action", string(created.RecommendedAction)).
		Msg("Symptom session submitted successfully")

	return created, nil
}

// GetSessionByID retrieves a full session. Only the owning patient or a provider
// context should call this; authorisation is enforced by the handler layer.
func (s *symptomCheckerService) GetSessionByID(ctx context.Context, id uuid.UUID) (telemedicine.SymptomCheckerSession, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("session_id", id.String()).
			Msg("GetSessionByID completed")
	}()

	// Try cache first
	cacheKey := sessionCacheKey(id)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached telemedicine.SymptomCheckerSession
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("session_id", id.String()).Msg("Session retrieved from cache")
			return cached, nil
		}
	}

	session, err := s.sessionRepo.GetSessionByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.SymptomCheckerSession{}, domain.NewAppError(err, "symptom session not found", 404)
		}
		s.logger.Error().Err(err).Str("session_id", id.String()).Msg("Failed to get session")
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(err, "failed to retrieve session", 500)
	}

	s.setSessionCache(ctx, session)
	return session, nil
}

// GetPatientSessions returns a paginated history of sessions for a patient.
func (s *symptomCheckerService) GetPatientSessions(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.SymptomSessionSummary, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("patient_id", patientID.String()).
			Int("limit", limit).
			Int("offset", offset).
			Msg("GetPatientSessions completed")
	}()

	// Validate and clamp pagination
	limit, offset = clampPagination(limit, offset)

	// Only cache the first page (offset==0) — subsequent pages are rarely hot
	if offset == 0 && s.cache != nil && s.cache.IsAvailable() {
		cacheKey := patientSessionsCacheKey(patientID, limit)
		var cached []telemedicine.SymptomSessionSummary
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Patient sessions retrieved from cache")
			return cached, nil
		}
	}

	sessions, err := s.sessionRepo.GetPatientSessions(ctx, patientID, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient sessions")
		return nil, domain.NewAppError(err, "failed to retrieve session history", 500)
	}

	if offset == 0 && s.cache != nil && s.cache.IsAvailable() {
		cacheKey := patientSessionsCacheKey(patientID, limit)
		if err := s.cache.Set(ctx, cacheKey, sessions, patientSessionsCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache patient sessions")
		}
	}

	return sessions, nil
}

// GetDependentSessions returns all sessions filed for a specific dependent.
func (s *symptomCheckerService) GetDependentSessions(ctx context.Context, patientID, dependentID uuid.UUID) ([]telemedicine.DependentSessionSummary, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("patient_id", patientID.String()).
			Str("dependent_id", dependentID.String()).
			Msg("GetDependentSessions completed")
	}()

	// Verify the dependent belongs to this patient before exposing data
	if err := s.validateDependent(ctx, patientID, dependentID); err != nil {
		return nil, err
	}

	sessions, err := s.sessionRepo.GetDependentSessions(ctx, patientID, dependentID)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", patientID.String()).
			Str("dependent_id", dependentID.String()).
			Msg("Failed to get dependent sessions")
		return nil, domain.NewAppError(err, "failed to retrieve dependent session history", 500)
	}

	return sessions, nil
}

// GetLatestEligibleSession returns the most recent telemedicine-eligible session
// for a patient (created within the last 24 hours with status=completed and
// recommended_action=telemedicine). This is the preflight check before the
// patient can see the provider list.
func (s *symptomCheckerService) GetLatestEligibleSession(ctx context.Context, patientID uuid.UUID) (telemedicine.EligibleSession, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("patient_id", patientID.String()).
			Msg("GetLatestEligibleSession completed")
	}()

	// Short cache TTL — eligibility is time-sensitive (24-hour window)
	cacheKey := eligibleSessionCacheKey(patientID)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached telemedicine.EligibleSession
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			s.logger.Debug().Str("patient_id", patientID.String()).Msg("Eligible session retrieved from cache")
			return cached, nil
		}
	}

	session, err := s.sessionRepo.GetLatestEligibleSession(ctx, patientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.EligibleSession{}, domain.NewAppError(err, "no eligible symptom session found — please complete the symptom checker first", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get eligible session")
		return telemedicine.EligibleSession{}, domain.NewAppError(err, "failed to check session eligibility", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, session, eligibleSessionCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache eligible session")
		}
	}

	return session, nil
}

// GetSessionWithPatientContext returns the rich provider-facing view joined with
// patient demographics and medical summary. Called when a provider accepts a
// consultation.
func (s *symptomCheckerService) GetSessionWithPatientContext(ctx context.Context, sessionID uuid.UUID) (telemedicine.SessionWithPatientContext, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("session_id", sessionID.String()).
			Msg("GetSessionWithPatientContext completed")
	}()

	// No cache here — this data is too sensitive to risk serving stale medical info
	context_data, err := s.sessionRepo.GetSessionWithPatientContext(ctx, sessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.SessionWithPatientContext{}, domain.NewAppError(err, "session not found", 404)
		}
		s.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("Failed to get session with patient context")
		return telemedicine.SessionWithPatientContext{}, domain.NewAppError(err, "failed to retrieve patient context", 500)
	}

	return context_data, nil
}

// ─── Lifecycle mutations ───────────────────────────────────────────────────────

// AbandonSession marks a session as abandoned. Called when a patient exits
// mid-flow without submitting.
func (s *symptomCheckerService) AbandonSession(ctx context.Context, sessionID, patientID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("session_id", sessionID.String()).
			Msg("AbandonSession completed")
	}()

	session, err := s.mustOwnSession(ctx, sessionID, patientID)
	if err != nil {
		return err
	}

	if session.Status != telemedicine.StatusCompleted {
		return domain.NewAppError(domain.ErrValidation, "only completed sessions can be abandoned", 400)
	}

	if err := s.sessionRepo.UpdateSessionStatus(ctx, sessionID, telemedicine.StatusAbandoned); err != nil {
		s.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("Failed to abandon session")
		return domain.NewAppError(err, "failed to abandon session", 500)
	}

	s.invalidateSessionCache(ctx, sessionID, patientID)

	s.logger.Info().
		Str("session_id", sessionID.String()).
		Str("patient_id", patientID.String()).
		Msg("Session abandoned")

	return nil
}

// MarkSessionConverted transitions a session to converted_to_consult.
// Called by the consultation service when a consultation is successfully created.
func (s *symptomCheckerService) MarkSessionConverted(ctx context.Context, sessionID uuid.UUID) error {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("session_id", sessionID.String()).
			Msg("MarkSessionConverted completed")
	}()

	// Verify the session exists and is in the right state
	session, err := s.sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(err, "session not found", 404)
		}
		return domain.NewAppError(err, "failed to retrieve session for conversion", 500)
	}

	if session.Status != telemedicine.StatusCompleted {
		return domain.NewAppError(domain.ErrValidation, "only completed sessions can be converted to a consultation", 400)
	}

	if err := s.sessionRepo.MarkSessionConverted(ctx, sessionID); err != nil {
		s.logger.Error().Err(err).Str("session_id", sessionID.String()).Msg("Failed to mark session converted")
		return domain.NewAppError(err, "failed to convert session", 500)
	}

	// Bust both the individual session cache and the patient's eligible-session cache
	s.invalidateSessionCache(ctx, sessionID, session.PatientID)

	s.logger.Info().
		Str("session_id", sessionID.String()).
		Str("patient_id", session.PatientID.String()).
		Msg("Session converted to consultation")

	return nil
}

// ─── Admin / analytics ────────────────────────────────────────────────────────

// GetSessionsByTriageLevel returns paginated sessions for an admin triage view.
func (s *symptomCheckerService) GetSessionsByTriageLevel(ctx context.Context, triageLevel telemedicine.TriageLevel, from, to time.Time, limit, offset int) ([]telemedicine.AdminSessionSummary, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Str("triage_level", string(triageLevel)).
			Msg("GetSessionsByTriageLevel completed")
	}()

	if !isValidTriageLevel(triageLevel) {
		return nil, domain.NewAppError(domain.ErrValidation, fmt.Sprintf("invalid triage_level: %s", triageLevel), 400)
	}

	if from.After(to) {
		return nil, domain.NewAppError(domain.ErrValidation, "from must be before to", 400)
	}

	limit, offset = clampPagination(limit, offset)

	cacheKey := triageCacheKey(triageLevel, from, to, limit, offset)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []telemedicine.AdminSessionSummary
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	sessions, err := s.sessionRepo.GetSessionsByTriageLevel(ctx, triageLevel, from, to, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("triage_level", string(triageLevel)).Msg("Failed to get sessions by triage level")
		return nil, domain.NewAppError(err, "failed to retrieve triage sessions", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, sessions, adminSessionsCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache triage sessions")
		}
	}

	return sessions, nil
}

// CountSessionsByOutcome returns per-action session counts within a time window.
func (s *symptomCheckerService) CountSessionsByOutcome(ctx context.Context, from, to time.Time) ([]telemedicine.SessionOutcomeCount, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().
			Dur("duration_ms", time.Since(start)).
			Msg("CountSessionsByOutcome completed")
	}()

	if from.After(to) {
		return nil, domain.NewAppError(domain.ErrValidation, "from must be before to", 400)
	}

	cacheKey := outcomeCacheKey(from, to)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []telemedicine.SessionOutcomeCount
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	counts, err := s.sessionRepo.CountSessionsByOutcome(ctx, from, to)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to count sessions by outcome")
		return nil, domain.NewAppError(err, "failed to count session outcomes", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, counts, adminSessionsCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache outcome counts")
		}
	}

	return counts, nil
}

// ─── Private helpers ──────────────────────────────────────────────────────────

// enrichWithAISummary calls the AI client and fills in TriageLevel, AISummary,
// and RecommendedAction on the session. If the AI is unavailable or fails, the
// method applies safe defaults so the session can still be persisted.
func (s *symptomCheckerService) enrichWithAISummary(ctx context.Context, session telemedicine.SymptomCheckerSession) telemedicine.SymptomCheckerSession {
	if s.aiClient == nil || !s.aiClient.IsAvailable() {
		s.logger.Warn().Msg("AI client unavailable, applying default triage")
		return s.applyDefaultTriage(session)
	}

	aiReq := ai.SymptomSummaryRequest{
		RawSymptoms:        session.ChiefComplaint + " — " + joinSymptoms(session.SymptomsReported),
		Severity:           severityLabel(session.SeverityScore),
		ExistingConditions: session.BodySystemsAffected, // best proxy we have pre-consultation
	}

	if session.SymptomDuration != nil {
		aiReq.Duration = *session.SymptomDuration
	}

	summary, err := s.aiClient.SummarizeSymptoms(ctx, aiReq)
	if err != nil {
		s.logger.Warn().Err(err).Msg("AI summarization failed, applying default triage")
		return s.applyDefaultTriage(session)
	}

	aiSummary := summary.ClinicalSummary
	session.AISummary = &aiSummary
	session.TriageLevel = telemedicine.TriageLevel(summary.TriageLevel)
	session.RecommendedAction = mapTriageToAction(session.TriageLevel)

	// Validate the AI returned a recognised triage level; fall back if not
	if !isValidTriageLevel(session.TriageLevel) {
		s.logger.Warn().
			Str("ai_triage", string(session.TriageLevel)).
			Msg("AI returned unrecognised triage level, defaulting to medium")
		session.TriageLevel = telemedicine.TriageMedium
		session.RecommendedAction = telemedicine.ActionTelemedicine
	}

	s.logger.Debug().
		Str("triage_level", string(session.TriageLevel)).
		Str("recommended_action", string(session.RecommendedAction)).
		Msg("AI enrichment successful")

	return session
}

// applyDefaultTriage sets conservative defaults when the AI is unavailable.
func (s *symptomCheckerService) applyDefaultTriage(session telemedicine.SymptomCheckerSession) telemedicine.SymptomCheckerSession {
	session.TriageLevel = telemedicine.TriageMedium
	session.RecommendedAction = telemedicine.ActionTelemedicine
	return session
}

// mustOwnSession fetches a session and verifies it belongs to the given patient.
func (s *symptomCheckerService) mustOwnSession(ctx context.Context, sessionID, patientID uuid.UUID) (telemedicine.SymptomCheckerSession, error) {
	session, err := s.sessionRepo.GetSessionByID(ctx, sessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.SymptomCheckerSession{}, domain.NewAppError(err, "session not found", 404)
		}
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(err, "failed to retrieve session", 500)
	}

	if session.PatientID != patientID {
		return telemedicine.SymptomCheckerSession{}, domain.NewAppError(domain.ErrForbidden, "session does not belong to this patient", 403)
	}

	return session, nil
}

// validateDependent checks that the dependent belongs to the patient.
// This relies on the patient repo exposing a dependent existence check.
func (s *symptomCheckerService) validateDependent(ctx context.Context, patientID, dependentID uuid.UUID) error {
	exists, err := s.patientRepo.DependentBelongsToPatient(ctx, patientID, dependentID)
	if err != nil {
		s.logger.Error().Err(err).
			Str("patient_id", patientID.String()).
			Str("dependent_id", dependentID.String()).
			Msg("Failed to validate dependent ownership")
		return domain.NewAppError(err, "failed to validate dependent", 500)
	}
	if !exists {
		return domain.NewAppError(domain.ErrForbidden, "dependent does not belong to this patient", 403)
	}
	return nil
}

// ─── Cache helpers ─────────────────────────────────────────────────────────────

func (s *symptomCheckerService) setSessionCache(ctx context.Context, session telemedicine.SymptomCheckerSession) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	if err := s.cache.Set(ctx, sessionCacheKey(session.ID), session, sessionCacheTTL); err != nil {
		s.logger.Warn().Err(err).Str("session_id", session.ID.String()).Msg("Failed to cache session")
	}
}

func (s *symptomCheckerService) invalidateSessionCache(ctx context.Context, sessionID, patientID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	keys := []string{
		sessionCacheKey(sessionID),
		eligibleSessionCacheKey(patientID),
	}
	for _, k := range keys {
		if err := s.cache.Delete(ctx, k); err != nil {
			s.logger.Warn().Err(err).Str("key", k).Msg("Failed to invalidate cache key")
		}
	}
}

func (s *symptomCheckerService) invalidatePatientSessionCache(ctx context.Context, patientID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	keys := []string{
		// invalidate the default first-page key; other page keys will expire naturally
		patientSessionsCacheKey(patientID, 20),
		eligibleSessionCacheKey(patientID),
	}
	for _, k := range keys {
		if err := s.cache.Delete(ctx, k); err != nil {
			s.logger.Warn().Err(err).Str("key", k).Msg("Failed to invalidate patient session cache key")
		}
	}
}

// ─── Cache key builders ───────────────────────────────────────────────────────

func sessionCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("symptom_session:%s", id.String())
}

func patientSessionsCacheKey(patientID uuid.UUID, limit int) string {
	return fmt.Sprintf("symptom_sessions:patient:%s:limit:%d", patientID.String(), limit)
}

func eligibleSessionCacheKey(patientID uuid.UUID) string {
	return fmt.Sprintf("symptom_session:eligible:%s", patientID.String())
}

func triageCacheKey(level telemedicine.TriageLevel, from, to time.Time, limit, offset int) string {
	return fmt.Sprintf("symptom_sessions:triage:%s:%d:%d:%d:%d",
		string(level), from.Unix(), to.Unix(), limit, offset)
}

func outcomeCacheKey(from, to time.Time) string {
	return fmt.Sprintf("symptom_sessions:outcomes:%d:%d", from.Unix(), to.Unix())
}

// ─── Misc helpers ─────────────────────────────────────────────────────────────

// mapTriageToAction maps a triage level to the recommended care pathway.
func mapTriageToAction(level telemedicine.TriageLevel) telemedicine.RecommendedAction {
	switch level {
	case telemedicine.TriageEmergency:
		return telemedicine.ActionEmergency
	case telemedicine.TriageHigh:
		return telemedicine.ActionVisitClinic
	case telemedicine.TriageLow:
		return telemedicine.ActionSelfCare
	default: // medium
		return telemedicine.ActionTelemedicine
	}
}

func isValidTriageLevel(level telemedicine.TriageLevel) bool {
	switch level {
	case telemedicine.TriageLow, telemedicine.TriageMedium, telemedicine.TriageHigh, telemedicine.TriageEmergency:
		return true
	}
	return false
}

func severityLabel(score *int) string {
	if score == nil {
		return ""
	}
	switch {
	case *score <= 3:
		return "mild"
	case *score <= 6:
		return "moderate"
	default:
		return "severe"
	}
}

func joinSymptoms(symptoms []string) string {
	result := ""
	for i, s := range symptoms {
		if i > 0 {
			result += ", "
		}
		result += s
	}
	return result
}

func clampPagination(limit, offset int) (int, int) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}
