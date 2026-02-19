// Package telemedicine implements the consultation service
package telemedicine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
)

// cache TTLs
const (
	consultationCacheTTL                = 5 * time.Minute
	patientConsultationsCacheTTL        = 3 * time.Minute
	providerActiveConsultationsCacheTTL = 30 * time.Second // hot path — keep short
	waitingRoomCacheTTL                 = 15 * time.Second // near-real-time
)

type consultationService struct {
	consultationRepo repository.ConsultationRepository
	availabilityRepo repository.ProviderAvailabilityRepository
	sessionRepo      repository.SymptomCheckerRepository
	cache            cache.Service
	logger           *zerolog.Logger
}

// NewConsultationService creates a new consultation service.
func NewConsultationService(
	consultationRepo repository.ConsultationRepository,
	availabilityRepo repository.ProviderAvailabilityRepository,
	sessionRepo repository.SymptomCheckerRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ConsultationService {
	return &consultationService{
		consultationRepo: consultationRepo,
		availabilityRepo: availabilityRepo,
		sessionRepo:      sessionRepo,
		cache:            cache,
		logger:           logger,
	}
}

// ─── Patient-Facing ───────────────────────────────────────────────────────────

// RequestConsultation creates a new consultation from a completed, eligible symptom session.
// Enforces one-active-consultation-per-patient and validates the symptom session exists.
func (s *consultationService) RequestConsultation(ctx context.Context, c telemedicine.Consultation) (telemedicine.Consultation, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().Dur("duration_ms", time.Since(start)).Str("patient_id", c.PatientID.String()).Msg("RequestConsultation completed")
	}()

	// Validate required fields
	if c.PatientID == uuid.Nil {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation, "patient_id is required", 400)
	}
	if c.SymptomSessionID == uuid.Nil {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation, "symptom_session_id is required", 400)
	}
	if c.Channel == "" {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation, "channel is required", 400)
	}
	if c.Channel != telemedicine.ChannelChat && c.Channel != telemedicine.ChannelVideo && c.Channel != telemedicine.ChannelPhone {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation, "channel must be one of: chat, video, phone", 400)
	}

	// Ensure patient has no active open consultation
	if _, err := s.consultationRepo.GetPatientActiveConsultation(ctx, c.PatientID); err == nil {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrConflict, "patient already has an active consultation", 409)
	} else if !errors.Is(err, domain.ErrNotFound) {
		s.logger.Error().Err(err).Str("patient_id", c.PatientID.String()).Msg("Failed to check active consultation")
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to validate patient consultation state", 500)
	}

	// Validate symptom session belongs to patient
	session, err := s.sessionRepo.GetSessionByID(ctx, c.SymptomSessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.Consultation{}, domain.NewAppError(err, "symptom session not found", 404)
		}
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to validate symptom session", 500)
	}
	if session.PatientID != c.PatientID {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrForbidden, "symptom session does not belong to this patient", 403)
	}
	if session.RecommendedAction != telemedicine.ActionTelemedicine {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation, "symptom session is not eligible for telemedicine", 400)
	}

	// Set triage level from session
	tl := string(session.TriageLevel)
	c.TriageLevelAtStart = &tl

	// Set fee currency default
	if c.FeeCurrency == "" {
		c.FeeCurrency = "ZAR"
	}

	created, err := s.consultationRepo.CreateConsultation(ctx, c)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", c.PatientID.String()).Msg("Failed to create consultation")
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to create consultation", 500)
	}

	// Mark the symptom session as converted
	if markErr := s.sessionRepo.MarkSessionConverted(ctx, c.SymptomSessionID); markErr != nil {
		s.logger.Warn().Err(markErr).Str("session_id", c.SymptomSessionID.String()).Msg("Failed to mark session as converted")
	}

	s.invalidatePatientConsultationCache(ctx, c.PatientID)
	s.setConsultationCache(ctx, created)

	s.logger.Info().
		Str("consultation_id", created.ID.String()).
		Str("patient_id", created.PatientID.String()).
		Str("channel", string(created.Channel)).
		Msg("Consultation created")

	return created, nil
}

// GetConsultationByID retrieves a consultation by ID.
func (s *consultationService) GetConsultationByID(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
	cacheKey := consultationCacheKey(id)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached telemedicine.Consultation
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	c, err := s.consultationRepo.GetConsultationByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.Consultation{}, domain.NewAppError(err, "consultation not found", 404)
		}
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to get consultation")
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to retrieve consultation", 500)
	}

	s.setConsultationCache(ctx, c)
	return c, nil
}

// GetConsultationWithDetails returns the hydrated consultation view for the chat screen.
func (s *consultationService) GetConsultationWithDetails(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationWithDetails, error) {
	result, err := s.consultationRepo.GetConsultationWithDetails(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ConsultationWithDetails{}, domain.NewAppError(err, "consultation not found", 404)
		}
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to get consultation with details")
		return telemedicine.ConsultationWithDetails{}, domain.NewAppError(err, "failed to retrieve consultation details", 500)
	}
	return result, nil
}

// GetPatientConsultations returns paginated consultation history for a patient.
func (s *consultationService) GetPatientConsultations(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.PatientConsultationSummary, error) {
	limit, offset = clampPagination(limit, offset)

	if offset == 0 && s.cache != nil && s.cache.IsAvailable() {
		cacheKey := patientConsultationsCacheKey(patientID, limit)
		var cached []telemedicine.PatientConsultationSummary
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	results, err := s.consultationRepo.GetPatientConsultations(ctx, patientID, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient consultations")
		return nil, domain.NewAppError(err, "failed to retrieve consultation history", 500)
	}

	if offset == 0 && s.cache != nil && s.cache.IsAvailable() {
		cacheKey := patientConsultationsCacheKey(patientID, limit)
		if err := s.cache.Set(ctx, cacheKey, results, patientConsultationsCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache patient consultations")
		}
	}

	return results, nil
}

// GetPatientActiveConsultation returns the patient's current open consultation.
// Returns domain.ErrNotFound when none exists — callers may treat this as "no active session".
func (s *consultationService) GetPatientActiveConsultation(ctx context.Context, patientID uuid.UUID) (telemedicine.ActiveConsultationCheck, error) {
	result, err := s.consultationRepo.GetPatientActiveConsultation(ctx, patientID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ActiveConsultationCheck{}, domain.NewAppError(err, "no active consultation", 404)
		}
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get active consultation")
		return telemedicine.ActiveConsultationCheck{}, domain.NewAppError(err, "failed to check active consultation", 500)
	}
	return result, nil
}

// CancelConsultation allows a patient or provider to cancel a pending/accepted consultation.
func (s *consultationService) CancelConsultation(ctx context.Context, id uuid.UUID, cancelledBy uuid.UUID) (telemedicine.Consultation, error) {
	c, err := s.mustGetConsultation(ctx, id)
	if err != nil {
		return telemedicine.Consultation{}, err
	}

	if c.Status != telemedicine.ConsultationStatusPendingAcceptance && c.Status != telemedicine.ConsultationStatusAccepted {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation,
			fmt.Sprintf("cannot cancel a consultation with status '%s'", c.Status), 400)
	}

	updated, err := s.consultationRepo.CancelConsultation(ctx, id, cancelledBy)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to cancel consultation")
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to cancel consultation", 500)
	}

	s.invalidateConsultationCache(ctx, id, c.PatientID)
	s.logger.Info().Str("consultation_id", id.String()).Str("cancelled_by", cancelledBy.String()).Msg("Consultation cancelled")
	return updated, nil
}

// SubmitPatientRating records the patient's post-consultation star rating and optional feedback.
func (s *consultationService) SubmitPatientRating(ctx context.Context, id uuid.UUID, patientID uuid.UUID, rating int, feedback *string) error {
	if rating < 1 || rating > 5 {
		return domain.NewAppError(domain.ErrValidation, "rating must be between 1 and 5", 400)
	}

	c, err := s.mustGetConsultation(ctx, id)
	if err != nil {
		return err
	}
	if c.PatientID != patientID {
		return domain.NewAppError(domain.ErrForbidden, "consultation does not belong to this patient", 403)
	}
	if c.Status != telemedicine.ConsultationStatusCompleted && c.Status != telemedicine.ConsultationStatusEscalated {
		return domain.NewAppError(domain.ErrValidation, "can only rate completed or escalated consultations", 400)
	}
	if c.PatientRating != nil {
		return domain.NewAppError(domain.ErrConflict, "consultation has already been rated", 409)
	}

	if err := s.consultationRepo.SubmitPatientRating(ctx, id, rating, feedback); err != nil {
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to submit rating")
		return domain.NewAppError(err, "failed to submit rating", 500)
	}

	s.invalidateConsultationCache(ctx, id, c.PatientID)
	return nil
}

// ─── Provider-Facing ─────────────────────────────────────────────────────────

// AcceptConsultation assigns a provider to a pending consultation, increments their
// active count, and optionally applies their fee override.
func (s *consultationService) AcceptConsultation(ctx context.Context, id uuid.UUID, providerStaffID uuid.UUID, clinicID uuid.UUID) (telemedicine.Consultation, error) {
	c, err := s.mustGetConsultation(ctx, id)
	if err != nil {
		return telemedicine.Consultation{}, err
	}

	if c.Status != telemedicine.ConsultationStatusPendingAcceptance {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation,
			fmt.Sprintf("consultation is not pending acceptance (current: %s)", c.Status), 400)
	}

	// Increment provider active count — repo enforces the capacity cap
	avail, err := s.availabilityRepo.IncrementActiveConsultations(ctx, providerStaffID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.Consultation{}, domain.NewAppError(domain.ErrConflict, "provider is at capacity or unavailable", 409)
		}
		s.logger.Error().Err(err).Str("staff_id", providerStaffID.String()).Msg("Failed to increment active consultations")
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to check provider capacity", 500)
	}

	updated, err := s.consultationRepo.AcceptConsultation(ctx, id, providerStaffID, clinicID)
	if err != nil {
		// Roll back the increment on failure
		if decErr := s.availabilityRepo.DecrementActiveConsultations(ctx, providerStaffID); decErr != nil {
			s.logger.Error().Err(decErr).Str("staff_id", providerStaffID.String()).Msg("Failed to rollback active consultations increment")
		}
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to accept consultation")
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to accept consultation", 500)
	}

	// Apply provider's fee override if set
	if avail.ConsultationFeeOverride != nil {
		if feeErr := s.consultationRepo.SetConsultationFee(ctx, id, *avail.ConsultationFeeOverride); feeErr != nil {
			s.logger.Warn().Err(feeErr).Str("consultation_id", id.String()).Msg("Failed to apply fee override")
		}
	}

	s.invalidateConsultationCache(ctx, id, c.PatientID)
	s.logger.Info().
		Str("consultation_id", id.String()).
		Str("staff_id", providerStaffID.String()).
		Msg("Consultation accepted")

	return updated, nil
}

// StartConsultation transitions an accepted consultation to in_progress on first message.
func (s *consultationService) StartConsultation(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
	c, err := s.mustGetConsultation(ctx, id)
	if err != nil {
		return telemedicine.Consultation{}, err
	}

	if c.Status != telemedicine.ConsultationStatusAccepted {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation,
			fmt.Sprintf("consultation must be in 'accepted' state to start (current: %s)", c.Status), 400)
	}

	updated, err := s.consultationRepo.StartConsultation(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to start consultation")
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to start consultation", 500)
	}

	s.invalidateConsultationCache(ctx, id, c.PatientID)
	return updated, nil
}

// CompleteConsultation closes an in_progress consultation and decrements the provider's count.
func (s *consultationService) CompleteConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
	c, err := s.mustGetConsultation(ctx, id)
	if err != nil {
		return telemedicine.Consultation{}, err
	}

	if c.Status != telemedicine.ConsultationStatusInProgress {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation,
			fmt.Sprintf("consultation must be in_progress to complete (current: %s)", c.Status), 400)
	}

	updated, err := s.consultationRepo.CompleteConsultation(ctx, id, endedBy)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to complete consultation")
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to complete consultation", 500)
	}

	s.decrementProviderCount(ctx, c.ProviderStaffID)
	s.invalidateConsultationCache(ctx, id, c.PatientID)
	s.logger.Info().Str("consultation_id", id.String()).Str("ended_by", endedBy.String()).Msg("Consultation completed")
	return updated, nil
}

// EscalateConsultation moves an in_progress consultation to escalated.
func (s *consultationService) EscalateConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
	c, err := s.mustGetConsultation(ctx, id)
	if err != nil {
		return telemedicine.Consultation{}, err
	}

	if c.Status != telemedicine.ConsultationStatusInProgress && c.Status != telemedicine.ConsultationStatusAccepted {
		return telemedicine.Consultation{}, domain.NewAppError(domain.ErrValidation,
			fmt.Sprintf("cannot escalate a consultation with status '%s'", c.Status), 400)
	}

	updated, err := s.consultationRepo.EscalateConsultation(ctx, id, endedBy)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to escalate consultation")
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to escalate consultation", 500)
	}

	s.decrementProviderCount(ctx, c.ProviderStaffID)
	s.invalidateConsultationCache(ctx, id, c.PatientID)
	s.logger.Info().Str("consultation_id", id.String()).Str("escalated_by", endedBy.String()).Msg("Consultation escalated")
	return updated, nil
}

// DeclineConsultation moves a pending consultation to declined so the patient can re-select.
func (s *consultationService) DeclineConsultation(ctx context.Context, id uuid.UUID) error {
	c, err := s.mustGetConsultation(ctx, id)
	if err != nil {
		return err
	}

	if c.Status != telemedicine.ConsultationStatusPendingAcceptance {
		return domain.NewAppError(domain.ErrValidation,
			fmt.Sprintf("can only decline a pending consultation (current: %s)", c.Status), 400)
	}

	if err := s.consultationRepo.DeclineConsultation(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to decline consultation")
		return domain.NewAppError(err, "failed to decline consultation", 500)
	}

	s.invalidateConsultationCache(ctx, id, c.PatientID)
	return nil
}

// MarkNoShow marks an accepted consultation as no_show when the patient does not appear.
func (s *consultationService) MarkNoShow(ctx context.Context, id uuid.UUID) error {
	c, err := s.mustGetConsultation(ctx, id)
	if err != nil {
		return err
	}

	if c.Status != telemedicine.ConsultationStatusAccepted {
		return domain.NewAppError(domain.ErrValidation,
			fmt.Sprintf("can only mark no-show for accepted consultations (current: %s)", c.Status), 400)
	}

	if err := s.consultationRepo.MarkNoShow(ctx, id); err != nil {
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to mark no-show")
		return domain.NewAppError(err, "failed to mark no-show", 500)
	}

	s.decrementProviderCount(ctx, c.ProviderStaffID)
	s.invalidateConsultationCache(ctx, id, c.PatientID)
	return nil
}

// GetProviderActiveConsultations returns all open consultations for a provider, ordered by triage.
func (s *consultationService) GetProviderActiveConsultations(ctx context.Context, providerStaffID uuid.UUID) ([]telemedicine.ProviderActiveConsultation, error) {
	cacheKey := providerActiveConsultationsCacheKey(providerStaffID)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []telemedicine.ProviderActiveConsultation
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	results, err := s.consultationRepo.GetProviderActiveConsultations(ctx, providerStaffID)
	if err != nil {
		s.logger.Error().Err(err).Str("staff_id", providerStaffID.String()).Msg("Failed to get provider active consultations")
		return nil, domain.NewAppError(err, "failed to retrieve active consultations", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, results, providerActiveConsultationsCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache provider active consultations")
		}
	}

	return results, nil
}

// GetWaitingRoom returns all pending_acceptance consultations for the provider waiting room.
func (s *consultationService) GetWaitingRoom(ctx context.Context) ([]telemedicine.WaitingRoomEntry, error) {
	cacheKey := "consultation:waiting_room"
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []telemedicine.WaitingRoomEntry
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	results, err := s.consultationRepo.GetWaitingRoom(ctx)
	if err != nil {
		s.logger.Error().Err(err).Msg("Failed to get waiting room")
		return nil, domain.NewAppError(err, "failed to retrieve waiting room", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, results, waitingRoomCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache waiting room")
		}
	}

	return results, nil
}

// GetProviderConsultationHistory returns paginated closed consultations for a provider.
func (s *consultationService) GetProviderConsultationHistory(ctx context.Context, providerStaffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderConsultationHistoryEntry, error) {
	limit, offset = clampPagination(limit, offset)

	results, err := s.consultationRepo.GetProviderConsultationHistory(ctx, providerStaffID, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("staff_id", providerStaffID.String()).Msg("Failed to get provider consultation history")
		return nil, domain.NewAppError(err, "failed to retrieve consultation history", 500)
	}

	return results, nil
}

// ─── Billing & Admin ──────────────────────────────────────────────────────────

// UpdatePaymentStatus updates the payment state and records a payment reference.
func (s *consultationService) UpdatePaymentStatus(ctx context.Context, id uuid.UUID, status telemedicine.PaymentStatus, reference *string) error {
	if err := s.consultationRepo.UpdatePaymentStatus(ctx, id, status, reference); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(err, "consultation not found", 404)
		}
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to update payment status")
		return domain.NewAppError(err, "failed to update payment status", 500)
	}
	s.invalidateCacheByID(ctx, id)
	return nil
}

// UpdateConsultationChannel changes the channel (e.g. chat → video).
func (s *consultationService) UpdateConsultationChannel(ctx context.Context, id uuid.UUID, channel telemedicine.ConsultationChannel) error {
	if err := s.consultationRepo.UpdateConsultationChannel(ctx, id, channel); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(err, "consultation not found", 404)
		}
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to update channel")
		return domain.NewAppError(err, "failed to update consultation channel", 500)
	}
	s.invalidateCacheByID(ctx, id)
	return nil
}

// LinkFollowUpAppointment associates a follow-up booking with a closed consultation.
func (s *consultationService) LinkFollowUpAppointment(ctx context.Context, id uuid.UUID, appointmentID uuid.UUID) error {
	if err := s.consultationRepo.LinkFollowUpAppointment(ctx, id, appointmentID); err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return domain.NewAppError(err, "consultation not found", 404)
		}
		s.logger.Error().Err(err).Str("consultation_id", id.String()).Msg("Failed to link follow-up appointment")
		return domain.NewAppError(err, "failed to link follow-up appointment", 500)
	}
	s.invalidateCacheByID(ctx, id)
	return nil
}

// ─── Private helpers ──────────────────────────────────────────────────────────

// mustGetConsultation fetches a consultation or returns a typed AppError.
func (s *consultationService) mustGetConsultation(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
	c, err := s.consultationRepo.GetConsultationByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.Consultation{}, domain.NewAppError(err, "consultation not found", 404)
		}
		return telemedicine.Consultation{}, domain.NewAppError(err, "failed to retrieve consultation", 500)
	}
	return c, nil
}

// decrementProviderCount safely decrements the provider's active consultation count.
func (s *consultationService) decrementProviderCount(ctx context.Context, providerStaffID *uuid.UUID) {
	if providerStaffID == nil {
		return
	}
	if err := s.availabilityRepo.DecrementActiveConsultations(ctx, *providerStaffID); err != nil {
		s.logger.Warn().Err(err).Str("staff_id", providerStaffID.String()).Msg("Failed to decrement active consultations")
	}
}

// ─── Cache helpers ────────────────────────────────────────────────────────────

func (s *consultationService) setConsultationCache(ctx context.Context, c telemedicine.Consultation) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	if err := s.cache.Set(ctx, consultationCacheKey(c.ID), c, consultationCacheTTL); err != nil {
		s.logger.Warn().Err(err).Str("consultation_id", c.ID.String()).Msg("Failed to cache consultation")
	}
}

func (s *consultationService) invalidateConsultationCache(ctx context.Context, id uuid.UUID, patientID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	for _, k := range []string{
		consultationCacheKey(id),
		patientConsultationsCacheKey(patientID, 20),
		"consultation:waiting_room",
	} {
		if err := s.cache.Delete(ctx, k); err != nil {
			s.logger.Warn().Err(err).Str("key", k).Msg("Failed to invalidate cache key")
		}
	}
}

func (s *consultationService) invalidateCacheByID(ctx context.Context, id uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	if err := s.cache.Delete(ctx, consultationCacheKey(id)); err != nil {
		s.logger.Warn().Err(err).Str("key", consultationCacheKey(id)).Msg("Failed to invalidate consultation cache key")
	}
}

func (s *consultationService) invalidatePatientConsultationCache(ctx context.Context, patientID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	for _, k := range []string{
		patientConsultationsCacheKey(patientID, 20),
		"consultation:waiting_room",
	} {
		if err := s.cache.Delete(ctx, k); err != nil {
			s.logger.Warn().Err(err).Str("key", k).Msg("Failed to invalidate cache key")
		}
	}
}

// ─── Cache key builders ───────────────────────────────────────────────────────

func consultationCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("consultation:%s", id.String())
}

func patientConsultationsCacheKey(patientID uuid.UUID, limit int) string {
	return fmt.Sprintf("consultations:patient:%s:limit:%d", patientID.String(), limit)
}

func providerActiveConsultationsCacheKey(staffID uuid.UUID) string {
	return fmt.Sprintf("consultations:provider:active:%s", staffID.String())
}
