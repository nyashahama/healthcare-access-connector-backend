// Package telemedicine implements the consultation notes service
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
	noteCacheTTL                = 5 * time.Minute
	providerNoteHistoryCacheTTL = 3 * time.Minute
	patientNoteHistoryCacheTTL  = 3 * time.Minute
	noteHistoryIndexTTL         = 5 * time.Minute
)

type consultationNotesService struct {
	notesRepo        repository.ConsultationNotesRepository
	consultationRepo repository.ConsultationRepository
	cache            cache.Service
	logger           *zerolog.Logger
}

// NewConsultationNotesService creates a new consultation notes service.
func NewConsultationNotesService(
	notesRepo repository.ConsultationNotesRepository,
	consultationRepo repository.ConsultationRepository,
	cache cache.Service,
	logger *zerolog.Logger,
) service.ConsultationNotesService {
	return &consultationNotesService{
		notesRepo:        notesRepo,
		consultationRepo: consultationRepo,
		cache:            cache,
		logger:           logger,
	}
}

// ─── Write Operations ─────────────────────────────────────────────────────────

// CreateNote opens a draft note for a consultation.
// A note may only be created once per consultation (UNIQUE constraint in DB).
// The consultation must be in progress or accepted when the provider opens the notes panel.
func (s *consultationNotesService) CreateNote(ctx context.Context, consultationID uuid.UUID, authoredByStaffID uuid.UUID) (telemedicine.ConsultationNote, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().Dur("duration_ms", time.Since(start)).Str("consultation_id", consultationID.String()).Msg("CreateNote completed")
	}()

	if consultationID == uuid.Nil {
		return telemedicine.ConsultationNote{}, domain.NewAppError(domain.ErrValidation, "consultation_id is required", 400)
	}
	if authoredByStaffID == uuid.Nil {
		return telemedicine.ConsultationNote{}, domain.NewAppError(domain.ErrValidation, "authored_by_staff_id is required", 400)
	}

	// Verify the consultation exists and is in an active state
	consultation, err := s.consultationRepo.GetConsultationByID(ctx, consultationID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ConsultationNote{}, domain.NewAppError(err, "consultation not found", 404)
		}
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to validate consultation", 500)
	}

	if consultation.Status != telemedicine.ConsultationStatusAccepted &&
		consultation.Status != telemedicine.ConsultationStatusInProgress {
		return telemedicine.ConsultationNote{}, domain.NewAppError(domain.ErrValidation,
			fmt.Sprintf("cannot create notes for a consultation with status '%s'", consultation.Status), 400)
	}

	// Prevent duplicate notes — check before hitting the unique constraint
	exists, err := s.notesRepo.NoteExistsForConsultation(ctx, consultationID)
	if err != nil {
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to check existing note", 500)
	}
	if exists {
		return telemedicine.ConsultationNote{}, domain.NewAppError(domain.ErrConflict, "a note already exists for this consultation", 409)
	}

	note, err := s.notesRepo.CreateNote(ctx, consultationID, authoredByStaffID)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to create consultation note")
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to create note", 500)
	}

	s.setNoteCache(ctx, note)
	s.invalidatePatientNoteHistoryCache(ctx, consultation.PatientID)
	s.logger.Info().Str("note_id", note.ID.String()).Str("consultation_id", consultationID.String()).Msg("Consultation note created")
	return note, nil
}

// UpdateNote auto-saves SOAP fields as the provider types.
// Finalised notes cannot be updated — the DB enforces this.
func (s *consultationNotesService) UpdateNote(ctx context.Context, id uuid.UUID, update telemedicine.ConsultationNote, requestingStaffID uuid.UUID) (telemedicine.ConsultationNote, error) {
	start := time.Now()
	defer func() {
		s.logger.Debug().Dur("duration_ms", time.Since(start)).Str("note_id", id.String()).Msg("UpdateNote completed")
	}()

	existing, err := s.notesRepo.GetNoteByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ConsultationNote{}, domain.NewAppError(err, "note not found", 404)
		}
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to retrieve note", 500)
	}

	if existing.IsFinalised {
		return telemedicine.ConsultationNote{}, domain.NewAppError(domain.ErrValidation, "cannot update a finalised note", 400)
	}
	if existing.AuthoredByStaffID != requestingStaffID {
		return telemedicine.ConsultationNote{}, domain.NewAppError(domain.ErrForbidden, "you may only update your own notes", 403)
	}

	updated, err := s.notesRepo.UpdateNote(ctx, id, update)
	if err != nil {
		s.logger.Error().Err(err).Str("note_id", id.String()).Msg("Failed to update consultation note")
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to update note", 500)
	}

	s.setNoteCache(ctx, updated)
	s.invalidatePatientHistoryByConsultation(ctx, existing.ConsultationID)
	return updated, nil
}

// FinaliseNote locks a note by its note ID. Called from the note panel when "End Consultation" is clicked.
func (s *consultationNotesService) FinaliseNote(ctx context.Context, id uuid.UUID, requestingStaffID uuid.UUID) (telemedicine.ConsultationNote, error) {
	existing, err := s.notesRepo.GetNoteByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ConsultationNote{}, domain.NewAppError(err, "note not found", 404)
		}
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to retrieve note", 500)
	}

	if existing.IsFinalised {
		return telemedicine.ConsultationNote{}, domain.NewAppError(domain.ErrConflict, "note is already finalised", 409)
	}
	if existing.AuthoredByStaffID != requestingStaffID {
		return telemedicine.ConsultationNote{}, domain.NewAppError(domain.ErrForbidden, "you may only finalise your own notes", 403)
	}

	finalised, err := s.notesRepo.FinaliseNote(ctx, id)
	if err != nil {
		s.logger.Error().Err(err).Str("note_id", id.String()).Msg("Failed to finalise consultation note")
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to finalise note", 500)
	}

	s.setNoteCache(ctx, finalised)
	s.invalidateProviderNoteHistoryCache(ctx, requestingStaffID)
	s.invalidatePatientHistoryByConsultation(ctx, existing.ConsultationID)
	s.logger.Info().Str("note_id", id.String()).Msg("Consultation note finalised")
	return finalised, nil
}

// FinaliseNoteByConsultation locks the note for a consultation by consultation ID.
// More natural to call from the consultation service when completing a consultation.
func (s *consultationNotesService) FinaliseNoteByConsultation(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error) {
	// Skip if no note exists yet (provider may not have opened the panel)
	exists, err := s.notesRepo.NoteExistsForConsultation(ctx, consultationID)
	if err != nil {
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to check note existence", 500)
	}
	if !exists {
		return telemedicine.ConsultationNote{}, domain.NewAppError(domain.ErrNotFound, "no note found for consultation", 404)
	}

	finalised, err := s.notesRepo.FinaliseNoteByConsultation(ctx, consultationID)
	if err != nil {
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to finalise note by consultation")
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to finalise note", 500)
	}

	s.setNoteCache(ctx, finalised)
	s.invalidateProviderNoteHistoryCache(ctx, finalised.AuthoredByStaffID)
	s.invalidatePatientHistoryByConsultation(ctx, consultationID)
	return finalised, nil
}

// ─── Read Operations ──────────────────────────────────────────────────────────

// GetNoteByID retrieves a full note by its primary key.
func (s *consultationNotesService) GetNoteByID(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error) {
	cacheKey := noteCacheKey(id)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached telemedicine.ConsultationNote
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	note, err := s.notesRepo.GetNoteByID(ctx, id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ConsultationNote{}, domain.NewAppError(err, "note not found", 404)
		}
		s.logger.Error().Err(err).Str("note_id", id.String()).Msg("Failed to get note")
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to retrieve note", 500)
	}

	s.setNoteCache(ctx, note)
	return note, nil
}

// GetNoteByConsultationID retrieves the note for a given consultation.
func (s *consultationNotesService) GetNoteByConsultationID(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error) {
	note, err := s.notesRepo.GetNoteByConsultationID(ctx, consultationID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ConsultationNote{}, domain.NewAppError(err, "note not found for consultation", 404)
		}
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to get note by consultation")
		return telemedicine.ConsultationNote{}, domain.NewAppError(err, "failed to retrieve note", 500)
	}
	return note, nil
}

// GetNoteWithProviderInfo returns the note joined with the authoring provider's profile.
// Used in patient records and admin audits.
func (s *consultationNotesService) GetNoteWithProviderInfo(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNoteWithProviderInfo, error) {
	result, err := s.notesRepo.GetNoteWithProviderInfo(ctx, consultationID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return telemedicine.ConsultationNoteWithProviderInfo{}, domain.NewAppError(err, "note not found for consultation", 404)
		}
		s.logger.Error().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to get note with provider info")
		return telemedicine.ConsultationNoteWithProviderInfo{}, domain.NewAppError(err, "failed to retrieve note", 500)
	}
	return result, nil
}

// ─── History ─────────────────────────────────────────────────────────────────

// GetProviderNoteHistory returns paginated finalised notes written by a provider.
func (s *consultationNotesService) GetProviderNoteHistory(ctx context.Context, staffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderNoteHistoryEntry, error) {
	limit, offset = clampPagination(limit, offset)

	if offset == 0 && s.cache != nil && s.cache.IsAvailable() {
		cacheKey := providerNoteHistoryCacheKey(staffID, limit)
		var cached []telemedicine.ProviderNoteHistoryEntry
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	results, err := s.notesRepo.GetProviderNoteHistory(ctx, staffID, limit, offset)
	if err != nil {
		s.logger.Error().Err(err).Str("staff_id", staffID.String()).Msg("Failed to get provider note history")
		return nil, domain.NewAppError(err, "failed to retrieve note history", 500)
	}

	if offset == 0 && s.cache != nil && s.cache.IsAvailable() {
		cacheKey := providerNoteHistoryCacheKey(staffID, limit)
		if err := s.cache.Set(ctx, cacheKey, results, providerNoteHistoryCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache provider note history")
		} else {
			s.registerProviderNoteHistoryCacheKey(ctx, staffID, cacheKey)
		}
	}

	return results, nil
}

// GetPatientNoteHistory returns all finalised notes across a patient's consultations.
// The underlying query returns all records (no server-side pagination); cache the full slice.
func (s *consultationNotesService) GetPatientNoteHistory(ctx context.Context, patientID uuid.UUID) ([]telemedicine.PatientNoteHistoryEntry, error) {
	cacheKey := patientNoteHistoryCacheKey(patientID)
	if s.cache != nil && s.cache.IsAvailable() {
		var cached []telemedicine.PatientNoteHistoryEntry
		if err := s.cache.Get(ctx, cacheKey, &cached); err == nil {
			return cached, nil
		}
	}

	results, err := s.notesRepo.GetPatientNoteHistory(ctx, patientID)
	if err != nil {
		s.logger.Error().Err(err).Str("patient_id", patientID.String()).Msg("Failed to get patient note history")
		return nil, domain.NewAppError(err, "failed to retrieve clinical history", 500)
	}

	if s.cache != nil && s.cache.IsAvailable() {
		if err := s.cache.Set(ctx, cacheKey, results, patientNoteHistoryCacheTTL); err != nil {
			s.logger.Warn().Err(err).Msg("Failed to cache patient note history")
		}
	}

	return results, nil
}

// ─── Cache helpers ─────────────────────────────────────────────────────────────

func (s *consultationNotesService) setNoteCache(ctx context.Context, note telemedicine.ConsultationNote) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	if err := s.cache.Set(ctx, noteCacheKey(note.ID), note, noteCacheTTL); err != nil {
		s.logger.Warn().Err(err).Str("note_id", note.ID.String()).Msg("Failed to cache note")
	}
}

func (s *consultationNotesService) invalidateProviderNoteHistoryCache(ctx context.Context, staffID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	keys := append(s.collectProviderNoteHistoryCacheKeys(ctx, staffID), providerNoteHistoryCacheKey(staffID, 20), providerNoteHistoryIndexKey(staffID))
	for _, key := range uniqueNoteCacheKeys(keys) {
		if err := s.cache.Delete(ctx, key); err != nil {
			s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate provider note history cache")
		}
	}
}

func (s *consultationNotesService) invalidatePatientNoteHistoryCache(ctx context.Context, patientID uuid.UUID) {
	if s.cache == nil || !s.cache.IsAvailable() || patientID == uuid.Nil {
		return
	}
	key := patientNoteHistoryCacheKey(patientID)
	if err := s.cache.Delete(ctx, key); err != nil {
		s.logger.Warn().Err(err).Str("key", key).Msg("Failed to invalidate patient note history cache")
	}
}

func (s *consultationNotesService) invalidatePatientHistoryByConsultation(ctx context.Context, consultationID uuid.UUID) {
	if consultationID == uuid.Nil {
		return
	}
	consultation, err := s.consultationRepo.GetConsultationByID(ctx, consultationID)
	if err != nil {
		s.logger.Warn().Err(err).Str("consultation_id", consultationID.String()).Msg("Failed to resolve consultation for patient note history invalidation")
		return
	}
	s.invalidatePatientNoteHistoryCache(ctx, consultation.PatientID)
}

func (s *consultationNotesService) registerProviderNoteHistoryCacheKey(ctx context.Context, staffID uuid.UUID, cacheKey string) {
	if s.cache == nil || !s.cache.IsAvailable() {
		return
	}
	keys := s.collectProviderNoteHistoryCacheKeys(ctx, staffID)
	keys = append(keys, cacheKey)
	if err := s.cache.Set(ctx, providerNoteHistoryIndexKey(staffID), uniqueNoteCacheKeys(keys), noteHistoryIndexTTL); err != nil {
		s.logger.Warn().Err(err).Str("staff_id", staffID.String()).Msg("Failed to update provider note history cache index")
	}
}

func (s *consultationNotesService) collectProviderNoteHistoryCacheKeys(ctx context.Context, staffID uuid.UUID) []string {
	if s.cache == nil || !s.cache.IsAvailable() {
		return nil
	}
	var keys []string
	if err := s.cache.Get(ctx, providerNoteHistoryIndexKey(staffID), &keys); err != nil {
		return nil
	}
	return keys
}

// ─── Cache key builders ───────────────────────────────────────────────────────

func noteCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("note:%s", id.String())
}

func providerNoteHistoryCacheKey(staffID uuid.UUID, limit int) string {
	return fmt.Sprintf("notes:provider:%s:limit:%d", staffID.String(), limit)
}

func patientNoteHistoryCacheKey(patientID uuid.UUID) string {
	return fmt.Sprintf("notes:patient:%s", patientID.String())
}

func providerNoteHistoryIndexKey(staffID uuid.UUID) string {
	return fmt.Sprintf("notes:provider:index:%s", staffID.String())
}

func uniqueNoteCacheKeys(keys []string) []string {
	seen := make(map[string]struct{}, len(keys))
	result := make([]string, 0, len(keys))
	for _, key := range keys {
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, key)
	}
	return result
}
