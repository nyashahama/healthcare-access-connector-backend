package telemedicine

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	notesDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "consultation_notes_db_query_duration_seconds",
			Help:    "Consultation notes database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	notesDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "consultation_notes_db_query_total",
			Help: "Total number of consultation notes database queries",
		},
		[]string{"operation", "status"},
	)
)

type consultationNotesRepository struct {
	querier sqlc.Querier
}

func NewConsultationNotesRepository(pool *pgxpool.Pool) repository.ConsultationNotesRepository {
	return NewConsultationNotesRepositoryWithQuerier(sqlc.New(pool))
}

func NewConsultationNotesRepositoryWithQuerier(querier sqlc.Querier) repository.ConsultationNotesRepository {
	return &consultationNotesRepository{querier: querier}
}

// ─── Core Write Operations ────────────────────────────────────────────────────

// CreateNote creates a draft note for a consultation.
// Called when the provider opens the notes panel.
func (r *consultationNotesRepository) CreateNote(ctx context.Context, consultationID uuid.UUID, authoredByStaffID uuid.UUID) (telemedicine.ConsultationNote, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.CreateConsultationNote(ctx, sqlc.CreateConsultationNoteParams{
		ConsultationID:    uuidToPgtypeUUID(consultationID),
		AuthoredByStaffID: uuidToPgtypeUUID(authoredByStaffID),
	})
	if err != nil {
		notesDBQueryTotal.WithLabelValues("create_note", "error").Inc()
		return telemedicine.ConsultationNote{}, r.handleError(err, "create note")
	}
	notesDBQueryTotal.WithLabelValues("create_note", "success").Inc()
	return r.mapToNote(row), nil
}

// UpdateNote auto-saves the SOAP fields as the provider types.
// Blocked at the SQL level once is_finalised = true.
func (r *consultationNotesRepository) UpdateNote(ctx context.Context, id uuid.UUID, update telemedicine.ConsultationNote) (telemedicine.ConsultationNote, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.UpdateConsultationNote(ctx, sqlc.UpdateConsultationNoteParams{
		ID:                  uuidToPgtypeUUID(id),
		Subjective:          pgtypeTextFromStringPtr(update.Subjective),
		Objective:           pgtypeTextFromStringPtr(update.Objective),
		Assessment:          pgtypeTextFromStringPtr(update.Assessment),
		Plan:                pgtypeTextFromStringPtr(update.Plan),
		DiagnosisCodes:      stringSliceToArray(update.DiagnosisCodes),
		PrescriptionIssued:  update.PrescriptionIssued,
		Column8:             interfaceToJSONRawMessage(update.PrescriptionDetails),
		ReferralRequired:    update.ReferralRequired,
		ReferralType:        pgtypeTextFromStringPtr(referralTypeToStringPtr(update.ReferralType)),
		ReferralNotes:       pgtypeTextFromStringPtr(update.ReferralNotes),
		FollowUpRecommended: update.FollowUpRecommended,
		FollowUpTimeframe:   pgtypeTextFromStringPtr(update.FollowUpTimeframe),
	})
	if err != nil {
		notesDBQueryTotal.WithLabelValues("update_note", "error").Inc()
		return telemedicine.ConsultationNote{}, r.handleError(err, "update note")
	}
	notesDBQueryTotal.WithLabelValues("update_note", "success").Inc()
	return r.mapToNote(row), nil
}

// FinaliseNote locks a note by its primary key.
// Called when the provider clicks "End Consultation".
func (r *consultationNotesRepository) FinaliseNote(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.FinaliseConsultationNote(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		notesDBQueryTotal.WithLabelValues("finalise_note", "error").Inc()
		return telemedicine.ConsultationNote{}, r.handleError(err, "finalise note")
	}
	notesDBQueryTotal.WithLabelValues("finalise_note", "success").Inc()
	return r.mapToNote(row), nil
}

// FinaliseNoteByConsultation locks a note by consultation ID — more natural
// from the service layer when only the consultation ID is in scope.
func (r *consultationNotesRepository) FinaliseNoteByConsultation(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.FinaliseNoteByConsultation(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		notesDBQueryTotal.WithLabelValues("finalise_note_by_consultation", "error").Inc()
		return telemedicine.ConsultationNote{}, r.handleError(err, "finalise note by consultation")
	}
	notesDBQueryTotal.WithLabelValues("finalise_note_by_consultation", "success").Inc()
	return r.mapToNote(row), nil
}

// ─── Read Operations ──────────────────────────────────────────────────────────

// GetNoteByID fetches a full note row by primary key.
func (r *consultationNotesRepository) GetNoteByID(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationNote, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GetNoteByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		notesDBQueryTotal.WithLabelValues("get_note_by_id", "error").Inc()
		return telemedicine.ConsultationNote{}, r.handleError(err, "get note by id")
	}
	notesDBQueryTotal.WithLabelValues("get_note_by_id", "success").Inc()
	return r.mapToNote(row), nil
}

// GetNoteByConsultationID fetches the note for a given consultation.
func (r *consultationNotesRepository) GetNoteByConsultationID(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNote, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GetNoteByConsultationID(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		notesDBQueryTotal.WithLabelValues("get_note_by_consultation_id", "error").Inc()
		return telemedicine.ConsultationNote{}, r.handleError(err, "get note by consultation id")
	}
	notesDBQueryTotal.WithLabelValues("get_note_by_consultation_id", "success").Inc()
	return r.mapToNote(row), nil
}

// GetNoteWithProviderInfo returns the note joined with the authoring provider's profile.
// Used in patient records and admin audits.
func (r *consultationNotesRepository) GetNoteWithProviderInfo(ctx context.Context, consultationID uuid.UUID) (telemedicine.ConsultationNoteWithProviderInfo, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GetNoteWithProviderInfo(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		notesDBQueryTotal.WithLabelValues("get_note_with_provider_info", "error").Inc()
		return telemedicine.ConsultationNoteWithProviderInfo{}, r.handleError(err, "get note with provider info")
	}
	notesDBQueryTotal.WithLabelValues("get_note_with_provider_info", "success").Inc()
	return r.mapToNoteWithProviderInfo(row), nil
}

// ─── Provider History ─────────────────────────────────────────────────────────

// GetProviderNoteHistory returns paginated finalised notes written by a provider.
func (r *consultationNotesRepository) GetProviderNoteHistory(ctx context.Context, staffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderNoteHistoryEntry, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetProviderNoteHistory(ctx, sqlc.GetProviderNoteHistoryParams{
		AuthoredByStaffID: uuidToPgtypeUUID(staffID),
		Limit:             int32(limit),
		Offset:            int32(offset),
	})
	if err != nil {
		notesDBQueryTotal.WithLabelValues("get_provider_note_history", "error").Inc()
		return nil, r.handleError(err, "get provider note history")
	}
	notesDBQueryTotal.WithLabelValues("get_provider_note_history", "success").Inc()
	return r.mapToProviderNoteHistoryEntries(rows), nil
}

// ─── Patient Record Access ────────────────────────────────────────────────────

// GetPatientNoteHistory returns all finalised notes for a patient across all consultations.
func (r *consultationNotesRepository) GetPatientNoteHistory(ctx context.Context, patientID uuid.UUID) ([]telemedicine.PatientNoteHistoryEntry, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetPatientNoteHistory(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		notesDBQueryTotal.WithLabelValues("get_patient_note_history", "error").Inc()
		return nil, r.handleError(err, "get patient note history")
	}
	notesDBQueryTotal.WithLabelValues("get_patient_note_history", "success").Inc()
	return r.mapToPatientNoteHistoryEntries(rows), nil
}

// ─── Quick Checks ─────────────────────────────────────────────────────────────

// NoteExistsForConsultation returns true if a note row exists for the consultation.
func (r *consultationNotesRepository) NoteExistsForConsultation(ctx context.Context, consultationID uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	exists, err := r.querier.NoteExistsForConsultation(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		notesDBQueryTotal.WithLabelValues("note_exists_for_consultation", "error").Inc()
		return false, r.handleError(err, "note exists for consultation")
	}
	notesDBQueryTotal.WithLabelValues("note_exists_for_consultation", "success").Inc()
	return exists, nil
}

// IsNoteFinalised returns whether the note for a consultation has been locked.
func (r *consultationNotesRepository) IsNoteFinalised(ctx context.Context, consultationID uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() { notesDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	isFinalised, err := r.querier.IsNoteFinalisedForConsultation(ctx, uuidToPgtypeUUID(consultationID))
	if err != nil {
		notesDBQueryTotal.WithLabelValues("is_note_finalised", "error").Inc()
		return false, r.handleError(err, "is note finalised")
	}
	notesDBQueryTotal.WithLabelValues("is_note_finalised", "success").Inc()
	return isFinalised, nil
}

// ─── Mapping helpers ─────────────────────────────────────────────────────────

func (r *consultationNotesRepository) mapToNote(row sqlc.ConsultationNote) telemedicine.ConsultationNote {
	return telemedicine.ConsultationNote{
		ID:                  pgtypeUUIDToUUID(row.ID),
		ConsultationID:      pgtypeUUIDToUUID(row.ConsultationID),
		AuthoredByStaffID:   pgtypeUUIDToUUID(row.AuthoredByStaffID),
		Subjective:          pgtypeTextToStringPtr(row.Subjective),
		Objective:           pgtypeTextToStringPtr(row.Objective),
		Assessment:          pgtypeTextToStringPtr(row.Assessment),
		Plan:                pgtypeTextToStringPtr(row.Plan),
		DiagnosisCodes:      row.DiagnosisCodes,
		PrescriptionIssued:  row.PrescriptionIssued,
		PrescriptionDetails: prescriptionItemsFromJSONB(row.PrescriptionDetails),
		ReferralRequired:    row.ReferralRequired,
		ReferralType:        referralTypePtr(pgtypeTextToStringPtr(row.ReferralType)),
		ReferralNotes:       pgtypeTextToStringPtr(row.ReferralNotes),
		FollowUpRecommended: row.FollowUpRecommended,
		FollowUpTimeframe:   pgtypeTextToStringPtr(row.FollowUpTimeframe),
		IsFinalised:         row.IsFinalised,
		FinalisedAt:         pgtypeTimestampToTimePtr(row.FinalisedAt),
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.UpdatedAt.Time,
	}
}

func (r *consultationNotesRepository) mapToNoteWithProviderInfo(row sqlc.GetNoteWithProviderInfoRow) telemedicine.ConsultationNoteWithProviderInfo {
	return telemedicine.ConsultationNoteWithProviderInfo{
		ConsultationNote: telemedicine.ConsultationNote{
			ID:                  pgtypeUUIDToUUID(row.ID),
			ConsultationID:      pgtypeUUIDToUUID(row.ConsultationID),
			AuthoredByStaffID:   pgtypeUUIDToUUID(row.AuthoredByStaffID),
			Subjective:          pgtypeTextToStringPtr(row.Subjective),
			Objective:           pgtypeTextToStringPtr(row.Objective),
			Assessment:          pgtypeTextToStringPtr(row.Assessment),
			Plan:                pgtypeTextToStringPtr(row.Plan),
			DiagnosisCodes:      row.DiagnosisCodes,
			PrescriptionIssued:  row.PrescriptionIssued,
			PrescriptionDetails: prescriptionItemsFromJSONB(row.PrescriptionDetails),
			ReferralRequired:    row.ReferralRequired,
			ReferralType:        referralTypePtr(pgtypeTextToStringPtr(row.ReferralType)),
			ReferralNotes:       pgtypeTextToStringPtr(row.ReferralNotes),
			FollowUpRecommended: row.FollowUpRecommended,
			FollowUpTimeframe:   pgtypeTextToStringPtr(row.FollowUpTimeframe),
			IsFinalised:         row.IsFinalised,
			FinalisedAt:         pgtypeTimestampToTimePtr(row.FinalisedAt),
			CreatedAt:           row.CreatedAt.Time,
			UpdatedAt:           row.UpdatedAt.Time,
		},
		ProviderFirstName: row.ProviderFirstName,
		ProviderLastName:  row.ProviderLastName,
		ProfessionalTitle: pgtypeTextToStringPtr(row.ProfessionalTitle),
		Specialization:    pgtypeTextToStringPtr(row.Specialization),
		HPCSNumber:        pgtypeTextToStringPtr(row.HpcsNumber),
	}
}

func (r *consultationNotesRepository) mapToProviderNoteHistoryEntry(row sqlc.GetProviderNoteHistoryRow) telemedicine.ProviderNoteHistoryEntry {
	return telemedicine.ProviderNoteHistoryEntry{
		ID:                  pgtypeUUIDToUUID(row.ID),
		ConsultationID:      pgtypeUUIDToUUID(row.ConsultationID),
		Assessment:          pgtypeTextToStringPtr(row.Assessment),
		Plan:                pgtypeTextToStringPtr(row.Plan),
		DiagnosisCodes:      row.DiagnosisCodes,
		PrescriptionIssued:  row.PrescriptionIssued,
		ReferralRequired:    row.ReferralRequired,
		FollowUpRecommended: row.FollowUpRecommended,
		FinalisedAt:         pgtypeTimestampToTimePtr(row.FinalisedAt),
		PatientFirstName:    row.PatientFirstName,
		PatientLastName:     row.PatientLastName,
	}
}

func (r *consultationNotesRepository) mapToProviderNoteHistoryEntries(rows []sqlc.GetProviderNoteHistoryRow) []telemedicine.ProviderNoteHistoryEntry {
	result := make([]telemedicine.ProviderNoteHistoryEntry, len(rows))
	for i, row := range rows {
		result[i] = r.mapToProviderNoteHistoryEntry(row)
	}
	return result
}

func (r *consultationNotesRepository) mapToPatientNoteHistoryEntry(row sqlc.GetPatientNoteHistoryRow) telemedicine.PatientNoteHistoryEntry {
	return telemedicine.PatientNoteHistoryEntry{
		ID:                  pgtypeUUIDToUUID(row.ID),
		ConsultationID:      pgtypeUUIDToUUID(row.ConsultationID),
		Subjective:          pgtypeTextToStringPtr(row.Subjective),
		Assessment:          pgtypeTextToStringPtr(row.Assessment),
		Plan:                pgtypeTextToStringPtr(row.Plan),
		DiagnosisCodes:      row.DiagnosisCodes,
		PrescriptionIssued:  row.PrescriptionIssued,
		PrescriptionDetails: prescriptionItemsFromJSONB(row.PrescriptionDetails),
		ReferralRequired:    row.ReferralRequired,
		ReferralType:        referralTypePtr(pgtypeTextToStringPtr(row.ReferralType)),
		FollowUpRecommended: row.FollowUpRecommended,
		FollowUpTimeframe:   pgtypeTextToStringPtr(row.FollowUpTimeframe),
		FinalisedAt:         pgtypeTimestampToTimePtr(row.FinalisedAt),
		ProviderFirstName:   row.ProviderFirstName,
		ProviderLastName:    row.ProviderLastName,
		ProfessionalTitle:   pgtypeTextToStringPtr(row.ProfessionalTitle),
	}
}

func (r *consultationNotesRepository) mapToPatientNoteHistoryEntries(rows []sqlc.GetPatientNoteHistoryRow) []telemedicine.PatientNoteHistoryEntry {
	result := make([]telemedicine.PatientNoteHistoryEntry, len(rows))
	for i, row := range rows {
		result[i] = r.mapToPatientNoteHistoryEntry(row)
	}
	return result
}

// ─── Error handling ───────────────────────────────────────────────────────────

func (r *consultationNotesRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
