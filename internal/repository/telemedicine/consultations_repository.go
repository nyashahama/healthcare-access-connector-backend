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
	consultationDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "consultation_db_query_duration_seconds",
			Help:    "Consultation database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	consultationDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "consultation_db_query_total",
			Help: "Total number of consultation database queries",
		},
		[]string{"operation", "status"},
	)
)

type consultationRepository struct {
	querier sqlc.Querier
}

func NewConsultationRepository(pool *pgxpool.Pool) repository.ConsultationRepository {
	return NewConsultationRepositoryWithQuerier(sqlc.New(pool))
}

func NewConsultationRepositoryWithQuerier(querier sqlc.Querier) repository.ConsultationRepository {
	return &consultationRepository{querier: querier}
}

// ─── Core CRUD ───────────────────────────────────────────────────────────────

// CreateConsultation opens a new consultation from a completed symptom session.
func (r *consultationRepository) CreateConsultation(ctx context.Context, c telemedicine.Consultation) (telemedicine.Consultation, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.CreateConsultation(ctx, sqlc.CreateConsultationParams{
		SymptomSessionID:   uuidToPgtypeUUID(c.SymptomSessionID),
		PatientID:          uuidToPgtypeUUID(c.PatientID),
		TriageLevelAtStart: pgtypeTextFromStringPtr(c.TriageLevelAtStart),
		Channel:            string(c.Channel),
		ConsultationFee:    float64PtrToPgtypeNumeric(c.ConsultationFee),
		FeeCurrency:        c.FeeCurrency,
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("create_consultation", "error").Inc()
		return telemedicine.Consultation{}, r.handleError(err, "create consultation")
	}
	consultationDBQueryTotal.WithLabelValues("create_consultation", "success").Inc()
	return r.mapToConsultation(row), nil
}

// GetConsultationByID fetches a full consultation row by primary key.
func (r *consultationRepository) GetConsultationByID(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GetConsultationByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("get_consultation_by_id", "error").Inc()
		return telemedicine.Consultation{}, r.handleError(err, "get consultation by id")
	}
	consultationDBQueryTotal.WithLabelValues("get_consultation_by_id", "success").Inc()
	return r.mapToConsultation(row), nil
}

// GetConsultationWithDetails fetches the full consultation joined with the session,
// patient profile, and provider profile. Used to hydrate the chat screen.
func (r *consultationRepository) GetConsultationWithDetails(ctx context.Context, id uuid.UUID) (telemedicine.ConsultationWithDetails, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GetConsultationWithDetails(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("get_consultation_with_details", "error").Inc()
		return telemedicine.ConsultationWithDetails{}, r.handleError(err, "get consultation with details")
	}
	consultationDBQueryTotal.WithLabelValues("get_consultation_with_details", "success").Inc()
	return r.mapToConsultationWithDetails(row), nil
}

// ─── Status Transitions ───────────────────────────────────────────────────────

// AcceptConsultation assigns a provider and moves the consultation to accepted.
// SQL guards on status = 'pending_acceptance' — returns domain.ErrNotFound otherwise.
func (r *consultationRepository) AcceptConsultation(ctx context.Context, id uuid.UUID, providerStaffID uuid.UUID, clinicID uuid.UUID) (telemedicine.Consultation, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.AcceptConsultation(ctx, sqlc.AcceptConsultationParams{
		ID:              uuidToPgtypeUUID(id),
		ProviderStaffID: uuidToPgtypeUUID(providerStaffID),
		ClinicID:        uuidToPgtypeUUID(clinicID),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("accept_consultation", "error").Inc()
		return telemedicine.Consultation{}, r.handleError(err, "accept consultation")
	}
	consultationDBQueryTotal.WithLabelValues("accept_consultation", "success").Inc()
	return r.mapToConsultation(row), nil
}

// StartConsultation moves the consultation from accepted to in_progress on first message.
func (r *consultationRepository) StartConsultation(ctx context.Context, id uuid.UUID) (telemedicine.Consultation, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.StartConsultation(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("start_consultation", "error").Inc()
		return telemedicine.Consultation{}, r.handleError(err, "start consultation")
	}
	consultationDBQueryTotal.WithLabelValues("start_consultation", "success").Inc()
	return r.mapToConsultation(row), nil
}

// CompleteConsultation closes an in_progress consultation and records duration.
func (r *consultationRepository) CompleteConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.CompleteConsultation(ctx, sqlc.CompleteConsultationParams{
		ID:      uuidToPgtypeUUID(id),
		EndedBy: uuidToPgtypeUUID(endedBy),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("complete_consultation", "error").Inc()
		return telemedicine.Consultation{}, r.handleError(err, "complete consultation")
	}
	consultationDBQueryTotal.WithLabelValues("complete_consultation", "success").Inc()
	return r.mapToConsultation(row), nil
}

// CancelConsultation cancels a pending or accepted consultation.
func (r *consultationRepository) CancelConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.CancelConsultation(ctx, sqlc.CancelConsultationParams{
		ID:      uuidToPgtypeUUID(id),
		EndedBy: uuidToPgtypeUUID(endedBy),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("cancel_consultation", "error").Inc()
		return telemedicine.Consultation{}, r.handleError(err, "cancel consultation")
	}
	consultationDBQueryTotal.WithLabelValues("cancel_consultation", "success").Inc()
	return r.mapToConsultation(row), nil
}

// DeclineConsultation moves a pending consultation to declined.
// The patient will see a fresh provider list.
func (r *consultationRepository) DeclineConsultation(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.DeclineConsultation(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("decline_consultation", "error").Inc()
		return r.handleError(err, "decline consultation")
	}
	consultationDBQueryTotal.WithLabelValues("decline_consultation", "success").Inc()
	return nil
}

// EscalateConsultation moves an in_progress consultation to escalated.
func (r *consultationRepository) EscalateConsultation(ctx context.Context, id uuid.UUID, endedBy uuid.UUID) (telemedicine.Consultation, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.EscalateConsultation(ctx, sqlc.EscalateConsultationParams{
		ID:      uuidToPgtypeUUID(id),
		EndedBy: uuidToPgtypeUUID(endedBy),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("escalate_consultation", "error").Inc()
		return telemedicine.Consultation{}, r.handleError(err, "escalate consultation")
	}
	consultationDBQueryTotal.WithLabelValues("escalate_consultation", "success").Inc()
	return r.mapToConsultation(row), nil
}

// MarkNoShow moves an accepted consultation to no_show.
func (r *consultationRepository) MarkNoShow(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.MarkNoShow(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("mark_no_show", "error").Inc()
		return r.handleError(err, "mark no show")
	}
	consultationDBQueryTotal.WithLabelValues("mark_no_show", "success").Inc()
	return nil
}

// UpdateConsultationChannel updates the channel (e.g. chat → video).
func (r *consultationRepository) UpdateConsultationChannel(ctx context.Context, id uuid.UUID, channel telemedicine.ConsultationChannel) error {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.UpdateConsultationChannel(ctx, sqlc.UpdateConsultationChannelParams{
		ID:      uuidToPgtypeUUID(id),
		Channel: string(channel),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("update_consultation_channel", "error").Inc()
		return r.handleError(err, "update consultation channel")
	}
	consultationDBQueryTotal.WithLabelValues("update_consultation_channel", "success").Inc()
	return nil
}

// ─── Billing ─────────────────────────────────────────────────────────────────

// UpdatePaymentStatus updates the payment state and records the payment reference.
func (r *consultationRepository) UpdatePaymentStatus(ctx context.Context, id uuid.UUID, status telemedicine.PaymentStatus, reference *string) error {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.UpdatePaymentStatus(ctx, sqlc.UpdatePaymentStatusParams{
		ID:               uuidToPgtypeUUID(id),
		PaymentStatus:    string(status),
		PaymentReference: pgtypeTextFromStringPtr(reference),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("update_payment_status", "error").Inc()
		return r.handleError(err, "update payment status")
	}
	consultationDBQueryTotal.WithLabelValues("update_payment_status", "success").Inc()
	return nil
}

// SetConsultationFee sets the consultation fee after provider acceptance.
func (r *consultationRepository) SetConsultationFee(ctx context.Context, id uuid.UUID, fee float64) error {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.SetConsultationFee(ctx, sqlc.SetConsultationFeeParams{
		ID:              uuidToPgtypeUUID(id),
		ConsultationFee: float64PtrToPgtypeNumeric(&fee),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("set_consultation_fee", "error").Inc()
		return r.handleError(err, "set consultation fee")
	}
	consultationDBQueryTotal.WithLabelValues("set_consultation_fee", "success").Inc()
	return nil
}

// ─── Rating ───────────────────────────────────────────────────────────────────

// SubmitPatientRating records the patient's post-consultation rating and feedback.
// No-ops if already rated or not in a completed/escalated state (SQL guards both).
func (r *consultationRepository) SubmitPatientRating(ctx context.Context, id uuid.UUID, rating int, feedback *string) error {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.SubmitPatientRating(ctx, sqlc.SubmitPatientRatingParams{
		ID:              uuidToPgtypeUUID(id),
		PatientRating:   intPtrToPgtypeInt4(&rating),
		PatientFeedback: pgtypeTextFromStringPtr(feedback),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("submit_patient_rating", "error").Inc()
		return r.handleError(err, "submit patient rating")
	}
	consultationDBQueryTotal.WithLabelValues("submit_patient_rating", "success").Inc()
	return nil
}

// LinkFollowUpAppointment associates a follow-up appointment with a consultation.
func (r *consultationRepository) LinkFollowUpAppointment(ctx context.Context, id uuid.UUID, appointmentID uuid.UUID) error {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.LinkFollowUpAppointment(ctx, sqlc.LinkFollowUpAppointmentParams{
		ID:                    uuidToPgtypeUUID(id),
		FollowUpAppointmentID: uuidToPgtypeUUID(appointmentID),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("link_follow_up_appointment", "error").Inc()
		return r.handleError(err, "link follow up appointment")
	}
	consultationDBQueryTotal.WithLabelValues("link_follow_up_appointment", "success").Inc()
	return nil
}

// ─── Patient-Facing ───────────────────────────────────────────────────────────

// GetPatientConsultations returns paginated consultation history for a patient.
func (r *consultationRepository) GetPatientConsultations(ctx context.Context, patientID uuid.UUID, limit, offset int) ([]telemedicine.PatientConsultationSummary, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetPatientConsultations(ctx, sqlc.GetPatientConsultationsParams{
		PatientID: uuidToPgtypeUUID(patientID),
		Limit:     int32(limit),
		Offset:    int32(offset),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("get_patient_consultations", "error").Inc()
		return nil, r.handleError(err, "get patient consultations")
	}
	consultationDBQueryTotal.WithLabelValues("get_patient_consultations", "success").Inc()
	return r.mapToPatientConsultationSummaries(rows), nil
}

// GetPatientActiveConsultation returns the patient's current open consultation.
// Returns domain.ErrNotFound when no open consultation exists.
func (r *consultationRepository) GetPatientActiveConsultation(ctx context.Context, patientID uuid.UUID) (telemedicine.ActiveConsultationCheck, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GetPatientActiveConsultation(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("get_patient_active_consultation", "error").Inc()
		return telemedicine.ActiveConsultationCheck{}, r.handleError(err, "get patient active consultation")
	}
	consultationDBQueryTotal.WithLabelValues("get_patient_active_consultation", "success").Inc()
	return telemedicine.ActiveConsultationCheck{
		ID:              pgtypeUUIDToUUID(row.ID),
		Status:          telemedicine.ConsultationStatus(row.Status),
		ProviderStaffID: uuidPtrToUUID(row.ProviderStaffID),
		Channel:         telemedicine.ConsultationChannel(row.Channel),
	}, nil
}

// ─── Provider-Facing ─────────────────────────────────────────────────────────

// GetProviderActiveConsultations returns all open consultations for a provider,
// ordered by triage priority then request time.
func (r *consultationRepository) GetProviderActiveConsultations(ctx context.Context, providerStaffID uuid.UUID) ([]telemedicine.ProviderActiveConsultation, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetProviderActiveConsultations(ctx, uuidToPgtypeUUID(providerStaffID))
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("get_provider_active_consultations", "error").Inc()
		return nil, r.handleError(err, "get provider active consultations")
	}
	consultationDBQueryTotal.WithLabelValues("get_provider_active_consultations", "success").Inc()
	return r.mapToProviderActiveConsultations(rows), nil
}

// GetWaitingRoom returns all pending_acceptance consultations, ordered by triage priority.
func (r *consultationRepository) GetWaitingRoom(ctx context.Context) ([]telemedicine.WaitingRoomEntry, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetWaitingRoom(ctx)
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("get_waiting_room", "error").Inc()
		return nil, r.handleError(err, "get waiting room")
	}
	consultationDBQueryTotal.WithLabelValues("get_waiting_room", "success").Inc()
	return r.mapToWaitingRoomEntries(rows), nil
}

// GetProviderConsultationHistory returns paginated closed consultations for a provider.
func (r *consultationRepository) GetProviderConsultationHistory(ctx context.Context, providerStaffID uuid.UUID, limit, offset int) ([]telemedicine.ProviderConsultationHistoryEntry, error) {
	start := time.Now()
	defer func() { consultationDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetProviderConsultationHistory(ctx, sqlc.GetProviderConsultationHistoryParams{
		ProviderStaffID: uuidToPgtypeUUID(providerStaffID),
		Limit:           int32(limit),
		Offset:          int32(offset),
	})
	if err != nil {
		consultationDBQueryTotal.WithLabelValues("get_provider_consultation_history", "error").Inc()
		return nil, r.handleError(err, "get provider consultation history")
	}
	consultationDBQueryTotal.WithLabelValues("get_provider_consultation_history", "success").Inc()
	return r.mapToProviderConsultationHistory(rows), nil
}

// ─── Mapping helpers ─────────────────────────────────────────────────────────

func (r *consultationRepository) mapToConsultation(row sqlc.Consultation) telemedicine.Consultation {
	return telemedicine.Consultation{
		ID:                    pgtypeUUIDToUUID(row.ID),
		SymptomSessionID:      pgtypeUUIDToUUID(row.SymptomSessionID),
		PatientID:             pgtypeUUIDToUUID(row.PatientID),
		ProviderStaffID:       uuidPtrToUUID(row.ProviderStaffID),
		ClinicID:              uuidPtrToUUID(row.ClinicID),
		Channel:               telemedicine.ConsultationChannel(row.Channel),
		TriageLevelAtStart:    pgtypeTextToStringPtr(row.TriageLevelAtStart),
		RequestedAt:           pgtypeTimestampToTimePtr(row.RequestedAt),
		AcceptedAt:            pgtypeTimestampToTimePtr(row.AcceptedAt),
		StartedAt:             pgtypeTimestampToTimePtr(row.StartedAt),
		EndedAt:               pgtypeTimestampToTimePtr(row.EndedAt),
		DurationSeconds:       pgtypeInt4ToIntPtr(row.DurationSeconds),
		Status:                telemedicine.ConsultationStatus(row.Status),
		EndedBy:               uuidPtrToUUID(row.EndedBy),
		EndReason:             endReasonPtr(pgtypeTextToStringPtr(row.EndReason)),
		ConsultationFee:       pgtypeNumericToFloat64Ptr(row.ConsultationFee),
		FeeCurrency:           row.FeeCurrency,
		PaymentStatus:         telemedicine.PaymentStatus(row.PaymentStatus),
		PaymentReference:      pgtypeTextToStringPtr(row.PaymentReference),
		PatientRating:         pgtypeInt4ToIntPtr(row.PatientRating),
		PatientFeedback:       pgtypeTextToStringPtr(row.PatientFeedback),
		RatedAt:               pgtypeTimestampToTimePtr(row.RatedAt),
		FollowUpAppointmentID: uuidPtrToUUID(row.FollowUpAppointmentID),
		CreatedAt:             row.CreatedAt.Time,
		UpdatedAt:             row.UpdatedAt.Time,
	}
}

func (r *consultationRepository) mapToConsultationWithDetails(row sqlc.GetConsultationWithDetailsRow) telemedicine.ConsultationWithDetails {
	sessionTriageLevel := row.SessionTriageLevel
	return telemedicine.ConsultationWithDetails{
		// All core Consultation fields
		Consultation: telemedicine.Consultation{
			ID:                    pgtypeUUIDToUUID(row.ID),
			SymptomSessionID:      pgtypeUUIDToUUID(row.SymptomSessionID),
			PatientID:             pgtypeUUIDToUUID(row.PatientID),
			ProviderStaffID:       uuidPtrToUUID(row.ProviderStaffID),
			ClinicID:              uuidPtrToUUID(row.ClinicID),
			Channel:               telemedicine.ConsultationChannel(row.Channel),
			TriageLevelAtStart:    pgtypeTextToStringPtr(row.TriageLevelAtStart),
			RequestedAt:           pgtypeTimestampToTimePtr(row.RequestedAt),
			AcceptedAt:            pgtypeTimestampToTimePtr(row.AcceptedAt),
			StartedAt:             pgtypeTimestampToTimePtr(row.StartedAt),
			EndedAt:               pgtypeTimestampToTimePtr(row.EndedAt),
			DurationSeconds:       pgtypeInt4ToIntPtr(row.DurationSeconds),
			Status:                telemedicine.ConsultationStatus(row.Status),
			EndedBy:               uuidPtrToUUID(row.EndedBy),
			EndReason:             endReasonPtr(pgtypeTextToStringPtr(row.EndReason)),
			ConsultationFee:       pgtypeNumericToFloat64Ptr(row.ConsultationFee),
			FeeCurrency:           row.FeeCurrency,
			PaymentStatus:         telemedicine.PaymentStatus(row.PaymentStatus),
			PaymentReference:      pgtypeTextToStringPtr(row.PaymentReference),
			PatientRating:         pgtypeInt4ToIntPtr(row.PatientRating),
			PatientFeedback:       pgtypeTextToStringPtr(row.PatientFeedback),
			RatedAt:               pgtypeTimestampToTimePtr(row.RatedAt),
			FollowUpAppointmentID: uuidPtrToUUID(row.FollowUpAppointmentID),
			CreatedAt:             row.CreatedAt.Time,
			UpdatedAt:             row.UpdatedAt.Time,
		},
		ChiefComplaint:               row.ChiefComplaint,
		AISummary:                    pgtypeTextToStringPtr(row.AiSummary),
		SessionTriageLevel:           &sessionTriageLevel,
		SymptomsReported:             stringSliceFromJSONB(row.SymptomsReported),
		PatientFirstName:             row.PatientFirstName,
		PatientLastName:              row.PatientLastName,
		PreferredCommunicationMethod: pgtypeTextToStringPtr(row.PreferredCommunicationMethod),
		ProviderFirstName:            pgtypeTextToStringPtr(row.ProviderFirstName),
		ProviderLastName:             pgtypeTextToStringPtr(row.ProviderLastName),
		ProviderSpecialization:       pgtypeTextToStringPtr(row.ProviderSpecialization),
		ProviderTitle:                pgtypeTextToStringPtr(row.ProviderTitle),
	}
}

func (r *consultationRepository) mapToPatientConsultationSummary(row sqlc.GetPatientConsultationsRow) telemedicine.PatientConsultationSummary {
	return telemedicine.PatientConsultationSummary{
		ID:                     pgtypeUUIDToUUID(row.ID),
		Status:                 telemedicine.ConsultationStatus(row.Status),
		Channel:                telemedicine.ConsultationChannel(row.Channel),
		TriageLevelAtStart:     pgtypeTextToStringPtr(row.TriageLevelAtStart),
		RequestedAt:            pgtypeTimestampToTimePtr(row.RequestedAt),
		StartedAt:              pgtypeTimestampToTimePtr(row.StartedAt),
		EndedAt:                pgtypeTimestampToTimePtr(row.EndedAt),
		DurationSeconds:        pgtypeInt4ToIntPtr(row.DurationSeconds),
		ConsultationFee:        pgtypeNumericToFloat64Ptr(row.ConsultationFee),
		PaymentStatus:          telemedicine.PaymentStatus(row.PaymentStatus),
		PatientRating:          pgtypeInt4ToIntPtr(row.PatientRating),
		ChiefComplaint:         row.ChiefComplaint,
		ProviderFirstName:      pgtypeTextToStringPtr(row.ProviderFirstName),
		ProviderLastName:       pgtypeTextToStringPtr(row.ProviderLastName),
		ProviderSpecialization: pgtypeTextToStringPtr(row.ProviderSpecialization),
	}
}

func (r *consultationRepository) mapToPatientConsultationSummaries(rows []sqlc.GetPatientConsultationsRow) []telemedicine.PatientConsultationSummary {
	result := make([]telemedicine.PatientConsultationSummary, len(rows))
	for i, row := range rows {
		result[i] = r.mapToPatientConsultationSummary(row)
	}
	return result
}

func (r *consultationRepository) mapToProviderActiveConsultation(row sqlc.GetProviderActiveConsultationsRow) telemedicine.ProviderActiveConsultation {
	return telemedicine.ProviderActiveConsultation{
		ID:                           pgtypeUUIDToUUID(row.ID),
		Status:                       telemedicine.ConsultationStatus(row.Status),
		TriageLevelAtStart:           pgtypeTextToStringPtr(row.TriageLevelAtStart),
		RequestedAt:                  pgtypeTimestampToTimePtr(row.RequestedAt),
		StartedAt:                    pgtypeTimestampToTimePtr(row.StartedAt),
		Channel:                      telemedicine.ConsultationChannel(row.Channel),
		PatientFirstName:             row.PatientFirstName,
		PatientLastName:              row.PatientLastName,
		PreferredCommunicationMethod: pgtypeTextToStringPtr(row.PreferredCommunicationMethod),
		RequiresInterpreter:          pgtypeBoolToBool(row.RequiresInterpreter),
		ChiefComplaint:               row.ChiefComplaint,
		AISummary:                    pgtypeTextToStringPtr(row.AiSummary),
		SeverityScore:                pgtypeInt4ToIntPtr(row.SeverityScore),
		UnreadMessages:               row.UnreadMessages,
	}
}

func (r *consultationRepository) mapToProviderActiveConsultations(rows []sqlc.GetProviderActiveConsultationsRow) []telemedicine.ProviderActiveConsultation {
	result := make([]telemedicine.ProviderActiveConsultation, len(rows))
	for i, row := range rows {
		result[i] = r.mapToProviderActiveConsultation(row)
	}
	return result
}

func (r *consultationRepository) mapToWaitingRoomEntry(row sqlc.GetWaitingRoomRow) telemedicine.WaitingRoomEntry {
	return telemedicine.WaitingRoomEntry{
		ID:                 pgtypeUUIDToUUID(row.ID),
		TriageLevelAtStart: pgtypeTextToStringPtr(row.TriageLevelAtStart),
		RequestedAt:        pgtypeTimestampToTimePtr(row.RequestedAt),
		Channel:            telemedicine.ConsultationChannel(row.Channel),
		ConsultationFee:    pgtypeNumericToFloat64Ptr(row.ConsultationFee),
		PatientFirstName:   row.PatientFirstName,
		PatientLastName:    row.PatientLastName,
		ChiefComplaint:     row.ChiefComplaint,
		SeverityScore:      pgtypeInt4ToIntPtr(row.SeverityScore),
		AISummary:          pgtypeTextToStringPtr(row.AiSummary),
	}
}

func (r *consultationRepository) mapToWaitingRoomEntries(rows []sqlc.GetWaitingRoomRow) []telemedicine.WaitingRoomEntry {
	result := make([]telemedicine.WaitingRoomEntry, len(rows))
	for i, row := range rows {
		result[i] = r.mapToWaitingRoomEntry(row)
	}
	return result
}

func (r *consultationRepository) mapToProviderConsultationHistoryEntry(row sqlc.GetProviderConsultationHistoryRow) telemedicine.ProviderConsultationHistoryEntry {
	return telemedicine.ProviderConsultationHistoryEntry{
		ID:               pgtypeUUIDToUUID(row.ID),
		Status:           telemedicine.ConsultationStatus(row.Status),
		Channel:          telemedicine.ConsultationChannel(row.Channel),
		RequestedAt:      pgtypeTimestampToTimePtr(row.RequestedAt),
		EndedAt:          pgtypeTimestampToTimePtr(row.EndedAt),
		DurationSeconds:  pgtypeInt4ToIntPtr(row.DurationSeconds),
		ConsultationFee:  pgtypeNumericToFloat64Ptr(row.ConsultationFee),
		PaymentStatus:    telemedicine.PaymentStatus(row.PaymentStatus),
		PatientRating:    pgtypeInt4ToIntPtr(row.PatientRating),
		EndReason:        endReasonPtr(pgtypeTextToStringPtr(row.EndReason)),
		PatientFirstName: row.PatientFirstName,
		PatientLastName:  row.PatientLastName,
		ChiefComplaint:   row.ChiefComplaint,
	}
}

func (r *consultationRepository) mapToProviderConsultationHistory(rows []sqlc.GetProviderConsultationHistoryRow) []telemedicine.ProviderConsultationHistoryEntry {
	result := make([]telemedicine.ProviderConsultationHistoryEntry, len(rows))
	for i, row := range rows {
		result[i] = r.mapToProviderConsultationHistoryEntry(row)
	}
	return result
}

// endReasonPtr converts a *string to a typed *ConsultationEndReason.
func endReasonPtr(s *string) *telemedicine.ConsultationEndReason {
	if s == nil {
		return nil
	}
	r := telemedicine.ConsultationEndReason(*s)
	return &r
}

// ─── Error handling ───────────────────────────────────────────────────────────

func (r *consultationRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
