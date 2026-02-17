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
	providerAvailabilityDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "provider_availability_db_query_duration_seconds",
			Help:    "Provider availability database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	providerAvailabilityDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "provider_availability_db_query_total",
			Help: "Total number of provider availability database queries",
		},
		[]string{"operation", "status"},
	)
)

type providerAvailabilityRepository struct {
	querier sqlc.Querier
}

func NewProviderAvailabilityRepository(pool *pgxpool.Pool) repository.ProviderAvailabilityRepository {
	return NewProviderAvailabilityRepositoryWithQuerier(sqlc.New(pool))
}

func NewProviderAvailabilityRepositoryWithQuerier(querier sqlc.Querier) repository.ProviderAvailabilityRepository {
	return &providerAvailabilityRepository{querier: querier}
}

// ─── Upsert / Initialise ─────────────────────────────────────────────────────

// UpsertAvailability creates a row on first login, touches updated_at on subsequent calls.
func (r *providerAvailabilityRepository) UpsertAvailability(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.UpsertProviderAvailability(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("upsert_availability", "error").Inc()
		return telemedicine.ProviderAvailability{}, r.handleError(err, "upsert availability")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("upsert_availability", "success").Inc()
	return r.mapToAvailability(row), nil
}

// ─── Status Transitions ───────────────────────────────────────────────────────

// GoOnline marks the provider online and records shift_start if not already set.
func (r *providerAvailabilityRepository) GoOnline(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GoOnline(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("go_online", "error").Inc()
		return telemedicine.ProviderAvailability{}, r.handleError(err, "go online")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("go_online", "success").Inc()
	return r.mapToAvailability(row), nil
}

// GoOffline marks the provider offline, clears is_accepting, and nulls shift_start.
func (r *providerAvailabilityRepository) GoOffline(ctx context.Context, staffID uuid.UUID) error {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.GoOffline(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("go_offline", "error").Inc()
		return r.handleError(err, "go offline")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("go_offline", "success").Inc()
	return nil
}

// SetAccepting toggles the provider's accepting state and optionally updates the
// fee override and estimated wait time via SQL COALESCE.
func (r *providerAvailabilityRepository) SetAccepting(ctx context.Context, staffID uuid.UUID, accepting bool, feeOverride *float64, waitMinutes *int) (telemedicine.ProviderAvailability, error) {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.SetAccepting(ctx, sqlc.SetAcceptingParams{
		StaffID:                 uuidToPgtypeUUID(staffID),
		IsAccepting:             accepting,
		ConsultationFeeOverride: float64PtrToPgtypeNumeric(feeOverride),
		EstimatedWaitMinutes:    intPtrToPgtypeInt4(waitMinutes),
	})
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("set_accepting", "error").Inc()
		return telemedicine.ProviderAvailability{}, r.handleError(err, "set accepting")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("set_accepting", "success").Inc()
	return r.mapToAvailability(row), nil
}

// UpdateStatus sets the provider's status enum and optional status message.
func (r *providerAvailabilityRepository) UpdateStatus(ctx context.Context, staffID uuid.UUID, status telemedicine.ProviderAvailabilityStatus, message *string) error {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.UpdateStatus(ctx, sqlc.UpdateStatusParams{
		StaffID:       uuidToPgtypeUUID(staffID),
		Status:        string(status),
		StatusMessage: pgtypeTextFromStringPtr(message),
	})
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("update_status", "error").Inc()
		return r.handleError(err, "update status")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("update_status", "success").Inc()
	return nil
}

// UpdateHeartbeat records the current timestamp as the provider's last_seen_at.
// Called every 30 s from the provider dashboard.
func (r *providerAvailabilityRepository) UpdateHeartbeat(ctx context.Context, staffID uuid.UUID) error {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.UpdateHeartbeat(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("update_heartbeat", "error").Inc()
		return r.handleError(err, "update heartbeat")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("update_heartbeat", "success").Inc()
	return nil
}

// ─── Concurrency Counters ─────────────────────────────────────────────────────

// IncrementActiveConsultations atomically increments the active count.
// The SQL WHERE clause enforces the cap — returns domain.ErrNotFound when the
// provider is already at capacity (0 rows match → no row returned).
func (r *providerAvailabilityRepository) IncrementActiveConsultations(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.IncrementActiveConsultations(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("increment_active_consultations", "error").Inc()
		return telemedicine.ProviderAvailability{}, r.handleError(err, "increment active consultations")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("increment_active_consultations", "success").Inc()
	return r.mapToAvailability(row), nil
}

// DecrementActiveConsultations decrements the count when a consultation closes.
func (r *providerAvailabilityRepository) DecrementActiveConsultations(ctx context.Context, staffID uuid.UUID) error {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.DecrementActiveConsultations(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("decrement_active_consultations", "error").Inc()
		return r.handleError(err, "decrement active consultations")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("decrement_active_consultations", "success").Inc()
	return nil
}

// SetMaxConcurrent updates the maximum concurrent consultation cap.
func (r *providerAvailabilityRepository) SetMaxConcurrent(ctx context.Context, staffID uuid.UUID, max int) error {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.SetMaxConcurrent(ctx, sqlc.SetMaxConcurrentParams{
		StaffID:                    uuidToPgtypeUUID(staffID),
		MaxConcurrentConsultations: int32(max),
	})
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("set_max_concurrent", "error").Inc()
		return r.handleError(err, "set max concurrent")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("set_max_concurrent", "success").Inc()
	return nil
}

// ─── Provider List (Patient-Facing) ──────────────────────────────────────────

// GetAvailableProviders returns providers who are online, accepting, and under
// capacity. Pass nil clinicID to show providers across all clinics.
func (r *providerAvailabilityRepository) GetAvailableProviders(ctx context.Context, clinicID *uuid.UUID) ([]telemedicine.AvailableProvider, error) {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetAvailableProviders(ctx, uuidPtrToPgtypeUUID(clinicID))
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("get_available_providers", "error").Inc()
		return nil, r.handleError(err, "get available providers")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("get_available_providers", "success").Inc()
	return r.mapToAvailableProviders(rows), nil
}

// GetAvailableProvidersBySpecialization returns providers filtered by specialization.
func (r *providerAvailabilityRepository) GetAvailableProvidersBySpecialization(ctx context.Context, specialization string) ([]telemedicine.AvailableProviderBySpecialization, error) {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetAvailableProvidersBySpecialization(ctx, pgtypeTextFromString(specialization))
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("get_available_providers_by_specialization", "error").Inc()
		return nil, r.handleError(err, "get available providers by specialization")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("get_available_providers_by_specialization", "success").Inc()
	return r.mapToAvailableProvidersBySpecialization(rows), nil
}

// ─── Provider Self-Reads ──────────────────────────────────────────────────────

// GetAvailabilityByStaffID fetches the full availability row for a provider.
func (r *providerAvailabilityRepository) GetAvailabilityByStaffID(ctx context.Context, staffID uuid.UUID) (telemedicine.ProviderAvailability, error) {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	row, err := r.querier.GetAvailabilityByStaffID(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("get_availability_by_staff_id", "error").Inc()
		return telemedicine.ProviderAvailability{}, r.handleError(err, "get availability by staff id")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("get_availability_by_staff_id", "success").Inc()
	return r.mapToAvailability(row), nil
}

// UpdateWaitTime sets the estimated wait minutes displayed to patients.
func (r *providerAvailabilityRepository) UpdateWaitTime(ctx context.Context, staffID uuid.UUID, minutes int) error {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.UpdateWaitTime(ctx, sqlc.UpdateWaitTimeParams{
		StaffID:              uuidToPgtypeUUID(staffID),
		EstimatedWaitMinutes: intPtrToPgtypeInt4(&minutes),
	})
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("update_wait_time", "error").Inc()
		return r.handleError(err, "update wait time")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("update_wait_time", "success").Inc()
	return nil
}

// ─── Background Job ───────────────────────────────────────────────────────────

// GetStaleProviders returns providers whose heartbeat is older than 2 minutes.
func (r *providerAvailabilityRepository) GetStaleProviders(ctx context.Context) ([]telemedicine.StaleProvider, error) {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	rows, err := r.querier.GetStaleProviders(ctx)
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("get_stale_providers", "error").Inc()
		return nil, r.handleError(err, "get stale providers")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("get_stale_providers", "success").Inc()
	result := make([]telemedicine.StaleProvider, len(rows))
	for i, row := range rows {
		result[i] = telemedicine.StaleProvider{StaffID: pgtypeUUIDToUUID(row)}
	}
	return result, nil
}

// SetStaleProvidersOffline bulk-marks all heartbeat-stale providers as offline.
func (r *providerAvailabilityRepository) SetStaleProvidersOffline(ctx context.Context) error {
	start := time.Now()
	defer func() { providerAvailabilityDBQueryDuration.Observe(time.Since(start).Seconds()) }()

	err := r.querier.SetStaleProvidersOffline(ctx)
	if err != nil {
		providerAvailabilityDBQueryTotal.WithLabelValues("set_stale_providers_offline", "error").Inc()
		return r.handleError(err, "set stale providers offline")
	}
	providerAvailabilityDBQueryTotal.WithLabelValues("set_stale_providers_offline", "success").Inc()
	return nil
}

// ─── Mapping helpers ─────────────────────────────────────────────────────────

func (r *providerAvailabilityRepository) mapToAvailability(row sqlc.ProviderAvailability) telemedicine.ProviderAvailability {
	return telemedicine.ProviderAvailability{
		ID:                         pgtypeUUIDToUUID(row.ID),
		StaffID:                    pgtypeUUIDToUUID(row.StaffID),
		IsOnline:                   row.IsOnline,
		IsAccepting:                row.IsAccepting,
		Status:                     telemedicine.ProviderAvailabilityStatus(row.Status),
		ActiveConsultationCount:    int(row.ActiveConsultationCount),
		MaxConcurrentConsultations: int(row.MaxConcurrentConsultations),
		EstimatedWaitMinutes:       pgtypeInt4ToIntPtr(row.EstimatedWaitMinutes),
		StatusMessage:              pgtypeTextToStringPtr(row.StatusMessage),
		ConsultationFeeOverride:    pgtypeNumericToFloat64Ptr(row.ConsultationFeeOverride),
		LastSeenAt:                 pgtypeTimestampToTimePtr(row.LastSeenAt),
		ShiftStart:                 pgtypeTimestampToTimePtr(row.ShiftStart),
		UpdatedAt:                  row.UpdatedAt.Time,
	}
}

func (r *providerAvailabilityRepository) mapToAvailableProvider(row sqlc.GetAvailableProvidersRow) telemedicine.AvailableProvider {
	return telemedicine.AvailableProvider{
		StaffID:                    pgtypeUUIDToUUID(row.StaffID),
		Status:                     telemedicine.ProviderAvailabilityStatus(row.Status),
		EstimatedWaitMinutes:       pgtypeInt4ToIntPtr(row.EstimatedWaitMinutes),
		ActiveConsultationCount:    int(row.ActiveConsultationCount),
		MaxConcurrentConsultations: int(row.MaxConcurrentConsultations),
		ConsultationFeeOverride:    pgtypeNumericToFloat64Ptr(row.ConsultationFeeOverride),
		StatusMessage:              pgtypeTextToStringPtr(row.StatusMessage),
		Title:                      pgtypeTextToStringPtr(row.Title),
		FirstName:                  row.FirstName,
		LastName:                   row.LastName,
		ProfessionalTitle:          pgtypeTextToStringPtr(row.ProfessionalTitle),
		Specialization:             pgtypeTextToStringPtr(row.Specialization),
		Bio:                        pgtypeTextToStringPtr(row.Bio),
		ProfilePictureURL:          pgtypeTextToStringPtr(row.ProfilePictureUrl),
		YearsExperience:            pgtypeInt4ToIntPtr(row.YearsExperience),
		LanguagesSpoken:            row.LanguagesSpoken,
	}
}

func (r *providerAvailabilityRepository) mapToAvailableProviders(rows []sqlc.GetAvailableProvidersRow) []telemedicine.AvailableProvider {
	result := make([]telemedicine.AvailableProvider, len(rows))
	for i, row := range rows {
		result[i] = r.mapToAvailableProvider(row)
	}
	return result
}

func (r *providerAvailabilityRepository) mapToAvailableProviderBySpecialization(row sqlc.GetAvailableProvidersBySpecializationRow) telemedicine.AvailableProviderBySpecialization {
	return telemedicine.AvailableProviderBySpecialization{
		StaffID:                 pgtypeUUIDToUUID(row.StaffID),
		Status:                  telemedicine.ProviderAvailabilityStatus(row.Status),
		EstimatedWaitMinutes:    pgtypeInt4ToIntPtr(row.EstimatedWaitMinutes),
		ConsultationFeeOverride: pgtypeNumericToFloat64Ptr(row.ConsultationFeeOverride),
		FirstName:               row.FirstName,
		LastName:                row.LastName,
		ProfessionalTitle:       pgtypeTextToStringPtr(row.ProfessionalTitle),
		Specialization:          pgtypeTextToStringPtr(row.Specialization),
		ProfilePictureURL:       pgtypeTextToStringPtr(row.ProfilePictureUrl),
		YearsExperience:         pgtypeInt4ToIntPtr(row.YearsExperience),
	}
}

func (r *providerAvailabilityRepository) mapToAvailableProvidersBySpecialization(rows []sqlc.GetAvailableProvidersBySpecializationRow) []telemedicine.AvailableProviderBySpecialization {
	result := make([]telemedicine.AvailableProviderBySpecialization, len(rows))
	for i, row := range rows {
		result[i] = r.mapToAvailableProviderBySpecialization(row)
	}
	return result
}

// ─── Error handling ───────────────────────────────────────────────────────────

func (r *providerAvailabilityRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
