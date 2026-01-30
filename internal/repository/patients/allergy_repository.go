package patients

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	allergyDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "allergy_db_query_duration_seconds",
			Help:    "Allergy database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	allergyDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "allergy_db_query_total",
			Help: "Total number of allergy database queries",
		},
		[]string{"operation", "status"},
	)
)

type allergyRepository struct {
	querier sqlc.Querier
}

func NewAllergyRepository(pool *pgxpool.Pool) repository.PatientAllergyRepository {
	return NewAllergyRepositoryWithQuerier(sqlc.New(pool))
}

func NewAllergyRepositoryWithQuerier(querier sqlc.Querier) repository.PatientAllergyRepository {
	return &allergyRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *allergyRepository) AddPatientAllergy(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error) {
	start := time.Now()
	defer func() {
		allergyDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.AddPatientAllergy(ctx, sqlc.AddPatientAllergyParams{
		PatientID:           uuidToPgtypeUUID(allergy.PatientID),
		AllergyName:         allergy.AllergyName,
		Severity:            allergy.Severity,
		ReactionDescription: pgtypeTextFromStringPtr(allergy.ReactionDescription),
		FirstIdentifiedDate: datePtrToPgtypeDate(allergy.FirstIdentifiedDate),
		LastOccurrenceDate:  datePtrToPgtypeDate(allergy.LastOccurrenceDate),
		Status:              pgtypeTextFromString(allergy.Status),
		Notes:               pgtypeTextFromStringPtr(allergy.Notes),
	})
	if err != nil {
		allergyDBQueryTotal.WithLabelValues("add_patient_allergy", "error").Inc()
		return patients.PatientAllergy{}, r.handleError(err, "add patient allergy")
	}

	allergyDBQueryTotal.WithLabelValues("add_patient_allergy", "success").Inc()
	return r.mapToPatientAllergy(created), nil
}

func (r *allergyRepository) GetPatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error) {
	start := time.Now()
	defer func() {
		allergyDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientAllergies(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		allergyDBQueryTotal.WithLabelValues("get_patient_allergies", "error").Inc()
		return nil, r.handleError(err, "get patient allergies")
	}

	allergies := make([]patients.PatientAllergy, len(rows))
	for i, row := range rows {
		allergies[i] = r.mapToPatientAllergy(sqlc.PatientAllergy{
			ID:                  row.ID,
			PatientID:           row.PatientID,
			AllergyName:         row.AllergyName,
			Severity:            row.Severity,
			ReactionDescription: row.ReactionDescription,
			FirstIdentifiedDate: row.FirstIdentifiedDate,
			LastOccurrenceDate:  row.LastOccurrenceDate,
			Status:              row.Status,
			Notes:               row.Notes,
			CreatedAt:           row.CreatedAt,
			UpdatedAt:           row.UpdatedAt,
		})
	}

	allergyDBQueryTotal.WithLabelValues("get_patient_allergies", "success").Inc()
	return allergies, nil
}

func (r *allergyRepository) GetActivePatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error) {
	start := time.Now()
	defer func() {
		allergyDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetActivePatientAllergies(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		allergyDBQueryTotal.WithLabelValues("get_active_patient_allergies", "error").Inc()
		return nil, r.handleError(err, "get active patient allergies")
	}

	allergies := make([]patients.PatientAllergy, len(rows))
	for i, row := range rows {
		allergies[i] = patients.PatientAllergy{
			ID:                  pgtypeUUIDToUUID(row.ID),
			PatientID:           patientID,
			AllergyName:         row.AllergyName,
			Severity:            row.Severity,
			ReactionDescription: pgtypeTextToStringPtr(row.ReactionDescription),
			FirstIdentifiedDate: pgtypeDateToTimePtr(row.FirstIdentifiedDate),
			LastOccurrenceDate:  pgtypeDateToTimePtr(row.LastOccurrenceDate),
			Notes:               pgtypeTextToStringPtr(row.Notes),
		}
	}

	allergyDBQueryTotal.WithLabelValues("get_active_patient_allergies", "success").Inc()
	return allergies, nil
}

func (r *allergyRepository) UpdatePatientAllergy(ctx context.Context, allergy patients.PatientAllergy) error {
	start := time.Now()
	defer func() {
		allergyDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientAllergy(ctx, sqlc.UpdatePatientAllergyParams{
		ID:                  uuidToPgtypeUUID(allergy.ID),
		AllergyName:         allergy.AllergyName,
		Severity:            allergy.Severity,
		ReactionDescription: pgtypeTextFromStringPtr(allergy.ReactionDescription),
		LastOccurrenceDate:  datePtrToPgtypeDate(allergy.LastOccurrenceDate),
		Status:              pgtypeTextFromString(allergy.Status),
		Notes:               pgtypeTextFromStringPtr(allergy.Notes),
	})
	if err != nil {
		allergyDBQueryTotal.WithLabelValues("update_patient_allergy", "error").Inc()
		return r.handleError(err, "update patient allergy")
	}

	allergyDBQueryTotal.WithLabelValues("update_patient_allergy", "success").Inc()
	return nil
}

func (r *allergyRepository) DeletePatientAllergy(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		allergyDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeletePatientAllergy(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		allergyDBQueryTotal.WithLabelValues("delete_patient_allergy", "error").Inc()
		return r.handleError(err, "delete patient allergy")
	}

	allergyDBQueryTotal.WithLabelValues("delete_patient_allergy", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *allergyRepository) mapToPatientAllergy(row sqlc.PatientAllergy) patients.PatientAllergy {
	return patients.PatientAllergy{
		ID:                  pgtypeUUIDToUUID(row.ID),
		PatientID:           pgtypeUUIDToUUID(row.PatientID),
		AllergyName:         row.AllergyName,
		Severity:            row.Severity,
		ReactionDescription: pgtypeTextToStringPtr(row.ReactionDescription),
		FirstIdentifiedDate: pgtypeDateToTimePtr(row.FirstIdentifiedDate),
		LastOccurrenceDate:  pgtypeDateToTimePtr(row.LastOccurrenceDate),
		Status:              pgtypeTextToString(row.Status),
		Notes:               pgtypeTextToStringPtr(row.Notes),
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.UpdatedAt.Time,
	}
}

func (r *allergyRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
