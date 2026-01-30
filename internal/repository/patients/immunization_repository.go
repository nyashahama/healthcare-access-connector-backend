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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	immunizationDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "immunization_db_query_duration_seconds",
			Help:    "Immunization database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	immunizationDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "immunization_db_query_total",
			Help: "Total number of immunization database queries",
		},
		[]string{"operation", "status"},
	)
)

type immunizationRepository struct {
	querier sqlc.Querier
}

func NewImmunizationRepository(pool *pgxpool.Pool) repository.PatientImmunizationRepository {
	return NewImmunizationRepositoryWithQuerier(sqlc.New(pool))
}

func NewImmunizationRepositoryWithQuerier(querier sqlc.Querier) repository.PatientImmunizationRepository {
	return &immunizationRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *immunizationRepository) AddPatientImmunization(ctx context.Context, immunization patients.PatientImmunization) (patients.PatientImmunization, error) {
	start := time.Now()
	defer func() {
		immunizationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.AddPatientImmunization(ctx, sqlc.AddPatientImmunizationParams{
		PatientID:          uuidToPgtypeUUID(immunization.PatientID),
		VaccineName:        immunization.VaccineName,
		VaccineType:        pgtypeTextFromStringPtr(immunization.VaccineType),
		AdministrationDate: pgtype.Date{Time: immunization.AdministrationDate},
		NextDueDate:        datePtrToPgtypeDate(immunization.NextDueDate),
		AdministeredBy:     pgtypeTextFromStringPtr(immunization.AdministeredBy),
		ClinicName:         pgtypeTextFromStringPtr(immunization.ClinicName),
		LotNumber:          pgtypeTextFromStringPtr(immunization.LotNumber),
		Manufacturer:       pgtypeTextFromStringPtr(immunization.Manufacturer),
		DoseNumber:         pgtype.Int4{Int32: int32(*immunization.DoseNumber), Valid: true},
		TotalDoses:         pgtype.Int4{Int32: int32(*immunization.TotalDoses), Valid: true},
		Notes:              pgtypeTextFromStringPtr(immunization.Notes),
		DocumentedBy:       uuidPtrToPgtypeUUID(immunization.DocumentedBy),
	})
	if err != nil {
		immunizationDBQueryTotal.WithLabelValues("add_patient_immunization", "error").Inc()
		return patients.PatientImmunization{}, r.handleError(err, "add patient immunization")
	}

	immunizationDBQueryTotal.WithLabelValues("add_patient_immunization", "success").Inc()
	return r.mapToPatientImmunization(created), nil
}

func (r *immunizationRepository) GetPatientImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error) {
	start := time.Now()
	defer func() {
		immunizationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientImmunizations(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		immunizationDBQueryTotal.WithLabelValues("get_patient_immunizations", "error").Inc()
		return nil, r.handleError(err, "get patient immunizations")
	}

	immunizations := make([]patients.PatientImmunization, len(rows))
	for i, row := range rows {
		immunizations[i] = r.mapToPatientImmunization(sqlc.PatientImmunization{
			ID:                 row.ID,
			PatientID:          row.PatientID,
			VaccineName:        row.VaccineName,
			VaccineType:        row.VaccineType,
			AdministrationDate: row.AdministrationDate,
			NextDueDate:        row.NextDueDate,
			AdministeredBy:     row.AdministeredBy,
			ClinicName:         row.ClinicName,
			DoseNumber:         row.DoseNumber,
			TotalDoses:         row.TotalDoses,
			Notes:              row.Notes,
			CreatedAt:          row.CreatedAt,
		})
	}

	immunizationDBQueryTotal.WithLabelValues("get_patient_immunizations", "success").Inc()
	return immunizations, nil
}

func (r *immunizationRepository) GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]patients.PatientImmunization, error) {
	start := time.Now()
	defer func() {
		immunizationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetUpcomingImmunizations(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		immunizationDBQueryTotal.WithLabelValues("get_upcoming_immunizations", "error").Inc()
		return nil, r.handleError(err, "get upcoming immunizations")
	}

	immunizations := make([]patients.PatientImmunization, len(rows))
	for i, row := range rows {
		immunizations[i] = patients.PatientImmunization{
			ID:          pgtypeUUIDToUUID(row.ID),
			PatientID:   patientID,
			VaccineName: row.VaccineName,
			VaccineType: pgtypeTextToStringPtr(row.VaccineType),
			NextDueDate: pgtypeDateToTimePtr(row.NextDueDate),
			DoseNumber:  pgtypeInt4ToIntPtr(row.DoseNumber),
			TotalDoses:  pgtypeInt4ToIntPtr(row.TotalDoses),
			Notes:       pgtypeTextToStringPtr(row.Notes),
		}
	}

	immunizationDBQueryTotal.WithLabelValues("get_upcoming_immunizations", "success").Inc()
	return immunizations, nil
}

func (r *immunizationRepository) UpdatePatientImmunization(ctx context.Context, immunization patients.PatientImmunization) error {
	start := time.Now()
	defer func() {
		immunizationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientImmunization(ctx, sqlc.UpdatePatientImmunizationParams{
		ID:          uuidToPgtypeUUID(immunization.ID),
		VaccineName: immunization.VaccineName,
		VaccineType: pgtypeTextFromStringPtr(immunization.VaccineType),
		NextDueDate: datePtrToPgtypeDate(immunization.NextDueDate),
		Notes:       pgtypeTextFromStringPtr(immunization.Notes),
	})
	if err != nil {
		immunizationDBQueryTotal.WithLabelValues("update_patient_immunization", "error").Inc()
		return r.handleError(err, "update patient immunization")
	}

	immunizationDBQueryTotal.WithLabelValues("update_patient_immunization", "success").Inc()
	return nil
}

func (r *immunizationRepository) DeletePatientImmunization(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		immunizationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeletePatientImmunization(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		immunizationDBQueryTotal.WithLabelValues("delete_patient_immunization", "error").Inc()
		return r.handleError(err, "delete patient immunization")
	}

	immunizationDBQueryTotal.WithLabelValues("delete_patient_immunization", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *immunizationRepository) mapToPatientImmunization(row sqlc.PatientImmunization) patients.PatientImmunization {
	return patients.PatientImmunization{
		ID:                 pgtypeUUIDToUUID(row.ID),
		PatientID:          pgtypeUUIDToUUID(row.PatientID),
		VaccineName:        row.VaccineName,
		VaccineType:        pgtypeTextToStringPtr(row.VaccineType),
		AdministrationDate: *pgtypeDateToTimePtr(row.AdministrationDate),
		NextDueDate:        pgtypeDateToTimePtr(row.NextDueDate),
		AdministeredBy:     pgtypeTextToStringPtr(row.AdministeredBy),
		ClinicName:         pgtypeTextToStringPtr(row.ClinicName),
		LotNumber:          pgtypeTextToStringPtr(row.LotNumber),
		Manufacturer:       pgtypeTextToStringPtr(row.Manufacturer),
		DoseNumber:         pgtypeInt4ToIntPtr(row.DoseNumber),
		TotalDoses:         pgtypeInt4ToIntPtr(row.TotalDoses),
		Notes:              pgtypeTextToStringPtr(row.Notes),
		DocumentedBy:       uuidPtrToUUID(row.DocumentedBy),
		CreatedAt:          row.CreatedAt.Time,
		UpdatedAt:          row.UpdatedAt.Time,
	}
}

func (r *immunizationRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
