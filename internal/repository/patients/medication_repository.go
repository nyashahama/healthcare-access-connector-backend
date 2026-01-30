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
	medicationDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "medication_db_query_duration_seconds",
			Help:    "Medication database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	medicationDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "medication_db_query_total",
			Help: "Total number of medication database queries",
		},
		[]string{"operation", "status"},
	)
)

type medicationRepository struct {
	querier sqlc.Querier
}

func NewMedicationRepository(pool *pgxpool.Pool) repository.PatientMedicationRepository {
	return NewMedicationRepositoryWithQuerier(sqlc.New(pool))
}

func NewMedicationRepositoryWithQuerier(querier sqlc.Querier) repository.PatientMedicationRepository {
	return &medicationRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *medicationRepository) AddPatientMedication(ctx context.Context, medication patients.PatientMedication) (patients.PatientMedication, error) {
	start := time.Now()
	defer func() {
		medicationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.AddPatientMedication(ctx, sqlc.AddPatientMedicationParams{
		PatientID:           uuidToPgtypeUUID(medication.PatientID),
		MedicationName:      medication.MedicationName,
		GenericName:         pgtypeTextFromStringPtr(medication.GenericName),
		Dosage:              pgtypeTextFromStringPtr(medication.Dosage),
		Frequency:           pgtypeTextFromStringPtr(medication.Frequency),
		Route:               pgtypeTextFromStringPtr(medication.Route),
		PrescribingDoctor:   pgtypeTextFromStringPtr(medication.PrescribingDoctor),
		PharmacyName:        pgtypeTextFromStringPtr(medication.PharmacyName),
		PrescriptionDate:    datePtrToPgtypeDate(medication.PrescriptionDate),
		StartDate:           datePtrToPgtypeDate(medication.StartDate),
		EndDate:             datePtrToPgtypeDate(medication.EndDate),
		ReasonForMedication: pgtypeTextFromStringPtr(medication.ReasonForMedication),
		Status:              pgtypeTextFromString(medication.Status),
		SideEffects:         pgtypeTextFromStringPtr(medication.SideEffects),
		Instructions:        pgtypeTextFromStringPtr(medication.Instructions),
	})
	if err != nil {
		medicationDBQueryTotal.WithLabelValues("add_patient_medication", "error").Inc()
		return patients.PatientMedication{}, r.handleError(err, "add patient medication")
	}

	medicationDBQueryTotal.WithLabelValues("add_patient_medication", "success").Inc()
	return r.mapToPatientMedication(created), nil
}

func (r *medicationRepository) GetPatientMedications(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientMedication, error) {
	start := time.Now()
	defer func() {
		medicationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientMedications(ctx, sqlc.GetPatientMedicationsParams{
		PatientID: uuidToPgtypeUUID(patientID),
		Column2:   *status,
	})
	if err != nil {
		medicationDBQueryTotal.WithLabelValues("get_patient_medications", "error").Inc()
		return nil, r.handleError(err, "get patient medications")
	}

	medications := make([]patients.PatientMedication, len(rows))
	for i, row := range rows {
		medications[i] = r.mapToPatientMedication(sqlc.PatientMedication{
			ID:                  row.ID,
			PatientID:           row.PatientID,
			MedicationName:      row.MedicationName,
			GenericName:         row.GenericName,
			Dosage:              row.Dosage,
			Frequency:           row.Frequency,
			Route:               row.Route,
			PrescribingDoctor:   row.PrescribingDoctor,
			StartDate:           row.StartDate,
			EndDate:             row.EndDate,
			ReasonForMedication: row.ReasonForMedication,
			Status:              row.Status,
			Instructions:        row.Instructions,
			SideEffects:         row.SideEffects,
			CreatedAt:           row.CreatedAt,
			UpdatedAt:           row.UpdatedAt,
		})
	}

	medicationDBQueryTotal.WithLabelValues("get_patient_medications", "success").Inc()
	return medications, nil
}

func (r *medicationRepository) GetActiveMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error) {
	start := time.Now()
	defer func() {
		medicationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetActiveMedications(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		medicationDBQueryTotal.WithLabelValues("get_active_medications", "error").Inc()
		return nil, r.handleError(err, "get active medications")
	}

	medications := make([]patients.PatientMedication, len(rows))
	for i, row := range rows {
		medications[i] = patients.PatientMedication{
			ID:                  pgtypeUUIDToUUID(row.ID),
			PatientID:           patientID,
			MedicationName:      row.MedicationName,
			GenericName:         pgtypeTextToStringPtr(row.GenericName),
			Dosage:              pgtypeTextToStringPtr(row.Dosage),
			Frequency:           pgtypeTextToStringPtr(row.Frequency),
			Route:               pgtypeTextToStringPtr(row.Route),
			PrescribingDoctor:   pgtypeTextToStringPtr(row.PrescribingDoctor),
			StartDate:           pgtypeDateToTimePtr(row.StartDate),
			ReasonForMedication: pgtypeTextToStringPtr(row.ReasonForMedication),
			Instructions:        pgtypeTextToStringPtr(row.Instructions),
		}
	}

	medicationDBQueryTotal.WithLabelValues("get_active_medications", "success").Inc()
	return medications, nil
}

func (r *medicationRepository) UpdatePatientMedication(ctx context.Context, medication patients.PatientMedication) error {
	start := time.Now()
	defer func() {
		medicationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientMedication(ctx, sqlc.UpdatePatientMedicationParams{
		ID:             uuidToPgtypeUUID(medication.ID),
		MedicationName: medication.MedicationName,
		GenericName:    pgtypeTextFromStringPtr(medication.GenericName),
		Dosage:         pgtypeTextFromStringPtr(medication.Dosage),
		Frequency:      pgtypeTextFromStringPtr(medication.Frequency),
		Route:          pgtypeTextFromStringPtr(medication.Route),
		EndDate:        datePtrToPgtypeDate(medication.EndDate),
		Status:         pgtypeTextFromString(medication.Status),
		SideEffects:    pgtypeTextFromStringPtr(medication.SideEffects),
		Instructions:   pgtypeTextFromStringPtr(medication.Instructions),
	})
	if err != nil {
		medicationDBQueryTotal.WithLabelValues("update_patient_medication", "error").Inc()
		return r.handleError(err, "update patient medication")
	}

	medicationDBQueryTotal.WithLabelValues("update_patient_medication", "success").Inc()
	return nil
}

func (r *medicationRepository) DeletePatientMedication(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		medicationDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeletePatientMedication(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		medicationDBQueryTotal.WithLabelValues("delete_patient_medication", "error").Inc()
		return r.handleError(err, "delete patient medication")
	}

	medicationDBQueryTotal.WithLabelValues("delete_patient_medication", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *medicationRepository) mapToPatientMedication(row sqlc.PatientMedication) patients.PatientMedication {
	return patients.PatientMedication{
		ID:                  pgtypeUUIDToUUID(row.ID),
		PatientID:           pgtypeUUIDToUUID(row.PatientID),
		MedicationName:      row.MedicationName,
		GenericName:         pgtypeTextToStringPtr(row.GenericName),
		Dosage:              pgtypeTextToStringPtr(row.Dosage),
		Frequency:           pgtypeTextToStringPtr(row.Frequency),
		Route:               pgtypeTextToStringPtr(row.Route),
		PrescribingDoctor:   pgtypeTextToStringPtr(row.PrescribingDoctor),
		PharmacyName:        pgtypeTextToStringPtr(row.PharmacyName),
		PrescriptionDate:    pgtypeDateToTimePtr(row.PrescriptionDate),
		StartDate:           pgtypeDateToTimePtr(row.StartDate),
		EndDate:             pgtypeDateToTimePtr(row.EndDate),
		ReasonForMedication: pgtypeTextToStringPtr(row.ReasonForMedication),
		Status:              pgtypeTextToString(row.Status),
		SideEffects:         pgtypeTextToStringPtr(row.SideEffects),
		Instructions:        pgtypeTextToStringPtr(row.Instructions),
		CreatedAt:           row.CreatedAt.Time,
		UpdatedAt:           row.UpdatedAt.Time,
	}
}

func (r *medicationRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
