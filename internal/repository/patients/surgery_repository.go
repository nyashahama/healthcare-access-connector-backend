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
	surgeryDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "surgery_db_query_duration_seconds",
			Help:    "Surgery database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	surgeryDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "surgery_db_query_total",
			Help: "Total number of surgery database queries",
		},
		[]string{"operation", "status"},
	)
)

type surgeryRepository struct {
	querier sqlc.Querier
}

func NewSurgeryRepository(pool *pgxpool.Pool) repository.PatientSurgeryRepository {
	return NewSurgeryRepositoryWithQuerier(sqlc.New(pool))
}

func NewSurgeryRepositoryWithQuerier(querier sqlc.Querier) repository.PatientSurgeryRepository {
	return &surgeryRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *surgeryRepository) AddPatientSurgery(ctx context.Context, surgery patients.PatientSurgery) (patients.PatientSurgery, error) {
	start := time.Now()
	defer func() {
		surgeryDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.AddPatientSurgery(ctx, sqlc.AddPatientSurgeryParams{
		PatientID:      uuidToPgtypeUUID(surgery.PatientID),
		ProcedureName:  surgery.ProcedureName,
		ProcedureDate:  pgtype.Date{Time: surgery.ProcedureDate},
		HospitalName:   pgtypeTextFromStringPtr(surgery.HospitalName),
		SurgeonName:    pgtypeTextFromStringPtr(surgery.SurgeonName),
		AnesthesiaType: pgtypeTextFromStringPtr(surgery.AnesthesiaType),
		Complications:  pgtypeTextFromStringPtr(surgery.Complications),
		RecoveryNotes:  pgtypeTextFromStringPtr(surgery.RecoveryNotes),
		Outcome:        pgtypeTextFromStringPtr(surgery.Outcome),
	})
	if err != nil {
		surgeryDBQueryTotal.WithLabelValues("add_patient_surgery", "error").Inc()
		return patients.PatientSurgery{}, r.handleError(err, "add patient surgery")
	}

	surgeryDBQueryTotal.WithLabelValues("add_patient_surgery", "success").Inc()
	return r.mapToPatientSurgery(created), nil
}

func (r *surgeryRepository) GetPatientSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error) {
	start := time.Now()
	defer func() {
		surgeryDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientSurgeries(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		surgeryDBQueryTotal.WithLabelValues("get_patient_surgeries", "error").Inc()
		return nil, r.handleError(err, "get patient surgeries")
	}

	surgeries := make([]patients.PatientSurgery, len(rows))
	for i, row := range rows {
		surgeries[i] = r.mapToPatientSurgery(sqlc.PatientSurgery{
			ID:             row.ID,
			PatientID:      row.PatientID,
			ProcedureName:  row.ProcedureName,
			ProcedureDate:  row.ProcedureDate,
			HospitalName:   row.HospitalName,
			SurgeonName:    row.SurgeonName,
			AnesthesiaType: row.AnesthesiaType,
			Complications:  row.Complications,
			RecoveryNotes:  row.RecoveryNotes,
			Outcome:        row.Outcome,
			CreatedAt:      row.CreatedAt,
			UpdatedAt:      row.UpdatedAt,
		})
	}

	surgeryDBQueryTotal.WithLabelValues("get_patient_surgeries", "success").Inc()
	return surgeries, nil
}

func (r *surgeryRepository) GetRecentSurgeries(ctx context.Context, patientID uuid.UUID) ([]patients.PatientSurgery, error) {
	start := time.Now()
	defer func() {
		surgeryDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetRecentSurgeries(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		surgeryDBQueryTotal.WithLabelValues("get_recent_surgeries", "error").Inc()
		return nil, r.handleError(err, "get recent surgeries")
	}

	surgeries := make([]patients.PatientSurgery, len(rows))
	for i, row := range rows {
		surgeries[i] = patients.PatientSurgery{
			ID:            pgtypeUUIDToUUID(row.ID),
			PatientID:     patientID,
			ProcedureName: row.ProcedureName,
			ProcedureDate: *pgtypeDateToTimePtr(row.ProcedureDate),
			HospitalName:  pgtypeTextToStringPtr(row.HospitalName),
			SurgeonName:   pgtypeTextToStringPtr(row.SurgeonName),
			Outcome:       pgtypeTextToStringPtr(row.Outcome),
		}
	}

	surgeryDBQueryTotal.WithLabelValues("get_recent_surgeries", "success").Inc()
	return surgeries, nil
}

func (r *surgeryRepository) UpdatePatientSurgery(ctx context.Context, surgery patients.PatientSurgery) error {
	start := time.Now()
	defer func() {
		surgeryDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientSurgery(ctx, sqlc.UpdatePatientSurgeryParams{
		ID:            uuidToPgtypeUUID(surgery.ID),
		ProcedureName: surgery.ProcedureName,
		ProcedureDate: pgtype.Date{Time: surgery.ProcedureDate},
		HospitalName:  pgtypeTextFromStringPtr(surgery.HospitalName),
		SurgeonName:   pgtypeTextFromStringPtr(surgery.SurgeonName),
		Complications: pgtypeTextFromStringPtr(surgery.Complications),
		RecoveryNotes: pgtypeTextFromStringPtr(surgery.RecoveryNotes),
		Outcome:       pgtypeTextFromStringPtr(surgery.Outcome),
	})
	if err != nil {
		surgeryDBQueryTotal.WithLabelValues("update_patient_surgery", "error").Inc()
		return r.handleError(err, "update patient surgery")
	}

	surgeryDBQueryTotal.WithLabelValues("update_patient_surgery", "success").Inc()
	return nil
}

func (r *surgeryRepository) DeletePatientSurgery(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		surgeryDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeletePatientSurgery(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		surgeryDBQueryTotal.WithLabelValues("delete_patient_surgery", "error").Inc()
		return r.handleError(err, "delete patient surgery")
	}

	surgeryDBQueryTotal.WithLabelValues("delete_patient_surgery", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *surgeryRepository) mapToPatientSurgery(row sqlc.PatientSurgery) patients.PatientSurgery {
	return patients.PatientSurgery{
		ID:             pgtypeUUIDToUUID(row.ID),
		PatientID:      pgtypeUUIDToUUID(row.PatientID),
		ProcedureName:  row.ProcedureName,
		ProcedureDate:  *pgtypeDateToTimePtr(row.ProcedureDate),
		HospitalName:   pgtypeTextToStringPtr(row.HospitalName),
		SurgeonName:    pgtypeTextToStringPtr(row.SurgeonName),
		AnesthesiaType: pgtypeTextToStringPtr(row.AnesthesiaType),
		Complications:  pgtypeTextToStringPtr(row.Complications),
		RecoveryNotes:  pgtypeTextToStringPtr(row.RecoveryNotes),
		Outcome:        pgtypeTextToStringPtr(row.Outcome),
		CreatedAt:      row.CreatedAt.Time,
		UpdatedAt:      row.UpdatedAt.Time,
	}
}

func (r *surgeryRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
