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
	conditionDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "condition_db_query_duration_seconds",
			Help:    "Condition database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	conditionDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "condition_db_query_total",
			Help: "Total number of condition database queries",
		},
		[]string{"operation", "status"},
	)
)

type conditionRepository struct {
	querier sqlc.Querier
}

func NewConditionRepository(pool *pgxpool.Pool) repository.PatientConditionRepository {
	return NewConditionRepositoryWithQuerier(sqlc.New(pool))
}

func NewConditionRepositoryWithQuerier(querier sqlc.Querier) repository.PatientConditionRepository {
	return &conditionRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *conditionRepository) AddPatientCondition(ctx context.Context, condition patients.PatientCondition) (patients.PatientCondition, error) {
	start := time.Now()
	defer func() {
		conditionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.AddPatientCondition(ctx, sqlc.AddPatientConditionParams{
		PatientID:       uuidToPgtypeUUID(condition.PatientID),
		ConditionName:   condition.ConditionName,
		Icd10Code:       pgtypeTextFromStringPtr(condition.ICD10Code),
		Type:            pgtypeTextFromStringPtr(condition.Type),
		DiagnosedDate:   datePtrToPgtypeDate(condition.DiagnosedDate),
		DiagnosedBy:     pgtypeTextFromStringPtr(condition.DiagnosedBy),
		Severity:        pgtypeTextFromStringPtr(condition.Severity),
		Status:          pgtypeTextFromString(condition.Status),
		Notes:           pgtypeTextFromStringPtr(condition.Notes),
		LastFlareUp:     datePtrToPgtypeDate(condition.LastFlareUp),
		NextCheckupDate: datePtrToPgtypeDate(condition.NextCheckupDate),
	})
	if err != nil {
		conditionDBQueryTotal.WithLabelValues("add_patient_condition", "error").Inc()
		return patients.PatientCondition{}, r.handleError(err, "add patient condition")
	}

	conditionDBQueryTotal.WithLabelValues("add_patient_condition", "success").Inc()
	return r.mapToPatientCondition(created), nil
}

func (r *conditionRepository) GetPatientConditions(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientCondition, error) {
	start := time.Now()
	defer func() {
		conditionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientConditions(ctx, sqlc.GetPatientConditionsParams{
		PatientID: uuidToPgtypeUUID(patientID),
		Column2:   *status,
	})
	if err != nil {
		conditionDBQueryTotal.WithLabelValues("get_patient_conditions", "error").Inc()
		return nil, r.handleError(err, "get patient conditions")
	}

	conditions := make([]patients.PatientCondition, len(rows))
	for i, row := range rows {
		conditions[i] = r.mapToPatientCondition(sqlc.PatientCondition{
			ID:              row.ID,
			PatientID:       row.PatientID,
			ConditionName:   row.ConditionName,
			Icd10Code:       row.Icd10Code,
			Type:            row.Type,
			DiagnosedDate:   row.DiagnosedDate,
			DiagnosedBy:     row.DiagnosedBy,
			Severity:        row.Severity,
			Status:          row.Status,
			Notes:           row.Notes,
			LastFlareUp:     row.LastFlareUp,
			NextCheckupDate: row.NextCheckupDate,
			CreatedAt:       row.CreatedAt,
			UpdatedAt:       row.UpdatedAt,
		})
	}

	conditionDBQueryTotal.WithLabelValues("get_patient_conditions", "success").Inc()
	return conditions, nil
}

func (r *conditionRepository) GetActiveConditions(ctx context.Context, patientID uuid.UUID) ([]patients.PatientCondition, error) {
	start := time.Now()
	defer func() {
		conditionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetActiveConditions(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		conditionDBQueryTotal.WithLabelValues("get_active_conditions", "error").Inc()
		return nil, r.handleError(err, "get active conditions")
	}

	conditions := make([]patients.PatientCondition, len(rows))
	for i, row := range rows {
		conditions[i] = patients.PatientCondition{
			ID:              pgtypeUUIDToUUID(row.ID),
			PatientID:       patientID,
			ConditionName:   row.ConditionName,
			Type:            pgtypeTextToStringPtr(row.Type),
			Severity:        pgtypeTextToStringPtr(row.Severity),
			DiagnosedDate:   pgtypeDateToTimePtr(row.DiagnosedDate),
			LastFlareUp:     pgtypeDateToTimePtr(row.LastFlareUp),
			NextCheckupDate: pgtypeDateToTimePtr(row.NextCheckupDate),
		}
	}

	conditionDBQueryTotal.WithLabelValues("get_active_conditions", "success").Inc()
	return conditions, nil
}

func (r *conditionRepository) UpdatePatientCondition(ctx context.Context, condition patients.PatientCondition) error {
	start := time.Now()
	defer func() {
		conditionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientCondition(ctx, sqlc.UpdatePatientConditionParams{
		ID:              uuidToPgtypeUUID(condition.ID),
		ConditionName:   condition.ConditionName,
		Icd10Code:       pgtypeTextFromStringPtr(condition.ICD10Code),
		Severity:        pgtypeTextFromStringPtr(condition.Severity),
		Status:          pgtypeTextFromString(condition.Status),
		Notes:           pgtypeTextFromStringPtr(condition.Notes),
		LastFlareUp:     datePtrToPgtypeDate(condition.LastFlareUp),
		NextCheckupDate: datePtrToPgtypeDate(condition.NextCheckupDate),
	})
	if err != nil {
		conditionDBQueryTotal.WithLabelValues("update_patient_condition", "error").Inc()
		return r.handleError(err, "update patient condition")
	}

	conditionDBQueryTotal.WithLabelValues("update_patient_condition", "success").Inc()
	return nil
}

func (r *conditionRepository) DeletePatientCondition(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		conditionDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeletePatientCondition(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		conditionDBQueryTotal.WithLabelValues("delete_patient_condition", "error").Inc()
		return r.handleError(err, "delete patient condition")
	}

	conditionDBQueryTotal.WithLabelValues("delete_patient_condition", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *conditionRepository) mapToPatientCondition(row sqlc.PatientCondition) patients.PatientCondition {
	return patients.PatientCondition{
		ID:              pgtypeUUIDToUUID(row.ID),
		PatientID:       pgtypeUUIDToUUID(row.PatientID),
		ConditionName:   row.ConditionName,
		ICD10Code:       pgtypeTextToStringPtr(row.Icd10Code),
		Type:            pgtypeTextToStringPtr(row.Type),
		DiagnosedDate:   pgtypeDateToTimePtr(row.DiagnosedDate),
		DiagnosedBy:     pgtypeTextToStringPtr(row.DiagnosedBy),
		Severity:        pgtypeTextToStringPtr(row.Severity),
		Status:          pgtypeTextToString(row.Status),
		Notes:           pgtypeTextToStringPtr(row.Notes),
		LastFlareUp:     pgtypeDateToTimePtr(row.LastFlareUp),
		NextCheckupDate: pgtypeDateToTimePtr(row.NextCheckupDate),
		CreatedAt:       row.CreatedAt.Time,
		UpdatedAt:       row.UpdatedAt.Time,
	}
}

func (r *conditionRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
