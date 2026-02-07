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
	familyHistoryDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "family_history_db_query_duration_seconds",
			Help:    "Family history database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	familyHistoryDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "family_history_db_query_total",
			Help: "Total number of family history database queries",
		},
		[]string{"operation", "status"},
	)
)

type familyHistoryRepository struct {
	querier sqlc.Querier
}

func NewFamilyHistoryRepository(pool *pgxpool.Pool) repository.PatientFamilyHistoryRepository {
	return NewFamilyHistoryRepositoryWithQuerier(sqlc.New(pool))
}

func NewFamilyHistoryRepositoryWithQuerier(querier sqlc.Querier) repository.PatientFamilyHistoryRepository {
	return &familyHistoryRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *familyHistoryRepository) AddFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) (patients.PatientFamilyHistory, error) {
	start := time.Now()
	defer func() {
		familyHistoryDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.AddFamilyHistory(ctx, sqlc.AddFamilyHistoryParams{
		PatientID:              uuidToPgtypeUUID(history.PatientID),
		Relative:               history.Relative,
		RelativeAgeAtDiagnosis: int32PtrToPgtypeInt4(history.RelativeAgeAtDiagnosis),
		ConditionName:          history.ConditionName,
		Notes:                  pgtypeTextFromStringPtr(history.Notes),
		IsAlive:                pgtype.Bool{Bool: *history.IsAlive, Valid: true},
		CauseOfDeath:           pgtypeTextFromStringPtr(history.CauseOfDeath),
		AgeAtDeath:             int32PtrToPgtypeInt4(history.AgeAtDeath),
	})
	if err != nil {
		familyHistoryDBQueryTotal.WithLabelValues("add_family_history", "error").Inc()
		return patients.PatientFamilyHistory{}, r.handleError(err, "add family history")
	}

	familyHistoryDBQueryTotal.WithLabelValues("add_family_history", "success").Inc()
	return r.mapToPatientFamilyHistory(created), nil
}

func (r *familyHistoryRepository) GetPatientFamilyHistory(ctx context.Context, patientID uuid.UUID) ([]patients.PatientFamilyHistory, error) {
	start := time.Now()
	defer func() {
		familyHistoryDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientFamilyHistory(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		familyHistoryDBQueryTotal.WithLabelValues("get_patient_family_history", "error").Inc()
		return nil, r.handleError(err, "get patient family history")
	}

	histories := make([]patients.PatientFamilyHistory, len(rows))
	for i, row := range rows {
		histories[i] = r.mapToPatientFamilyHistory(sqlc.PatientFamilyHistory{
			ID:                     row.ID,
			PatientID:              row.PatientID,
			Relative:               row.Relative,
			RelativeAgeAtDiagnosis: row.RelativeAgeAtDiagnosis,
			ConditionName:          row.ConditionName,
			Notes:                  row.Notes,
			IsAlive:                row.IsAlive,
			CauseOfDeath:           row.CauseOfDeath,
			AgeAtDeath:             row.AgeAtDeath,
			CreatedAt:              row.CreatedAt,
		})
	}

	familyHistoryDBQueryTotal.WithLabelValues("get_patient_family_history", "success").Inc()
	return histories, nil
}

func (r *familyHistoryRepository) UpdateFamilyHistory(ctx context.Context, history patients.PatientFamilyHistory) error {
	start := time.Now()
	defer func() {
		familyHistoryDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateFamilyHistory(ctx, sqlc.UpdateFamilyHistoryParams{
		ID:                     uuidToPgtypeUUID(history.ID),
		Relative:               history.Relative,
		RelativeAgeAtDiagnosis: int32PtrToPgtypeInt4(history.RelativeAgeAtDiagnosis),
		ConditionName:          history.ConditionName,
		Notes:                  pgtypeTextFromStringPtr(history.Notes),
		IsAlive:                pgtype.Bool{Bool: *history.IsAlive, Valid: true},
		CauseOfDeath:           pgtypeTextFromStringPtr(history.CauseOfDeath),
		AgeAtDeath:             int32PtrToPgtypeInt4(history.AgeAtDeath),
	})
	if err != nil {
		familyHistoryDBQueryTotal.WithLabelValues("update_family_history", "error").Inc()
		return r.handleError(err, "update family history")
	}

	familyHistoryDBQueryTotal.WithLabelValues("update_family_history", "success").Inc()
	return nil
}

func (r *familyHistoryRepository) DeleteFamilyHistory(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		familyHistoryDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteFamilyHistory(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		familyHistoryDBQueryTotal.WithLabelValues("delete_family_history", "error").Inc()
		return r.handleError(err, "delete family history")
	}

	familyHistoryDBQueryTotal.WithLabelValues("delete_family_history", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *familyHistoryRepository) mapToPatientFamilyHistory(row sqlc.PatientFamilyHistory) patients.PatientFamilyHistory {
	return patients.PatientFamilyHistory{
		ID:                     pgtypeUUIDToUUID(row.ID),
		PatientID:              pgtypeUUIDToUUID(row.PatientID),
		Relative:               row.Relative,
		RelativeAgeAtDiagnosis: pgtypeInt4ToIntPtr(row.RelativeAgeAtDiagnosis),
		ConditionName:          row.ConditionName,
		Notes:                  pgtypeTextToStringPtr(row.Notes),
		IsAlive:                pgtypeBoolToBoolPtr(row.IsAlive),
		CauseOfDeath:           pgtypeTextToStringPtr(row.CauseOfDeath),
		AgeAtDeath:             pgtypeInt4ToIntPtr(row.AgeAtDeath),
		CreatedAt:              row.CreatedAt.Time,
	}
}

func (r *familyHistoryRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
