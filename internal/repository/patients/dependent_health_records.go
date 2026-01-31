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
	dependentHealthDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dependent_health_db_query_duration_seconds",
			Help:    "Dependent health database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	dependentHealthDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dependent_health_db_query_total",
			Help: "Total number of dependent health database queries",
		},
		[]string{"operation", "status"},
	)
)

type dependentHealthRecordRepository struct {
	querier sqlc.Querier
}

func NewDependentHealthRecordRepository(pool *pgxpool.Pool) repository.DependentHealthRecordRepository {
	return NewDependentHealthRecordRepositoryWithQuerier(sqlc.New(pool))
}

func NewDependentHealthRecordRepositoryWithQuerier(querier sqlc.Querier) repository.DependentHealthRecordRepository {
	return &dependentHealthRecordRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *dependentHealthRecordRepository) AddDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) (patients.DependentHealthRecord, error) {
	start := time.Now()
	defer func() {
		dependentHealthDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.AddDependentHealthRecord(ctx, sqlc.AddDependentHealthRecordParams{
		DependentID:         uuidToPgtypeUUID(record.DependentID),
		RecordType:          pgtypeTextFromStringPtr(record.RecordType),
		RecordDate:          pgtype.Date{Time: record.RecordDate, Valid: true},
		WeightKg:            float64PtrToPgtypeNumeric(record.WeightKg),
		HeightCm:            float64PtrToPgtypeNumeric(record.HeightCm),
		HeadCircumferenceCm: float64PtrToPgtypeNumeric(record.HeadCircumferenceCm),
		TemperatureC:        float64PtrToPgtypeNumeric(record.TemperatureC),
		Notes:               pgtypeTextFromStringPtr(record.Notes),
		ProviderName:        pgtypeTextFromStringPtr(record.ProviderName),
		ClinicName:          pgtypeTextFromStringPtr(record.ClinicName),
		NextAppointmentDate: datePtrToPgtypeDate(record.NextAppointmentDate),
		Documents:           interfaceToPgtypeJSON(record.Documents),
	})
	if err != nil {
		dependentHealthDBQueryTotal.WithLabelValues("add_dependent_health_record", "error").Inc()
		return patients.DependentHealthRecord{}, r.handleError(err, "add dependent health record")
	}

	dependentHealthDBQueryTotal.WithLabelValues("add_dependent_health_record", "success").Inc()
	return r.mapToDependentHealthRecord(created), nil
}

func (r *dependentHealthRecordRepository) GetDependentHealthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error) {
	start := time.Now()
	defer func() {
		dependentHealthDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetDependentHealthRecords(ctx, uuidToPgtypeUUID(dependentID))
	if err != nil {
		dependentHealthDBQueryTotal.WithLabelValues("get_dependent_health_records", "error").Inc()
		return nil, r.handleError(err, "get dependent health records")
	}

	records := make([]patients.DependentHealthRecord, len(rows))
	for i, row := range rows {
		records[i] = patients.DependentHealthRecord{
			ID:                  pgtypeUUIDToUUID(row.ID),
			DependentID:         dependentID,
			RecordType:          pgtypeTextToStringPtr(row.RecordType),
			RecordDate:          row.RecordDate.Time,
			WeightKg:            pgtypeNumericToFloat64Ptr(row.WeightKg),
			HeightCm:            pgtypeNumericToFloat64Ptr(row.HeightCm),
			HeadCircumferenceCm: pgtypeNumericToFloat64Ptr(row.HeadCircumferenceCm),
			TemperatureC:        pgtypeNumericToFloat64Ptr(row.TemperatureC),
			Notes:               pgtypeTextToStringPtr(row.Notes),
			ProviderName:        pgtypeTextToStringPtr(row.ProviderName),
			ClinicName:          pgtypeTextToStringPtr(row.ClinicName),
			NextAppointmentDate: pgtypeDateToTimePtr(row.NextAppointmentDate),
			CreatedAt:           row.CreatedAt.Time,
		}
	}

	dependentHealthDBQueryTotal.WithLabelValues("get_dependent_health_records", "success").Inc()
	return records, nil
}

func (r *dependentHealthRecordRepository) GetGrowthRecords(ctx context.Context, dependentID uuid.UUID) ([]patients.DependentHealthRecord, error) {
	start := time.Now()
	defer func() {
		dependentHealthDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetGrowthRecords(ctx, uuidToPgtypeUUID(dependentID))
	if err != nil {
		dependentHealthDBQueryTotal.WithLabelValues("get_growth_records", "error").Inc()
		return nil, r.handleError(err, "get growth records")
	}

	records := make([]patients.DependentHealthRecord, len(rows))
	for i, row := range rows {
		records[i] = patients.DependentHealthRecord{
			ID:                  pgtypeUUIDToUUID(row.ID),
			DependentID:         dependentID,
			RecordDate:          row.RecordDate.Time,
			WeightKg:            pgtypeNumericToFloat64Ptr(row.WeightKg),
			HeightCm:            pgtypeNumericToFloat64Ptr(row.HeightCm),
			HeadCircumferenceCm: pgtypeNumericToFloat64Ptr(row.HeadCircumferenceCm),
			Notes:               pgtypeTextToStringPtr(row.Notes),
		}
	}

	dependentHealthDBQueryTotal.WithLabelValues("get_growth_records", "success").Inc()
	return records, nil
}

func (r *dependentHealthRecordRepository) UpdateDependentHealthRecord(ctx context.Context, record patients.DependentHealthRecord) error {
	start := time.Now()
	defer func() {
		dependentHealthDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateDependentHealthRecord(ctx, sqlc.UpdateDependentHealthRecordParams{
		ID:                  uuidToPgtypeUUID(record.ID),
		RecordType:          pgtypeTextFromStringPtr(record.RecordType),
		WeightKg:            float64PtrToPgtypeNumeric(record.WeightKg),
		HeightCm:            float64PtrToPgtypeNumeric(record.HeightCm),
		HeadCircumferenceCm: float64PtrToPgtypeNumeric(record.HeadCircumferenceCm),
		TemperatureC:        float64PtrToPgtypeNumeric(record.TemperatureC),
		Notes:               pgtypeTextFromStringPtr(record.Notes),
		NextAppointmentDate: datePtrToPgtypeDate(record.NextAppointmentDate),
	})
	if err != nil {
		dependentHealthDBQueryTotal.WithLabelValues("update_dependent_health_record", "error").Inc()
		return r.handleError(err, "update dependent health record")
	}

	dependentHealthDBQueryTotal.WithLabelValues("update_dependent_health_record", "success").Inc()
	return nil
}

func (r *dependentHealthRecordRepository) DeleteDependentHealthRecord(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		dependentHealthDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteDependentHealthRecord(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		dependentHealthDBQueryTotal.WithLabelValues("delete_dependent_health_record", "error").Inc()
		return r.handleError(err, "delete dependent health record")
	}

	dependentHealthDBQueryTotal.WithLabelValues("delete_dependent_health_record", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *dependentHealthRecordRepository) mapToDependentHealthRecord(row sqlc.DependentHealthRecord) patients.DependentHealthRecord {
	return patients.DependentHealthRecord{
		ID:                  pgtypeUUIDToUUID(row.ID),
		DependentID:         pgtypeUUIDToUUID(row.DependentID),
		RecordType:          pgtypeTextToStringPtr(row.RecordType),
		RecordDate:          row.RecordDate.Time,
		WeightKg:            pgtypeNumericToFloat64Ptr(row.WeightKg),
		HeightCm:            pgtypeNumericToFloat64Ptr(row.HeightCm),
		HeadCircumferenceCm: pgtypeNumericToFloat64Ptr(row.HeadCircumferenceCm),
		TemperatureC:        pgtypeNumericToFloat64Ptr(row.TemperatureC),
		Notes:               pgtypeTextToStringPtr(row.Notes),
		ProviderName:        pgtypeTextToStringPtr(row.ProviderName),
		ClinicName:          pgtypeTextToStringPtr(row.ClinicName),
		NextAppointmentDate: pgtypeDateToTimePtr(row.NextAppointmentDate),
		Documents:           pgtypeJSONToInterface(row.Documents),
		CreatedAt:           row.CreatedAt.Time,
	}
}

func (r *dependentHealthRecordRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// Additional helper functions needed for JSONB handling
