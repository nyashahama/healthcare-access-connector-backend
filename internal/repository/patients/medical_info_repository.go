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
	medicalInfoDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "medical_info_db_query_duration_seconds",
			Help:    "Medical info database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	medicalInfoDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "medical_info_db_query_total",
			Help: "Total number of medical info database queries",
		},
		[]string{"operation", "status"},
	)
)

type medicalInfoRepository struct {
	querier sqlc.Querier
}

func NewMedicalInfoRepository(pool *pgxpool.Pool) repository.PatientMedicalInfoRepository {
	return NewMedicalInfoRepositoryWithQuerier(sqlc.New(pool))
}

func NewMedicalInfoRepositoryWithQuerier(querier sqlc.Querier) repository.PatientMedicalInfoRepository {
	return &medicalInfoRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *medicalInfoRepository) CreateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) (patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.CreatePatientMedicalInfo(ctx, sqlc.CreatePatientMedicalInfoParams{
		PatientID:              uuidToPgtypeUUID(info.PatientID),
		BloodType:              pgtypeTextFromStringPtr(info.BloodType),
		BloodTypeLastTested:    datePtrToPgtypeDate(info.BloodTypeLastTested),
		HeightCm:               float64PtrToPgtypeNumeric(info.HeightCm),
		WeightKg:               float64PtrToPgtypeNumeric(info.WeightKg),
		Bmi:                    float64PtrToPgtypeNumeric(info.BMI),
		LastMeasuredDate:       datePtrToPgtypeDate(info.LastMeasuredDate),
		OverallHealthStatus:    pgtypeTextFromStringPtr(info.OverallHealthStatus),
		HealthSummary:          pgtypeTextFromStringPtr(info.HealthSummary),
		PrimaryCarePhysician:   pgtypeTextFromStringPtr(info.PrimaryCarePhysician),
		PrimaryClinicID:        uuidPtrToPgtypeUUID(info.PrimaryClinicID),
		OrganDonor:             pgtype.Bool{Bool: info.OrganDonor, Valid: true},
		AdvanceDirectiveExists: pgtype.Bool{Bool: info.AdvanceDirectiveExists, Valid: true},
		AdvanceDirectiveUrl:    pgtypeTextFromStringPtr(info.AdvanceDirectiveURL),
		DnrStatus:              pgtype.Bool{Bool: info.DNRStatus, Valid: true},
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("create_medical_info", "error").Inc()
		return patients.PatientMedicalInfo{}, r.handleError(err, "create medical info")
	}

	medicalInfoDBQueryTotal.WithLabelValues("create_medical_info", "success").Inc()
	return r.mapToPatientMedicalInfo(created), nil
}

func (r *medicalInfoRepository) GetMedicalInfoByID(ctx context.Context, id uuid.UUID) (patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetPatientMedicalInfoByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_medical_info_by_id", "error").Inc()
		return patients.PatientMedicalInfo{}, r.handleError(err, "get medical info by id")
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_medical_info_by_id", "success").Inc()
	return r.mapToPatientMedicalInfo(row), nil
}

func (r *medicalInfoRepository) GetMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) (patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetPatientMedicalInfo(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_medical_info_by_patient_id", "error").Inc()
		return patients.PatientMedicalInfo{}, r.handleError(err, "get medical info by patient id")
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_medical_info_by_patient_id", "success").Inc()
	return r.mapToPatientMedicalInfo(row), nil
}

func (r *medicalInfoRepository) UpdateMedicalInfo(ctx context.Context, info patients.PatientMedicalInfo) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientMedicalInfo(ctx, sqlc.UpdatePatientMedicalInfoParams{
		PatientID:            uuidToPgtypeUUID(info.PatientID),
		BloodType:            pgtypeTextFromStringPtr(info.BloodType),
		BloodTypeLastTested:  datePtrToPgtypeDate(info.BloodTypeLastTested),
		HeightCm:             float64PtrToPgtypeNumeric(info.HeightCm),
		WeightKg:             float64PtrToPgtypeNumeric(info.WeightKg),
		Bmi:                  float64PtrToPgtypeNumeric(info.BMI),
		LastMeasuredDate:     datePtrToPgtypeDate(info.LastMeasuredDate),
		OverallHealthStatus:  pgtypeTextFromStringPtr(info.OverallHealthStatus),
		HealthSummary:        pgtypeTextFromStringPtr(info.HealthSummary),
		PrimaryCarePhysician: pgtypeTextFromStringPtr(info.PrimaryCarePhysician),
		PrimaryClinicID:      uuidPtrToPgtypeUUID(info.PrimaryClinicID),
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_medical_info", "error").Inc()
		return r.handleError(err, "update medical info")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_medical_info", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) DeleteMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeletePatientMedicalInfo(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("delete_medical_info_by_patient_id", "error").Inc()
		return r.handleError(err, "delete medical info by patient id")
	}

	medicalInfoDBQueryTotal.WithLabelValues("delete_medical_info_by_patient_id", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *medicalInfoRepository) mapToPatientMedicalInfo(row sqlc.PatientMedicalInfo) patients.PatientMedicalInfo {
	return patients.PatientMedicalInfo{
		ID:                     pgtypeUUIDToUUID(row.ID),
		PatientID:              pgtypeUUIDToUUID(row.PatientID),
		BloodType:              pgtypeTextToStringPtr(row.BloodType),
		BloodTypeLastTested:    pgtypeDateToTimePtr(row.BloodTypeLastTested),
		HeightCm:               pgtypeNumericToFloat64Ptr(row.HeightCm),
		WeightKg:               pgtypeNumericToFloat64Ptr(row.WeightKg),
		BMI:                    pgtypeNumericToFloat64Ptr(row.Bmi),
		LastMeasuredDate:       pgtypeDateToTimePtr(row.LastMeasuredDate),
		OverallHealthStatus:    pgtypeTextToStringPtr(row.OverallHealthStatus),
		HealthSummary:          pgtypeTextToStringPtr(row.HealthSummary),
		PrimaryCarePhysician:   pgtypeTextToStringPtr(row.PrimaryCarePhysician),
		PrimaryClinicID:        uuidPtrToUUID(row.PrimaryClinicID),
		OrganDonor:             pgtypeBoolToBool(row.OrganDonor),
		AdvanceDirectiveExists: pgtypeBoolToBool(row.AdvanceDirectiveExists),
		AdvanceDirectiveURL:    pgtypeTextToStringPtr(row.AdvanceDirectiveUrl),
		DNRStatus:              pgtypeBoolToBool(row.DnrStatus),
		CreatedAt:              row.CreatedAt.Time,
		UpdatedAt:              row.UpdatedAt.Time,
	}
}

func (r *medicalInfoRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
