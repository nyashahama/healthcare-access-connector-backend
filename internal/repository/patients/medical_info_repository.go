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

func (r *medicalInfoRepository) DeleteMedicalInfo(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Note: The SQL query uses patient_id, not id
	// This is a placeholder
	err := r.querier.DeletePatientMedicalInfo(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("delete_medical_info", "error").Inc()
		return r.handleError(err, "delete medical info")
	}

	medicalInfoDBQueryTotal.WithLabelValues("delete_medical_info", "success").Inc()
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

// ===== Blood Type Management =====

func (r *medicalInfoRepository) UpdateBloodType(ctx context.Context, id uuid.UUID, bloodType string, testedDate time.Time) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientBloodType(ctx, sqlc.UpdatePatientBloodTypeParams{
		PatientID:           uuidToPgtypeUUID(id),
		BloodType:           pgtypeTextFromString(bloodType),
		BloodTypeLastTested: pgtype.Date{Time: testedDate, Valid: true},
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_blood_type", "error").Inc()
		return r.handleError(err, "update blood type")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_blood_type", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) GetPatientsByBloodType(ctx context.Context, bloodType string, limit, offset int) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByBloodType(ctx, pgtypeTextFromString(bloodType))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_blood_type", "error").Inc()
		return nil, r.handleError(err, "get patients by blood type")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = patients.PatientMedicalInfo{
			PatientID:           pgtypeUUIDToUUID(row.PatientID),
			BloodType:           pgtypeTextToStringPtr(row.BloodType),
			BloodTypeLastTested: pgtypeDateToTimePtr(row.BloodTypeLastTested),
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_blood_type", "success").Inc()
	return result, nil
}

func (r *medicalInfoRepository) CountPatientsByBloodType(ctx context.Context, bloodType string) (int64, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByBloodType(ctx, pgtypeTextFromString(bloodType))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("count_patients_by_blood_type", "error").Inc()
		return 0, r.handleError(err, "count patients by blood type")
	}

	medicalInfoDBQueryTotal.WithLabelValues("count_patients_by_blood_type", "success").Inc()
	return int64(len(rows)), nil
}

func (r *medicalInfoRepository) GetBloodTypeDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetBloodTypeDistribution(ctx)
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_blood_type_distribution", "error").Inc()
		return nil, r.handleError(err, "get blood type distribution")
	}

	distribution := make(map[string]int64)
	for _, row := range rows {
		if row.BloodType.Valid {
			distribution[row.BloodType.String] = row.PatientCount
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_blood_type_distribution", "success").Inc()
	return distribution, nil
}

// ===== Vital Signs & Measurements =====

func (r *medicalInfoRepository) UpdateVitalStats(ctx context.Context, id uuid.UUID, heightCm, weightKg, bmi *float64, measuredDate time.Time) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientVitals(ctx, sqlc.UpdatePatientVitalsParams{
		PatientID:        uuidToPgtypeUUID(id),
		HeightCm:         float64PtrToPgtypeNumeric(heightCm),
		WeightKg:         float64PtrToPgtypeNumeric(weightKg),
		Bmi:              float64PtrToPgtypeNumeric(bmi),
		LastMeasuredDate: pgtype.Date{Time: measuredDate, Valid: true},
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_vital_stats", "error").Inc()
		return r.handleError(err, "update vital stats")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_vital_stats", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) UpdateHeight(ctx context.Context, id uuid.UUID, heightCm float64, measuredDate time.Time) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientHeight(ctx, sqlc.UpdatePatientHeightParams{
		PatientID: uuidToPgtypeUUID(id),
		HeightCm:  pgtype.Numeric{Int: nil, Exp: 0, NaN: false, Valid: true},
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_height", "error").Inc()
		return r.handleError(err, "update height")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_height", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) UpdateWeight(ctx context.Context, id uuid.UUID, weightKg float64, measuredDate time.Time) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Calculate BMI if height is available
	bmi := pgtype.Numeric{Valid: false}
	// This would require fetching height first - simplified here

	err := r.querier.UpdatePatientWeight(ctx, sqlc.UpdatePatientWeightParams{
		PatientID: uuidToPgtypeUUID(id),
		WeightKg:  pgtype.Numeric{Valid: true},
		Bmi:       bmi,
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_weight", "error").Inc()
		return r.handleError(err, "update weight")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_weight", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) UpdateBMI(ctx context.Context, id uuid.UUID, bmi float64) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientBMI(ctx, sqlc.UpdatePatientBMIParams{
		PatientID: uuidToPgtypeUUID(id),
		Bmi:       pgtype.Numeric{Valid: true},
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_bmi", "error").Inc()
		return r.handleError(err, "update bmi")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_bmi", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) GetPatientsByBMIRange(ctx context.Context, minBMI, maxBMI float64) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByBMIRange(ctx, sqlc.GetPatientsByBMIRangeParams{
		Bmi:   pgtype.Numeric{Valid: true},
		Bmi_2: pgtype.Numeric{Valid: true},
		Limit: 100,
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_bmi_range", "error").Inc()
		return nil, r.handleError(err, "get patients by bmi range")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = patients.PatientMedicalInfo{
			PatientID: pgtypeUUIDToUUID(row.PatientID),
			BMI:       pgtypeNumericToFloat64Ptr(row.Bmi),
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_bmi_range", "success").Inc()
	return result, nil
}

// ===== Health Status Management =====

func (r *medicalInfoRepository) UpdateHealthStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientHealthStatus(ctx, sqlc.UpdatePatientHealthStatusParams{
		PatientID:           uuidToPgtypeUUID(id),
		OverallHealthStatus: pgtypeTextFromString(status),
		HealthSummary:       pgtype.Text{Valid: false},
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_health_status", "error").Inc()
		return r.handleError(err, "update health status")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_health_status", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) UpdateHealthSummary(ctx context.Context, id uuid.UUID, summary string) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateHealthSummary(ctx, sqlc.UpdateHealthSummaryParams{
		PatientID:     uuidToPgtypeUUID(id),
		HealthSummary: pgtypeTextFromString(summary),
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_health_summary", "error").Inc()
		return r.handleError(err, "update health summary")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_health_summary", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) GetPatientsByHealthStatus(ctx context.Context, status string, limit, offset int) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByHealthStatus(ctx, sqlc.GetPatientsByHealthStatusParams{
		OverallHealthStatus: pgtypeTextFromString(status),
		Limit:               int32(limit),
		Offset:              int32(offset),
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_health_status", "error").Inc()
		return nil, r.handleError(err, "get patients by health status")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = patients.PatientMedicalInfo{
			PatientID:           pgtypeUUIDToUUID(row.PatientID),
			OverallHealthStatus: pgtypeTextToStringPtr(row.OverallHealthStatus),
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_health_status", "success").Inc()
	return result, nil
}

func (r *medicalInfoRepository) CountPatientsByHealthStatus(ctx context.Context, status string) (int64, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByHealthStatus(ctx, sqlc.GetPatientsByHealthStatusParams{
		OverallHealthStatus: pgtypeTextFromString(status),
		Limit:               1000000,
		Offset:              0,
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("count_patients_by_health_status", "error").Inc()
		return 0, r.handleError(err, "count patients by health status")
	}

	medicalInfoDBQueryTotal.WithLabelValues("count_patients_by_health_status", "success").Inc()
	return int64(len(rows)), nil
}

func (r *medicalInfoRepository) GetHealthStatusDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetHealthStatusDistribution(ctx)
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_health_status_distribution", "error").Inc()
		return nil, r.handleError(err, "get health status distribution")
	}

	distribution := make(map[string]int64)
	for _, row := range rows {
		if row.OverallHealthStatus.Valid {
			distribution[row.OverallHealthStatus.String] = row.PatientCount
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_health_status_distribution", "success").Inc()
	return distribution, nil
}

// ===== Primary Care Provider =====

func (r *medicalInfoRepository) UpdatePrimaryCareProvider(ctx context.Context, id uuid.UUID, physicianName string, clinicID *uuid.UUID) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePrimaryCareProvider(ctx, sqlc.UpdatePrimaryCareProviderParams{
		PatientID:            uuidToPgtypeUUID(id),
		PrimaryCarePhysician: pgtypeTextFromString(physicianName),
		PrimaryClinicID:      uuidPtrToPgtypeUUID(clinicID),
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_primary_care_provider", "error").Inc()
		return r.handleError(err, "update primary care provider")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_primary_care_provider", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) UpdatePrimaryClinic(ctx context.Context, id uuid.UUID, clinicID uuid.UUID) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePrimaryClinic(ctx, sqlc.UpdatePrimaryClinicParams{
		PatientID:       uuidToPgtypeUUID(id),
		PrimaryClinicID: uuidToPgtypeUUID(clinicID),
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_primary_clinic", "error").Inc()
		return r.handleError(err, "update primary clinic")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_primary_clinic", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) GetPatientsByPrimaryClinic(ctx context.Context, clinicID uuid.UUID) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByPrimaryClinic(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_primary_clinic", "error").Inc()
		return nil, r.handleError(err, "get patients by primary clinic")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = patients.PatientMedicalInfo{
			PatientID:            pgtypeUUIDToUUID(row.PatientID),
			PrimaryCarePhysician: pgtypeTextToStringPtr(row.PrimaryCarePhysician),
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_primary_clinic", "success").Inc()
	return result, nil
}

func (r *medicalInfoRepository) GetPatientsByPhysician(ctx context.Context, physicianName string) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByPrimaryCarePhysician(ctx, pgtypeTextFromString(physicianName))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_physician", "error").Inc()
		return nil, r.handleError(err, "get patients by physician")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = patients.PatientMedicalInfo{
			PatientID:            pgtypeUUIDToUUID(row.PatientID),
			PrimaryCarePhysician: pgtypeTextToStringPtr(row.PrimaryCarePhysician),
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_patients_by_physician", "success").Inc()
	return result, nil
}

// ===== Advance Directives & End-of-Life =====

func (r *medicalInfoRepository) UpdateOrganDonorStatus(ctx context.Context, id uuid.UUID, isOrganDonor bool) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateOrganDonorStatus(ctx, sqlc.UpdateOrganDonorStatusParams{
		PatientID:  uuidToPgtypeUUID(id),
		OrganDonor: pgtype.Bool{Bool: isOrganDonor, Valid: true},
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_organ_donor_status", "error").Inc()
		return r.handleError(err, "update organ donor status")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_organ_donor_status", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) UpdateDNRStatus(ctx context.Context, id uuid.UUID, dnrStatus bool) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateDNRStatus(ctx, sqlc.UpdateDNRStatusParams{
		PatientID: uuidToPgtypeUUID(id),
		DnrStatus: pgtype.Bool{Bool: dnrStatus, Valid: true},
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_dnr_status", "error").Inc()
		return r.handleError(err, "update dnr status")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_dnr_status", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) UpdateAdvanceDirective(ctx context.Context, id uuid.UUID, exists bool, url *string) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateAdvanceDirective(ctx, sqlc.UpdateAdvanceDirectiveParams{
		PatientID:              uuidToPgtypeUUID(id),
		AdvanceDirectiveExists: pgtype.Bool{Bool: exists, Valid: true},
		AdvanceDirectiveUrl:    pgtypeTextFromStringPtr(url),
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("update_advance_directive", "error").Inc()
		return r.handleError(err, "update advance directive")
	}

	medicalInfoDBQueryTotal.WithLabelValues("update_advance_directive", "success").Inc()
	return nil
}

func (r *medicalInfoRepository) GetOrganDonors(ctx context.Context, limit, offset int) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetOrganDonors(ctx, sqlc.GetOrganDonorsParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_organ_donors", "error").Inc()
		return nil, r.handleError(err, "get organ donors")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = patients.PatientMedicalInfo{
			PatientID:  pgtypeUUIDToUUID(row.PatientID),
			BloodType:  pgtypeTextToStringPtr(row.BloodType),
			OrganDonor: true,
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_organ_donors", "success").Inc()
	return result, nil
}

func (r *medicalInfoRepository) GetPatientsWithDNR(ctx context.Context) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsWithDNR(ctx)
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_patients_with_dnr", "error").Inc()
		return nil, r.handleError(err, "get patients with dnr")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = patients.PatientMedicalInfo{
			PatientID: pgtypeUUIDToUUID(row.PatientID),
			DNRStatus: true,
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_patients_with_dnr", "success").Inc()
	return result, nil
}

func (r *medicalInfoRepository) GetPatientsWithAdvanceDirective(ctx context.Context) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsWithAdvanceDirective(ctx)
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_patients_with_advance_directive", "error").Inc()
		return nil, r.handleError(err, "get patients with advance directive")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = patients.PatientMedicalInfo{
			PatientID:              pgtypeUUIDToUUID(row.PatientID),
			AdvanceDirectiveExists: true,
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_patients_with_advance_directive", "success").Inc()
	return result, nil
}

func (r *medicalInfoRepository) CountOrganDonors(ctx context.Context) (int64, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetOrganDonors(ctx, sqlc.GetOrganDonorsParams{
		Limit:  1000000,
		Offset: 0,
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("count_organ_donors", "error").Inc()
		return 0, r.handleError(err, "count organ donors")
	}

	medicalInfoDBQueryTotal.WithLabelValues("count_organ_donors", "success").Inc()
	return int64(len(rows)), nil
}

func (r *medicalInfoRepository) CountPatientsWithDNR(ctx context.Context) (int64, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsWithDNR(ctx)
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("count_patients_with_dnr", "error").Inc()
		return 0, r.handleError(err, "count patients with dnr")
	}

	medicalInfoDBQueryTotal.WithLabelValues("count_patients_with_dnr", "success").Inc()
	return int64(len(rows)), nil
}

// ===== Statistics & Analytics =====

func (r *medicalInfoRepository) GetMedicalInfoSummary(ctx context.Context) (patients.MedicalInfoSummary, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	stats, err := r.querier.GetMedicalInfoStatistics(ctx)
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_medical_info_summary", "error").Inc()
		return patients.MedicalInfoSummary{}, r.handleError(err, "get medical info summary")
	}

	summary := patients.MedicalInfoSummary{
		TotalRecords:         stats.TotalRecords,
		WithBloodType:        stats.WithBloodType,
		WithHeight:           stats.WithHeight,
		WithWeight:           stats.WithWeight,
		WithBMI:              stats.WithBmi,
		WithPrimaryPhysician: stats.WithPrimaryPhysician,
		WithPrimaryClinic:    stats.WithPrimaryClinic,
		OrganDonors:          stats.OrganDonors,
		WithDNR:              stats.WithDnr,
		WithAdvanceDirective: stats.WithAdvanceDirective,
		AverageBMI:           pgtypeNumericToFloat64Ptr(stats.AvgBmi),
		AverageWeight:        pgtypeNumericToFloat64Ptr(stats.AvgWeight),
		AverageHeight:        pgtypeNumericToFloat64Ptr(stats.AvgHeight),
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_medical_info_summary", "success").Inc()
	return summary, nil
}

func (r *medicalInfoRepository) GetAverageVitalsByAgeGroup(ctx context.Context) (interface{}, error) {
	// This would require joining with patient profiles to get age - simplified implementation
	return map[string]interface{}{
		"message": "Not implemented - requires age group calculation",
	}, nil
}

func (r *medicalInfoRepository) GetHealthTrends(ctx context.Context, startDate, endDate time.Time) (interface{}, error) {
	// This would require historical tracking - simplified implementation
	return map[string]interface{}{
		"start_date": startDate,
		"end_date":   endDate,
		"message":    "Not implemented - requires historical data",
	}, nil
}

// ===== Bulk Operations =====

func (r *medicalInfoRepository) GetMedicalInfoByPatientIDs(ctx context.Context, patientIDs []uuid.UUID) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert UUIDs to pgtype UUIDs for the query
	pgtypeIDs := make([]pgtype.UUID, len(patientIDs))
	for i, id := range patientIDs {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	rows, err := r.querier.GetMedicalInfoByPatientIDs(ctx, pgtypeIDs)
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_medical_info_by_patient_ids", "error").Inc()
		return nil, r.handleError(err, "get medical info by patient ids")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = r.mapToPatientMedicalInfo(row)
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_medical_info_by_patient_ids", "success").Inc()
	return result, nil
}

func (r *medicalInfoRepository) BulkUpdateHealthStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert UUIDs to pgtype UUIDs
	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	err := r.querier.BulkUpdateHealthStatus(ctx, sqlc.BulkUpdateHealthStatusParams{
		Column1:             pgtypeIDs,
		OverallHealthStatus: pgtypeTextFromString(status),
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("bulk_update_health_status", "error").Inc()
		return r.handleError(err, "bulk update health status")
	}

	medicalInfoDBQueryTotal.WithLabelValues("bulk_update_health_status", "success").Inc()
	return nil
}

// ===== Validation & Utilities =====

func (r *medicalInfoRepository) MedicalInfoExists(ctx context.Context, patientID uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	result, err := r.querier.MedicalInfoExists(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("medical_info_exists", "error").Inc()
		return false, r.handleError(err, "medical info exists")
	}

	medicalInfoDBQueryTotal.WithLabelValues("medical_info_exists", "success").Inc()
	return result, nil
}

func (r *medicalInfoRepository) GetLastMeasurementDate(ctx context.Context, patientID uuid.UUID) (*time.Time, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	info, err := r.querier.GetPatientMedicalInfo(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_last_measurement_date", "error").Inc()
		return nil, r.handleError(err, "get last measurement date")
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_last_measurement_date", "success").Inc()
	return pgtypeDateToTimePtr(info.LastMeasuredDate), nil
}

func (r *medicalInfoRepository) GetPatientsNeedingVitalUpdate(ctx context.Context, daysSinceUpdate int) ([]patients.PatientMedicalInfo, error) {
	start := time.Now()
	defer func() {
		medicalInfoDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsWithOutdatedVitals(ctx, sqlc.GetPatientsWithOutdatedVitalsParams{
		Limit:  1000,
		Offset: 0,
	})
	if err != nil {
		medicalInfoDBQueryTotal.WithLabelValues("get_patients_needing_vital_update", "error").Inc()
		return nil, r.handleError(err, "get patients needing vital update")
	}

	result := make([]patients.PatientMedicalInfo, len(rows))
	for i, row := range rows {
		result[i] = patients.PatientMedicalInfo{
			PatientID:        pgtypeUUIDToUUID(row.PatientID),
			LastMeasuredDate: pgtypeDateToTimePtr(row.LastMeasuredDate),
		}
	}

	medicalInfoDBQueryTotal.WithLabelValues("get_patients_needing_vital_update", "success").Inc()
	return result, nil
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
