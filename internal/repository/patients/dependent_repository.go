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
	dependentDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dependent_db_query_duration_seconds",
			Help:    "Dependent database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	dependentDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dependent_db_query_total",
			Help: "Total number of dependent database queries",
		},
		[]string{"operation", "status"},
	)
)

type dependentRepository struct {
	querier sqlc.Querier
}

func NewDependentRepository(pool *pgxpool.Pool) repository.PatientDependentRepository {
	return NewDependentRepositoryWithQuerier(sqlc.New(pool))
}

func NewDependentRepositoryWithQuerier(querier sqlc.Querier) repository.PatientDependentRepository {
	return &dependentRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *dependentRepository) AddPatientDependent(ctx context.Context, dependent patients.PatientDependent) (patients.PatientDependent, error) {
	start := time.Now()
	defer func() {
		dependentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.AddPatientDependent(ctx, sqlc.AddPatientDependentParams{
		PatientID:               uuidToPgtypeUUID(dependent.PatientID),
		FirstName:               dependent.FirstName,
		LastName:                dependent.LastName,
		DateOfBirth:             pgtype.Date{Time: dependent.DateOfBirth},
		Gender:                  pgtypeTextFromStringPtr(dependent.Gender),
		Relationship:            dependent.Relationship,
		BloodType:               pgtypeTextFromStringPtr(dependent.BloodType),
		HealthStatus:            pgtypeTextFromStringPtr(dependent.HealthStatus),
		PrimaryPediatrician:     pgtypeTextFromStringPtr(dependent.PrimaryPediatrician),
		ClinicID:                uuidPtrToPgtypeUUID(dependent.ClinicID),
		BirthWeightKg:           float64PtrToPgtypeNumeric(dependent.BirthWeightKg),
		BirthHeightCm:           float64PtrToPgtypeNumeric(dependent.BirthHeightCm),
		SchoolName:              pgtypeTextFromStringPtr(dependent.SchoolName),
		Grade:                   pgtypeTextFromStringPtr(dependent.Grade),
		HasLegalGuardianship:    pgtype.Bool{Bool: dependent.HasLegalGuardianship, Valid: true},
		GuardianshipDocumentUrl: pgtypeTextFromStringPtr(dependent.GuardianshipDocumentURL),
		HasSpecialNeeds:         pgtype.Bool{Bool: dependent.HasSpecialNeeds, Valid: true},
		SpecialNeedsDescription: pgtypeTextFromStringPtr(dependent.SpecialNeedsDescription),
	})
	if err != nil {
		dependentDBQueryTotal.WithLabelValues("add_patient_dependent", "error").Inc()
		return patients.PatientDependent{}, r.handleError(err, "add patient dependent")
	}

	dependentDBQueryTotal.WithLabelValues("add_patient_dependent", "success").Inc()
	return r.mapToPatientDependent(created), nil
}

func (r *dependentRepository) GetPatientDependents(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error) {
	start := time.Now()
	defer func() {
		dependentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientDependents(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		dependentDBQueryTotal.WithLabelValues("get_patient_dependents", "error").Inc()
		return nil, r.handleError(err, "get patient dependents")
	}

	dependents := make([]patients.PatientDependent, len(rows))
	for i, row := range rows {
		dependents[i] = patients.PatientDependent{
			ID:                  pgtypeUUIDToUUID(row.ID),
			PatientID:           patientID,
			FirstName:           row.FirstName,
			LastName:            row.LastName,
			DateOfBirth:         *pgtypeDateToTimePtr(row.DateOfBirth),
			Gender:              pgtypeTextToStringPtr(row.Gender),
			Relationship:        row.Relationship,
			BloodType:           pgtypeTextToStringPtr(row.BloodType),
			HealthStatus:        pgtypeTextToStringPtr(row.HealthStatus),
			PrimaryPediatrician: pgtypeTextToStringPtr(row.PrimaryPediatrician),
			SchoolName:          pgtypeTextToStringPtr(row.SchoolName),
			Grade:               pgtypeTextToStringPtr(row.Grade),
			HasSpecialNeeds:     row.HasSpecialNeeds.Bool,
			CreatedAt:           row.CreatedAt.Time,
			UpdatedAt:           row.UpdatedAt.Time,
		}
	}

	dependentDBQueryTotal.WithLabelValues("get_patient_dependents", "success").Inc()
	return dependents, nil
}

func (r *dependentRepository) GetDependentChildren(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error) {
	start := time.Now()
	defer func() {
		dependentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetDependentChildren(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		dependentDBQueryTotal.WithLabelValues("get_dependent_children", "error").Inc()
		return nil, r.handleError(err, "get dependent children")
	}

	dependents := make([]patients.PatientDependent, len(rows))
	for i, row := range rows {
		dependents[i] = patients.PatientDependent{
			ID:           pgtypeUUIDToUUID(row.ID),
			PatientID:    patientID,
			FirstName:    row.FirstName,
			LastName:     row.LastName,
			DateOfBirth:  *pgtypeDateToTimePtr(row.DateOfBirth),
			Gender:       pgtypeTextToStringPtr(row.Gender),
			HealthStatus: pgtypeTextToStringPtr(row.HealthStatus),
			SchoolName:   pgtypeTextToStringPtr(row.SchoolName),
			Grade:        pgtypeTextToStringPtr(row.Grade),
		}
	}

	dependentDBQueryTotal.WithLabelValues("get_dependent_children", "success").Inc()
	return dependents, nil
}

func (r *dependentRepository) UpdatePatientDependent(ctx context.Context, dependent patients.PatientDependent) error {
	start := time.Now()
	defer func() {
		dependentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientDependent(ctx, sqlc.UpdatePatientDependentParams{
		ID:                      uuidToPgtypeUUID(dependent.ID),
		FirstName:               dependent.FirstName,
		LastName:                dependent.LastName,
		DateOfBirth:             pgtype.Date{Time: dependent.DateOfBirth},
		Gender:                  pgtypeTextFromStringPtr(dependent.Gender),
		BloodType:               pgtypeTextFromStringPtr(dependent.BloodType),
		HealthStatus:            pgtypeTextFromStringPtr(dependent.HealthStatus),
		PrimaryPediatrician:     pgtypeTextFromStringPtr(dependent.PrimaryPediatrician),
		ClinicID:                uuidPtrToPgtypeUUID(dependent.ClinicID),
		SchoolName:              pgtypeTextFromStringPtr(dependent.SchoolName),
		Grade:                   pgtypeTextFromStringPtr(dependent.Grade),
		HasSpecialNeeds:         pgtype.Bool{Bool: dependent.HasSpecialNeeds, Valid: true},
		SpecialNeedsDescription: pgtypeTextFromStringPtr(dependent.SpecialNeedsDescription),
	})
	if err != nil {
		dependentDBQueryTotal.WithLabelValues("update_patient_dependent", "error").Inc()
		return r.handleError(err, "update patient dependent")
	}

	dependentDBQueryTotal.WithLabelValues("update_patient_dependent", "success").Inc()
	return nil
}

func (r *dependentRepository) DeletePatientDependent(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		dependentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeletePatientDependent(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		dependentDBQueryTotal.WithLabelValues("delete_patient_dependent", "error").Inc()
		return r.handleError(err, "delete patient dependent")
	}

	dependentDBQueryTotal.WithLabelValues("delete_patient_dependent", "success").Inc()
	return nil
}

// ===== Helper Functions =====

func (r *dependentRepository) mapToPatientDependent(row sqlc.PatientDependent) patients.PatientDependent {
	return patients.PatientDependent{
		ID:                      pgtypeUUIDToUUID(row.ID),
		PatientID:               pgtypeUUIDToUUID(row.PatientID),
		FirstName:               row.FirstName,
		LastName:                row.LastName,
		DateOfBirth:             *pgtypeDateToTimePtr(row.DateOfBirth),
		Gender:                  pgtypeTextToStringPtr(row.Gender),
		Relationship:            row.Relationship,
		BloodType:               pgtypeTextToStringPtr(row.BloodType),
		HealthStatus:            pgtypeTextToStringPtr(row.HealthStatus),
		PrimaryPediatrician:     pgtypeTextToStringPtr(row.PrimaryPediatrician),
		ClinicID:                uuidPtrToUUID(row.ClinicID),
		BirthWeightKg:           pgtypeNumericToFloat64Ptr(row.BirthWeightKg),
		BirthHeightCm:           pgtypeNumericToFloat64Ptr(row.BirthHeightCm),
		SchoolName:              pgtypeTextToStringPtr(row.SchoolName),
		Grade:                   pgtypeTextToStringPtr(row.Grade),
		HasLegalGuardianship:    pgtypeBoolToBool(row.HasLegalGuardianship),
		GuardianshipDocumentURL: pgtypeTextToStringPtr(row.GuardianshipDocumentUrl),
		HasSpecialNeeds:         pgtypeBoolToBool(row.HasSpecialNeeds),
		SpecialNeedsDescription: pgtypeTextToStringPtr(row.SpecialNeedsDescription),
		CreatedAt:               row.CreatedAt.Time,
		UpdatedAt:               row.UpdatedAt.Time,
	}
}

func (r *dependentRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}

// Helper conversion functions

func pgtypeFloat8ToFloat64Ptr(val pgtype.Float8) *float64 {
	if !val.Valid {
		return nil
	}
	return &val.Float64
}

func pgtypeUUIDToUUIDPtr(val pgtype.UUID) *uuid.UUID {
	if !val.Valid {
		return nil
	}
	result := uuid.UUID(val.Bytes)
	return &result
}
