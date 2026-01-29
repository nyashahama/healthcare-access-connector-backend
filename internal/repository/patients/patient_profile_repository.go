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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	patientDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "patient_db_query_duration_seconds",
			Help:    "Patient database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	patientDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patient_db_query_total",
			Help: "Total number of patient database queries",
		},
		[]string{"operation", "status"},
	)
)

type patientRepository struct {
	querier sqlc.Querier
}

// NewPatientRepository creates a new patient repository using a pool
func NewPatientRepository(pool *pgxpool.Pool) repository.PatientProfileRepository {
	return NewPatientRepositoryWithQuerier(sqlc.New(pool))
}

// NewPatientRepositoryWithQuerier creates a new patient repository using a provided querier (for transactions)
func NewPatientRepositoryWithQuerier(querier sqlc.Querier) repository.PatientProfileRepository {
	return &patientRepository{
		querier: querier,
	}
}

func (r *patientRepository) CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert language preferences to PostgreSQL array
	var languagePrefs pgtype.FlatArray[string]
	if len(profile.LanguagePreferences) > 0 {
		languagePrefs = profile.LanguagePreferences
	} else {
		languagePrefs = []string{"English"}
	}

	created, err := r.querier.CreatePatientProfile(ctx, sqlc.CreatePatientProfileParams{
		UserID:                       uuidToPgtypeUUID(profile.UserID),
		FirstName:                    profile.FirstName,
		LastName:                     profile.LastName,
		PreferredName:                pgtypeTextFromStringPtr(profile.PreferredName),
		DateOfBirth:                  datePtrToPgtypeDate(profile.DateOfBirth),
		Gender:                       pgtypeTextFromStringPtr(profile.Gender),
		PreferredGenderPronouns:      pgtypeTextFromStringPtr(profile.PreferredGenderPronouns),
		PrimaryAddress:               pgtypeTextFromStringPtr(profile.PrimaryAddress),
		City:                         pgtypeTextFromStringPtr(profile.City),
		Province:                     pgtypeTextFromStringPtr(profile.Province),
		PostalCode:                   pgtypeTextFromStringPtr(profile.PostalCode),
		Country:                      pgtypeTextFromString(profile.Country),
		LanguagePreferences:          languagePrefs,
		HomeLanguage:                 pgtypeTextFromStringPtr(profile.HomeLanguage),
		RequiresInterpreter:          pgtype.Bool{Bool: profile.RequiresInterpreter, Valid: true},
		PreferredCommunicationMethod: pgtypeTextFromString(profile.PreferredCommunicationMethod),
		MedicalAidNumber:             pgtypeTextFromStringPtr(profile.MedicalAidNumber),
		MedicalAidProvider:           pgtypeTextFromStringPtr(profile.MedicalAidProvider),
		HasMedicalAid:                pgtype.Bool{Bool: profile.HasMedicalAid, Valid: true},
		NationalIDNumber:             pgtypeTextFromStringPtr(profile.NationalIDNumber),
		EmploymentStatus:             pgtypeTextFromStringPtr(profile.EmploymentStatus),
		EducationLevel:               pgtypeTextFromStringPtr(profile.EducationLevel),
		HouseholdIncomeRange:         pgtypeTextFromStringPtr(profile.HouseholdIncomeRange),
		Timezone:                     pgtypeTextFromString(profile.Timezone),
		ReferredBy:                   uuidPtrToPgtypeUUID(profile.ReferredBy),
		ReferralCode:                 pgtypeTextFromStringPtr(profile.ReferralCode),
		AcceptsMarketingEmails:       pgtype.Bool{Bool: profile.AcceptsMarketingEmails, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("create_patient_profile", "error").Inc()
		return patients.PatientProfile{}, r.handleError(err, "create patient profile")
	}

	patientDBQueryTotal.WithLabelValues("create_patient_profile", "success").Inc()
	return r.mapToPatientProfile(created), nil
}

func (r *patientRepository) GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("get_patient_profile_by_id", "not_found").Inc()
			return patients.PatientProfile{}, domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("get_patient_profile_by_id", "error").Inc()
		return patients.PatientProfile{}, r.handleError(err, "get patient profile by ID")
	}

	patientDBQueryTotal.WithLabelValues("get_patient_profile_by_id", "success").Inc()
	return r.mapToPatientProfile(profile), nil
}

func (r *patientRepository) GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByUserID(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("get_patient_profile_by_user_id", "not_found").Inc()
			return patients.PatientProfile{}, domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("get_patient_profile_by_user_id", "error").Inc()
		return patients.PatientProfile{}, r.handleError(err, "get patient profile by user ID")
	}

	patientDBQueryTotal.WithLabelValues("get_patient_profile_by_user_id", "success").Inc()
	return r.mapToPatientProfile(profile), nil
}

func (r *patientRepository) GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByNationalID(ctx, pgtype.Text{String: nationalID, Valid: true})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("get_patient_profile_by_national_id", "not_found").Inc()
			return patients.PatientProfile{}, domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("get_patient_profile_by_national_id", "error").Inc()
		return patients.PatientProfile{}, r.handleError(err, "get patient profile by national ID")
	}

	patientDBQueryTotal.WithLabelValues("get_patient_profile_by_national_id", "success").Inc()
	return r.mapToPatientProfile(profile), nil
}

func (r *patientRepository) UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdatePatientProfile(ctx, sqlc.UpdatePatientProfileParams{
		ID:                           uuidToPgtypeUUID(profile.ID),
		FirstName:                    profile.FirstName,
		LastName:                     profile.LastName,
		PreferredName:                pgtypeTextFromStringPtr(profile.PreferredName),
		DateOfBirth:                  datePtrToPgtypeDate(profile.DateOfBirth),
		Gender:                       pgtypeTextFromStringPtr(profile.Gender),
		PreferredGenderPronouns:      pgtypeTextFromStringPtr(profile.PreferredGenderPronouns),
		PrimaryAddress:               pgtypeTextFromStringPtr(profile.PrimaryAddress),
		City:                         pgtypeTextFromStringPtr(profile.City),
		Province:                     pgtypeTextFromStringPtr(profile.Province),
		PostalCode:                   pgtypeTextFromStringPtr(profile.PostalCode),
		Country:                      pgtypeTextFromString(profile.Country),
		PreferredCommunicationMethod: pgtypeTextFromString(profile.PreferredCommunicationMethod),
		EmploymentStatus:             pgtypeTextFromStringPtr(profile.EmploymentStatus),
		EducationLevel:               pgtypeTextFromStringPtr(profile.EducationLevel),
		HouseholdIncomeRange:         pgtypeTextFromStringPtr(profile.HouseholdIncomeRange),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_patient_profile", "error").Inc()
		return r.handleError(err, "update patient profile")
	}

	patientDBQueryTotal.WithLabelValues("update_patient_profile", "success").Inc()
	return nil
}

func (r *patientRepository) DeletePatientProfile(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeletePatientProfile(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		patientDBQueryTotal.WithLabelValues("delete_patient_profile", "error").Inc()
		return r.handleError(err, "delete patient profile")
	}

	patientDBQueryTotal.WithLabelValues("delete_patient_profile", "success").Inc()
	return nil
}

func (r *patientRepository) DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeletePatientProfileByUserID(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		patientDBQueryTotal.WithLabelValues("delete_patient_profile_by_user_id", "error").Inc()
		return r.handleError(err, "delete patient profile by user ID")
	}

	patientDBQueryTotal.WithLabelValues("delete_patient_profile_by_user_id", "success").Inc()
	return nil
}

// handleError converts database errors to domain errors
func (r *patientRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			if pgErr.ConstraintName == "patient_profiles_user_id_key" {
				return fmt.Errorf("patient profile already exists for user: %w", err)
			}
			if pgErr.ConstraintName == "patient_profiles_national_id_number_key" {
				return fmt.Errorf("national ID already registered: %w", err)
			}
			return fmt.Errorf("duplicate constraint violation: %w", err)
		case "23503": // foreign_key_violation
			return fmt.Errorf("foreign key violation: %w", err)
		case "23514": // check_violation
			return fmt.Errorf("check constraint violation: %w", err)
		}
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

func (r *patientRepository) mapToPatientProfile(row sqlc.PatientProfile) patients.PatientProfile {
	return patients.PatientProfile{
		ID:                           pgtypeUUIDToUUID(row.ID),
		UserID:                       pgtypeUUIDToUUID(row.UserID),
		FirstName:                    row.FirstName,
		LastName:                     row.LastName,
		PreferredName:                pgtypeTextToStringPtr(row.PreferredName),
		DateOfBirth:                  pgtypeDateToTimePtr(row.DateOfBirth),
		Gender:                       pgtypeTextToStringPtr(row.Gender),
		PreferredGenderPronouns:      pgtypeTextToStringPtr(row.PreferredGenderPronouns),
		PrimaryAddress:               pgtypeTextToStringPtr(row.PrimaryAddress),
		City:                         pgtypeTextToStringPtr(row.City),
		Province:                     pgtypeTextToStringPtr(row.Province),
		PostalCode:                   pgtypeTextToStringPtr(row.PostalCode),
		Country:                      pgtypeTextToString(row.Country),
		LanguagePreferences:          row.LanguagePreferences,
		HomeLanguage:                 pgtypeTextToStringPtr(row.HomeLanguage),
		RequiresInterpreter:          pgtypeBoolToBool(row.RequiresInterpreter),
		PreferredCommunicationMethod: pgtypeTextToString(row.PreferredCommunicationMethod),
		MedicalAidNumber:             pgtypeTextToStringPtr(row.MedicalAidNumber),
		MedicalAidProvider:           pgtypeTextToStringPtr(row.MedicalAidProvider),
		HasMedicalAid:                pgtypeBoolToBool(row.HasMedicalAid),
		NationalIDNumber:             pgtypeTextToStringPtr(row.NationalIDNumber),
		EmploymentStatus:             pgtypeTextToStringPtr(row.EmploymentStatus),
		EducationLevel:               pgtypeTextToStringPtr(row.EducationLevel),
		HouseholdIncomeRange:         pgtypeTextToStringPtr(row.HouseholdIncomeRange),
		ProfilePictureURL:            pgtypeTextToStringPtr(row.ProfilePictureUrl),
		Timezone:                     pgtypeTextToString(row.Timezone),
		LastProfileUpdate:            pgtypeTimestampToTimePtr(row.LastProfileUpdate),
		ReferredBy:                   uuidPtrToUUID(row.ReferredBy),
		ReferralCode:                 pgtypeTextToStringPtr(row.ReferralCode),
		AcceptsMarketingEmails:       pgtypeBoolToBool(row.AcceptsMarketingEmails),
		CreatedAt:                    row.CreatedAt.Time,
		UpdatedAt:                    row.UpdatedAt.Time,
	}
}
