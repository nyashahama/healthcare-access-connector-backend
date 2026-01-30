package patients

import (
	"context"
	"database/sql"
	"encoding/json"
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

// ===== Personal Information Updates =====

func (r *patientRepository) UpdatePersonalInfo(ctx context.Context, id uuid.UUID, firstName, lastName string, preferredName *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// First get the user_id for this profile
	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_personal_info", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_personal_info", "error").Inc()
		return r.handleError(err, "get profile for update personal info")
	}

	err = r.querier.UpdatePatientPersonalInfo(ctx, sqlc.UpdatePatientPersonalInfoParams{
		UserID:                  profile.UserID,
		FirstName:               firstName,
		LastName:                lastName,
		PreferredName:           pgtypeTextFromStringPtr(preferredName),
		DateOfBirth:             profile.DateOfBirth,
		Gender:                  profile.Gender,
		PreferredGenderPronouns: profile.PreferredGenderPronouns,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_personal_info", "error").Inc()
		return r.handleError(err, "update personal info")
	}

	patientDBQueryTotal.WithLabelValues("update_personal_info", "success").Inc()
	return nil
}

func (r *patientRepository) UpdateDateOfBirth(ctx context.Context, id uuid.UUID, dob time.Time) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get current profile to update using existing method
	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.DateOfBirth = &dob
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateGenderInfo(ctx context.Context, id uuid.UUID, gender *string, pronouns *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.Gender = gender
	profile.PreferredGenderPronouns = pronouns
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateProfilePicture(ctx context.Context, id uuid.UUID, pictureURL string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_profile_picture", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_profile_picture", "error").Inc()
		return r.handleError(err, "get profile for update picture")
	}

	err = r.querier.UpdatePatientProfilePicture(ctx, sqlc.UpdatePatientProfilePictureParams{
		UserID:            profile.UserID,
		ProfilePictureUrl: pgtype.Text{String: pictureURL, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_profile_picture", "error").Inc()
		return r.handleError(err, "update profile picture")
	}

	patientDBQueryTotal.WithLabelValues("update_profile_picture", "success").Inc()
	return nil
}

func (r *patientRepository) UpdatePreferredName(ctx context.Context, id uuid.UUID, preferredName *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.PreferredName = preferredName
	return r.UpdatePatientProfile(ctx, profile)
}

// ===== Contact Information Updates =====

func (r *patientRepository) UpdateContactInfo(ctx context.Context, id uuid.UUID, address, city, province, postalCode *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_contact_info", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_contact_info", "error").Inc()
		return r.handleError(err, "get profile for update contact info")
	}

	err = r.querier.UpdatePatientContactInfo(ctx, sqlc.UpdatePatientContactInfoParams{
		UserID:                       profile.UserID,
		PrimaryAddress:               pgtypeTextFromStringPtr(address),
		City:                         pgtypeTextFromStringPtr(city),
		Province:                     pgtypeTextFromStringPtr(province),
		PostalCode:                   pgtypeTextFromStringPtr(postalCode),
		Country:                      profile.Country,
		PreferredCommunicationMethod: profile.PreferredCommunicationMethod,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_contact_info", "error").Inc()
		return r.handleError(err, "update contact info")
	}

	patientDBQueryTotal.WithLabelValues("update_contact_info", "success").Inc()
	return nil
}

func (r *patientRepository) UpdateAddress(ctx context.Context, id uuid.UUID, address, city, province, postalCode, country *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.PrimaryAddress = address
	profile.City = city
	profile.Province = province
	profile.PostalCode = postalCode
	if country != nil {
		profile.Country = *country
	}
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdatePrimaryAddress(ctx context.Context, id uuid.UUID, address string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.PrimaryAddress = &address
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateLocation(ctx context.Context, id uuid.UUID, city, province *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.City = city
	profile.Province = province
	return r.UpdatePatientProfile(ctx, profile)
}

// ===== Communication Preferences =====

func (r *patientRepository) UpdateCommunicationPreferences(ctx context.Context, id uuid.UUID, method string, languages []string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.PreferredCommunicationMethod = method
	profile.LanguagePreferences = languages
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdatePreferredCommunicationMethod(ctx context.Context, id uuid.UUID, method string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.PreferredCommunicationMethod = method
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateLanguagePreferences(ctx context.Context, id uuid.UUID, languages []string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_language_preferences", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_language_preferences", "error").Inc()
		return r.handleError(err, "get profile for update language preferences")
	}

	err = r.querier.UpdatePatientLanguagePreferences(ctx, sqlc.UpdatePatientLanguagePreferencesParams{
		UserID:              profile.UserID,
		LanguagePreferences: languages,
		HomeLanguage:        profile.HomeLanguage,
		RequiresInterpreter: profile.RequiresInterpreter,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_language_preferences", "error").Inc()
		return r.handleError(err, "update language preferences")
	}

	patientDBQueryTotal.WithLabelValues("update_language_preferences", "success").Inc()
	return nil
}

func (r *patientRepository) UpdateHomeLanguage(ctx context.Context, id uuid.UUID, language string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.HomeLanguage = &language
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateInterpreterRequirement(ctx context.Context, id uuid.UUID, requiresInterpreter bool) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.RequiresInterpreter = requiresInterpreter
	return r.UpdatePatientProfile(ctx, profile)
}

// ===== Medical Aid Information =====

func (r *patientRepository) UpdateMedicalAidInfo(ctx context.Context, id uuid.UUID, hasMedicalAid bool, provider, number *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_medical_aid_info", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_medical_aid_info", "error").Inc()
		return r.handleError(err, "get profile for update medical aid info")
	}

	err = r.querier.UpdatePatientMedicalAidInfo(ctx, sqlc.UpdatePatientMedicalAidInfoParams{
		UserID:             profile.UserID,
		MedicalAidNumber:   pgtypeTextFromStringPtr(number),
		MedicalAidProvider: pgtypeTextFromStringPtr(provider),
		HasMedicalAid:      pgtype.Bool{Bool: hasMedicalAid, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_medical_aid_info", "error").Inc()
		return r.handleError(err, "update medical aid info")
	}

	patientDBQueryTotal.WithLabelValues("update_medical_aid_info", "success").Inc()
	return nil
}

func (r *patientRepository) UpdateMedicalAidNumber(ctx context.Context, id uuid.UUID, number string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.MedicalAidNumber = &number
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateMedicalAidProvider(ctx context.Context, id uuid.UUID, provider string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.MedicalAidProvider = &provider
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateMedicalAidStatus(ctx context.Context, id uuid.UUID, hasMedicalAid bool) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.HasMedicalAid = hasMedicalAid
	return r.UpdatePatientProfile(ctx, profile)
}

// ===== Health System Identifiers =====

func (r *patientRepository) UpdateNationalIDNumber(ctx context.Context, id uuid.UUID, nationalID string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_national_id", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_national_id", "error").Inc()
		return r.handleError(err, "get profile for update national ID")
	}

	err = r.querier.UpdatePatientNationalID(ctx, sqlc.UpdatePatientNationalIDParams{
		UserID:           profile.UserID,
		NationalIDNumber: pgtype.Text{String: nationalID, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_national_id", "error").Inc()
		return r.handleError(err, "update national ID")
	}

	patientDBQueryTotal.WithLabelValues("update_national_id", "success").Inc()
	return nil
}

func (r *patientRepository) UpdateHealthSystemIdentifiers(ctx context.Context, id uuid.UUID, nationalID *string, medicalAidNumber *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.NationalIDNumber = nationalID
	profile.MedicalAidNumber = medicalAidNumber
	return r.UpdatePatientProfile(ctx, profile)
}

// ===== Demographic & Socioeconomic Information =====

func (r *patientRepository) UpdateEmploymentStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.EmploymentStatus = &status
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateEducationLevel(ctx context.Context, id uuid.UUID, level string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.EducationLevel = &level
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateHouseholdIncomeRange(ctx context.Context, id uuid.UUID, incomeRange string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	profile.HouseholdIncomeRange = &incomeRange
	return r.UpdatePatientProfile(ctx, profile)
}

func (r *patientRepository) UpdateDemographicInfo(ctx context.Context, id uuid.UUID, employmentStatus, educationLevel, incomeRange *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_demographic_info", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_demographic_info", "error").Inc()
		return r.handleError(err, "get profile for update demographic info")
	}

	err = r.querier.UpdatePatientDemographicInfo(ctx, sqlc.UpdatePatientDemographicInfoParams{
		UserID:               profile.UserID,
		EmploymentStatus:     pgtypeTextFromStringPtr(employmentStatus),
		EducationLevel:       pgtypeTextFromStringPtr(educationLevel),
		HouseholdIncomeRange: pgtypeTextFromStringPtr(incomeRange),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_demographic_info", "error").Inc()
		return r.handleError(err, "update demographic info")
	}

	patientDBQueryTotal.WithLabelValues("update_demographic_info", "success").Inc()
	return nil
}

// ===== Profile Settings & Preferences =====

func (r *patientRepository) UpdateTimezone(ctx context.Context, id uuid.UUID, timezone string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_timezone", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_timezone", "error").Inc()
		return r.handleError(err, "get profile for update timezone")
	}

	err = r.querier.UpdatePatientTimezone(ctx, sqlc.UpdatePatientTimezoneParams{
		UserID:   profile.UserID,
		Timezone: pgtype.Text{String: timezone, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_timezone", "error").Inc()
		return r.handleError(err, "update timezone")
	}

	patientDBQueryTotal.WithLabelValues("update_timezone", "success").Inc()
	return nil
}

func (r *patientRepository) UpdateMarketingPreferences(ctx context.Context, id uuid.UUID, acceptsMarketing bool) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_marketing_preferences", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_marketing_preferences", "error").Inc()
		return r.handleError(err, "get profile for update marketing preferences")
	}

	err = r.querier.UpdatePatientMarketingPreferences(ctx, sqlc.UpdatePatientMarketingPreferencesParams{
		UserID:                 profile.UserID,
		AcceptsMarketingEmails: pgtype.Bool{Bool: acceptsMarketing, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_marketing_preferences", "error").Inc()
		return r.handleError(err, "update marketing preferences")
	}

	patientDBQueryTotal.WithLabelValues("update_marketing_preferences", "success").Inc()
	return nil
}

func (r *patientRepository) UpdateReferralInfo(ctx context.Context, id uuid.UUID, referredBy *uuid.UUID, referralCode *string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("update_referral_info", "not_found").Inc()
			return domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("update_referral_info", "error").Inc()
		return r.handleError(err, "get profile for update referral info")
	}

	err = r.querier.UpdatePatientReferralInfo(ctx, sqlc.UpdatePatientReferralInfoParams{
		UserID:       profile.UserID,
		ReferredBy:   uuidPtrToPgtypeUUID(referredBy),
		ReferralCode: pgtypeTextFromStringPtr(referralCode),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("update_referral_info", "error").Inc()
		return r.handleError(err, "update referral info")
	}

	patientDBQueryTotal.WithLabelValues("update_referral_info", "success").Inc()
	return nil
}

func (r *patientRepository) UpdateLastProfileUpdate(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	now := time.Now()
	profile.LastProfileUpdate = &now
	return r.UpdatePatientProfile(ctx, profile)
}

// ===== Querying & Search =====

func (r *patientRepository) ListPatientProfiles(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Use a basic search with no filters
	rows, err := r.querier.SearchPatients(ctx, sqlc.SearchPatientsParams{
		Column1: "",   // NULL
		Column2: "",   // NULL
		Column3: "",   // NULL
		Column4: true, // NULL
		Column5: "",   // NULL
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("list_patient_profiles", "error").Inc()
		return nil, r.handleError(err, "list patient profiles")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("list_patient_profiles", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) SearchPatientProfiles(ctx context.Context, query string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.SearchPatientsByName(ctx, sqlc.SearchPatientsByNameParams{
		Column1: pgtype.Text{String: query, Valid: query != ""},
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("search_patient_profiles", "error").Inc()
		return nil, r.handleError(err, "search patient profiles")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("search_patient_profiles", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) AdvancedSearchPatients(ctx context.Context, params patients.AdvancedSearchParams) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.AdvancedPatientSearch(ctx, sqlc.AdvancedPatientSearchParams{
		Column1:  *params.Query,
		Column2:  *params.Province,
		Column3:  *params.City,
		Column4:  *params.HasMedicalAid,
		Column5:  *params.Gender,
		Column6:  *params.CommunicationMethod,
		Column7:  *params.EmploymentStatus,
		Column8:  *params.MedicalAidProvider,
		Column9:  *params.RequiresInterpreter,
		Column10: *params.AcceptsMarketingEmails,
		Limit:    int32(params.Limit),
		Offset:   int32(params.Offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("advanced_search_patients", "error").Inc()
		return nil, r.handleError(err, "advanced search patients")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("advanced_search_patients", "success").Inc()
	return profiles, nil
}

// ===== Geographic Queries =====

func (r *patientRepository) GetPatientsByProvince(ctx context.Context, province string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByProvince(ctx, sqlc.GetPatientsByProvinceParams{
		Province: pgtype.Text{String: province, Valid: true},
		Limit:    int32(limit),
		Offset:   int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_province", "error").Inc()
		return nil, r.handleError(err, "get patients by province")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_province", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByCity(ctx context.Context, city string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByCity(ctx, sqlc.GetPatientsByCityParams{
		City:   pgtype.Text{String: city, Valid: true},
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_city", "error").Inc()
		return nil, r.handleError(err, "get patients by city")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_city", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByProvinceAndCity(ctx context.Context, province, city string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByProvinceAndCity(ctx, sqlc.GetPatientsByProvinceAndCityParams{
		Province: pgtype.Text{String: province, Valid: true},
		City:     pgtype.Text{String: city, Valid: true},
		Limit:    int32(limit),
		Offset:   int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_province_city", "error").Inc()
		return nil, r.handleError(err, "get patients by province and city")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_province_city", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsInArea(ctx context.Context, province, city *string) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	if province != nil && city != nil {
		return r.GetPatientsByProvinceAndCity(ctx, *province, *city, 1000, 0)
	} else if province != nil {
		return r.GetPatientsByProvince(ctx, *province, 1000, 0)
	} else if city != nil {
		return r.GetPatientsByCity(ctx, *city, 1000, 0)
	}

	// If both are nil, return empty
	patientDBQueryTotal.WithLabelValues("get_patients_in_area", "success").Inc()
	return []patients.PatientProfile{}, nil
}

// ===== Medical Aid Queries =====

func (r *patientRepository) GetPatientsByMedicalAidProvider(ctx context.Context, provider string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByMedicalAidProvider(ctx, sqlc.GetPatientsByMedicalAidProviderParams{
		MedicalAidProvider: pgtype.Text{String: provider, Valid: true},
		Limit:              int32(limit),
		Offset:             int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_medical_aid_provider", "error").Inc()
		return nil, r.handleError(err, "get patients by medical aid provider")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_medical_aid_provider", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsWithMedicalAid(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsWithMedicalAid(ctx, sqlc.GetPatientsWithMedicalAidParams{
		Column1: "", // NULL
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_with_medical_aid", "error").Inc()
		return nil, r.handleError(err, "get patients with medical aid")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_with_medical_aid", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsWithoutMedicalAid(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsWithoutMedicalAid(ctx, sqlc.GetPatientsWithoutMedicalAidParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_without_medical_aid", "error").Inc()
		return nil, r.handleError(err, "get patients without medical aid")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_without_medical_aid", "success").Inc()
	return profiles, nil
}

// ===== Communication & Language Queries =====

func (r *patientRepository) GetPatientsByPreferredLanguage(ctx context.Context, language string) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByLanguage(ctx, sqlc.GetPatientsByLanguageParams{
		HomeLanguage: pgtype.Text{String: language, Valid: true},
		Limit:        1000,
		Offset:       0,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_preferred_language", "error").Inc()
		return nil, r.handleError(err, "get patients by preferred language")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_preferred_language", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsRequiringInterpreter(ctx context.Context) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsRequiringInterpreter(ctx, sqlc.GetPatientsRequiringInterpreterParams{
		Limit:  1000,
		Offset: 0,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_requiring_interpreter", "error").Inc()
		return nil, r.handleError(err, "get patients requiring interpreter")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_requiring_interpreter", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByHomeLanguage(ctx context.Context, language string) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Use the language query which checks both home_language and language_preferences
	rows, err := r.querier.GetPatientsByLanguage(ctx, sqlc.GetPatientsByLanguageParams{
		HomeLanguage: pgtype.Text{String: language, Valid: true},
		Limit:        1000,
		Offset:       0,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_home_language", "error").Inc()
		return nil, r.handleError(err, "get patients by home language")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_home_language", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByCommunicationMethod(ctx context.Context, method string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByCommunicationMethod(ctx, sqlc.GetPatientsByCommunicationMethodParams{
		PreferredCommunicationMethod: pgtype.Text{String: method, Valid: true},
		Limit:                        int32(limit),
		Offset:                       int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_communication_method", "error").Inc()
		return nil, r.handleError(err, "get patients by communication method")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_communication_method", "success").Inc()
	return profiles, nil
}

// ===== Demographic Queries =====

func (r *patientRepository) GetPatientsByGender(ctx context.Context, gender string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByGender(ctx, sqlc.GetPatientsByGenderParams{
		Gender: pgtype.Text{String: gender, Valid: true},
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_gender", "error").Inc()
		return nil, r.handleError(err, "get patients by gender")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_gender", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByAgeRange(ctx context.Context, minAge, maxAge int, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Calculate date range for age
	now := time.Now()
	minDate := now.AddDate(-maxAge, 0, 0)
	maxDate := now.AddDate(-minAge, 0, 0)

	rows, err := r.querier.GetPatientsByAgeRange(ctx, sqlc.GetPatientsByAgeRangeParams{
		DateOfBirth:   pgtype.Date{Time: minDate, Valid: true},
		DateOfBirth_2: pgtype.Date{Time: maxDate, Valid: true},
		Limit:         int32(limit),
		Offset:        int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_age_range", "error").Inc()
		return nil, r.handleError(err, "get patients by age range")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_age_range", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByEmploymentStatus(ctx context.Context, status string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByEmploymentStatus(ctx, sqlc.GetPatientsByEmploymentStatusParams{
		EmploymentStatus: pgtype.Text{String: status, Valid: true},
		Limit:            int32(limit),
		Offset:           int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_employment_status", "error").Inc()
		return nil, r.handleError(err, "get patients by employment status")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_employment_status", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByEducationLevel(ctx context.Context, level string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByEducationLevel(ctx, sqlc.GetPatientsByEducationLevelParams{
		EducationLevel: pgtype.Text{String: level, Valid: true},
		Limit:          int32(limit),
		Offset:         int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_education_level", "error").Inc()
		return nil, r.handleError(err, "get patients by education level")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_education_level", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByIncomeRange(ctx context.Context, incomeRange string, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByIncomeRange(ctx, sqlc.GetPatientsByIncomeRangeParams{
		HouseholdIncomeRange: pgtype.Text{String: incomeRange, Valid: true},
		Limit:                int32(limit),
		Offset:               int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_income_range", "error").Inc()
		return nil, r.handleError(err, "get patients by income range")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_income_range", "success").Inc()
	return profiles, nil
}

// ===== Marketing & Consent =====

func (r *patientRepository) GetPatientsAcceptingMarketing(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsAcceptingMarketing(ctx, sqlc.GetPatientsAcceptingMarketingParams{
		Column1: "", // NULL province
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_accepting_marketing", "error").Inc()
		return nil, r.handleError(err, "get patients accepting marketing")

	}
	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_accepting_marketing", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsOptedOutOfMarketing(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get all patients and filter out those not accepting marketing
	allPatients, err := r.ListPatientProfiles(ctx, limit+offset, 0)
	if err != nil {
		return nil, err
	}

	var optedOut []patients.PatientProfile
	count := 0
	for _, patient := range allPatients {
		if !patient.AcceptsMarketingEmails {
			if count >= offset && len(optedOut) < limit {
				optedOut = append(optedOut, patient)
			}
			count++
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_opted_out_marketing", "success").Inc()
	return optedOut, nil
}

// ===== Referral Queries =====

func (r *patientRepository) GetPatientsByReferrer(ctx context.Context, referrerID uuid.UUID) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByReferrer(ctx, sqlc.GetPatientsByReferrerParams{
		ReferredBy: uuidToPgtypeUUID(referrerID),
		Limit:      1000,
		Offset:     0,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_referrer", "error").Inc()
		return nil, r.handleError(err, "get patients by referrer")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_referrer", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByReferralCode(ctx context.Context, referralCode string) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsByReferralCode(ctx, pgtype.Text{String: referralCode, Valid: true})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_referral_code", "error").Inc()
		return nil, r.handleError(err, "get patients by referral code")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_referral_code", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetReferralStatistics(ctx context.Context, referrerID uuid.UUID) (int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	patients, err := r.GetPatientsByReferrer(ctx, referrerID)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_referral_statistics", "error").Inc()
		return 0, err
	}

	patientDBQueryTotal.WithLabelValues("get_referral_statistics", "success").Inc()
	return int64(len(patients)), nil
}

// ===== Profile Completion & Quality =====

func (r *patientRepository) GetIncompleteProfiles(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetIncompleteProfiles(ctx, sqlc.GetIncompleteProfilesParams{
		Column1: pgtype.Bool{Bool: false, Valid: false}, // NULL for medical aid check
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_incomplete_profiles", "error").Inc()
		return nil, r.handleError(err, "get incomplete profiles")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_incomplete_profiles", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetProfilesWithMissingContactInfo(ctx context.Context) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get profiles missing critical contact info
	rows, err := r.querier.GetProfilesMissingCriticalInfo(ctx, sqlc.GetProfilesMissingCriticalInfoParams{
		Limit:  1000,
		Offset: 0,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_profiles_missing_contact_info", "error").Inc()
		return nil, r.handleError(err, "get profiles missing contact info")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_profiles_missing_contact_info", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetProfilesWithMissingDemographics(ctx context.Context) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get all profiles and filter those missing demographic info
	allPatients, err := r.ListPatientProfiles(ctx, 1000, 0)
	if err != nil {
		return nil, err
	}

	var missingDemographics []patients.PatientProfile
	for _, patient := range allPatients {
		if patient.EmploymentStatus == nil || patient.EducationLevel == nil || patient.HouseholdIncomeRange == nil {
			missingDemographics = append(missingDemographics, patient)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_profiles_missing_demographics", "success").Inc()
	return missingDemographics, nil
}

func (r *patientRepository) GetRecentlyUpdatedProfiles(ctx context.Context, since time.Time, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetRecentlyUpdatedProfiles(ctx, sqlc.GetRecentlyUpdatedProfilesParams{
		LastProfileUpdate: pgtype.Timestamp{Time: since, Valid: true},
		Limit:             int32(limit),
		Offset:            int32(offset),
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_recently_updated_profiles", "error").Inc()
		return nil, r.handleError(err, "get recently updated profiles")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_recently_updated_profiles", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetStaleProfiles(ctx context.Context, olderThan time.Time) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaleProfiles(ctx, sqlc.GetStaleProfilesParams{
		LastProfileUpdate: pgtype.Timestamp{Time: olderThan, Valid: true},
		Limit:             1000,
		Offset:            0,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_stale_profiles", "error").Inc()
		return nil, r.handleError(err, "get stale profiles")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_stale_profiles", "success").Inc()
	return profiles, nil
}

// ===== Statistics & Analytics =====

func (r *patientRepository) GetPatientDemographicsSummary(ctx context.Context) (patients.PatientDemographicsSummary, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	summary, err := r.querier.GetPatientDemographicsSummary(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patient_demographics_summary", "error").Inc()
		return patients.PatientDemographicsSummary{}, r.handleError(err, "get patient demographics summary")
	}

	patientDBQueryTotal.WithLabelValues("get_patient_demographics_summary", "success").Inc()
	return patients.PatientDemographicsSummary{
		TotalPatients:        summary.TotalPatients,
		ProvincesCovered:     summary.ProvincesCovered,
		CitiesCovered:        summary.CitiesCovered,
		WithMedicalAid:       summary.WithMedicalAid,
		RequiringInterpreter: summary.RequiringInterpreter,
		MarketingOptIn:       summary.MarketingOptIn,
		AverageAge:           summary.AverageAge,
	}, nil
}

func (r *patientRepository) GetProvinceDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.CountPatientsByProvince(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_province_distribution", "error").Inc()
		return nil, r.handleError(err, "get province distribution")
	}

	distribution := make(map[string]int64)
	for _, row := range rows {
		distribution[row.Province.String] = row.PatientCount
	}

	patientDBQueryTotal.WithLabelValues("get_province_distribution", "success").Inc()
	return distribution, nil
}

func (r *patientRepository) GetCityDistribution(ctx context.Context, province *string) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.CountPatientsByCity(ctx, sqlc.CountPatientsByCityParams{
		Column1: *province,
		Limit:   1000,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_city_distribution", "error").Inc()
		return nil, r.handleError(err, "get city distribution")
	}

	distribution := make(map[string]int64)
	for _, row := range rows {
		key := fmt.Sprintf("%s, %s", row.City, row.Province)
		distribution[key] = row.PatientCount
	}

	patientDBQueryTotal.WithLabelValues("get_city_distribution", "success").Inc()
	return distribution, nil
}

func (r *patientRepository) GetGenderDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	result, err := r.querier.CountPatientsByGender(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_gender_distribution", "error").Inc()
		return nil, r.handleError(err, "get gender distribution")
	}

	distribution := make(map[string]int64)
	distribution["male"] = result.MaleCount
	distribution["female"] = result.FemaleCount
	distribution["other"] = result.OtherCount
	distribution["prefer_not_to_say"] = result.PreferNotToSayCount

	patientDBQueryTotal.WithLabelValues("get_gender_distribution", "success").Inc()
	return distribution, nil
}

func (r *patientRepository) GetAgeDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetAgeDistribution(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_age_distribution", "error").Inc()
		return nil, r.handleError(err, "get age distribution")
	}

	distribution := make(map[string]int64)
	for _, row := range rows {
		distribution[row.AgeGroup] = row.PatientCount
	}

	patientDBQueryTotal.WithLabelValues("get_age_distribution", "success").Inc()
	return distribution, nil
}

func (r *patientRepository) GetMedicalAidProviderDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.CountPatientsByMedicalAidProvider(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_medical_aid_provider_distribution", "error").Inc()
		return nil, r.handleError(err, "get medical aid provider distribution")
	}

	distribution := make(map[string]int64)
	for _, row := range rows {
		if row.MedicalAidProvider.Valid {
			distribution[row.MedicalAidProvider.String] = row.PatientCount
		}
	}

	patientDBQueryTotal.WithLabelValues("get_medical_aid_provider_distribution", "success").Inc()
	return distribution, nil
}

func (r *patientRepository) GetLanguageDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetLanguageDistribution(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_language_distribution", "error").Inc()
		return nil, r.handleError(err, "get language distribution")
	}

	distribution := make(map[string]int64)
	for _, row := range rows {
		distribution[interfaceToString(row.Language)] = row.PatientCount
	}

	patientDBQueryTotal.WithLabelValues("get_language_distribution", "success").Inc()
	return distribution, nil
}

func (r *patientRepository) GetCommunicationMethodDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	result, err := r.querier.CountPatientsByCommunicationMethod(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_communication_method_distribution", "error").Inc()
		return nil, r.handleError(err, "get communication method distribution")
	}

	distribution := make(map[string]int64)
	distribution["sms"] = result.SmsCount
	distribution["email"] = result.EmailCount
	distribution["whatsapp"] = result.WhatsappCount
	distribution["call"] = result.CallCount

	patientDBQueryTotal.WithLabelValues("get_communication_method_distribution", "success").Inc()
	return distribution, nil
}

func (r *patientRepository) GetEmploymentStatusDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get all patients and count by employment status
	allPatients, err := r.ListPatientProfiles(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	distribution := make(map[string]int64)
	for _, patient := range allPatients {
		if patient.EmploymentStatus != nil {
			distribution[*patient.EmploymentStatus]++
		} else {
			distribution["unknown"]++
		}
	}

	patientDBQueryTotal.WithLabelValues("get_employment_status_distribution", "success").Inc()
	return distribution, nil
}

func (r *patientRepository) GetEducationLevelDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get all patients and count by education level
	allPatients, err := r.ListPatientProfiles(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	distribution := make(map[string]int64)
	for _, patient := range allPatients {
		if patient.EducationLevel != nil {
			distribution[*patient.EducationLevel]++
		} else {
			distribution["unknown"]++
		}
	}

	patientDBQueryTotal.WithLabelValues("get_education_level_distribution", "success").Inc()
	return distribution, nil
}

func (r *patientRepository) GetIncomeRangeDistribution(ctx context.Context) (map[string]int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get all patients and count by income range
	allPatients, err := r.ListPatientProfiles(ctx, 10000, 0)
	if err != nil {
		return nil, err
	}

	distribution := make(map[string]int64)
	for _, patient := range allPatients {
		if patient.HouseholdIncomeRange != nil {
			distribution[*patient.HouseholdIncomeRange]++
		} else {
			distribution["unknown"]++
		}
	}

	patientDBQueryTotal.WithLabelValues("get_income_range_distribution", "success").Inc()
	return distribution, nil
}

// ===== Counting & Existence Checks =====

func (r *patientRepository) CountPatientProfiles(ctx context.Context) (int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	summary, err := r.querier.GetPatientDemographicsSummary(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("count_patient_profiles", "error").Inc()
		return 0, r.handleError(err, "count patient profiles")
	}

	patientDBQueryTotal.WithLabelValues("count_patient_profiles", "success").Inc()
	return summary.TotalPatients, nil
}

func (r *patientRepository) CountPatientsByProvince(ctx context.Context, province string) (int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get distribution and find specific province
	distribution, err := r.GetProvinceDistribution(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("count_patients_by_province", "error").Inc()
		return 0, err
	}

	count, exists := distribution[province]
	if !exists {
		count = 0
	}

	patientDBQueryTotal.WithLabelValues("count_patients_by_province", "success").Inc()
	return count, nil
}

func (r *patientRepository) CountPatientsByCity(ctx context.Context, city string) (int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get all patients and count by city
	allPatients, err := r.ListPatientProfiles(ctx, 10000, 0)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("count_patients_by_city", "error").Inc()
		return 0, err
	}

	var count int64
	for _, patient := range allPatients {
		if patient.City != nil && *patient.City == city {
			count++
		}
	}

	patientDBQueryTotal.WithLabelValues("count_patients_by_city", "success").Inc()
	return count, nil
}

func (r *patientRepository) CountPatientsWithMedicalAid(ctx context.Context) (int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	result, err := r.querier.CountPatientsByMedicalAidStatus(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("count_patients_with_medical_aid", "error").Inc()
		return 0, r.handleError(err, "count patients with medical aid")
	}

	patientDBQueryTotal.WithLabelValues("count_patients_with_medical_aid", "success").Inc()
	return result.WithMedicalAid, nil
}

func (r *patientRepository) CountPatientsRequiringInterpreter(ctx context.Context) (int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	summary, err := r.querier.GetPatientDemographicsSummary(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("count_patients_requiring_interpreter", "error").Inc()
		return 0, r.handleError(err, "count patients requiring interpreter")
	}

	patientDBQueryTotal.WithLabelValues("count_patients_requiring_interpreter", "success").Inc()
	return summary.RequiringInterpreter, nil
}

func (r *patientRepository) CountPatientsAcceptingMarketing(ctx context.Context) (int64, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	summary, err := r.querier.GetPatientDemographicsSummary(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("count_patients_accepting_marketing", "error").Inc()
		return 0, r.handleError(err, "count patients accepting marketing")
	}

	patientDBQueryTotal.WithLabelValues("count_patients_accepting_marketing", "success").Inc()
	return summary.MarketingOptIn, nil
}

func (r *patientRepository) ProfileExists(ctx context.Context, id uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Use ValidatePatientExists which expects user_id, so get profile first
	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("profile_exists", "not_found").Inc()
			return false, nil
		}
		patientDBQueryTotal.WithLabelValues("profile_exists", "error").Inc()
		return false, r.handleError(err, "check profile exists")
	}

	result, err := r.querier.ValidatePatientExists(ctx, profile.UserID)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("profile_exists", "error").Inc()
		return false, r.handleError(err, "validate patient exists")
	}

	patientDBQueryTotal.WithLabelValues("profile_exists", "success").Inc()
	return result, nil
}

func (r *patientRepository) ProfileExistsByUserID(ctx context.Context, userID uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	result, err := r.querier.ValidatePatientExists(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		patientDBQueryTotal.WithLabelValues("profile_exists_by_user_id", "error").Inc()
		return false, r.handleError(err, "validate patient exists by user ID")
	}

	patientDBQueryTotal.WithLabelValues("profile_exists_by_user_id", "success").Inc()
	return result, nil
}

func (r *patientRepository) NationalIDExists(ctx context.Context, nationalID string, excludeID *uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var excludeUUID pgtype.UUID
	if excludeID != nil {
		excludeUUID = uuidToPgtypeUUID(*excludeID)
	}

	result, err := r.querier.CheckNationalIDExists(ctx, sqlc.CheckNationalIDExistsParams{
		NationalIDNumber: pgtype.Text{String: nationalID, Valid: true},
		Column2:          excludeUUID,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("national_id_exists", "error").Inc()
		return false, r.handleError(err, "check national ID exists")
	}

	patientDBQueryTotal.WithLabelValues("national_id_exists", "success").Inc()
	return result, nil
}

// ===== Bulk Operations =====

func (r *patientRepository) GetPatientsByIDs(ctx context.Context, ids []uuid.UUID) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert UUIDs to pgtype.UUID
	pgUUIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgUUIDs[i] = uuidToPgtypeUUID(id)
	}

	rows, err := r.querier.GetPatientProfilesByIDs(ctx, pgUUIDs)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_ids", "error").Inc()
		return nil, r.handleError(err, "get patients by IDs")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		profiles = append(profiles, r.mapToPatientProfile(row))
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_ids", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetPatientsByUserIDs(ctx context.Context, userIDs []uuid.UUID) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert UUIDs to pgtype.UUID
	pgUUIDs := make([]pgtype.UUID, len(userIDs))
	for i, id := range userIDs {
		pgUUIDs[i] = uuidToPgtypeUUID(id)
	}

	rows, err := r.querier.GetPatientProfilesByUserIDs(ctx, pgUUIDs)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patients_by_user_ids", "error").Inc()
		return nil, r.handleError(err, "get patients by user IDs")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile for each result
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_patients_by_user_ids", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) BulkUpdateCommunicationMethod(ctx context.Context, ids []uuid.UUID, method string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert UUIDs to pgtype.UUID
	pgUUIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgUUIDs[i] = uuidToPgtypeUUID(id)
	}

	err := r.querier.BulkUpdateCommunicationMethod(ctx, sqlc.BulkUpdateCommunicationMethodParams{
		Column1:                      pgUUIDs,
		PreferredCommunicationMethod: pgtype.Text{String: method, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("bulk_update_communication_method", "error").Inc()
		return r.handleError(err, "bulk update communication method")
	}

	patientDBQueryTotal.WithLabelValues("bulk_update_communication_method", "success").Inc()
	return nil
}

func (r *patientRepository) BulkUpdateMarketingPreferences(ctx context.Context, ids []uuid.UUID, acceptsMarketing bool) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert UUIDs to pgtype.UUID
	pgUUIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgUUIDs[i] = uuidToPgtypeUUID(id)
	}

	err := r.querier.BulkUpdateMarketingConsent(ctx, sqlc.BulkUpdateMarketingConsentParams{
		Column1:                pgUUIDs,
		AcceptsMarketingEmails: pgtype.Bool{Bool: acceptsMarketing, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("bulk_update_marketing_preferences", "error").Inc()
		return r.handleError(err, "bulk update marketing preferences")
	}

	patientDBQueryTotal.WithLabelValues("bulk_update_marketing_preferences", "success").Inc()
	return nil
}

func (r *patientRepository) BulkUpdateTimezone(ctx context.Context, ids []uuid.UUID, timezone string) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Update each individually since there's no bulk timezone update query
	for _, id := range ids {
		if err := r.UpdateTimezone(ctx, id, timezone); err != nil {
			return err
		}
	}

	patientDBQueryTotal.WithLabelValues("bulk_update_timezone", "success").Inc()
	return nil
}

// ===== Compliance & Data Management =====

func (r *patientRepository) ExportPatientData(ctx context.Context, patientID uuid.UUID) ([]byte, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get the user_id for this profile
	profile, err := r.querier.GetPatientProfileByID(ctx, uuidToPgtypeUUID(patientID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			patientDBQueryTotal.WithLabelValues("export_patient_data", "not_found").Inc()
			return nil, domain.ErrNotFound
		}
		patientDBQueryTotal.WithLabelValues("export_patient_data", "error").Inc()
		return nil, r.handleError(err, "get profile for export")
	}

	result, err := r.querier.ExportPatientData(ctx, profile.UserID)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("export_patient_data", "error").Inc()
		return nil, r.handleError(err, "export patient data")
	}

	// Convert to JSON bytes
	jsonData, err := json.Marshal(result)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("export_patient_data", "error").Inc()
		return nil, fmt.Errorf("marshal patient data to JSON: %w", err)
	}

	patientDBQueryTotal.WithLabelValues("export_patient_data", "success").Inc()
	return jsonData, nil
}

func (r *patientRepository) AnonymizePatientProfile(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get the profile
	profile, err := r.GetPatientProfileByID(ctx, id)
	if err != nil {
		return err
	}

	// Anonymize sensitive fields
	profile.FirstName = "ANONYMIZED"
	profile.LastName = "ANONYMIZED"
	profile.PreferredName = nil
	profile.PrimaryAddress = nil
	profile.NationalIDNumber = nil
	profile.MedicalAidNumber = nil
	profile.ProfilePictureURL = nil

	// Update the profile
	err = r.UpdatePatientProfile(ctx, profile)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("anonymize_patient_profile", "error").Inc()
		return r.handleError(err, "anonymize patient profile")
	}

	patientDBQueryTotal.WithLabelValues("anonymize_patient_profile", "success").Inc()
	return nil
}

func (r *patientRepository) GetProfilesForDataRetentionReview(ctx context.Context, inactiveDays int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Calculate cutoff date
	cutoffDate := time.Now().AddDate(0, 0, -inactiveDays)

	// Get inactive patients
	rows, err := r.querier.GetInactivePatients(ctx, sqlc.GetInactivePatientsParams{
		Limit:  1000,
		Offset: 0,
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_profiles_for_data_retention_review", "error").Inc()
		return nil, r.handleError(err, "get profiles for data retention review")
	}

	// Filter by cutoff date
	var profiles []patients.PatientProfile
	for _, row := range rows {
		lastActivity := row.LastProfileUpdate.Time
		if row.LastProfileUpdate.Valid && lastActivity.Before(cutoffDate) {
			// Get full profile
			fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
			if err == nil {
				profiles = append(profiles, fullProfile)
			}
		}
	}

	patientDBQueryTotal.WithLabelValues("get_profiles_for_data_retention_review", "success").Inc()
	return profiles, nil
}

// ===== Time-based Queries =====

func (r *patientRepository) GetProfilesCreatedBetween(ctx context.Context, startDate, endDate time.Time, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPatientsForDataExport(ctx, sqlc.GetPatientsForDataExportParams{
		CreatedAt:   pgtype.Timestamp{Time: startDate, Valid: true},
		CreatedAt_2: pgtype.Timestamp{Time: endDate, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_profiles_created_between", "error").Inc()
		return nil, r.handleError(err, "get profiles created between")
	}

	// Apply limit and offset
	var profiles []patients.PatientProfile
	for i, row := range rows {
		if i >= offset && len(profiles) < limit {
			// Get full profile
			fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
			if err == nil {
				profiles = append(profiles, fullProfile)
			}
		}
	}

	patientDBQueryTotal.WithLabelValues("get_profiles_created_between", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetProfilesUpdatedBetween(ctx context.Context, startDate, endDate time.Time, limit, offset int) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetUpdatedPatientsInPeriod(ctx, sqlc.GetUpdatedPatientsInPeriodParams{
		UpdatedAt:   pgtype.Timestamp{Time: startDate, Valid: true},
		UpdatedAt_2: pgtype.Timestamp{Time: endDate, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_profiles_updated_between", "error").Inc()
		return nil, r.handleError(err, "get profiles updated between")
	}

	// Apply limit and offset
	var profiles []patients.PatientProfile
	for i, row := range rows {
		if i >= offset && len(profiles) < limit {
			// Get full profile
			fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
			if err == nil {
				profiles = append(profiles, fullProfile)
			}
		}
	}

	patientDBQueryTotal.WithLabelValues("get_profiles_updated_between", "success").Inc()
	return profiles, nil
}

func (r *patientRepository) GetNewPatientsInPeriod(ctx context.Context, startDate, endDate time.Time) ([]patients.PatientProfile, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetNewPatientsInPeriod(ctx, sqlc.GetNewPatientsInPeriodParams{
		CreatedAt:   pgtype.Timestamp{Time: startDate, Valid: true},
		CreatedAt_2: pgtype.Timestamp{Time: endDate, Valid: true},
	})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_new_patients_in_period", "error").Inc()
		return nil, r.handleError(err, "get new patients in period")
	}

	var profiles []patients.PatientProfile
	for _, row := range rows {
		// Get full profile
		fullProfile, err := r.GetPatientProfileByID(ctx, pgtypeUUIDToUUID(row.ID))
		if err == nil {
			profiles = append(profiles, fullProfile)
		}
	}

	patientDBQueryTotal.WithLabelValues("get_new_patients_in_period", "success").Inc()
	return profiles, nil
}

// ===== Reporting =====

func (r *patientRepository) GeneratePatientDemographicsReport(ctx context.Context, startDate, endDate *time.Time) (interface{}, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get summary
	summary, err := r.GetPatientDemographicsSummary(ctx)
	if err != nil {
		return nil, err
	}

	// Get distributions
	provinceDist, _ := r.GetProvinceDistribution(ctx)
	genderDist, _ := r.GetGenderDistribution(ctx)
	ageDist, _ := r.GetAgeDistribution(ctx)
	languageDist, _ := r.GetLanguageDistribution(ctx)

	// Build report
	report := map[string]interface{}{
		"summary": summary,
		"distributions": map[string]interface{}{
			"provinces": provinceDist,
			"gender":    genderDist,
			"age":       ageDist,
			"language":  languageDist,
		},
		"period": map[string]interface{}{
			"start_date": startDate,
			"end_date":   endDate,
		},
		"generated_at": time.Now(),
	}

	patientDBQueryTotal.WithLabelValues("generate_patient_demographics_report", "success").Inc()
	return report, nil
}

func (r *patientRepository) GenerateGeographicDistributionReport(ctx context.Context) (interface{}, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get province metrics
	provinceRows, err := r.querier.GetProvinceMetrics(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("generate_geographic_distribution_report", "error").Inc()
		return nil, r.handleError(err, "get province metrics")
	}

	// Get city distribution
	cityDist, _ := r.GetCityDistribution(ctx, nil)

	report := map[string]interface{}{
		"province_metrics":  provinceRows,
		"city_distribution": cityDist,
		"total_provinces":   len(provinceRows),
		"generated_at":      time.Now(),
	}

	patientDBQueryTotal.WithLabelValues("generate_geographic_distribution_report", "success").Inc()
	return report, nil
}

func (r *patientRepository) GenerateMedicalAidCoverageReport(ctx context.Context) (interface{}, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get medical aid status
	statusResult, err := r.querier.CountPatientsByMedicalAidStatus(ctx)
	if err != nil {
		patientDBQueryTotal.WithLabelValues("generate_medical_aid_coverage_report", "error").Inc()
		return nil, r.handleError(err, "count patients by medical aid status")
	}

	// Get provider distribution
	providerDist, _ := r.GetMedicalAidProviderDistribution(ctx)

	report := map[string]interface{}{
		"coverage_summary": map[string]int64{
			"with_medical_aid":    statusResult.WithMedicalAid,
			"without_medical_aid": statusResult.WithoutMedicalAid,
			"total":               statusResult.TotalPatients,
			"coverage_percentage": (statusResult.WithMedicalAid * 100) / statusResult.TotalPatients,
		},
		"provider_distribution": providerDist,
		"generated_at":          time.Now(),
	}

	patientDBQueryTotal.WithLabelValues("generate_medical_aid_coverage_report", "success").Inc()
	return report, nil
}

func (r *patientRepository) GetPatientGrowthMetrics(ctx context.Context, startDate, endDate time.Time) (interface{}, error) {
	start := time.Now()
	defer func() {
		patientDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Get registration trends
	trends, err := r.querier.GetPatientRegistrationTrends(ctx, pgtype.Timestamp{Time: startDate, Valid: true})
	if err != nil {
		patientDBQueryTotal.WithLabelValues("get_patient_growth_metrics", "error").Inc()
		return nil, r.handleError(err, "get patient registration trends")
	}

	// Calculate growth metrics
	var totalNew int64
	var maxDaily int64
	dailyGrowth := make(map[string]int64)

	for _, trend := range trends {
		if trend.RegistrationDate.Time.After(startDate) && trend.RegistrationDate.Time.Before(endDate) {
			dateStr := trend.RegistrationDate.Time.Format("2006-01-02")
			dailyGrowth[dateStr] = trend.NewPatients
			totalNew += trend.NewPatients
			if trend.NewPatients > maxDaily {
				maxDaily = trend.NewPatients
			}
		}
	}

	metrics := map[string]interface{}{
		"period": map[string]interface{}{
			"start_date": startDate,
			"end_date":   endDate,
		},
		"total_new_patients": totalNew,
		"max_daily_new":      maxDaily,
		"average_daily_new":  totalNew / int64(len(dailyGrowth)),
		"daily_growth":       dailyGrowth,
		"generated_at":       time.Now(),
	}

	patientDBQueryTotal.WithLabelValues("get_patient_growth_metrics", "success").Inc()
	return metrics, nil
}

// Helper function to convert *bool to pgtype.Bool
func pgtypeBoolFromBoolPtr(b *bool) pgtype.Bool {
	if b == nil {
		return pgtype.Bool{}
	}
	return pgtype.Bool{Bool: *b, Valid: true}
}

// Note: Some of the methods above reference fields like Email and Phone that aren't in the PatientProfile struct.
// These would need to be added or the methods adjusted based on the actual data model.
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
