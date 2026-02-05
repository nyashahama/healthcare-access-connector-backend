package providers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ============================================
// METRICS
// ============================================

var (
	clinicDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "clinic_db_query_duration_seconds",
			Help:    "Clinic database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	clinicDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "clinic_db_query_total",
			Help: "Total number of clinic database queries",
		},
		[]string{"operation", "status"},
	)
)

// ============================================
// REPOSITORY IMPLEMENTATION
// ============================================

type clinicRepository struct {
	querier sqlc.Querier
}

// NewClinicRepository creates a new clinic repository using a pool
func NewClinicRepository(pool *pgxpool.Pool) repository.ClinicRepository {
	return NewClinicRepositoryWithQuerier(sqlc.New(pool))
}

// NewClinicRepositoryWithQuerier creates a new clinic repository using a provided querier (for transactions)
func NewClinicRepositoryWithQuerier(querier sqlc.Querier) repository.ClinicRepository {
	return &clinicRepository{
		querier: querier,
	}
}

// ============================================
// BASIC CRUD OPERATIONS
// ============================================

func (r *clinicRepository) CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert JSONB fields to json.RawMessage
	operatingHoursJSON, err := jsonbFromMap(clinic.OperatingHours)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal operating_hours: %w", err)
	}

	servicesJSON, err := jsonbFromStringSlice(clinic.Services)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal services: %w", err)
	}

	specialtiesJSON, err := jsonbFromStringSlice(clinic.Specialties)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal specialties: %w", err)
	}

	// languagesSpokenJSON, err := jsonbFromStringSlice(clinic.LanguagesSpoken)
	// if err != nil {
	// 	return providers.Clinic{}, fmt.Errorf("marshal languages_spoken: %w", err)
	// }

	facilitiesJSON, err := jsonbFromStringSlice(clinic.Facilities)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal facilities: %w", err)
	}

	// Workaround for accepts_medical_aid (BOOLEAN mapped as json.RawMessage)
	/* acceptsMedicalAidJSON := boolToPgtypeJSON(clinic.AcceptsMedicalAid) */

	medicalAidProvidersJSON, err := jsonbFromStringSlice(clinic.MedicalAidProviders)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal medical_aid_providers: %w", err)
	}

	paymentMethodsJSON, err := jsonbFromStringSlice(clinic.PaymentMethods)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal payment_methods: %w", err)
	}

	// Convert fee_structure string to JSON
	// var feeStructureJSON json.RawMessage
	// if clinic.FeeStructure != nil && *clinic.FeeStructure != "" {
	// 	feeStructureJSON = json.RawMessage(fmt.Sprintf(`"%s"`, *clinic.FeeStructure))
	// }

	certificationsJSON, err := jsonbFromMap(clinic.Certifications)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal certifications: %w", err)
	}

	// Map to sqlc params with the auto-generated ColumnXX names
	params := sqlc.CreateClinicParams{
		ClinicName:          clinic.ClinicName,
		ClinicType:          clinic.ClinicType,
		RegistrationNumber:  pgtypeTextFromStringPtr(clinic.RegistrationNumber),
		AccreditationNumber: pgtypeTextFromStringPtr(clinic.AccreditationNumber),
		PrimaryPhone:        pgtypeTextFromStringPtr(clinic.PrimaryPhone),
		SecondaryPhone:      pgtypeTextFromStringPtr(clinic.SecondaryPhone),
		EmergencyPhone:      pgtypeTextFromStringPtr(clinic.EmergencyPhone),
		Email:               pgtypeTextFromStringPtr(clinic.Email),
		Website:             pgtypeTextFromStringPtr(clinic.Website),
		PhysicalAddress:     clinic.PhysicalAddress,
		City:                pgtypeTextFromStringPtr(clinic.City),
		Province:            pgtypeTextFromStringPtr(clinic.Province),
		PostalCode:          pgtypeTextFromStringPtr(clinic.PostalCode),
		Country:             pgtypeTextFromString(clinic.Country),
		Latitude:            float64PtrToPgtypeNumeric(clinic.Latitude),
		Longitude:           float64PtrToPgtypeNumeric(clinic.Longitude),
		GooglePlaceID:       pgtypeTextFromStringPtr(clinic.GooglePlaceID),
		Description:         pgtypeTextFromStringPtr(clinic.Description),
		YearEstablished:     intPtrToPgtypeInt4(clinic.YearEstablished),
		OwnershipType:       pgtypeTextFromStringPtr(clinic.OwnershipType),
		BedCount:            intPtrToPgtypeInt4(clinic.BedCount),

		// JSONB fields - mapped to ColumnXX by sqlc
		Column22:          operatingHoursJSON,                           // operating_hours
		Column23:          servicesJSON,                                 // services
		Column24:          specialtiesJSON,                              // specialties
		LanguagesSpoken:   clinic.LanguagesSpoken,                       // languages_spoken
		Column26:          facilitiesJSON,                               // facilities
		AcceptsMedicalAid: pgtype.Bool{Bool: clinic.AcceptsMedicalAid},  // accepts_medical_aid (workaround)
		Column28:          medicalAidProvidersJSON,                      // medical_aid_providers
		Column29:          paymentMethodsJSON,                           // payment_methods
		FeeStructure:      pgtypeTextFromStringPtr(clinic.FeeStructure), // fee_structure

		AccreditationBody: pgtypeTextFromStringPtr(clinic.AccreditationBody),

		AccreditationExpiry: pgtype.Date{Time: *clinic.AccreditationExpiry}, // accreditation_expiry (workaround)
		Column33:            certificationsJSON,                             // certifications

		PatientCapacity:        intPtrToPgtypeInt4(clinic.PatientCapacity),
		AverageWaitTimeMinutes: intPtrToPgtypeInt4(clinic.AverageWaitTimeMinutes),
		ContactPersonName:      pgtypeTextFromStringPtr(clinic.ContactPersonName),
		ContactPersonRole:      pgtypeTextFromStringPtr(clinic.ContactPersonRole),
		ContactPersonPhone:     pgtypeTextFromStringPtr(clinic.ContactPersonPhone),
		ContactPersonEmail:     pgtypeTextFromStringPtr(clinic.ContactPersonEmail),
	}

	created, err := r.querier.CreateClinic(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("create_clinic", "error").Inc()
		return providers.Clinic{}, r.handleError(err, "create clinic")
	}

	clinicDBQueryTotal.WithLabelValues("create_clinic", "success").Inc()
	return r.mapToClinic(created), nil
}

func (r *clinicRepository) GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	c, err := r.querier.GetClinicByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			clinicDBQueryTotal.WithLabelValues("get_clinic_by_id", "not_found").Inc()
			return providers.Clinic{}, domain.ErrClinicNotFound
		}
		clinicDBQueryTotal.WithLabelValues("get_clinic_by_id", "error").Inc()
		return providers.Clinic{}, err
	}

	clinicDBQueryTotal.WithLabelValues("get_clinic_by_id", "success").Inc()
	return r.mapToClinicFromGetByID(c), nil
}

func (r *clinicRepository) UpdateClinic(ctx context.Context, clinic providers.Clinic) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	operatingHoursJSON, err := jsonbFromMap(clinic.OperatingHours)
	if err != nil {
		return fmt.Errorf("marshal operating hours: %w", err)
	}

	params := sqlc.UpdateClinicParams{
		ID:             uuidToPgtypeUUID(clinic.ID),
		ClinicName:     clinic.ClinicName,
		ClinicType:     clinic.ClinicType,
		PrimaryPhone:   pgtypeTextFromStringPtr(clinic.PrimaryPhone),
		SecondaryPhone: pgtypeTextFromStringPtr(clinic.SecondaryPhone),
		EmergencyPhone: pgtypeTextFromStringPtr(clinic.EmergencyPhone),
		Email:          pgtypeTextFromStringPtr(clinic.Email),
		Website:        pgtypeTextFromStringPtr(clinic.Website),
		Description:    pgtypeTextFromStringPtr(clinic.Description),
		OperatingHours: operatingHoursJSON,
	}

	err = r.querier.UpdateClinic(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic", "error").Inc()
		return r.handleError(err, "update clinic")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic", "success").Inc()
	return nil
}

func (r *clinicRepository) DeleteClinic(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteClinic(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("delete_clinic", "error").Inc()
		return r.handleError(err, "delete clinic")
	}

	clinicDBQueryTotal.WithLabelValues("delete_clinic", "success").Inc()
	return nil
}

// ============================================
// VERIFICATION & STATUS
// ============================================

func (r *clinicRepository) VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.VerifyClinicParams{
		ID:                uuidToPgtypeUUID(id),
		VerifiedBy:        uuidToPgtypeUUID(verifiedBy),
		VerificationNotes: pgtypeTextFromStringPtr(&notes),
	}

	err := r.querier.VerifyClinic(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("verify_clinic", "error").Inc()
		return r.handleError(err, "verify clinic")
	}

	clinicDBQueryTotal.WithLabelValues("verify_clinic", "success").Inc()
	return nil
}

func (r *clinicRepository) RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.RejectClinicVerificationParams{
		ID:                uuidToPgtypeUUID(id),
		VerifiedBy:        uuidToPgtypeUUID(verifiedBy),
		VerificationNotes: pgtypeTextFromStringPtr(&notes),
	}

	err := r.querier.RejectClinicVerification(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("reject_clinic_verification", "error").Inc()
		return r.handleError(err, "reject clinic verification")
	}

	clinicDBQueryTotal.WithLabelValues("reject_clinic_verification", "success").Inc()
	return nil
}

func (r *clinicRepository) UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateClinicVerificationStatusParams{
		ID:                 uuidToPgtypeUUID(id),
		VerificationStatus: pgtypeTextFromString(status),
	}

	err := r.querier.UpdateClinicVerificationStatus(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_verification_status", "error").Inc()
		return r.handleError(err, "update clinic verification status")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_verification_status", "success").Inc()
	return nil
}

func (r *clinicRepository) DeactivateClinic(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeactivateClinic(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("deactivate_clinic", "error").Inc()
		return r.handleError(err, "deactivate clinic")
	}

	clinicDBQueryTotal.WithLabelValues("deactivate_clinic", "success").Inc()
	return nil
}

func (r *clinicRepository) ReactivateClinic(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.ReactivateClinic(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("reactivate_clinic", "error").Inc()
		return r.handleError(err, "reactivate clinic")
	}

	clinicDBQueryTotal.WithLabelValues("reactivate_clinic", "success").Inc()
	return nil
}

// ============================================
// SEARCH & DISCOVERY
// ============================================

func (r *clinicRepository) SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	sqlParams := sqlc.SearchClinicsParams{
		Column1: pgtypeTextFromString(params.Query),
		Column2: stringPtrToString(params.Province),
		Column3: stringPtrToString(params.City),
		Column4: stringPtrToString(params.ClinicType),
		Limit:   int32(params.Limit),
		Offset:  int32(params.Offset),
	}

	rows, err := r.querier.SearchClinics(ctx, sqlParams)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("search_clinics", "error").Inc()
		return nil, r.handleError(err, "search clinics")
	}

	results := make([]providers.ClinicSearchResult, len(rows))
	for i, row := range rows {
		results[i] = providers.ClinicSearchResult{
			Clinic: r.mapToClinicFromSearch(row),
		}
	}

	clinicDBQueryTotal.WithLabelValues("search_clinics", "success").Inc()
	return results, nil
}

// ============================================
// FILTERING & LISTING
// ============================================

func (r *clinicRepository) GetClinics(ctx context.Context) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetAllClinics(ctx)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("list_clinics", "error").Inc()
		return nil, r.handleError(err, "list clinics")
	}

	clinics := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		clinics[i] = r.mapToClinic(row)
	}

	clinicDBQueryTotal.WithLabelValues("list_clinics", "success").Inc()
	return clinics, nil
}

// ============================================
// ERROR HANDLING
// ============================================

func (r *clinicRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			if strings.Contains(pgErr.ConstraintName, "registration_number") {
				return domain.ErrDuplicateRegistrationNumber
			}
			if strings.Contains(pgErr.ConstraintName, "email") {
				return domain.ErrDuplicateEmail
			}
			if strings.Contains(pgErr.ConstraintName, "primary_phone") {
				return domain.ErrDuplicatePhone
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

// ============================================
// MAPPING FUNCTIONS
// ============================================

func (r *clinicRepository) mapToClinic(row sqlc.Clinic) providers.Clinic {
	return providers.Clinic{
		ID:         pgtypeUUIDToUUID(row.ID),
		ClinicName: row.ClinicName,
		ClinicType: row.ClinicType,

		RegistrationNumber:  pgtypeTextToStringPtr(row.RegistrationNumber),
		AccreditationNumber: pgtypeTextToStringPtr(row.AccreditationNumber),
		PrimaryPhone:        pgtypeTextToStringPtr(row.PrimaryPhone),
		SecondaryPhone:      pgtypeTextToStringPtr(row.SecondaryPhone),
		EmergencyPhone:      pgtypeTextToStringPtr(row.EmergencyPhone),
		Email:               pgtypeTextToStringPtr(row.Email),
		Website:             pgtypeTextToStringPtr(row.Website),

		PhysicalAddress: row.PhysicalAddress,
		City:            pgtypeTextToStringPtr(row.City),
		Province:        pgtypeTextToStringPtr(row.Province),
		PostalCode:      pgtypeTextToStringPtr(row.PostalCode),
		Country:         pgtypeTextToString(row.Country),

		Latitude:      pgtypeNumericToFloat64Ptr(row.Latitude),
		Longitude:     pgtypeNumericToFloat64Ptr(row.Longitude),
		GooglePlaceID: pgtypeTextToStringPtr(row.GooglePlaceID),
		Description:   pgtypeTextToStringPtr(row.Description),

		YearEstablished: pgtypeInt4ToIntPtr(row.YearEstablished),
		OwnershipType:   pgtypeTextToStringPtr(row.OwnershipType),
		BedCount:        pgtypeInt4ToIntPtr(row.BedCount),

		OperatingHours: mapFromJSONB(row.OperatingHours),
		Services:       stringSliceFromJSONB(row.Services),
		Specialties:    stringSliceFromJSONB(row.Specialties),

		LanguagesSpoken: row.LanguagesSpoken,

		Facilities:          stringSliceFromJSONB(row.Facilities),
		AcceptsMedicalAid:   pgtypeBoolToBool(row.AcceptsMedicalAid),
		MedicalAidProviders: stringSliceFromJSONB(row.MedicalAidProviders),
		PaymentMethods:      stringSliceFromJSONB(row.PaymentMethods),

		FeeStructure: pgtypeTextToStringPtr(row.FeeStructure),

		AccreditationBody:   pgtypeTextToStringPtr(row.AccreditationBody),
		AccreditationExpiry: pgtypeDateToTimePtr(row.AccreditationExpiry),
		Certifications:      mapFromJSONB(row.Certifications),

		IsVerified:         pgtypeBoolToBool(row.IsVerified),
		VerificationStatus: pgtypeTextToString(row.VerificationStatus),
		VerificationNotes:  pgtypeTextToStringPtr(row.VerificationNotes),
		VerifiedBy:         uuidPtrToUUID(row.VerifiedBy),
		VerificationDate:   pgtypeTimestampToTimePtr(row.VerificationDate),

		PatientCapacity:        pgtypeInt4ToIntPtr(row.PatientCapacity),
		AverageWaitTimeMinutes: pgtypeInt4ToIntPtr(row.AverageWaitTimeMinutes),
		Rating:                 pgtypeNumericToFloat64Ptr(row.Rating),
		ReviewCount:            pgtypeInt4ToInt(row.ReviewCount),

		ContactPersonName:  pgtypeTextToStringPtr(row.ContactPersonName),
		ContactPersonRole:  pgtypeTextToStringPtr(row.ContactPersonRole),
		ContactPersonPhone: pgtypeTextToStringPtr(row.ContactPersonPhone),
		ContactPersonEmail: pgtypeTextToStringPtr(row.ContactPersonEmail),

		CreatedAt: row.CreatedAt.Time,
		UpdatedAt: row.UpdatedAt.Time,
	}
}

func (r *clinicRepository) mapToClinicFromGetByID(row sqlc.Clinic) providers.Clinic {
	return r.mapToClinic(row)
}

func (r *clinicRepository) mapToClinicFromList(row sqlc.ListClinicsRow) providers.Clinic {
	return providers.Clinic{
		ID:                 pgtypeUUIDToUUID(row.ID),
		ClinicName:         row.ClinicName,
		ClinicType:         row.ClinicType,
		City:               pgtypeTextToStringPtr(row.City),
		Province:           pgtypeTextToStringPtr(row.Province),
		PhysicalAddress:    row.PhysicalAddress,
		PrimaryPhone:       pgtypeTextToStringPtr(row.PrimaryPhone),
		Email:              pgtypeTextToStringPtr(row.Email),
		IsVerified:         pgtypeBoolToBool(row.IsVerified),
		VerificationStatus: pgtypeTextToString(row.VerificationStatus),
		Rating:             pgtypeNumericToFloat64Ptr(row.Rating),
		ReviewCount:        pgtypeInt4ToInt(row.ReviewCount),
		CreatedAt:          row.CreatedAt.Time,
	}
}

func (r *clinicRepository) mapToClinicFromSearch(row sqlc.SearchClinicsRow) providers.Clinic {
	return providers.Clinic{
		ID:                 pgtypeUUIDToUUID(row.ID),
		ClinicName:         row.ClinicName,
		ClinicType:         row.ClinicType,
		City:               pgtypeTextToStringPtr(row.City),
		Province:           pgtypeTextToStringPtr(row.Province),
		PhysicalAddress:    row.PhysicalAddress,
		PrimaryPhone:       pgtypeTextToStringPtr(row.PrimaryPhone),
		Email:              pgtypeTextToStringPtr(row.Email),
		Rating:             pgtypeNumericToFloat64Ptr(row.Rating),
		ReviewCount:        pgtypeInt4ToInt(row.ReviewCount),
		VerificationStatus: pgtypeTextToString(row.VerificationStatus),
		AcceptsMedicalAid:  pgtypeBoolToBool(row.AcceptsMedicalAid),
		CreatedAt:          row.CreatedAt.Time,
	}
}
