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
	pool    *pgxpool.Pool
}

// NewClinicRepository creates a new clinic repository using a pool
func NewClinicRepository(pool *pgxpool.Pool) repository.ClinicRepository {
	return &clinicRepository{
		querier: sqlc.New(pool),
		pool:    pool,
	}
}

// NewClinicRepositoryWithQuerier creates a new clinic repository using a provided querier (for transactions)
func NewClinicRepositoryWithQuerier(querier sqlc.Querier) repository.ClinicRepository {
	return &clinicRepository{
		querier: querier,
	}
}

// ============================================
// CORE CRUD OPERATIONS
// ============================================

func (r *clinicRepository) CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	operatingHoursJSON, err := jsonbFromMap(clinic.OperatingHours)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal operating hours: %w", err)
	}

	servicesJSON, err := jsonbFromStringSlice(clinic.Services)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal services: %w", err)
	}

	specialtiesJSON, err := jsonbFromStringSlice(clinic.Specialties)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal specialties: %w", err)
	}

	facilitiesJSON, err := jsonbFromStringSlice(clinic.Facilities)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal facilities: %w", err)
	}

	medicalAidProvidersJSON, err := jsonbFromStringSlice(clinic.MedicalAidProviders)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal medical aid providers: %w", err)
	}

	paymentMethodsJSON, err := jsonbFromStringSlice(clinic.PaymentMethods)
	if err != nil {
		return providers.Clinic{}, fmt.Errorf("marshal payment methods: %w", err)
	}

	certificationsJSON, _ := jsonbFromMap(nil)

	params := sqlc.CreateClinicParams{
		ClinicName:             clinic.ClinicName,
		ClinicType:             clinic.ClinicType,
		RegistrationNumber:     pgtypeTextFromStringPtr(clinic.RegistrationNumber),
		AccreditationNumber:    pgtypeTextFromStringPtr(clinic.AccreditationNumber),
		PrimaryPhone:           pgtypeTextFromStringPtr(clinic.PrimaryPhone),
		SecondaryPhone:         pgtypeTextFromStringPtr(clinic.SecondaryPhone),
		EmergencyPhone:         pgtypeTextFromStringPtr(clinic.EmergencyPhone),
		Email:                  pgtypeTextFromStringPtr(clinic.Email),
		Website:                pgtypeTextFromStringPtr(clinic.Website),
		PhysicalAddress:        clinic.PhysicalAddress,
		City:                   pgtypeTextFromStringPtr(clinic.City),
		Province:               pgtypeTextFromStringPtr(clinic.Province),
		PostalCode:             pgtypeTextFromStringPtr(clinic.PostalCode),
		Country:                pgtypeTextFromString(clinic.Country),
		Latitude:               float64PtrToPgtypeNumeric(clinic.Latitude),
		Longitude:              float64PtrToPgtypeNumeric(clinic.Longitude),
		GooglePlaceID:          pgtypeTextFromStringPtr(clinic.GooglePlaceID),
		Description:            pgtypeTextFromStringPtr(clinic.Description),
		YearEstablished:        intPtrToPgtypeInt4(clinic.YearEstablished),
		OwnershipType:          pgtypeTextFromStringPtr(clinic.OwnershipType),
		BedCount:               intPtrToPgtypeInt4(clinic.BedCount),
		OperatingHours:         operatingHoursJSON,
		Services:               servicesJSON,
		Specialties:            specialtiesJSON,
		LanguagesSpoken:        stringSliceToArray(clinic.LanguagesSpoken),
		Facilities:             facilitiesJSON,
		AcceptsMedicalAid:      pgtype.Bool{Bool: clinic.AcceptsMedicalAid, Valid: true},
		MedicalAidProviders:    medicalAidProvidersJSON,
		PaymentMethods:         paymentMethodsJSON,
		FeeStructure:           pgtypeTextFromStringPtr(clinic.FeeStructure),
		AccreditationBody:      pgtypeTextFromStringPtr(clinic.AccreditationBody),
		AccreditationExpiry:    datePtrToPgtypeDate(clinic.AccreditationExpiry),
		Certifications:         certificationsJSON,
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

	// servicesJSON, err := jsonbFromStringSlice(clinic.Services)
	// if err != nil {
	// 	return fmt.Errorf("marshal services: %w", err)
	// }
	//
	// specialtiesJSON, err := jsonbFromStringSlice(clinic.Specialties)
	// if err != nil {
	// 	return fmt.Errorf("marshal specialties: %w", err)
	// }
	//
	// facilitiesJSON, err := jsonbFromStringSlice(clinic.Facilities)
	// if err != nil {
	// 	return fmt.Errorf("marshal facilities: %w", err)
	// }
	//
	// medicalAidProvidersJSON, err := jsonbFromStringSlice(clinic.MedicalAidProviders)
	// if err != nil {
	// 	return fmt.Errorf("marshal medical aid providers: %w", err)
	// }
	//
	// paymentMethodsJSON, err := jsonbFromStringSlice(clinic.PaymentMethods)
	// if err != nil {
	// 	return fmt.Errorf("marshal payment methods: %w", err)
	// }

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

func (r *clinicRepository) GetClinicsByIDs(ctx context.Context, ids []uuid.UUID) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	clinics, err := r.querier.GetClinicsByIDs(ctx, pgtypeIDs)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_ids", "error").Inc()
		return nil, fmt.Errorf("get clinics by ids: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_ids", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = r.mapToClinicFromGetByID(c)
	}

	return result, nil
}

// ============================================
// LOCATION MANAGEMENT
// ============================================

func (r *clinicRepository) UpdateClinicLocation(ctx context.Context, id uuid.UUID, location providers.ClinicLocation) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateClinicLocationParams{
		ID:              uuidToPgtypeUUID(id),
		PhysicalAddress: location.PhysicalAddress,
		City:            pgtypeTextFromStringPtr(location.City),
		Province:        pgtypeTextFromStringPtr(location.Province),
		PostalCode:      pgtypeTextFromStringPtr(location.PostalCode),
		Country:         pgtypeTextFromStringPtr(location.Country),
		Latitude:        float64PtrToPgtypeNumeric(location.Latitude),
		Longitude:       float64PtrToPgtypeNumeric(location.Longitude),
		GooglePlaceID:   pgtypeTextFromStringPtr(location.GooglePlaceID),
	}

	err := r.querier.UpdateClinicLocation(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_location", "error").Inc()
		return r.handleError(err, "update clinic location")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_location", "success").Inc()
	return nil
}

func (r *clinicRepository) UpdateClinicCoordinates(ctx context.Context, id uuid.UUID, latitude, longitude float64) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateClinicCoordinatesParams{
		ID:        uuidToPgtypeUUID(id),
		Latitude:  float64PtrToPgtypeNumeric(&latitude),
		Longitude: float64PtrToPgtypeNumeric(&longitude),
	}

	err := r.querier.UpdateClinicCoordinates(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_coordinates", "error").Inc()
		return r.handleError(err, "update clinic coordinates")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_coordinates", "success").Inc()
	return nil
}

// ============================================
// CONTACT INFORMATION
// ============================================

func (r *clinicRepository) UpdateClinicContact(ctx context.Context, id uuid.UUID, contact providers.ClinicContact) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateClinicContactParams{
		ID:                 uuidToPgtypeUUID(id),
		PrimaryPhone:       pgtypeTextFromStringPtr(contact.PrimaryPhone),
		SecondaryPhone:     pgtypeTextFromStringPtr(contact.SecondaryPhone),
		EmergencyPhone:     pgtypeTextFromStringPtr(contact.EmergencyPhone),
		Email:              pgtypeTextFromStringPtr(contact.Email),
		Website:            pgtypeTextFromStringPtr(contact.Website),
		ContactPersonName:  pgtypeTextFromStringPtr(contact.ContactPersonName),
		ContactPersonRole:  pgtypeTextFromStringPtr(contact.ContactPersonRole),
		ContactPersonPhone: pgtypeTextFromStringPtr(contact.ContactPersonPhone),
		ContactPersonEmail: pgtypeTextFromStringPtr(contact.ContactPersonEmail),
	}

	err := r.querier.UpdateClinicContact(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_contact", "error").Inc()
		return r.handleError(err, "update clinic contact")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_contact", "success").Inc()
	return nil
}

// ============================================
// SERVICES & CAPABILITIES
// ============================================

func (r *clinicRepository) UpdateClinicServices(ctx context.Context, id uuid.UUID, services providers.ClinicServicesUpdate) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	servicesJSON, err := jsonbFromStringSlice(services.Services)
	if err != nil {
		return fmt.Errorf("marshal services: %w", err)
	}

	specialtiesJSON, err := jsonbFromStringSlice(services.Specialties)
	if err != nil {
		return fmt.Errorf("marshal specialties: %w", err)
	}

	facilitiesJSON, err := jsonbFromStringSlice(services.Facilities)
	if err != nil {
		return fmt.Errorf("marshal facilities: %w", err)
	}

	params := sqlc.UpdateClinicServicesParams{
		ID:              uuidToPgtypeUUID(id),
		Services:        servicesJSON,
		Specialties:     specialtiesJSON,
		Facilities:      facilitiesJSON,
		LanguagesSpoken: stringSliceToArray(services.LanguagesSpoken),
	}

	err = r.querier.UpdateClinicServices(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_services", "error").Inc()
		return r.handleError(err, "update clinic services")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_services", "success").Inc()
	return nil
}

func (r *clinicRepository) UpdateClinicOperatingHours(ctx context.Context, id uuid.UUID, hours map[string]any) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	hoursJSON, err := jsonbFromMap(hours)
	if err != nil {
		return fmt.Errorf("marshal operating hours: %w", err)
	}

	params := sqlc.UpdateClinicOperatingHoursParams{
		ID:             uuidToPgtypeUUID(id),
		OperatingHours: hoursJSON,
	}

	err = r.querier.UpdateClinicOperatingHours(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_operating_hours", "error").Inc()
		return r.handleError(err, "update clinic operating hours")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_operating_hours", "success").Inc()
	return nil
}

// ============================================
// PAYMENT & INSURANCE
// ============================================

func (r *clinicRepository) UpdateClinicPaymentInfo(ctx context.Context, id uuid.UUID, payment providers.ClinicPaymentInfo) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	medicalAidProvidersJSON, err := jsonbFromStringSlice(payment.MedicalAidProviders)
	if err != nil {
		return fmt.Errorf("marshal medical aid providers: %w", err)
	}

	paymentMethodsJSON, err := jsonbFromStringSlice(payment.PaymentMethods)
	if err != nil {
		return fmt.Errorf("marshal payment methods: %w", err)
	}

	params := sqlc.UpdateClinicPaymentInfoParams{
		ID:                  uuidToPgtypeUUID(id),
		AcceptsMedicalAid:   pgtype.Bool{Bool: payment.AcceptsMedicalAid, Valid: true},
		MedicalAidProviders: medicalAidProvidersJSON,
		PaymentMethods:      paymentMethodsJSON,
		FeeStructure:        pgtypeTextFromStringPtr(payment.FeeStructure),
	}

	err = r.querier.UpdateClinicPaymentInfo(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_payment_info", "error").Inc()
		return r.handleError(err, "update clinic payment info")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_payment_info", "success").Inc()
	return nil
}

// ============================================
// ACCREDITATION & CERTIFICATION
// ============================================

func (r *clinicRepository) UpdateClinicAccreditation(ctx context.Context, id uuid.UUID, accreditation providers.ClinicAccreditation) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	certificationsJSON, err := jsonbFromMap(accreditation.Certifications)
	if err != nil {
		return fmt.Errorf("marshal certifications: %w", err)
	}

	params := sqlc.UpdateClinicAccreditationParams{
		ID:                  uuidToPgtypeUUID(id),
		AccreditationNumber: pgtypeTextFromStringPtr(accreditation.AccreditationNumber),
		AccreditationBody:   pgtypeTextFromStringPtr(accreditation.AccreditationBody),
		AccreditationExpiry: datePtrToPgtypeDate(accreditation.AccreditationExpiry),
		Certifications:      certificationsJSON,
	}

	err = r.querier.UpdateClinicAccreditation(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_accreditation", "error").Inc()
		return r.handleError(err, "update clinic accreditation")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_accreditation", "success").Inc()
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
		VerificationNotes: pgtypeTextFromString(notes),
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
		VerificationNotes: pgtypeTextFromString(notes),
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
// RATINGS & REVIEWS
// ============================================

func (r *clinicRepository) UpdateClinicRating(ctx context.Context, id uuid.UUID, rating float64, reviewCount int) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateClinicRatingParams{
		ID:          uuidToPgtypeUUID(id),
		Rating:      float64PtrToPgtypeNumeric(&rating),
		ReviewCount: intPtrToPgtypeInt4(&reviewCount),
	}

	err := r.querier.UpdateClinicRating(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_rating", "error").Inc()
		return r.handleError(err, "update clinic rating")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_rating", "success").Inc()
	return nil
}

func (r *clinicRepository) IncrementReviewCount(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.IncrementReviewCount(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("increment_review_count", "error").Inc()
		return r.handleError(err, "increment review count")
	}

	clinicDBQueryTotal.WithLabelValues("increment_review_count", "success").Inc()
	return nil
}

// ============================================
// OPERATIONAL METRICS
// ============================================

func (r *clinicRepository) UpdateClinicCapacity(ctx context.Context, id uuid.UUID, patientCapacity, bedCount int) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateClinicCapacityParams{
		ID:              uuidToPgtypeUUID(id),
		PatientCapacity: intPtrToPgtypeInt4(&patientCapacity),
		BedCount:        intPtrToPgtypeInt4(&bedCount),
	}

	err := r.querier.UpdateClinicCapacity(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_capacity", "error").Inc()
		return r.handleError(err, "update clinic capacity")
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_capacity", "success").Inc()
	return nil
}

func (r *clinicRepository) UpdateAverageWaitTime(ctx context.Context, id uuid.UUID, minutes int) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateAverageWaitTimeParams{
		ID:                     uuidToPgtypeUUID(id),
		AverageWaitTimeMinutes: intPtrToPgtypeInt4(&minutes),
	}

	err := r.querier.UpdateAverageWaitTime(ctx, params)
	clinicDBQueryTotal.WithLabelValues("update_average_wait_time", "error").Inc()
	if err != nil {
		return r.handleError(err, "update average wait time")
	}

	clinicDBQueryTotal.WithLabelValues("update_average_wait_time", "success").Inc()
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
		return nil, fmt.Errorf("search clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("search_clinics", "success").Inc()

	results := make([]providers.ClinicSearchResult, len(rows))
	for i, row := range rows {
		results[i] = providers.ClinicSearchResult{
			Clinic: r.mapToClinicFromSearch(row),
		}
	}

	return results, nil
}

func (r *clinicRepository) SearchClinicsByName(ctx context.Context, name string, province *string, limit, offset int) ([]providers.ClinicSearchResult, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.SearchClinicsByNameParams{
		Column1: pgtypeTextFromString(name),
		Column2: stringPtrToString(province),
		Limit:   int32(limit),
		Offset:  int32(offset),
	}

	rows, err := r.querier.SearchClinicsByName(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("search_clinics_by_name", "error").Inc()
		return nil, fmt.Errorf("search clinics by name: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("search_clinics_by_name", "success").Inc()

	results := make([]providers.ClinicSearchResult, len(rows))
	for i, row := range rows {
		results[i] = providers.ClinicSearchResult{
			Clinic: r.mapToClinicFromSearch(row),
		}
	}

	return results, nil
}

func (r *clinicRepository) SearchClinicsByLocation(ctx context.Context, lat, lng, radiusKm float64, limit int) ([]providers.ClinicSearchResult, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.SearchClinicsByLocationParams{
		Latitude:  float64PtrToPgtypeNumeric(&lat),
		Longitude: float64PtrToPgtypeNumeric(&lng),
		RadiusKm:  float64PtrToPgtypeNumeric(&radiusKm),
		Limit:     int32(limit),
	}

	rows, err := r.querier.SearchClinicsByLocation(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("search_clinics_by_location", "error").Inc()
		return nil, fmt.Errorf("search clinics by location: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("search_clinics_by_location", "success").Inc()

	results := make([]providers.ClinicSearchResult, len(rows))
	for i, row := range rows {
		distanceKm := pgtypeNumericToFloat64Ptr(row.DistanceKm)
		results[i] = providers.ClinicSearchResult{
			Clinic:     r.mapToClinicFromSearch(row.Clinic),
			DistanceKm: distanceKm,
		}
	}

	return results, nil
}

func (r *clinicRepository) GetNearbyClinicsByService(ctx context.Context, lat, lng, radiusKm float64, service string, limit int) ([]providers.ClinicSearchResult, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetNearbyClinicsByServiceParams{
		Latitude:  float64PtrToPgtypeNumeric(&lat),
		Longitude: float64PtrToPgtypeNumeric(&lng),
		RadiusKm:  float64PtrToPgtypeNumeric(&radiusKm),
		Service:   pgtypeTextFromString(service),
		Limit:     int32(limit),
	}

	rows, err := r.querier.GetNearbyClinicsByService(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_nearby_clinics_by_service", "error").Inc()
		return nil, fmt.Errorf("get nearby clinics by service: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_nearby_clinics_by_service", "success").Inc()

	results := make([]providers.ClinicSearchResult, len(rows))
	for i, row := range rows {
		distanceKm := pgtypeNumericToFloat64Ptr(row.DistanceKm)
		results[i] = providers.ClinicSearchResult{
			Clinic:     r.mapToClinicFromSearch(row.Clinic),
			DistanceKm: distanceKm,
		}
	}

	return results, nil
}

// ============================================
// FILTERING & LISTING
// ============================================

func (r *clinicRepository) GetClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.ListClinicsParams{
		Column1: stringPtrToString(filters.ClinicType),
		Column2: stringPtrToString(filters.Province),
		Column3: stringPtrToString(filters.City),
		Column4: stringPtrToString(filters.VerificationStatus),
		Limit:   int32(limit),
		Offset:  int32(offset),
	}

	rows, err := r.querier.ListClinics(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics", "error").Inc()
		return nil, fmt.Errorf("get clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetVerifiedClinics(ctx context.Context, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetVerifiedClinicsParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	}

	rows, err := r.querier.GetVerifiedClinics(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_verified_clinics", "error").Inc()
		return nil, fmt.Errorf("get verified clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_verified_clinics", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetPendingClinics(ctx context.Context, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// params := sqlc.GetPendingClinicsParams{
	// 	Limit:  int32(limit),
	// 	Offset: int32(offset),
	// }
	//
	// rows, err := r.querier.GetPendingClinics(ctx, params)
	// if err != nil {
	// 	clinicDBQueryTotal.WithLabelValues("get_pending_clinics", "error").Inc()
	// 	return nil, fmt.Errorf("get pending clinics: %w", err)
	// }
	//
	// clinicDBQueryTotal.WithLabelValues("get_pending_clinics", "success").Inc()
	//
	// result := make([]providers.Clinic, len(rows))
	// for i, row := range rows {
	// 	result[i] = r.mapToClinicFromList(row)
	// }

	result := make([]providers.Clinic, 10)

	return result, nil
}

func (r *clinicRepository) GetClinicsByProvince(ctx context.Context, province string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicsByProvinceParams{
		Province: pgtypeTextFromString(province),
		Limit:    int32(limit),
		Offset:   int32(offset),
	}

	rows, err := r.querier.GetClinicsByProvince(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_province", "error").Inc()
		return nil, fmt.Errorf("get clinics by province: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_province", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetClinicsByCity(ctx context.Context, province, city string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// params := sqlc.GetClinicsByCityParams{
	// 	Province: pgtypeTextFromString(province),
	// 	City:     pgtypeTextFromString(city),
	// 	Limit:    int32(limit),
	// 	Offset:   int32(offset),
	// }
	//
	// rows, err := r.querier.GetClinicsByCity(ctx, params)
	// if err != nil {
	// 	clinicDBQueryTotal.WithLabelValues("get_clinics_by_city", "error").Inc()
	// 	return nil, fmt.Errorf("get clinics by city: %w", err)
	// }
	//
	// clinicDBQueryTotal.WithLabelValues("get_clinics_by_city", "success").Inc()
	//
	// result := make([]providers.Clinic, len(rows))
	// for i, row := range rows {
	// 	result[i] = r.mapToClinicFromList(row)
	// }
	result := make([]providers.Clinic, 10)
	return result, nil
}

func (r *clinicRepository) GetClinicsByType(ctx context.Context, clinicType string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicsByTypeParams{
		ClinicType: clinicType,
		Limit:      int32(limit),
		Offset:     int32(offset),
	}

	rows, err := r.querier.GetClinicsByType(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_type", "error").Inc()
		return nil, fmt.Errorf("get clinics by type: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_type", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

// ============================================
// SERVICES & SPECIALTIES
// ============================================

func (r *clinicRepository) GetClinicsByService(ctx context.Context, service string, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicsByServiceParams{
		Column1: pgtypeTextFromString(service),
		Column2: pgtypeTextFromStringPtr(province),
		Limit:   int32(limit),
		Offset:  int32(offset),
	}

	rows, err := r.querier.GetClinicsByService(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_service", "error").Inc()
		return nil, fmt.Errorf("get clinics by service: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_service", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetClinicsBySpecialty(ctx context.Context, specialty string, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicsBySpecialtyParams{
		Column1: pgtypeTextFromString(specialty),
		Column2: pgtypeTextFromStringPtr(province),
		Limit:   int32(limit),
		Offset:  int32(offset),
	}

	rows, err := r.querier.GetClinicsBySpecialty(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_specialty", "error").Inc()
		return nil, fmt.Errorf("get clinics by specialty: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_specialty", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetClinicsWithFacility(ctx context.Context, facility string, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicsWithFacilityParams{
		Column1: pgtypeTextFromString(facility),
		Column2: pgtypeTextFromStringPtr(province),
		Limit:   int32(limit),
		Offset:  int32(offset),
	}

	rows, err := r.querier.GetClinicsWithFacility(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_with_facility", "error").Inc()
		return nil, fmt.Errorf("get clinics with facility: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_with_facility", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

// ============================================
// LANGUAGE SUPPORT
// ============================================

func (r *clinicRepository) GetClinicsByLanguage(ctx context.Context, language string, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// params := sqlc.GetClinicsByLanguageParams{
	// 	Language: pgtypeTextFromString(language),
	// 	Province: pgtypeTextFromStringPtr(province),
	// 	Limit:    int32(limit),
	// 	Offset:   int32(offset),
	// }
	//
	// rows, err := r.querier.GetClinicsByLanguage(ctx, params)
	// if err != nil {
	// 	clinicDBQueryTotal.WithLabelValues("get_clinics_by_language", "error").Inc()
	// 	return nil, fmt.Errorf("get clinics by language: %w", err)
	// }
	//
	// clinicDBQueryTotal.WithLabelValues("get_clinics_by_language", "success").Inc()
	//
	// result := make([]providers.Clinic, len(rows))
	// for i, row := range rows {
	// 	result[i] = r.mapToClinicFromList(row)
	// }
	//

	result := make([]providers.Clinic, 10)
	return result, nil
}

// ============================================
// MEDICAL AID & PAYMENT
// ============================================

func (r *clinicRepository) GetClinicsAcceptingMedicalAid(ctx context.Context, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicsAcceptingMedicalAidParams{
		Column1: stringPtrToString(province),
		Limit:   int32(limit),
		Offset:  int32(offset),
	}

	rows, err := r.querier.GetClinicsAcceptingMedicalAid(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_accepting_medical_aid", "error").Inc()
		return nil, fmt.Errorf("get clinics accepting medical aid: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_accepting_medical_aid", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetClinicsByMedicalAidProvider(ctx context.Context, provider string, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// params := sqlc.GetClinicsByMedicalAidProviderParams{
	// 	Provider: pgtypeTextFromString(provider),
	// 	Province: pgtypeTextFromStringPtr(province),
	// 	Limit:    int32(limit),
	// 	Offset:   int32(offset),
	// }
	//
	// rows, err := r.querier.GetClinicsByMedicalAidProvider(ctx, params)
	// if err != nil {
	// 	clinicDBQueryTotal.WithLabelValues("get_clinics_by_medical_aid_provider", "error").Inc()
	// 	return nil, fmt.Errorf("get clinics by medical aid provider: %w", err)
	// }
	//
	// clinicDBQueryTotal.WithLabelValues("get_clinics_by_medical_aid_provider", "success").Inc()
	//
	// result := make([]providers.Clinic, len(rows))
	// for i, row := range rows {
	// 	result[i] = r.mapToClinicFromList(row)
	// }
	result := make([]providers.Clinic, 10)
	return result, nil
}

func (r *clinicRepository) GetClinicsByPaymentMethod(ctx context.Context, method map[string]any, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	methodJSON, err := jsonbFromMap(method)
	if err != nil {
		return nil, fmt.Errorf("marshal payment method: %w", err)
	}

	params := sqlc.GetClinicsByPaymentMethodParams{
		Column1: methodJSON,
		Column2: stringPtrToString(province),
		Limit:   int32(limit),
		Offset:  int32(offset),
	}

	rows, err := r.querier.GetClinicsByPaymentMethod(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_payment_method", "error").Inc()
		return nil, fmt.Errorf("get clinics by payment method: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_payment_method", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetClinicsByFeeStructure(ctx context.Context, feeStructure string, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicsByFeeStructureParams{
		FeeStructure: pgtypeTextFromString(feeStructure),
		Column2:      stringPtrToString(province),
		Limit:        int32(limit),
		Offset:       int32(offset),
	}

	rows, err := r.querier.GetClinicsByFeeStructure(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_fee_structure", "error").Inc()
		return nil, fmt.Errorf("get clinics by fee structure: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_fee_structure", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

// ============================================
// RANKING & DISCOVERY
// ============================================

func (r *clinicRepository) GetTopRatedClinics(ctx context.Context, province *string, minReviews, limit int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetTopRatedClinicsParams{
		Column1:     stringPtrToString(province),
		ReviewCount: int32(minReviews),
		Limit:       int32(limit),
	}

	rows, err := r.querier.GetTopRatedClinics(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_top_rated_clinics", "error").Inc()
		return nil, fmt.Errorf("get top rated clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_top_rated_clinics", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetMostReviewedClinics(ctx context.Context, province *string, limit int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetMostReviewedClinicsParams{
		Column1: stringPtrToString(province),
		Limit:   int32(limit),
	}

	rows, err := r.querier.GetMostReviewedClinics(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_most_reviewed_clinics", "error").Inc()
		return nil, fmt.Errorf("get most reviewed clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_most_reviewed_clinics", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetRecentlyAddedClinics(ctx context.Context, province *string, limit int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetRecentlyAddedClinicsParams{
		Column1: stringPtrToString(province),
		Limit:   int32(limit),
	}

	rows, err := r.querier.GetRecentlyAddedClinics(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_recently_added_clinics", "error").Inc()
		return nil, fmt.Errorf("get recently added clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_recently_added_clinics", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

func (r *clinicRepository) GetRecentlyVerifiedClinics(ctx context.Context, limit int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetRecentlyVerifiedClinics(ctx, int32(limit))
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_recently_verified_clinics", "error").Inc()
		return nil, fmt.Errorf("get recently verified clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_recently_verified_clinics", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

// ============================================
// STATISTICS & ANALYTICS
// ============================================

func (r *clinicRepository) GetClinicStatistics(ctx context.Context, id uuid.UUID) (providers.ClinicStatistics, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetClinicStatistics(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinic_statistics", "error").Inc()
		return providers.ClinicStatistics{}, fmt.Errorf("get clinic statistics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinic_statistics", "success").Inc()

	return providers.ClinicStatistics{
		ID:                  pgtypeUUIDToUUID(row.ID),
		ClinicName:          row.ClinicName,
		ReviewCount:         pgtypeInt4ToInt(row.ReviewCount),
		Rating:              pgtypeNumericToFloat64Ptr(row.Rating),
		PatientCapacity:     pgtypeInt4ToIntPtr(row.PatientCapacity),
		BedCount:            pgtypeInt4ToIntPtr(row.BedCount),
		ActiveStaffCount:    row.ActiveStaffCount,
		TotalStaffCount:     row.TotalStaffCount,
		ActiveServicesCount: row.ActiveServicesCount,
		TotalServicesCount:  row.TotalServicesCount,
	}, nil
}

func (r *clinicRepository) GetClinicMetrics(ctx context.Context) (providers.ClinicMetrics, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetClinicMetrics(ctx)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinic_metrics", "error").Inc()
		return providers.ClinicMetrics{}, fmt.Errorf("get clinic metrics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinic_metrics", "success").Inc()

	return providers.ClinicMetrics{
		TotalClinics:    row.TotalClinics,
		VerifiedClinics: row.VerifiedClinics,
		PendingClinics:  row.PendingClinics,
		RejectedClinics: row.RejectedClinics,
		ActiveClinics:   row.ActiveClinics,
		TotalReviews:    row.TotalReviews,
		TotalBeds:       row.TotalBeds,
	}, nil
}

func (r *clinicRepository) GetClinicTypeDistribution(ctx context.Context) ([]providers.ClinicTypeDistribution, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetClinicTypeDistribution(ctx)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinic_type_distribution", "error").Inc()
		return nil, fmt.Errorf("get clinic type distribution: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinic_type_distribution", "success").Inc()

	result := make([]providers.ClinicTypeDistribution, len(rows))
	for i, row := range rows {
		result[i] = providers.ClinicTypeDistribution{
			ClinicType:    pgtypeTextToString(row.ClinicType),
			Count:         row.Count,
			AverageRating: pgtypeNumericToFloat64Ptr(row.AverageRating),
		}
	}

	return result, nil
}

func (r *clinicRepository) GetClinicProvinceDistribution(ctx context.Context) ([]providers.ClinicProvinceDistribution, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetClinicProvinceDistribution(ctx)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinic_province_distribution", "error").Inc()
		return nil, fmt.Errorf("get clinic province distribution: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinic_province_distribution", "success").Inc()

	result := make([]providers.ClinicProvinceDistribution, len(rows))
	for i, row := range rows {
		result[i] = providers.ClinicProvinceDistribution{
			Province:      pgtypeTextToString(row.Province),
			Count:         row.Count,
			AverageRating: pgtypeNumericToFloat64Ptr(row.AverageRating),
		}
	}

	return result, nil
}

func (r *clinicRepository) GetClinicOwnershipDistribution(ctx context.Context) ([]providers.ClinicOwnershipDistribution, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetClinicOwnershipDistribution(ctx)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinic_ownership_distribution", "error").Inc()
		return nil, fmt.Errorf("get clinic ownership distribution: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinic_ownership_distribution", "success").Inc()

	result := make([]providers.ClinicOwnershipDistribution, len(rows))
	for i, row := range rows {
		result[i] = providers.ClinicOwnershipDistribution{
			OwnershipType: pgtypeTextToString(row.OwnershipType),
			Count:         row.Count,
			AverageRating: pgtypeNumericToFloat64Ptr(row.AverageRating),
		}
	}

	return result, nil
}

// ============================================
// COUNTING & EXISTENCE CHECKS
// ============================================

func (r *clinicRepository) CountClinics(ctx context.Context, clinicType, province, verificationStatus *string) (int64, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CountClinicsParams{
		ClinicType:         pgtypeTextFromStringPtr(clinicType),
		Province:           pgtypeTextFromStringPtr(province),
		VerificationStatus: pgtypeTextFromStringPtr(verificationStatus),
	}

	count, err := r.querier.CountClinics(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("count_clinics", "error").Inc()
		return 0, fmt.Errorf("count clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("count_clinics", "success").Inc()
	return count, nil
}

func (r *clinicRepository) CountVerifiedClinics(ctx context.Context) (int64, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	count, err := r.querier.CountVerifiedClinics(ctx)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("count_verified_clinics", "error").Inc()
		return 0, fmt.Errorf("count verified clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("count_verified_clinics", "success").Inc()
	return count, nil
}

func (r *clinicRepository) CountClinicsByProvince(ctx context.Context, province string) (int64, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	count, err := r.querier.CountClinicsByProvince(ctx, pgtypeTextFromString(province))
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("count_clinics_by_province", "error").Inc()
		return 0, fmt.Errorf("count clinics by province: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("count_clinics_by_province", "success").Inc()
	return count, nil
}

func (r *clinicRepository) ClinicExists(ctx context.Context, id uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	exists, err := r.querier.ClinicExists(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("clinic_exists", "error").Inc()
		return false, fmt.Errorf("clinic exists: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("clinic_exists", "success").Inc()
	return exists, nil
}

func (r *clinicRepository) CheckRegistrationNumberExists(ctx context.Context, registrationNumber string, excludeID *uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CheckRegistrationNumberExistsParams{
		RegistrationNumber: pgtypeTextFromString(registrationNumber),
		ExcludeID:          uuidPtrToPgtypeUUID(excludeID),
	}

	exists, err := r.querier.CheckRegistrationNumberExists(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("check_registration_number_exists", "error").Inc()
		return false, fmt.Errorf("check registration number exists: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("check_registration_number_exists", "success").Inc()
	return exists, nil
}

func (r *clinicRepository) CheckEmailExists(ctx context.Context, email string, excludeID *uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CheckClinicEmailExistsParams{
		Email:     pgtypeTextFromString(email),
		ExcludeID: uuidPtrToPgtypeUUID(excludeID),
	}

	exists, err := r.querier.CheckClinicEmailExists(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("check_email_exists", "error").Inc()
		return false, fmt.Errorf("check email exists: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("check_email_exists", "success").Inc()
	return exists, nil
}

func (r *clinicRepository) CheckPhoneExists(ctx context.Context, phone string, excludeID *uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CheckClinicPhoneExistsParams{
		PrimaryPhone: pgtypeTextFromString(phone),
		ExcludeID:    uuidPtrToPgtypeUUID(excludeID),
	}

	exists, err := r.querier.CheckClinicPhoneExists(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("check_phone_exists", "error").Inc()
		return false, fmt.Errorf("check phone exists: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("check_phone_exists", "success").Inc()
	return exists, nil
}

// ============================================
// BULK OPERATIONS
// ============================================

func (r *clinicRepository) BulkUpdateVerificationStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	params := sqlc.BulkUpdateVerificationStatusParams{
		Ids:                pgtypeIDs,
		VerificationStatus: pgtypeTextFromString(status),
	}

	err := r.querier.BulkUpdateVerificationStatus(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("bulk_update_verification_status", "error").Inc()
		return r.handleError(err, "bulk update verification status")
	}

	clinicDBQueryTotal.WithLabelValues("bulk_update_verification_status", "success").Inc()
	return nil
}

func (r *clinicRepository) BulkVerifyClinics(ctx context.Context, ids []uuid.UUID, verifiedBy uuid.UUID) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	params := sqlc.BulkVerifyClinicsParams{
		Ids:        pgtypeIDs,
		VerifiedBy: uuidToPgtypeUUID(verifiedBy),
	}

	err := r.querier.BulkVerifyClinics(ctx, params)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("bulk_verify_clinics", "error").Inc()
		return r.handleError(err, "bulk verify clinics")
	}

	clinicDBQueryTotal.WithLabelValues("bulk_verify_clinics", "success").Inc()
	return nil
}

// ============================================
// REFERENCE DATA LOOKUPS
// ============================================

func (r *clinicRepository) GetClinicByRegistrationNumber(ctx context.Context, registrationNumber string) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	c, err := r.querier.GetClinicByRegistrationNumber(ctx, pgtypeTextFromString(registrationNumber))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			clinicDBQueryTotal.WithLabelValues("get_clinic_by_registration_number", "not_found").Inc()
			return providers.Clinic{}, domain.ErrClinicNotFound
		}
		clinicDBQueryTotal.WithLabelValues("get_clinic_by_registration_number", "error").Inc()
		return providers.Clinic{}, err
	}

	clinicDBQueryTotal.WithLabelValues("get_clinic_by_registration_number", "success").Inc()
	return r.mapToClinic(c), nil
}

func (r *clinicRepository) GetClinicByEmail(ctx context.Context, email string) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	c, err := r.querier.GetClinicByEmail(ctx, pgtypeTextFromString(email))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			clinicDBQueryTotal.WithLabelValues("get_clinic_by_email", "not_found").Inc()
			return providers.Clinic{}, domain.ErrClinicNotFound
		}
		clinicDBQueryTotal.WithLabelValues("get_clinic_by_email", "error").Inc()
		return providers.Clinic{}, err
	}

	clinicDBQueryTotal.WithLabelValues("get_clinic_by_email", "success").Inc()
	return r.mapToClinic(c), nil
}

func (r *clinicRepository) GetClinicByPhone(ctx context.Context, phone string) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	c, err := r.querier.GetClinicByPhone(ctx, pgtypeTextFromString(phone))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			clinicDBQueryTotal.WithLabelValues("get_clinic_by_phone", "not_found").Inc()
			return providers.Clinic{}, domain.ErrClinicNotFound
		}
		clinicDBQueryTotal.WithLabelValues("get_clinic_by_phone", "error").Inc()
		return providers.Clinic{}, err
	}

	clinicDBQueryTotal.WithLabelValues("get_clinic_by_phone", "success").Inc()
	return r.mapToClinic(c), nil
}

// ============================================
// ADVANCED SEARCH
// ============================================

func (r *clinicRepository) SearchClinicsAdvanced(ctx context.Context, params providers.ClinicAdvancedSearchParams) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	servicesJSON, err := jsonbFromMap(params.Services)
	if err != nil {
		return nil, fmt.Errorf("marshal services: %w", err)
	}

	specialtiesJSON, err := jsonbFromMap(params.Specialties)
	if err != nil {
		return nil, fmt.Errorf("marshal specialties: %w", err)
	}

	sqlParams := sqlc.SearchClinicsAdvancedParams{
		Query:             pgtypeTextFromStringPtr(params.Query),
		Province:          pgtypeTextFromStringPtr(params.Province),
		City:              pgtypeTextFromStringPtr(params.City),
		ClinicType:        pgtypeTextFromStringPtr(params.ClinicType),
		OwnershipType:     pgtypeTextFromStringPtr(params.OwnershipType),
		AcceptsMedicalAid: params.AcceptsMedicalAid,
		Services:          servicesJSON,
		Specialties:       specialtiesJSON,
		Limit:             int32(params.Limit),
		Offset:            int32(params.Offset),
	}

	rows, err := r.querier.SearchClinicsAdvanced(ctx, sqlParams)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("search_clinics_advanced", "error").Inc()
		return nil, fmt.Errorf("search clinics advanced: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("search_clinics_advanced", "success").Inc()

	result := make([]providers.Clinic, len(rows))
	for i, row := range rows {
		result[i] = r.mapToClinicFromList(row)
	}

	return result, nil
}

// ============================================
// ACCREDITATION MANAGEMENT
// ============================================

func (r *clinicRepository) GetClinicsWithExpiredAccreditation(ctx context.Context) ([]providers.ClinicAccreditationInfo, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetClinicsWithExpiredAccreditation(ctx)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_with_expired_accreditation", "error").Inc()
		return nil, fmt.Errorf("get clinics with expired accreditation: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_with_expired_accreditation", "success").Inc()

	result := make([]providers.ClinicAccreditationInfo, len(rows))
	for i, row := range rows {
		result[i] = providers.ClinicAccreditationInfo{
			ID:                  pgtypeUUIDToUUID(row.ID),
			ClinicName:          row.ClinicName,
			AccreditationNumber: pgtypeTextToStringPtr(row.AccreditationNumber),
			AccreditationBody:   pgtypeTextToStringPtr(row.AccreditationBody),
			AccreditationExpiry: pgtypeDateToTimePtr(row.AccreditationExpiry),
			Email:               pgtypeTextToStringPtr(row.Email),
			PrimaryPhone:        pgtypeTextToStringPtr(row.PrimaryPhone),
		}
	}

	return result, nil
}

func (r *clinicRepository) GetClinicsNeedingReaccreditation(ctx context.Context) ([]providers.ClinicAccreditationInfo, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetClinicsNeedingReaccreditation(ctx)
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_needing_reaccreditation", "error").Inc()
		return nil, fmt.Errorf("get clinics needing reaccreditation: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_needing_reaccreditation", "success").Inc()

	result := make([]providers.ClinicAccreditationInfo, len(rows))
	for i, row := range rows {
		result[i] = providers.ClinicAccreditationInfo{
			ID:                  pgtypeUUIDToUUID(row.ID),
			ClinicName:          row.ClinicName,
			AccreditationNumber: pgtypeTextToStringPtr(row.AccreditationNumber),
			AccreditationBody:   pgtypeTextToStringPtr(row.AccreditationBody),
			AccreditationExpiry: pgtypeDateToTimePtr(row.AccreditationExpiry),
			Email:               pgtypeTextToStringPtr(row.Email),
			PrimaryPhone:        pgtypeTextToStringPtr(row.PrimaryPhone),
		}
	}

	return result, nil
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
		ID:              pgtypeUUIDToUUID(row.ID),
		ClinicName:      row.ClinicName,
		ClinicType:      row.ClinicType,
		City:            pgtypeTextToStringPtr(row.City),
		Province:        pgtypeTextToStringPtr(row.Province),
		PhysicalAddress: row.PhysicalAddress,
		PrimaryPhone:    pgtypeTextToStringPtr(row.PrimaryPhone),
		Rating:          pgtypeNumericToFloat64Ptr(row.Rating),
		ReviewCount:     pgtypeInt4ToInt(row.ReviewCount),
	}
}
