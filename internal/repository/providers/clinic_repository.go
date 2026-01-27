package providers

import (
	"context"
	"database/sql"
	"encoding/json"
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
// BASIC CRUD OPERATIONS
// ============================================

func (r *clinicRepository) CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.CreateClinic(ctx, sqlc.CreateClinicParams{
		ClinicName:         clinic.ClinicName,
		ClinicType:         clinic.ClinicType,
		RegistrationNumber: pgtypeTextFromStringPtr(clinic.RegistrationNumber),
		PrimaryPhone:       pgtypeTextFromStringPtr(clinic.PrimaryPhone),
		Email:              pgtypeTextFromStringPtr(clinic.Email),
		PhysicalAddress:    clinic.PhysicalAddress,
		City:               pgtypeTextFromStringPtr(clinic.City),
		Province:           pgtypeTextFromStringPtr(clinic.Province),
		PostalCode:         pgtypeTextFromStringPtr(clinic.PostalCode),
		Country:            pgtypeTextFromString(clinic.Country),
		Latitude:           float64PtrToPgtypeNumeric(clinic.Latitude),
		Longitude:          float64PtrToPgtypeNumeric(clinic.Longitude),
		Description:        pgtypeTextFromStringPtr(clinic.Description),
		OwnershipType:      pgtypeTextFromStringPtr(clinic.OwnershipType),
		AcceptsMedicalAid:  pgtype.Bool{Bool: clinic.AcceptsMedicalAid, Valid: true},
		VerificationStatus: pgtypeTextFromString(clinic.VerificationStatus),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("create_clinic", "error").Inc()
		return providers.Clinic{}, r.handleError(err, "create clinic")
	}

	clinicDBQueryTotal.WithLabelValues("create_clinic", "success").Inc()
	return r.mapToClinicFromCreate(created), nil
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

func (r *clinicRepository) GetClinicsByIDs(ctx context.Context, ids []uuid.UUID) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert UUIDs to pgtype.UUID
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

func (r *clinicRepository) UpdateClinic(ctx context.Context, clinic providers.Clinic) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert OperatingHours (map[string]any -> []byte)
	operatingHoursJSON, err := jsonbFromMap(clinic.OperatingHours)
	if err != nil {
		return fmt.Errorf("failed to marshal operating hours: %w", err)
	}

	// Convert Services ([]string -> []byte)
	servicesJSON, err := jsonbFromStringSlice(clinic.Services)
	if err != nil {
		return fmt.Errorf("failed to marshal services: %w", err)
	}

	// Convert Specialties ([]string -> []byte)
	specialtiesJSON, err := jsonbFromStringSlice(clinic.Specialties)
	if err != nil {
		return fmt.Errorf("failed to marshal specialties: %w", err)
	}

	err = r.querier.UpdateClinic(ctx, sqlc.UpdateClinicParams{
		ID:                uuidToPgtypeUUID(clinic.ID),
		ClinicName:        clinic.ClinicName,
		PrimaryPhone:      pgtypeTextFromStringPtr(clinic.PrimaryPhone),
		Email:             pgtypeTextFromStringPtr(clinic.Email),
		Description:       pgtypeTextFromStringPtr(clinic.Description),
		OperatingHours:    operatingHoursJSON,
		Services:          servicesJSON,
		Specialties:       specialtiesJSON,
		AcceptsMedicalAid: pgtype.Bool{Bool: clinic.AcceptsMedicalAid, Valid: true},
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic", "error").Inc()
		return fmt.Errorf("failed to update clinic: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic", "success").Inc()
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
		return fmt.Errorf("deactivate clinic: %w", err)
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
		return fmt.Errorf("reactivate clinic: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("reactivate_clinic", "success").Inc()
	return nil
}

// ============================================
// LISTING & SEARCH OPERATIONS
// ============================================

func (r *clinicRepository) ListClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	clinicType := ""
	if filters.ClinicType != nil {
		clinicType = *filters.ClinicType
	}

	province := ""
	if filters.Province != nil {
		province = *filters.Province
	}

	city := ""
	if filters.City != nil {
		city = *filters.City
	}

	verificationStatus := ""
	if filters.VerificationStatus != nil {
		verificationStatus = *filters.VerificationStatus
	}

	clinics, err := r.querier.ListClinics(ctx, sqlc.ListClinicsParams{
		Column1: clinicType,
		Column2: province,
		Column3: city,
		Column4: verificationStatus,
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("list_clinics", "error").Inc()
		return nil, fmt.Errorf("list clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("list_clinics", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = r.mapToClinicFromList(c)
	}

	return result, nil
}

func (r *clinicRepository) CountClinics(ctx context.Context, filters providers.ClinicFilters) (int64, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	clinicType := ""
	if filters.ClinicType != nil {
		clinicType = *filters.ClinicType
	}

	province := ""
	if filters.Province != nil {
		province = *filters.Province
	}

	verificationStatus := ""
	if filters.VerificationStatus != nil {
		verificationStatus = *filters.VerificationStatus
	}

	count, err := r.querier.CountClinics(ctx, sqlc.CountClinicsParams{
		Column1: clinicType,
		Column2: province,
		Column3: verificationStatus,
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("count_clinics", "error").Inc()
		return 0, fmt.Errorf("count clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("count_clinics", "success").Inc()
	return count, nil
}

func (r *clinicRepository) SearchClinics(ctx context.Context, query string, province *string, city *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	provinceVal := ""
	if province != nil {
		provinceVal = *province
	}

	cityVal := ""
	if city != nil {
		cityVal = *city
	}

	clinics, err := r.querier.SearchClinics(ctx, sqlc.SearchClinicsParams{
		Column1: pgtype.Text{String: query, Valid: true},
		Column2: provinceVal,
		Column3: cityVal,
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("search_clinics", "error").Inc()
		return nil, fmt.Errorf("search clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("search_clinics", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = r.mapToClinicFromSearch(c)
	}

	return result, nil
}

func (r *clinicRepository) SearchClinicsByLocation(ctx context.Context, latitude, longitude, radiusKm float64) ([]repository.ClinicSearchResult, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert radius to pgtype.Numeric
	radiusNumeric := float64PtrToPgtypeNumeric(&radiusKm)

	clinics, err := r.querier.SearchClinicsByLocation(ctx, sqlc.SearchClinicsByLocationParams{
		Radians:   latitude,
		Radians_2: longitude,
		Latitude:  radiusNumeric,
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("search_clinics_by_location", "error").Inc()
		return nil, fmt.Errorf("search clinics by location: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("search_clinics_by_location", "success").Inc()

	result := make([]repository.ClinicSearchResult, len(clinics))
	for i, c := range clinics {
		result[i] = r.mapToClinicSearchResult(c)
	}

	return result, nil
}

// ============================================
// VERIFICATION & STATUS MANAGEMENT
// ============================================

func (r *clinicRepository) VerifyClinic(ctx context.Context, id uuid.UUID, verifiedBy uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.VerifyClinic(ctx, sqlc.VerifyClinicParams{
		ID:                uuidToPgtypeUUID(id),
		VerifiedBy:        uuidToPgtypeUUID(verifiedBy),
		VerificationNotes: pgtypeTextFromString(notes),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("verify_clinic", "error").Inc()
		return fmt.Errorf("verify clinic: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("verify_clinic", "success").Inc()
	return nil
}

func (r *clinicRepository) GetVerifiedClinics(ctx context.Context, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	clinics, err := r.querier.GetVerifiedClinics(ctx, sqlc.GetVerifiedClinicsParams{
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_verified_clinics", "error").Inc()
		return nil, fmt.Errorf("get verified clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_verified_clinics", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = providers.Clinic{
			ID:              pgtypeUUIDToUUID(c.ID),
			ClinicName:      c.ClinicName,
			ClinicType:      c.ClinicType,
			City:            pgtypeTextToStringPtr(c.City),
			Province:        pgtypeTextToStringPtr(c.Province),
			PhysicalAddress: c.PhysicalAddress,
			PrimaryPhone:    pgtypeTextToStringPtr(c.PrimaryPhone),
			Email:           pgtypeTextToStringPtr(c.Email),
			Rating:          pgtypeNumericToFloat64Ptr(c.Rating),
			ReviewCount:     pgtypeInt4ToInt(c.ReviewCount),
			CreatedAt:       c.CreatedAt.Time,
		}
	}

	return result, nil
}

func (r *clinicRepository) UpdateClinicStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateClinicStatus(ctx, sqlc.UpdateClinicStatusParams{
		ID:                 uuidToPgtypeUUID(id),
		VerificationStatus: pgtypeTextFromString(status),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_status", "error").Inc()
		return fmt.Errorf("update clinic status: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_status", "success").Inc()
	return nil
}

func (r *clinicRepository) UpdateClinicLocation(ctx context.Context, id uuid.UUID, latitude, longitude *float64, address, city, province, postalCode string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	lat := float64PtrToPgtypeNumeric(latitude)
	lon := float64PtrToPgtypeNumeric(longitude)

	err := r.querier.UpdateClinicLocation(ctx, sqlc.UpdateClinicLocationParams{
		ID:              uuidToPgtypeUUID(id),
		Latitude:        lat,
		Longitude:       lon,
		PhysicalAddress: address,
		City:            pgtypeTextFromString(city),
		Province:        pgtypeTextFromString(province),
		PostalCode:      pgtypeTextFromString(postalCode),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_location", "error").Inc()
		return fmt.Errorf("update clinic location: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_location", "success").Inc()
	return nil
}

func (r *clinicRepository) UpdateClinicContact(ctx context.Context, id uuid.UUID, primaryPhone, secondaryPhone, emergencyPhone, email, website *string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateClinicContact(ctx, sqlc.UpdateClinicContactParams{
		ID:             uuidToPgtypeUUID(id),
		PrimaryPhone:   pgtypeTextFromStringPtr(primaryPhone),
		SecondaryPhone: pgtypeTextFromStringPtr(secondaryPhone),
		EmergencyPhone: pgtypeTextFromStringPtr(emergencyPhone),
		Email:          pgtypeTextFromStringPtr(email),
		Website:        pgtypeTextFromStringPtr(website),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_contact", "error").Inc()
		return fmt.Errorf("update clinic contact: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_contact", "success").Inc()
	return nil
}

func (r *clinicRepository) UpdateClinicServices(ctx context.Context, id uuid.UUID, services, specialties, facilities []string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	servicesJSON, err := jsonbFromStringSlice(services)
	if err != nil {
		return fmt.Errorf("marshal services: %w", err)
	}

	specialtiesJSON, err := jsonbFromStringSlice(specialties)
	if err != nil {
		return fmt.Errorf("marshal specialties: %w", err)
	}

	facilitiesJSON, err := jsonbFromStringSlice(facilities)
	if err != nil {
		return fmt.Errorf("marshal facilities: %w", err)
	}

	err = r.querier.UpdateClinicServices(ctx, sqlc.UpdateClinicServicesParams{
		ID:          uuidToPgtypeUUID(id),
		Services:    servicesJSON,
		Specialties: specialtiesJSON,
		Facilities:  facilitiesJSON,
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_services", "error").Inc()
		return fmt.Errorf("update clinic services: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_services", "success").Inc()
	return nil
}

func (r *clinicRepository) UpdateClinicMedicalAid(ctx context.Context, id uuid.UUID, acceptsMedicalAid bool, medicalAidProviders []string, paymentMethods []string, feeStructure *string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	providersJSON, err := jsonbFromStringSlice(medicalAidProviders)
	if err != nil {
		return fmt.Errorf("marshal medical aid providers: %w", err)
	}

	paymentMethodsJSON, err := jsonbFromStringSlice(paymentMethods)
	if err != nil {
		return fmt.Errorf("marshal payment methods: %w", err)
	}

	err = r.querier.UpdateClinicMedicalAid(ctx, sqlc.UpdateClinicMedicalAidParams{
		ID:                  uuidToPgtypeUUID(id),
		AcceptsMedicalAid:   pgtype.Bool{Bool: acceptsMedicalAid, Valid: true},
		MedicalAidProviders: providersJSON,
		PaymentMethods:      paymentMethodsJSON,
		FeeStructure:        pgtypeTextFromStringPtr(feeStructure),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_medical_aid", "error").Inc()
		return fmt.Errorf("update clinic medical aid: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_medical_aid", "success").Inc()
	return nil
}

func (r *clinicRepository) GetClinicsByVerificationStatus(ctx context.Context, status string, limit, offset int) ([]providers.Clinic, error) {
	filters := providers.ClinicFilters{
		VerificationStatus: &status,
	}
	return r.ListClinics(ctx, filters, limit, offset)
}

func (r *clinicRepository) GetPendingVerifications(ctx context.Context) ([]providers.Clinic, error) {
	status := "pending"
	return r.GetClinicsByVerificationStatus(ctx, status, 100, 0)
}

// ============================================
// RATING & REVIEW MANAGEMENT
// ============================================

func (r *clinicRepository) UpdateClinicRating(ctx context.Context, id uuid.UUID, rating float64, reviewCount int) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateClinicRating(ctx, sqlc.UpdateClinicRatingParams{
		ID:          uuidToPgtypeUUID(id),
		Rating:      float64PtrToPgtypeNumeric(&rating),
		ReviewCount: intPtrToPgtypeInt4(&reviewCount),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("update_clinic_rating", "error").Inc()
		return fmt.Errorf("update clinic rating: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("update_clinic_rating", "success").Inc()
	return nil
}

func (r *clinicRepository) GetTopRatedClinics(ctx context.Context, province *string, limit int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	provinceVal := ""
	if province != nil {
		provinceVal = *province
	}

	clinics, err := r.querier.GetTopRatedClinics(ctx, sqlc.GetTopRatedClinicsParams{
		Column1: provinceVal,
		Limit:   int32(limit),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_top_rated_clinics", "error").Inc()
		return nil, fmt.Errorf("get top rated clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_top_rated_clinics", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = providers.Clinic{
			ID:              pgtypeUUIDToUUID(c.ID),
			ClinicName:      c.ClinicName,
			ClinicType:      c.ClinicType,
			City:            pgtypeTextToStringPtr(c.City),
			Province:        pgtypeTextToStringPtr(c.Province),
			PhysicalAddress: c.PhysicalAddress,
			PrimaryPhone:    pgtypeTextToStringPtr(c.PrimaryPhone),
			Rating:          pgtypeNumericToFloat64Ptr(c.Rating),
			ReviewCount:     pgtypeInt4ToInt(c.ReviewCount),
		}
	}

	return result, nil
}

func (r *clinicRepository) GetRecentlyAddedClinics(ctx context.Context, province *string, limit int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	provinceVal := ""
	if province != nil {
		provinceVal = *province
	}

	clinics, err := r.querier.GetRecentlyAddedClinics(ctx, sqlc.GetRecentlyAddedClinicsParams{
		Column1: provinceVal,
		Limit:   int32(limit),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_recently_added_clinics", "error").Inc()
		return nil, fmt.Errorf("get recently added clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_recently_added_clinics", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = providers.Clinic{
			ID:              pgtypeUUIDToUUID(c.ID),
			ClinicName:      c.ClinicName,
			ClinicType:      c.ClinicType,
			City:            pgtypeTextToStringPtr(c.City),
			Province:        pgtypeTextToStringPtr(c.Province),
			PhysicalAddress: c.PhysicalAddress,
			PrimaryPhone:    pgtypeTextToStringPtr(c.PrimaryPhone),
			Rating:          pgtypeNumericToFloat64Ptr(c.Rating),
			ReviewCount:     pgtypeInt4ToInt(c.ReviewCount),
			CreatedAt:       c.CreatedAt.Time,
		}
	}

	return result, nil
}

// ============================================
// GEOGRAPHIC & LOCATION OPERATIONS
// ============================================

func (r *clinicRepository) GetClinicsByProvince(ctx context.Context, province string, limit, offset int) ([]providers.Clinic, error) {
	filters := providers.ClinicFilters{
		Province: &province,
	}
	return r.ListClinics(ctx, filters, limit, offset)
}

func (r *clinicRepository) GetClinicsByCity(ctx context.Context, city string, limit, offset int) ([]providers.Clinic, error) {
	filters := providers.ClinicFilters{
		City: &city,
	}
	return r.ListClinics(ctx, filters, limit, offset)
}

func (r *clinicRepository) GetNearbyClinics(ctx context.Context, latitude, longitude float64, limit int) ([]repository.ClinicSearchResult, error) {
	// Default radius of 50km
	return r.SearchClinicsByLocation(ctx, latitude, longitude, 50.0)
}

// ============================================
// SPECIALTY & SERVICE OPERATIONS
// ============================================

func (r *clinicRepository) GetClinicsByService(ctx context.Context, service string, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Create JSONB array for the service
	serviceJSON, err := json.Marshal([]string{service})
	if err != nil {
		return nil, fmt.Errorf("marshal service to JSON: %w", err)
	}

	provinceVal := ""
	if province != nil {
		provinceVal = *province
	}

	clinics, err := r.querier.GetClinicsByService(ctx, sqlc.GetClinicsByServiceParams{
		Column1: serviceJSON,
		Column2: provinceVal,
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_service", "error").Inc()
		return nil, fmt.Errorf("get clinics by service: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_service", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = providers.Clinic{
			ID:              pgtypeUUIDToUUID(c.ID),
			ClinicName:      c.ClinicName,
			ClinicType:      c.ClinicType,
			City:            pgtypeTextToStringPtr(c.City),
			Province:        pgtypeTextToStringPtr(c.Province),
			PhysicalAddress: c.PhysicalAddress,
			PrimaryPhone:    pgtypeTextToStringPtr(c.PrimaryPhone),
			Rating:          pgtypeNumericToFloat64Ptr(c.Rating),
			ReviewCount:     pgtypeInt4ToInt(c.ReviewCount),
		}
	}

	return result, nil
}

func (r *clinicRepository) GetClinicsBySpecialty(ctx context.Context, specialty string, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Create JSONB array for the specialty
	specialtyJSON, err := json.Marshal([]string{specialty})
	if err != nil {
		return nil, fmt.Errorf("marshal specialty to JSON: %w", err)
	}

	provinceVal := ""
	if province != nil {
		provinceVal = *province
	}

	clinics, err := r.querier.GetClinicsBySpecialty(ctx, sqlc.GetClinicsBySpecialtyParams{
		Column1: specialtyJSON,
		Column2: provinceVal,
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_specialty", "error").Inc()
		return nil, fmt.Errorf("get clinics by specialty: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_specialty", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = providers.Clinic{
			ID:              pgtypeUUIDToUUID(c.ID),
			ClinicName:      c.ClinicName,
			ClinicType:      c.ClinicType,
			City:            pgtypeTextToStringPtr(c.City),
			Province:        pgtypeTextToStringPtr(c.Province),
			PhysicalAddress: c.PhysicalAddress,
			PrimaryPhone:    pgtypeTextToStringPtr(c.PrimaryPhone),
			Rating:          pgtypeNumericToFloat64Ptr(c.Rating),
			ReviewCount:     pgtypeInt4ToInt(c.ReviewCount),
		}
	}

	return result, nil
}

func (r *clinicRepository) GetClinicsAcceptingMedicalAid(ctx context.Context, provider *string, province *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	provinceVal := ""
	if province != nil {
		provinceVal = *province
	}

	var providerJSON []byte
	if provider != nil {
		p, err := json.Marshal([]string{*provider})
		if err != nil {
			return nil, fmt.Errorf("marshal provider to JSON: %w", err)
		}
		providerJSON = p
	}

	clinics, err := r.querier.GetClinicsAcceptingMedicalAid(ctx, sqlc.GetClinicsAcceptingMedicalAidParams{
		Column1: provinceVal,
		Column2: providerJSON,
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_accepting_medical_aid", "error").Inc()
		return nil, fmt.Errorf("get clinics accepting medical aid: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_accepting_medical_aid", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = providers.Clinic{
			ID:                  pgtypeUUIDToUUID(c.ID),
			ClinicName:          c.ClinicName,
			ClinicType:          c.ClinicType,
			City:                pgtypeTextToStringPtr(c.City),
			Province:            pgtypeTextToStringPtr(c.Province),
			PhysicalAddress:     c.PhysicalAddress,
			PrimaryPhone:        pgtypeTextToStringPtr(c.PrimaryPhone),
			Rating:              pgtypeNumericToFloat64Ptr(c.Rating),
			ReviewCount:         pgtypeInt4ToInt(c.ReviewCount),
			MedicalAidProviders: stringSliceFromJSONB(c.MedicalAidProviders),
		}
	}

	return result, nil
}

// ============================================
// OWNERSHIP TYPE OPERATIONS
// ============================================

func (r *clinicRepository) GetClinicsByOwnership(ctx context.Context, ownershipType string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	clinics, err := r.querier.GetClinicsByOwnership(ctx, sqlc.GetClinicsByOwnershipParams{
		OwnershipType: pgtype.Text{String: ownershipType, Valid: true},
		Limit:         int32(limit),
		Offset:        int32(offset),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("get_clinics_by_ownership", "error").Inc()
		return nil, fmt.Errorf("get clinics by ownership: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("get_clinics_by_ownership", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = providers.Clinic{
			ID:              pgtypeUUIDToUUID(c.ID),
			ClinicName:      c.ClinicName,
			ClinicType:      c.ClinicType,
			City:            pgtypeTextToStringPtr(c.City),
			Province:        pgtypeTextToStringPtr(c.Province),
			PhysicalAddress: c.PhysicalAddress,
			OwnershipType:   pgtypeTextToStringPtr(c.OwnershipType),
			Rating:          pgtypeNumericToFloat64Ptr(c.Rating),
			ReviewCount:     pgtypeInt4ToInt(c.ReviewCount),
		}
	}

	return result, nil
}

// ============================================
// STATISTICS & ANALYTICS
// ============================================

func (r *clinicRepository) GetClinicStatistics(ctx context.Context, id uuid.UUID) (repository.ClinicStatistics, error) {
	// This would require joins with appointments, reviews, and staff tables
	// For now, return basic stats from the clinic record
	clinic, err := r.GetClinicByID(ctx, id)
	if err != nil {
		return repository.ClinicStatistics{}, err
	}

	stats := repository.ClinicStatistics{
		ClinicID:     id,
		TotalReviews: int64(clinic.ReviewCount),
	}

	if clinic.Rating != nil {
		stats.AverageRating = *clinic.Rating
	}

	// TODO: Add queries for appointments and staff when those tables are ready

	return stats, nil
}

func (r *clinicRepository) GetClinicMetrics(ctx context.Context) (repository.ClinicMetrics, error) {
	// Get total counts by verification status
	all, err := r.CountClinics(ctx, providers.ClinicFilters{})
	if err != nil {
		return repository.ClinicMetrics{}, err
	}

	verified := "verified"
	verifiedCount, _ := r.CountClinics(ctx, providers.ClinicFilters{VerificationStatus: &verified})

	pending := "pending"
	pendingCount, _ := r.CountClinics(ctx, providers.ClinicFilters{VerificationStatus: &pending})

	rejected := "rejected"
	rejectedCount, _ := r.CountClinics(ctx, providers.ClinicFilters{VerificationStatus: &rejected})

	// TODO: Add more detailed metrics (by type, province, ownership)

	return repository.ClinicMetrics{
		TotalClinics:       all,
		VerifiedClinics:    verifiedCount,
		PendingClinics:     pendingCount,
		RejectedClinics:    rejectedCount,
		ClinicsByType:      make(map[string]int64),
		ClinicsByProvince:  make(map[string]int64),
		ClinicsByOwnership: make(map[string]int64),
	}, nil
}

// ============================================
// BULK OPERATIONS
// ============================================

func (r *clinicRepository) BulkUpdateVerificationStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert UUIDs to pgtype.UUID
	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	err := r.querier.BulkUpdateVerificationStatus(ctx, sqlc.BulkUpdateVerificationStatusParams{
		Column1:            pgtypeIDs,
		VerificationStatus: pgtypeTextFromString(status),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("bulk_update_verification_status", "error").Inc()
		return fmt.Errorf("bulk update verification status: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("bulk_update_verification_status", "success").Inc()
	return nil
}

func (r *clinicRepository) BulkUpdateProvince(ctx context.Context, ids []uuid.UUID, province string) error {
	// This would require a custom SQL query
	// For now, update one by one in a transaction
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// TODO: Implement when needed
	// For now, just commit the empty transaction
	return tx.Commit(ctx)
}

// ============================================
// UNIQUENESS & EXISTENCE CHECKS
// ============================================

func (r *clinicRepository) ClinicExists(ctx context.Context, id uuid.UUID) (bool, error) {
	_, err := r.GetClinicByID(ctx, id)
	if errors.Is(err, domain.ErrClinicNotFound) {
		return false, nil
	}
	return err == nil, err
}

func (r *clinicRepository) IsRegistrationNumberUnique(ctx context.Context, registrationNumber string, excludeID *uuid.UUID) (bool, error) {
	var excludePg pgtype.UUID
	if excludeID != nil {
		excludePg = uuidToPgtypeUUID(*excludeID)
	} else {
		excludePg.Valid = false
	}

	exists, err := r.querier.CheckRegistrationNumberExists(ctx, sqlc.CheckRegistrationNumberExistsParams{
		RegistrationNumber: pgtypeTextFromString(registrationNumber),
		Column2:            excludePg,
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("is_reg_num_unique", "error").Inc()
		return false, r.handleError(err, "check registration unique")
	}
	clinicDBQueryTotal.WithLabelValues("is_reg_num_unique", "success").Inc()
	return !exists, nil
}

func (r *clinicRepository) GetClinicByRegistrationNumber(ctx context.Context, registrationNumber string) (providers.Clinic, error) {
	// This would require a custom SQL query
	// For now, fetch all and search
	// TODO: Add index and custom query
	allClinics, err := r.ListClinics(ctx, providers.ClinicFilters{}, 1000, 0)
	if err != nil {
		return providers.Clinic{}, err
	}

	for _, clinic := range allClinics {
		if clinic.RegistrationNumber != nil && *clinic.RegistrationNumber == registrationNumber {
			return clinic, nil
		}
	}

	return providers.Clinic{}, domain.ErrClinicNotFound
}

// ============================================
// EXPORT & REPORTING
// ============================================

func (r *clinicRepository) ExportClinicData(ctx context.Context, id uuid.UUID) ([]byte, error) {
	clinic, err := r.GetClinicByID(ctx, id)
	if err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(clinic, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal clinic data: %w", err)
	}

	return data, nil
}

func (r *clinicRepository) GetClinicsForExport(ctx context.Context, filters providers.ClinicFilters) ([]providers.Clinic, error) {
	// Export all clinics matching filters (no pagination)
	return r.ListClinics(ctx, filters, 10000, 0)
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

func (r *clinicRepository) mapToClinicFromCreate(row sqlc.CreateClinicRow) providers.Clinic {
	return providers.Clinic{
		ID:                 pgtypeUUIDToUUID(row.ID),
		ClinicName:         row.ClinicName,
		ClinicType:         row.ClinicType,
		City:               pgtypeTextToStringPtr(row.City),
		Province:           pgtypeTextToStringPtr(row.Province),
		VerificationStatus: pgtypeTextToString(row.VerificationStatus),
		CreatedAt:          row.CreatedAt.Time,
		UpdatedAt:          row.UpdatedAt.Time,
	}
}

func (r *clinicRepository) mapToClinicFromGetByID(row sqlc.Clinic) providers.Clinic {
	return providers.Clinic{
		ID:                     pgtypeUUIDToUUID(row.ID),
		ClinicName:             row.ClinicName,
		ClinicType:             row.ClinicType,
		RegistrationNumber:     pgtypeTextToStringPtr(row.RegistrationNumber),
		AccreditationNumber:    pgtypeTextToStringPtr(row.AccreditationNumber),
		PrimaryPhone:           pgtypeTextToStringPtr(row.PrimaryPhone),
		SecondaryPhone:         pgtypeTextToStringPtr(row.SecondaryPhone),
		EmergencyPhone:         pgtypeTextToStringPtr(row.EmergencyPhone),
		Email:                  pgtypeTextToStringPtr(row.Email),
		Website:                pgtypeTextToStringPtr(row.Website),
		PhysicalAddress:        row.PhysicalAddress,
		City:                   pgtypeTextToStringPtr(row.City),
		Province:               pgtypeTextToStringPtr(row.Province),
		PostalCode:             pgtypeTextToStringPtr(row.PostalCode),
		Country:                pgtypeTextToString(row.Country),
		Latitude:               pgtypeNumericToFloat64Ptr(row.Latitude),
		Longitude:              pgtypeNumericToFloat64Ptr(row.Longitude),
		GooglePlaceID:          pgtypeTextToStringPtr(row.GooglePlaceID),
		Description:            pgtypeTextToStringPtr(row.Description),
		YearEstablished:        pgtypeInt4ToIntPtr(row.YearEstablished),
		OwnershipType:          pgtypeTextToStringPtr(row.OwnershipType),
		BedCount:               pgtypeInt4ToIntPtr(row.BedCount),
		OperatingHours:         mapFromJSONB(row.OperatingHours),
		Services:               stringSliceFromJSONB(row.Services),
		Specialties:            stringSliceFromJSONB(row.Specialties),
		LanguagesSpoken:        row.LanguagesSpoken,
		Facilities:             stringSliceFromJSONB(row.Facilities),
		AcceptsMedicalAid:      pgtypeBoolToBool(row.AcceptsMedicalAid),
		MedicalAidProviders:    stringSliceFromJSONB(row.MedicalAidProviders),
		PaymentMethods:         stringSliceFromJSONB(row.PaymentMethods),
		FeeStructure:           pgtypeTextToStringPtr(row.FeeStructure),
		AccreditationBody:      pgtypeTextToStringPtr(row.AccreditationBody),
		AccreditationExpiry:    pgtypeDateToTimePtr(row.AccreditationExpiry),
		IsVerified:             pgtypeBoolToBool(row.IsVerified),
		VerificationStatus:     pgtypeTextToString(row.VerificationStatus),
		VerificationNotes:      pgtypeTextToStringPtr(row.VerificationNotes),
		VerifiedBy:             uuidPtrToUUID(row.VerifiedBy),
		VerificationDate:       pgtypeTimestampToTimePtr(row.VerificationDate),
		PatientCapacity:        pgtypeInt4ToIntPtr(row.PatientCapacity),
		AverageWaitTimeMinutes: pgtypeInt4ToIntPtr(row.AverageWaitTimeMinutes),
		Rating:                 pgtypeNumericToFloat64Ptr(row.Rating),
		ReviewCount:            pgtypeInt4ToInt(row.ReviewCount),
		ContactPersonName:      pgtypeTextToStringPtr(row.ContactPersonName),
		ContactPersonRole:      pgtypeTextToStringPtr(row.ContactPersonRole),
		ContactPersonPhone:     pgtypeTextToStringPtr(row.ContactPersonPhone),
		ContactPersonEmail:     pgtypeTextToStringPtr(row.ContactPersonEmail),
		CreatedAt:              row.CreatedAt.Time,
		UpdatedAt:              row.UpdatedAt.Time,
	}
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

func (r *clinicRepository) mapToClinicSearchResult(row sqlc.SearchClinicsByLocationRow) repository.ClinicSearchResult {
	distanceKm := 0.0
	if distPtr := pgtypeNumericToFloat64Ptr(row.DistanceKm); distPtr != nil {
		distanceKm = *distPtr
	}

	return repository.ClinicSearchResult{
		Clinic: providers.Clinic{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicName:      row.ClinicName,
			ClinicType:      row.ClinicType,
			PhysicalAddress: row.PhysicalAddress,
			City:            pgtypeTextToStringPtr(row.City),
			Province:        pgtypeTextToStringPtr(row.Province),
			PrimaryPhone:    pgtypeTextToStringPtr(row.PrimaryPhone),
			Latitude:        pgtypeNumericToFloat64Ptr(row.Latitude),
			Longitude:       pgtypeNumericToFloat64Ptr(row.Longitude),
			Rating:          pgtypeNumericToFloat64Ptr(row.Rating),
		},
		DistanceKm: distanceKm,
	}
}
