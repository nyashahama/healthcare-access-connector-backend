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
	serviceDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "service_db_query_duration_seconds",
			Help:    "Service database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	serviceDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "service_db_query_total",
			Help: "Total number of service database queries",
		},
		[]string{"operation", "status"},
	)
)

// ============================================
// REPOSITORY IMPLEMENTATION
// ============================================

type serviceRepository struct {
	querier sqlc.Querier
	pool    *pgxpool.Pool
}

// NewServiceRepository creates a new service repository using a pool
func NewServiceRepository(pool *pgxpool.Pool) repository.ServiceRepository {
	return &serviceRepository{
		querier: sqlc.New(pool),
		pool:    pool,
	}
}

// NewServiceRepositoryWithQuerier creates a new service repository using a provided querier (for transactions)
func NewServiceRepositoryWithQuerier(querier sqlc.Querier) repository.ServiceRepository {
	return &serviceRepository{
		querier: querier,
	}
}

// ============================================
// BASIC CRUD OPERATIONS
// ============================================

func (r *serviceRepository) CreateClinicService(ctx context.Context, service providers.ClinicService) (providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	medicalAidCodesJSON, err := jsonbFromMap(service.MedicalAidCodes)
	if err != nil {
		return providers.ClinicService{}, fmt.Errorf("marshal medical aid codes: %w", err)
	}

	providedByStaffIDs := make([]pgtype.UUID, len(service.ProvidedByStaffIDs))
	for i, id := range service.ProvidedByStaffIDs {
		providedByStaffIDs[i] = uuidToPgtypeUUID(id)
	}

	params := sqlc.CreateClinicServiceParams{
		ClinicID:                uuidToPgtypeUUID(service.ClinicID),
		ServiceName:             service.ServiceName,
		ServiceCategory:         pgtypeTextFromStringPtr(service.ServiceCategory),
		Description:             pgtypeTextFromStringPtr(service.Description),
		DurationMinutes:         intPtrToPgtypeInt4(service.DurationMinutes),
		PreparationInstructions: pgtypeTextFromStringPtr(service.PreparationInstructions),
		FollowUpRequired:        pgtype.Bool{Bool: service.FollowUpRequired, Valid: true},
		FollowUpDays:            intPtrToPgtypeInt4(service.FollowUpDays),
		MinimumAge:              intPtrToPgtypeInt4(service.MinimumAge),
		MaximumAge:              intPtrToPgtypeInt4(service.MaximumAge),
		GenderRestriction:       pgtypeTextFromStringPtr(service.GenderRestriction),
		Prerequisites:           service.Prerequisites,
		Cost:                    float64PtrToPgtypeNumeric(service.Cost),
		CostCurrency:            pgtypeTextFromString(service.CostCurrency),
		IsCoveredByMedicalAid:   pgtype.Bool{Bool: service.IsCoveredByMedicalAid, Valid: true},
		MedicalAidCodes:         medicalAidCodesJSON,
		IsActive:                pgtype.Bool{Bool: service.IsActive, Valid: true},
		AvailableDays:           service.AvailableDays,
		RequiresAppointment:     pgtype.Bool{Bool: service.RequiresAppointment, Valid: true},
		WalkInAllowed:           pgtype.Bool{Bool: service.WalkInAllowed, Valid: true},
		ProvidedByStaffIds:      providedByStaffIDs,
	}

	created, err := r.querier.CreateClinicService(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("create_clinic_service", "error").Inc()
		return providers.ClinicService{}, r.handleError(err, "create clinic service")
	}

	serviceDBQueryTotal.WithLabelValues("create_clinic_service", "success").Inc()
	return r.mapToClinicService(created), nil
}

func (r *serviceRepository) GetServiceByID(ctx context.Context, id uuid.UUID) (providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	s, err := r.querier.GetServiceByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			serviceDBQueryTotal.WithLabelValues("get_service_by_id", "not_found").Inc()
			return providers.ClinicService{}, domain.ErrServiceNotFound
		}
		serviceDBQueryTotal.WithLabelValues("get_service_by_id", "error").Inc()
		return providers.ClinicService{}, err
	}

	serviceDBQueryTotal.WithLabelValues("get_service_by_id", "success").Inc()
	return r.mapToClinicService(s), nil
}

func (r *serviceRepository) UpdateClinicService(ctx context.Context, service providers.ClinicService) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateClinicServiceParams{
		ID:                    uuidToPgtypeUUID(service.ID),
		ServiceName:           service.ServiceName,
		ServiceCategory:       pgtypeTextFromStringPtr(service.ServiceCategory),
		Description:           pgtypeTextFromStringPtr(service.Description),
		DurationMinutes:       intPtrToPgtypeInt4(service.DurationMinutes),
		Cost:                  float64PtrToPgtypeNumeric(service.Cost),
		IsCoveredByMedicalAid: pgtype.Bool{Bool: service.IsCoveredByMedicalAid, Valid: true},
		RequiresAppointment:   pgtype.Bool{Bool: service.RequiresAppointment, Valid: true},
		WalkInAllowed:         pgtype.Bool{Bool: service.WalkInAllowed, Valid: true},
	}

	err := r.querier.UpdateClinicService(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("update_clinic_service", "error").Inc()
		return r.handleError(err, "update clinic service")
	}

	serviceDBQueryTotal.WithLabelValues("update_clinic_service", "success").Inc()
	return nil
}

func (r *serviceRepository) DeleteClinicService(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteClinicService(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("delete_clinic_service", "error").Inc()
		return r.handleError(err, "delete clinic service")
	}

	serviceDBQueryTotal.WithLabelValues("delete_clinic_service", "success").Inc()
	return nil
}

// ============================================
// SERVICE STATUS MANAGEMENT
// ============================================

func (r *serviceRepository) ActivateService(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.ActivateService(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("activate_service", "error").Inc()
		return r.handleError(err, "activate service")
	}

	serviceDBQueryTotal.WithLabelValues("activate_service", "success").Inc()
	return nil
}

func (r *serviceRepository) DeactivateService(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeactivateService(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("deactivate_service", "error").Inc()
		return r.handleError(err, "deactivate service")
	}

	serviceDBQueryTotal.WithLabelValues("deactivate_service", "success").Inc()
	return nil
}

func (r *serviceRepository) ToggleServiceStatus(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.ToggleServiceStatus(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("toggle_service_status", "error").Inc()
		return r.handleError(err, "toggle service status")
	}

	serviceDBQueryTotal.WithLabelValues("toggle_service_status", "success").Inc()
	return nil
}

// ============================================
// SERVICE DETAILS MANAGEMENT
// ============================================

func (r *serviceRepository) UpdateServiceDetails(ctx context.Context, id uuid.UUID, details providers.ServiceDetails) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateServiceDetailsParams{
		ID:                      uuidToPgtypeUUID(id),
		Description:             pgtypeTextFromStringPtr(details.Description),
		DurationMinutes:         intPtrToPgtypeInt4(details.DurationMinutes),
		PreparationInstructions: pgtypeTextFromStringPtr(details.PreparationInstructions),
		FollowUpRequired:        pgtype.Bool{Bool: details.FollowUpRequired, Valid: true},
		FollowUpDays:            intPtrToPgtypeInt4(details.FollowUpDays),
	}

	err := r.querier.UpdateServiceDetails(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("update_service_details", "error").Inc()
		return r.handleError(err, "update service details")
	}

	serviceDBQueryTotal.WithLabelValues("update_service_details", "success").Inc()
	return nil
}

func (r *serviceRepository) UpdateServiceEligibility(ctx context.Context, id uuid.UUID, eligibility providers.ServiceEligibility) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateServiceEligibilityParams{
		ID:                uuidToPgtypeUUID(id),
		MinimumAge:        intPtrToPgtypeInt4(eligibility.MinimumAge),
		MaximumAge:        intPtrToPgtypeInt4(eligibility.MaximumAge),
		GenderRestriction: pgtypeTextFromStringPtr(eligibility.GenderRestriction),
		Prerequisites:     eligibility.Prerequisites,
	}

	err := r.querier.UpdateServiceEligibility(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("update_service_eligibility", "error").Inc()
		return r.handleError(err, "update service eligibility")
	}

	serviceDBQueryTotal.WithLabelValues("update_service_eligibility", "success").Inc()
	return nil
}

func (r *serviceRepository) UpdateServiceCost(ctx context.Context, id uuid.UUID, cost providers.ServiceCost) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	medicalAidCodesJSON, err := jsonbFromMap(cost.MedicalAidCodes)
	if err != nil {
		return fmt.Errorf("marshal medical aid codes: %w", err)
	}

	params := sqlc.UpdateServiceCostParams{
		ID:                    uuidToPgtypeUUID(id),
		Cost:                  float64PtrToPgtypeNumeric(cost.Cost),
		CostCurrency:          pgtypeTextFromStringPtr(&cost.CostCurrency),
		IsCoveredByMedicalAid: pgtype.Bool{Bool: cost.IsCoveredByMedicalAid, Valid: true},
		MedicalAidCodes:       medicalAidCodesJSON,
	}

	err = r.querier.UpdateServiceCost(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("update_service_cost", "error").Inc()
		return r.handleError(err, "update service cost")
	}

	serviceDBQueryTotal.WithLabelValues("update_service_cost", "success").Inc()
	return nil
}

func (r *serviceRepository) UpdateServiceAvailability(ctx context.Context, id uuid.UUID, availability providers.ServiceAvailability) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateServiceAvailabilityParams{
		ID:                  uuidToPgtypeUUID(id),
		AvailableDays:       availability.AvailableDays,
		RequiresAppointment: pgtype.Bool{Bool: availability.RequiresAppointment, Valid: true},
		WalkInAllowed:       pgtype.Bool{Bool: availability.WalkInAllowed, Valid: true},
	}

	err := r.querier.UpdateServiceAvailability(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("update_service_availability", "error").Inc()
		return r.handleError(err, "update service availability")
	}

	serviceDBQueryTotal.WithLabelValues("update_service_availability", "success").Inc()
	return nil
}

// ============================================
// SERVICE STAFF MANAGEMENT
// ============================================

func (r *serviceRepository) UpdateServiceStaff(ctx context.Context, id uuid.UUID, staffIDs []uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeStaffIDs := make([]pgtype.UUID, len(staffIDs))
	for i, staffID := range staffIDs {
		pgtypeStaffIDs[i] = uuidToPgtypeUUID(staffID)
	}

	params := sqlc.UpdateServiceStaffParams{
		ID:                 uuidToPgtypeUUID(id),
		ProvidedByStaffIds: pgtypeStaffIDs,
	}

	err := r.querier.UpdateServiceStaff(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("update_service_staff", "error").Inc()
		return r.handleError(err, "update service staff")
	}

	serviceDBQueryTotal.WithLabelValues("update_service_staff", "success").Inc()
	return nil
}

func (r *serviceRepository) AddStaffToService(ctx context.Context, serviceID, staffID uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.AddStaffToServiceParams{
		ID:          uuidToPgtypeUUID(serviceID),
		ArrayAppend: uuidToPgtypeUUID(staffID),
	}

	err := r.querier.AddStaffToService(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("add_staff_to_service", "error").Inc()
		return r.handleError(err, "add staff to service")
	}

	serviceDBQueryTotal.WithLabelValues("add_staff_to_service", "success").Inc()
	return nil
}

func (r *serviceRepository) RemoveStaffFromService(ctx context.Context, serviceID, staffID uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.RemoveStaffFromServiceParams{
		ID:          uuidToPgtypeUUID(serviceID),
		ArrayRemove: uuidToPgtypeUUID(staffID),
	}

	err := r.querier.RemoveStaffFromService(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("remove_staff_from_service", "error").Inc()
		return r.handleError(err, "remove staff from service")
	}

	serviceDBQueryTotal.WithLabelValues("remove_staff_from_service", "success").Inc()
	return nil
}

// ============================================
// SERVICE METRICS & RATINGS
// ============================================

func (r *serviceRepository) UpdateServiceRating(ctx context.Context, id uuid.UUID, rating float64, reviewCount int) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateServiceRatingParams{
		ID:            uuidToPgtypeUUID(id),
		AverageRating: float64PtrToPgtypeNumeric(&rating),
		ReviewCount:   intPtrToPgtypeInt4(&reviewCount),
	}

	err := r.querier.UpdateServiceRating(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("update_service_rating", "error").Inc()
		return r.handleError(err, "update service rating")
	}

	serviceDBQueryTotal.WithLabelValues("update_service_rating", "success").Inc()
	return nil
}

func (r *serviceRepository) IncrementServiceReviewCount(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.IncrementServiceReviewCount(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("increment_service_review_count", "error").Inc()
		return r.handleError(err, "increment service review count")
	}

	serviceDBQueryTotal.WithLabelValues("increment_service_review_count", "success").Inc()
	return nil
}

func (r *serviceRepository) UpdateServicePopularity(ctx context.Context, id uuid.UUID, score int) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateServicePopularityParams{
		ID:              uuidToPgtypeUUID(id),
		PopularityScore: intPtrToPgtypeInt4(&score),
	}

	err := r.querier.UpdateServicePopularity(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("update_service_popularity", "error").Inc()
		return r.handleError(err, "update service popularity")
	}

	serviceDBQueryTotal.WithLabelValues("update_service_popularity", "success").Inc()
	return nil
}

func (r *serviceRepository) IncrementPopularityScore(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.IncrementPopularityScore(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("increment_popularity_score", "error").Inc()
		return r.handleError(err, "increment popularity score")
	}

	serviceDBQueryTotal.WithLabelValues("increment_popularity_score", "success").Inc()
	return nil
}

// ============================================
// QUERYING BY CLINIC
// ============================================

func (r *serviceRepository) GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetClinicServices(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_clinic_services", "error").Inc()
		return nil, r.handleError(err, "get clinic services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:                    pgtypeUUIDToUUID(row.ID),
			ClinicID:              pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:           row.ServiceName,
			ServiceCategory:       pgtypeTextToStringPtr(row.ServiceCategory),
			Description:           pgtypeTextToStringPtr(row.Description),
			DurationMinutes:       pgtypeInt4ToIntPtr(row.DurationMinutes),
			Cost:                  pgtypeNumericToFloat64Ptr(row.Cost),
			CostCurrency:          pgtypeTextToString(row.CostCurrency),
			IsCoveredByMedicalAid: pgtypeBoolToBool(row.IsCoveredByMedicalAid),
			IsActive:              pgtypeBoolToBool(row.IsActive),
			RequiresAppointment:   pgtypeBoolToBool(row.RequiresAppointment),
			WalkInAllowed:         pgtypeBoolToBool(row.WalkInAllowed),
			AverageRating:         pgtypeNumericToFloat64Ptr(row.AverageRating),
			ReviewCount:           pgtypeInt4ToInt(row.ReviewCount),
			PopularityScore:       pgtypeInt4ToInt(row.PopularityScore),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_clinic_services", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetActiveClinicServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetActiveClinicServices(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_active_clinic_services", "error").Inc()
		return nil, r.handleError(err, "get active clinic services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:                    pgtypeUUIDToUUID(row.ID),
			ClinicID:              pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:           row.ServiceName,
			ServiceCategory:       pgtypeTextToStringPtr(row.ServiceCategory),
			Description:           pgtypeTextToStringPtr(row.Description),
			DurationMinutes:       pgtypeInt4ToIntPtr(row.DurationMinutes),
			Cost:                  pgtypeNumericToFloat64Ptr(row.Cost),
			CostCurrency:          pgtypeTextToString(row.CostCurrency),
			IsCoveredByMedicalAid: pgtypeBoolToBool(row.IsCoveredByMedicalAid),
			RequiresAppointment:   pgtypeBoolToBool(row.RequiresAppointment),
			WalkInAllowed:         pgtypeBoolToBool(row.WalkInAllowed),
			AverageRating:         pgtypeNumericToFloat64Ptr(row.AverageRating),
			ReviewCount:           pgtypeInt4ToInt(row.ReviewCount),
			PopularityScore:       pgtypeInt4ToInt(row.PopularityScore),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_active_clinic_services", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetClinicServicesByCategory(ctx context.Context, clinicID uuid.UUID, category string) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicServicesByCategoryParams{
		ClinicID:        uuidToPgtypeUUID(clinicID),
		ServiceCategory: pgtypeTextFromString(category),
	}

	rows, err := r.querier.GetClinicServicesByCategory(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_clinic_services_by_category", "error").Inc()
		return nil, r.handleError(err, "get clinic services by category")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			Description:     pgtypeTextToStringPtr(row.Description),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
			DurationMinutes: pgtypeInt4ToIntPtr(row.DurationMinutes),
			IsActive:        pgtypeBoolToBool(row.IsActive),
			AverageRating:   pgtypeNumericToFloat64Ptr(row.AverageRating),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_clinic_services_by_category", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetClinicServicesByStaff(ctx context.Context, clinicID, staffID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetClinicServicesByStaffParams{
		ClinicID:           uuidToPgtypeUUID(clinicID),
		ProvidedByStaffIds: uuidToPgtypeUUID(staffID),
	}

	rows, err := r.querier.GetClinicServicesByStaff(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_clinic_services_by_staff", "error").Inc()
		return nil, r.handleError(err, "get clinic services by staff")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
			DurationMinutes: pgtypeInt4ToIntPtr(row.DurationMinutes),
			IsActive:        pgtypeBoolToBool(row.IsActive),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_clinic_services_by_staff", "success").Inc()
	return services, nil
}

// ============================================
// SEARCH & FILTERING
// ============================================

func (r *serviceRepository) SearchServices(ctx context.Context, query string, clinicID *uuid.UUID, limit, offset int) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var pgtypeClinicID pgtype.UUID
	if clinicID != nil {
		pgtypeClinicID = uuidToPgtypeUUID(*clinicID)
	}

	params := sqlc.SearchServicesParams{
		Column1: pgtypeTextFromString(query),
		Column2: pgtypeClinicID,
		Limit:   int32(limit),
		Offset:  int32(offset),
	}

	rows, err := r.querier.SearchServices(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("search_services", "error").Inc()
		return nil, r.handleError(err, "search services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:                    pgtypeUUIDToUUID(row.ID),
			ClinicID:              pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:           row.ServiceName,
			ServiceCategory:       pgtypeTextToStringPtr(row.ServiceCategory),
			Description:           pgtypeTextToStringPtr(row.Description),
			Cost:                  pgtypeNumericToFloat64Ptr(row.Cost),
			DurationMinutes:       pgtypeInt4ToIntPtr(row.DurationMinutes),
			IsCoveredByMedicalAid: pgtypeBoolToBool(row.IsCoveredByMedicalAid),
			AverageRating:         pgtypeNumericToFloat64Ptr(row.AverageRating),
		}
	}

	serviceDBQueryTotal.WithLabelValues("search_services", "success").Inc()
	return services, nil
}

func (r *serviceRepository) SearchServicesByCategory(ctx context.Context, category string, clinicID *uuid.UUID, limit, offset int) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var pgtypeClinicID pgtype.UUID
	if clinicID != nil {
		pgtypeClinicID = uuidToPgtypeUUID(*clinicID)
	}

	params := sqlc.SearchServicesByCategoryParams{
		ServiceCategory: pgtypeTextFromString(category),
		Column2:         pgtypeClinicID,
		Limit:           int32(limit),
		Offset:          int32(offset),
	}

	rows, err := r.querier.SearchServicesByCategory(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("search_services_by_category", "error").Inc()
		return nil, r.handleError(err, "search services by category")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			Description:     pgtypeTextToStringPtr(row.Description),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
			DurationMinutes: pgtypeInt4ToIntPtr(row.DurationMinutes),
			AverageRating:   pgtypeNumericToFloat64Ptr(row.AverageRating),
		}
	}

	serviceDBQueryTotal.WithLabelValues("search_services_by_category", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetServicesByPriceRange(ctx context.Context, clinicID uuid.UUID, minCost, maxCost float64) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetServicesByPriceRangeParams{
		ClinicID: uuidToPgtypeUUID(clinicID),
		Cost:     float64PtrToPgtypeNumeric(&minCost),
		Cost_2:   float64PtrToPgtypeNumeric(&maxCost),
	}

	rows, err := r.querier.GetServicesByPriceRange(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_services_by_price_range", "error").Inc()
		return nil, r.handleError(err, "get services by price range")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
			CostCurrency:    pgtypeTextToString(row.CostCurrency),
			DurationMinutes: pgtypeInt4ToIntPtr(row.DurationMinutes),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_services_by_price_range", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetFreeServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetFreeServices(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_free_services", "error").Inc()
		return nil, r.handleError(err, "get free services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			Description:     pgtypeTextToStringPtr(row.Description),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_free_services", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetWalkInServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetWalkInServices(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_walk_in_services", "error").Inc()
		return nil, r.handleError(err, "get walk in services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
			DurationMinutes: pgtypeInt4ToIntPtr(row.DurationMinutes),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_walk_in_services", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetAppointmentOnlyServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetAppointmentOnlyServices(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_appointment_only_services", "error").Inc()
		return nil, r.handleError(err, "get appointment only services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:                  pgtypeUUIDToUUID(row.ID),
			ClinicID:            pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:         row.ServiceName,
			ServiceCategory:     pgtypeTextToStringPtr(row.ServiceCategory),
			Cost:                pgtypeNumericToFloat64Ptr(row.Cost),
			DurationMinutes:     pgtypeInt4ToIntPtr(row.DurationMinutes),
			RequiresAppointment: pgtypeBoolToBool(row.RequiresAppointment),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_appointment_only_services", "success").Inc()
	return services, nil
}

// ============================================
// MEDICAL AID COVERAGE
// ============================================

func (r *serviceRepository) GetMedicalAidCoveredServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetMedicalAidCoveredServices(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_medical_aid_covered_services", "error").Inc()
		return nil, r.handleError(err, "get medical aid covered services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:                    pgtypeUUIDToUUID(row.ID),
			ClinicID:              pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:           row.ServiceName,
			ServiceCategory:       pgtypeTextToStringPtr(row.ServiceCategory),
			Cost:                  pgtypeNumericToFloat64Ptr(row.Cost),
			IsCoveredByMedicalAid: pgtypeBoolToBool(row.IsCoveredByMedicalAid),
			MedicalAidCodes:       mapFromJSONB(row.MedicalAidCodes),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_medical_aid_covered_services", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetServicesByMedicalAidCode(ctx context.Context, code map[string]any) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	codeJSON, err := jsonbFromMap(code)
	if err != nil {
		return nil, fmt.Errorf("marshal medical aid code: %w", err)
	}

	rows, err := r.querier.GetServicesByMedicalAidCode(ctx, codeJSON)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_services_by_medical_aid_code", "error").Inc()
		return nil, r.handleError(err, "get services by medical aid code")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
			MedicalAidCodes: mapFromJSONB(row.MedicalAidCodes),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_services_by_medical_aid_code", "success").Inc()
	return services, nil
}

// ============================================
// AGE & ELIGIBILITY FILTERING
// ============================================

func (r *serviceRepository) GetServicesForAge(ctx context.Context, clinicID uuid.UUID, age int) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetServicesForAgeParams{
		ClinicID:   uuidToPgtypeUUID(clinicID),
		MinimumAge: intPtrToPgtypeInt4(&age),
	}

	rows, err := r.querier.GetServicesForAge(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_services_for_age", "error").Inc()
		return nil, r.handleError(err, "get services for age")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			MinimumAge:      pgtypeInt4ToIntPtr(row.MinimumAge),
			MaximumAge:      pgtypeInt4ToIntPtr(row.MaximumAge),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_services_for_age", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetServicesForGender(ctx context.Context, clinicID uuid.UUID, gender string) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetServicesForGenderParams{
		ClinicID:          uuidToPgtypeUUID(clinicID),
		GenderRestriction: pgtypeTextFromString(gender),
	}

	rows, err := r.querier.GetServicesForGender(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_services_for_gender", "error").Inc()
		return nil, r.handleError(err, "get services for gender")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:                pgtypeUUIDToUUID(row.ID),
			ClinicID:          pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:       row.ServiceName,
			ServiceCategory:   pgtypeTextToStringPtr(row.ServiceCategory),
			GenderRestriction: pgtypeTextToStringPtr(row.GenderRestriction),
			Cost:              pgtypeNumericToFloat64Ptr(row.Cost),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_services_for_gender", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetPediatricServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPediatricServices(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_pediatric_services", "error").Inc()
		return nil, r.handleError(err, "get pediatric services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			MinimumAge:      pgtypeInt4ToIntPtr(row.MinimumAge),
			MaximumAge:      pgtypeInt4ToIntPtr(row.MaximumAge),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_pediatric_services", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetPreventiveServices(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPreventiveServices(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_preventive_services", "error").Inc()
		return nil, r.handleError(err, "get preventive services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			Description:     pgtypeTextToStringPtr(row.Description),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
			DurationMinutes: pgtypeInt4ToIntPtr(row.DurationMinutes),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_preventive_services", "success").Inc()
	return services, nil
}

// ============================================
// POPULAR & RECOMMENDED SERVICES
// ============================================

func (r *serviceRepository) GetTopRatedServices(ctx context.Context, minReviews int, clinicID *uuid.UUID, limit int) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var pgtypeClinicID pgtype.UUID
	if clinicID != nil {
		pgtypeClinicID = uuidToPgtypeUUID(*clinicID)
	}

	params := sqlc.GetTopRatedServicesParams{
		ReviewCount: pgtype.Int4{Int32: int32(minReviews), Valid: true},
		Column2:     pgtypeClinicID,
		Limit:       int32(limit),
	}

	rows, err := r.querier.GetTopRatedServices(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_top_rated_services", "error").Inc()
		return nil, r.handleError(err, "get top rated services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			AverageRating:   pgtypeNumericToFloat64Ptr(row.AverageRating),
			ReviewCount:     pgtypeInt4ToInt(row.ReviewCount),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_top_rated_services", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetMostPopularServices(ctx context.Context, clinicID uuid.UUID, limit int) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetMostPopularServicesParams{
		ClinicID: uuidToPgtypeUUID(clinicID),
		Limit:    int32(limit),
	}

	rows, err := r.querier.GetMostPopularServices(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_most_popular_services", "error").Inc()
		return nil, r.handleError(err, "get most popular services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			PopularityScore: pgtypeInt4ToInt(row.PopularityScore),
			AverageRating:   pgtypeNumericToFloat64Ptr(row.AverageRating),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_most_popular_services", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetRecentlyAddedServices(ctx context.Context, clinicID uuid.UUID, limit int) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetRecentlyAddedServicesParams{
		ClinicID: uuidToPgtypeUUID(clinicID),
		Limit:    int32(limit),
	}

	rows, err := r.querier.GetRecentlyAddedServices(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_recently_added_services", "error").Inc()
		return nil, r.handleError(err, "get recently added services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
			CreatedAt:       row.CreatedAt.Time,
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_recently_added_services", "success").Inc()
	return services, nil
}

// ============================================
// STATISTICS & ANALYTICS
// ============================================

func (r *serviceRepository) GetServiceStatistics(ctx context.Context, id uuid.UUID) (providers.ServiceStatistics, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetServiceStatistics(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_service_statistics", "error").Inc()
		return providers.ServiceStatistics{}, r.handleError(err, "get service statistics")
	}

	stats := providers.ServiceStatistics{
		ID:              pgtypeUUIDToUUID(row.ID),
		ServiceName:     row.ServiceName,
		AverageRating:   pgtypeNumericToFloat64Ptr(row.AverageRating),
		ReviewCount:     pgtypeInt4ToInt(row.ReviewCount),
		PopularityScore: pgtypeInt4ToInt(row.PopularityScore),
		Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
		CreatedAt:       row.CreatedAt.Time,
	}

	serviceDBQueryTotal.WithLabelValues("get_service_statistics", "success").Inc()
	return stats, nil
}

func (r *serviceRepository) GetClinicServiceMetrics(ctx context.Context, clinicID uuid.UUID) (providers.ServiceMetrics, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetClinicServiceMetrics(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_clinic_service_metrics", "error").Inc()
		return providers.ServiceMetrics{}, r.handleError(err, "get clinic service metrics")
	}

	metrics := providers.ServiceMetrics{
		TotalServices:      row.TotalServices,
		ActiveServices:     row.ActiveServices,
		InactiveServices:   row.InactiveServices,
		AverageCost:        row.AverageCost,
		AverageDuration:    float64PtrToFloat64(row.AvgDuration),
		OverallRating:      float64PtrToFloat64(row.OverallRating),
		TotalReviews:       row.TotalReviews,
		MedicalAidServices: row.MedicalAidServices,
		WalkInServices:     row.WalkInServices,
	}

	serviceDBQueryTotal.WithLabelValues("get_clinic_service_metrics", "success").Inc()
	return metrics, nil
}

func (r *serviceRepository) GetServiceCategoryDistribution(ctx context.Context, clinicID uuid.UUID) ([]providers.ServiceCategoryDistribution, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetServiceCategoryDistribution(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_service_category_distribution", "error").Inc()
		return nil, r.handleError(err, "get service category distribution")
	}

	distributions := make([]providers.ServiceCategoryDistribution, len(rows))
	for i, row := range rows {
		distributions[i] = providers.ServiceCategoryDistribution{
			ServiceCategory: row.ServiceCategory,
			Count:           row.Count,
			AverageCost:     float64PtrToFloat64(pgtypeNumericToFloat64Ptr(row.AvgCost)),
			AverageRating:   float64PtrToFloat64(pgtypeNumericToFloat64Ptr(row.AvgRating)),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_service_category_distribution", "success").Inc()
	return distributions, nil
}

func (r *serviceRepository) GetServicePriceDistribution(ctx context.Context, clinicID uuid.UUID) ([]providers.ServicePriceDistribution, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetServicePriceDistribution(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_service_price_distribution", "error").Inc()
		return nil, r.handleError(err, "get service price distribution")
	}

	distributions := make([]providers.ServicePriceDistribution, len(rows))
	for i, row := range rows {
		distributions[i] = providers.ServicePriceDistribution{
			PriceRange:    row.PriceRange,
			Count:         row.Count,
			AverageRating: float64PtrToFloat64(pgtypeNumericToFloat64Ptr(row.AvgRating)),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_service_price_distribution", "success").Inc()
	return distributions, nil
}

// ============================================
// COUNTING & EXISTENCE CHECKS
// ============================================

func (r *serviceRepository) CountClinicServices(ctx context.Context, clinicID uuid.UUID, isActive *bool) (int64, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var pgtypeIsActive pgtype.Bool
	if isActive != nil {
		pgtypeIsActive = pgtype.Bool{Bool: *isActive, Valid: true}
	}

	params := sqlc.CountClinicServicesParams{
		ClinicID: uuidToPgtypeUUID(clinicID),
		Column2:  pgtypeIsActive,
	}

	count, err := r.querier.CountClinicServices(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("count_clinic_services", "error").Inc()
		return 0, r.handleError(err, "count clinic services")
	}

	serviceDBQueryTotal.WithLabelValues("count_clinic_services", "success").Inc()
	return count, nil
}

func (r *serviceRepository) CountServicesByCategory(ctx context.Context, clinicID uuid.UUID, category string) (int64, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CountServicesByCategoryParams{
		ClinicID:        uuidToPgtypeUUID(clinicID),
		ServiceCategory: pgtypeTextFromString(category),
	}

	count, err := r.querier.CountServicesByCategory(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("count_services_by_category", "error").Inc()
		return 0, r.handleError(err, "count services by category")
	}

	serviceDBQueryTotal.WithLabelValues("count_services_by_category", "success").Inc()
	return count, nil
}

func (r *serviceRepository) ServiceExists(ctx context.Context, id uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	exists, err := r.querier.ServiceExists(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("service_exists", "error").Inc()
		return false, r.handleError(err, "check service exists")
	}

	serviceDBQueryTotal.WithLabelValues("service_exists", "success").Inc()
	return exists, nil
}

func (r *serviceRepository) CheckServiceNameExists(ctx context.Context, clinicID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CheckServiceNameExistsParams{
		ClinicID:    uuidToPgtypeUUID(clinicID),
		ServiceName: name,
		Column3:     uuidPtrToPgtypeUUID(excludeID),
	}

	exists, err := r.querier.CheckServiceNameExists(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("check_service_name_exists", "error").Inc()
		return false, r.handleError(err, "check service name exists")
	}

	serviceDBQueryTotal.WithLabelValues("check_service_name_exists", "success").Inc()
	return exists, nil
}

// ============================================
// BULK OPERATIONS
// ============================================

func (r *serviceRepository) GetServicesByIDs(ctx context.Context, ids []uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	rows, err := r.querier.GetServicesByIDs(ctx, pgtypeIDs)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_services_by_ids", "error").Inc()
		return nil, fmt.Errorf("get services by ids: %w", err)
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = r.mapToClinicService(row)
	}

	serviceDBQueryTotal.WithLabelValues("get_services_by_ids", "success").Inc()
	return services, nil
}

func (r *serviceRepository) BulkActivateServices(ctx context.Context, ids []uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	err := r.querier.BulkActivateServices(ctx, pgtypeIDs)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("bulk_activate_services", "error").Inc()
		return r.handleError(err, "bulk activate services")
	}

	serviceDBQueryTotal.WithLabelValues("bulk_activate_services", "success").Inc()
	return nil
}

func (r *serviceRepository) BulkDeactivateServices(ctx context.Context, ids []uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	err := r.querier.BulkDeactivateServices(ctx, pgtypeIDs)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("bulk_deactivate_services", "error").Inc()
		return r.handleError(err, "bulk deactivate services")
	}

	serviceDBQueryTotal.WithLabelValues("bulk_deactivate_services", "success").Inc()
	return nil
}

func (r *serviceRepository) BulkUpdateServiceCategory(ctx context.Context, ids []uuid.UUID, category string) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	params := sqlc.BulkUpdateServiceCategoryParams{
		Column1:         pgtypeIDs,
		ServiceCategory: pgtypeTextFromString(category),
	}

	err := r.querier.BulkUpdateServiceCategory(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("bulk_update_service_category", "error").Inc()
		return r.handleError(err, "bulk update service category")
	}

	serviceDBQueryTotal.WithLabelValues("bulk_update_service_category", "success").Inc()
	return nil
}

func (r *serviceRepository) DeactivateClinicServices(ctx context.Context, clinicID uuid.UUID) error {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeactivateClinicServices(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("deactivate_clinic_services", "error").Inc()
		return r.handleError(err, "deactivate clinic services")
	}

	serviceDBQueryTotal.WithLabelValues("deactivate_clinic_services", "success").Inc()
	return nil
}

// ============================================
// AVAILABILITY & SCHEDULING
// ============================================

func (r *serviceRepository) GetServicesAvailableOnDay(ctx context.Context, clinicID uuid.UUID, day string) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetServicesAvailableOnDayParams{
		ClinicID:      uuidToPgtypeUUID(clinicID),
		AvailableDays: pgtypeTextFromString(day),
	}

	rows, err := r.querier.GetServicesAvailableOnDay(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_services_available_on_day", "error").Inc()
		return nil, r.handleError(err, "get services available on day")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ServiceName:     row.ServiceName,
			ServiceCategory: pgtypeTextToStringPtr(row.ServiceCategory),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
			DurationMinutes: pgtypeInt4ToIntPtr(row.DurationMinutes),
			AvailableDays:   row.AvailableDays,
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_services_available_on_day", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetServicesRequiringFollowUp(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetServicesRequiringFollowUp(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_services_requiring_follow_up", "error").Inc()
		return nil, r.handleError(err, "get services requiring follow up")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:               pgtypeUUIDToUUID(row.ID),
			ClinicID:         pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:      row.ServiceName,
			FollowUpRequired: pgtypeBoolToBool(row.FollowUpRequired),
			FollowUpDays:     pgtypeInt4ToIntPtr(row.FollowUpDays),
			Cost:             pgtypeNumericToFloat64Ptr(row.Cost),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_services_requiring_follow_up", "success").Inc()
	return services, nil
}

func (r *serviceRepository) GetQuickServices(ctx context.Context, clinicID uuid.UUID, maxDurationMinutes int) ([]providers.ClinicService, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetQuickServicesParams{
		ClinicID:        uuidToPgtypeUUID(clinicID),
		DurationMinutes: int4(maxDurationMinutes),
	}

	rows, err := r.querier.GetQuickServices(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_quick_services", "error").Inc()
		return nil, r.handleError(err, "get quick services")
	}

	services := make([]providers.ClinicService, len(rows))
	for i, row := range rows {
		services[i] = providers.ClinicService{
			ID:              pgtypeUUIDToUUID(row.ID),
			ClinicID:        pgtypeUUIDToUUID(row.ClinicID),
			ServiceName:     row.ServiceName,
			DurationMinutes: pgtypeInt4ToIntPtr(row.DurationMinutes),
			Cost:            pgtypeNumericToFloat64Ptr(row.Cost),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_quick_services", "success").Inc()
	return services, nil
}

// ============================================
// COMPARISON & CROSS-CLINIC QUERIES
// ============================================

func (r *serviceRepository) CompareServiceAcrossClinics(ctx context.Context, serviceName string) ([]providers.ServiceComparison, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.CompareServiceAcrossClinics(ctx, serviceName)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("compare_service_across_clinics", "error").Inc()
		return nil, r.handleError(err, "compare service across clinics")
	}

	comparisons := make([]providers.ServiceComparison, len(rows))
	for i, row := range rows {
		comparisons[i] = providers.ServiceComparison{
			ClinicID:              pgtypeUUIDToUUID(row.ClinicID),
			ClinicName:            row.ClinicName,
			Cost:                  pgtypeNumericToFloat64Ptr(row.Cost),
			DurationMinutes:       pgtypeInt4ToIntPtr(row.DurationMinutes),
			AverageRating:         pgtypeNumericToFloat64Ptr(row.AverageRating),
			IsCoveredByMedicalAid: pgtypeBoolToBool(row.IsCoveredByMedicalAid),
		}
	}

	serviceDBQueryTotal.WithLabelValues("compare_service_across_clinics", "success").Inc()
	return comparisons, nil
}

func (r *serviceRepository) GetCheapestServiceProviders(ctx context.Context, serviceName string, limit int) ([]providers.ServiceProvider, error) {
	start := time.Now()
	defer func() {
		serviceDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetCheapestServiceProvidersParams{
		Column1: pgtypeTextFromString(serviceName),
		Limit:   int32(limit),
	}

	rows, err := r.querier.GetCheapestServiceProviders(ctx, params)
	if err != nil {
		serviceDBQueryTotal.WithLabelValues("get_cheapest_service_providers", "error").Inc()
		return nil, r.handleError(err, "get cheapest service providers")
	}

	providersList := make([]providers.ServiceProvider, len(rows))
	for i, row := range rows {
		providersList[i] = providers.ServiceProvider{
			ClinicID:    pgtypeUUIDToUUID(row.ClinicID),
			ClinicName:  row.ClinicName,
			ServiceName: row.ServiceName,
			Cost:        pgtypeNumericToFloat64Ptr(row.Cost),
			City:        pgtypeTextToStringPtr(row.City),
			Province:    pgtypeTextToStringPtr(row.Province),
		}
	}

	serviceDBQueryTotal.WithLabelValues("get_cheapest_service_providers", "success").Inc()
	return providersList, nil
}

// ============================================
// ERROR HANDLING
// ============================================

func (r *serviceRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			if strings.Contains(pgErr.ConstraintName, "service_name") {
				return domain.ErrDuplicate
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

func (r *serviceRepository) mapToClinicService(row sqlc.ClinicService) providers.ClinicService {
	return providers.ClinicService{
		ID:                      pgtypeUUIDToUUID(row.ID),
		ClinicID:                pgtypeUUIDToUUID(row.ClinicID),
		ServiceName:             row.ServiceName,
		ServiceCategory:         pgtypeTextToStringPtr(row.ServiceCategory),
		Description:             pgtypeTextToStringPtr(row.Description),
		DurationMinutes:         pgtypeInt4ToIntPtr(row.DurationMinutes),
		PreparationInstructions: pgtypeTextToStringPtr(row.PreparationInstructions),
		FollowUpRequired:        pgtypeBoolToBool(row.FollowUpRequired),
		FollowUpDays:            pgtypeInt4ToIntPtr(row.FollowUpDays),
		MinimumAge:              pgtypeInt4ToIntPtr(row.MinimumAge),
		MaximumAge:              pgtypeInt4ToIntPtr(row.MaximumAge),
		GenderRestriction:       pgtypeTextToStringPtr(row.GenderRestriction),
		Prerequisites:           row.Prerequisites,
		Cost:                    pgtypeNumericToFloat64Ptr(row.Cost),
		CostCurrency:            pgtypeTextToString(row.CostCurrency),
		IsCoveredByMedicalAid:   pgtypeBoolToBool(row.IsCoveredByMedicalAid),
		MedicalAidCodes:         mapFromJSONB(row.MedicalAidCodes),
		IsActive:                pgtypeBoolToBool(row.IsActive),
		AvailableDays:           row.AvailableDays,
		RequiresAppointment:     pgtypeBoolToBool(row.RequiresAppointment),
		WalkInAllowed:           pgtypeBoolToBool(row.WalkInAllowed),
		ProvidedByStaffIDs:      r.uuidArrayToUUIDs(row.ProvidedByStaffIds),
		PopularityScore:         pgtypeInt4ToInt(row.PopularityScore),
		AverageRating:           pgtypeNumericToFloat64Ptr(row.AverageRating),
		ReviewCount:             pgtypeInt4ToInt(row.ReviewCount),
		CreatedAt:               row.CreatedAt.Time,
		UpdatedAt:               row.UpdatedAt.Time,
	}
}

func (r *serviceRepository) uuidArrayToUUIDs(pgtypeUUIDs []pgtype.UUID) []uuid.UUID {
	if pgtypeUUIDs == nil {
		return nil
	}
	uuids := make([]uuid.UUID, len(pgtypeUUIDs))
	for i, pgUUID := range pgtypeUUIDs {
		uuids[i] = pgtypeUUIDToUUID(pgUUID)
	}
	return uuids
}
