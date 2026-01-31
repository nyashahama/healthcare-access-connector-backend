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
