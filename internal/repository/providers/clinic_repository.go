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

func (r *clinicRepository) CreateClinic(ctx context.Context, clinic providers.Clinic) (providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.CreateClinic(ctx, sqlc.CreateClinicParams{
		ClinicName:         clinic.ClinicName,
		RegistrationNumber: pgtype.Text{String: *clinic.RegistrationNumber, Valid: true},
		ClinicType:         clinic.ClinicType,
		PrimaryPhone:       pgtype.Text{String: *clinic.PrimaryPhone, Valid: true},
		Email:              pgtype.Text{String: *clinic.Email, Valid: true},
		PhysicalAddress:    clinic.PhysicalAddress,
		City:               pgtypeTextFromStringPtr(clinic.City),
		Province:           pgtypeTextFromStringPtr(clinic.Province),
		PostalCode:         pgtypeTextFromStringPtr(clinic.PostalCode),
		Country:            pgtypeTextFromString(clinic.Country),
		Latitude:           float64PtrToPgtypeNumeric(*&clinic.Latitude),
		Longitude:          float64PtrToPgtypeNumeric(*&clinic.Longitude),
		Description:        pgtype.Text{String: *clinic.Description, Valid: true},
		OwnershipType:      pgtype.Text{String: *clinic.OwnershipType, Valid: true},
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
			clinicDBQueryTotal.WithLabelValues("get clinic by id", "not found").Inc()
			return providers.Clinic{}, err
		}
		clinicDBQueryTotal.WithLabelValues("get clinic by id", "success")
		return providers.Clinic{}, err
	}
	return r.mapToClinicFromGetByID(c), nil
}

func (r *clinicRepository) ListClinics(ctx context.Context, filters providers.ClinicFilters, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	clinics, err := r.querier.ListClinics(ctx, sqlc.ListClinicsParams{
		Column1: *filters.ClinicType,
		Column2: *filters.Province,
		Column3: *filters.City,
		Column4: *filters.VerificationStatus,
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("list clinics", "not found").Inc()
		return nil, fmt.Errorf("list clinics: %w", err)
	}

	clinicDBQueryTotal.WithLabelValues("list clinics", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = r.mapToClinicFromList(c)
	}

	return result, nil
}

func (r *clinicRepository) SearchClinics(ctx context.Context, query string, province *string, city *string, limit, offset int) ([]providers.Clinic, error) {
	start := time.Now()
	defer func() {
		clinicDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	clinics, err := r.querier.SearchClinics(ctx, sqlc.SearchClinicsParams{
		Column1: pgtype.Text{String: query, Valid: true},
		Column2: *province,
		Column3: *city,
		Limit:   int32(limit),
		Offset:  int32(offset),
	})
	if err != nil {
		clinicDBQueryTotal.WithLabelValues("search clinics", "not found").Inc()
		return nil, fmt.Errorf("search clinics :%w", err)
	}
	clinicDBQueryTotal.WithLabelValues("search clinics", "success").Inc()

	result := make([]providers.Clinic, len(clinics))
	for i, c := range clinics {
		result[i] = r.mapToClinicFromSearch(c)
	}

	return result, nil
}

// handleError converts database errors to domain errors
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

// Mapping functions
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
	var rating *float64
	if row.Rating.Valid {
		ratingVal, _ := row.Rating.Float64Value()
		val := ratingVal.Float64
		rating = &val
	}

	return providers.Clinic{
		ID:                 pgtypeUUIDToUUID(row.ID),
		ClinicName:         row.ClinicName,
		ClinicType:         row.ClinicType,
		RegistrationNumber: pgtypeTextToStringPtr(row.RegistrationNumber),
		PrimaryPhone:       pgtypeTextToStringPtr(row.PrimaryPhone),
		Email:              pgtypeTextToStringPtr(row.Email),
		PhysicalAddress:    row.PhysicalAddress,
		City:               pgtypeTextToStringPtr(row.City),
		Province:           pgtypeTextToStringPtr(row.Province),
		PostalCode:         pgtypeTextToStringPtr(row.PostalCode),
		Country:            pgtypeTextToString(row.Country),
		Latitude:           pgtypeNumericToFloat64Ptr(row.Latitude),
		Longitude:          pgtypeNumericToFloat64Ptr(row.Longitude),
		Description:        pgtypeTextToStringPtr(row.Description),
		OwnershipType:      pgtypeTextToStringPtr(row.OwnershipType),
		AcceptsMedicalAid:  pgtypeBoolToBool(row.AcceptsMedicalAid),
		IsVerified:         pgtypeBoolToBool(row.IsVerified),
		VerificationStatus: pgtypeTextToString(row.VerificationStatus),
		Rating:             rating,
		ReviewCount:        pgtypeInt4ToInt(row.ReviewCount),
		CreatedAt:          row.CreatedAt.Time,
		UpdatedAt:          row.UpdatedAt.Time,
	}
}

func (r *clinicRepository) mapToClinicFromList(row sqlc.ListClinicsRow) providers.Clinic {
	var rating *float64
	if row.Rating.Valid {
		ratingVal, _ := row.Rating.Float64Value()
		val := ratingVal.Float64
		rating = &val
	}

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
		Rating:             rating,
		ReviewCount:        pgtypeInt4ToInt(row.ReviewCount),
		CreatedAt:          row.CreatedAt.Time,
	}
}

func (r *clinicRepository) mapToClinicFromSearch(row sqlc.SearchClinicsRow) providers.Clinic {
	var rating *float64
	if row.Rating.Valid {
		ratingVal, _ := row.Rating.Float64Value()
		val := ratingVal.Float64
		rating = &val
	}

	return providers.Clinic{
		ID:              pgtypeUUIDToUUID(row.ID),
		ClinicName:      row.ClinicName,
		ClinicType:      row.ClinicType,
		City:            pgtypeTextToStringPtr(row.City),
		Province:        pgtypeTextToStringPtr(row.Province),
		PhysicalAddress: row.PhysicalAddress,
		PrimaryPhone:    pgtypeTextToStringPtr(row.PrimaryPhone),
		Rating:          rating,
		ReviewCount:     pgtypeInt4ToInt(row.ReviewCount),
	}
}

func (r *clinicRepository) mapToClinicFromSearchByLocation(row sqlc.SearchClinicsByLocationRow) providers.Clinic {
	return providers.Clinic{
		ID:              pgtypeUUIDToUUID(row.ID),
		ClinicName:      row.ClinicName,
		ClinicType:      row.ClinicType,
		PhysicalAddress: row.PhysicalAddress,
		City:            pgtypeTextToStringPtr(row.City),
		Province:        pgtypeTextToStringPtr(row.Province),
		PrimaryPhone:    pgtypeTextToStringPtr(row.PrimaryPhone),
		Latitude:        pgtypeNumericToFloat64Ptr(row.Latitude),
		Longitude:       pgtypeNumericToFloat64Ptr(row.Latitude),
		Rating:          pgtypeNumericToFloat64Ptr(row.Rating),
	}
}
