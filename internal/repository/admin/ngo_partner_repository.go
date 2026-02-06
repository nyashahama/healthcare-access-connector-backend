package admin

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	ngoPartnerDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "ngo_partner_db_query_duration_seconds",
			Help:    "NGO partner database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	ngoPartnerDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ngo_partner_db_query_total",
			Help: "Total number of NGO partner database queries",
		},
		[]string{"operation", "status"},
	)
)

type ngoPartnerRepository struct {
	querier sqlc.Querier
}

func NewNGOPartnerRepository(pool *pgxpool.Pool) repository.NGOPartnerRepository {
	return NewNGOPartnerRepositoryWithQuerier(sqlc.New(pool))
}

func NewNGOPartnerRepositoryWithQuerier(querier sqlc.Querier) repository.NGOPartnerRepository {
	return &ngoPartnerRepository{
		querier: querier,
	}
}

// ===== Core CRUD Operations =====

func (r *ngoPartnerRepository) CreateNGOPartner(ctx context.Context, partner admin.NGOPartner) (admin.NGOPartner, error) {
	start := time.Now()
	defer func() {
		ngoPartnerDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	created, err := r.querier.CreateNGOPartner(ctx, sqlc.CreateNGOPartnerParams{
		UserID:               uuidToPgtypeUUID(partner.UserID),
		OrganizationName:     partner.OrganizationName,
		OrganizationType:     pgtypeTextFromStringPtr(partner.OrganizationType),
		RegistrationNumber:   pgtypeTextFromStringPtr(partner.RegistrationNumber),
		TaxID:                pgtypeTextFromStringPtr(partner.TaxID),
		OrganizationAddress:  pgtypeTextFromStringPtr(partner.OrganizationAddress),
		OrganizationPhone:    pgtypeTextFromStringPtr(partner.OrganizationPhone),
		OrganizationEmail:    pgtypeTextFromStringPtr(partner.OrganizationEmail),
		Website:              pgtypeTextFromStringPtr(partner.Website),
		ContactPersonName:    pgtypeTextFromStringPtr(partner.ContactPersonName),
		ContactPersonRole:    pgtypeTextFromStringPtr(partner.ContactPersonRole),
		ContactPersonPhone:   pgtypeTextFromStringPtr(partner.ContactPersonPhone),
		ContactPersonEmail:   pgtypeTextFromStringPtr(partner.ContactPersonEmail),
		PartnershipType:      pgtypeTextFromStringPtr(partner.PartnershipType),
		PartnershipStartDate: datePtrToPgtypeDate(partner.PartnershipStartDate),
		PartnershipEndDate:   datePtrToPgtypeDate(partner.PartnershipEndDate),
		PartnershipStatus:    pgtypeTextFromString(partner.PartnershipStatus),
		OperatingRegions:     partner.OperatingRegions,
		FocusAreas:           partner.FocusAreas,
		CanAccessReports:     pgtype.Bool{Bool: partner.CanAccessReports, Valid: true},
		ReportAccessLevel:    pgtypeTextFromStringPtr(partner.ReportAccessLevel),
		CustomReportFilters:  interfaceToPgtypeJSON(partner.CustomReportFilters),
		LogoUrl:              pgtypeTextFromStringPtr(partner.LogoURL),
		BrandingColor:        pgtypeTextFromStringPtr(partner.BrandingColor),
	})
	if err != nil {
		ngoPartnerDBQueryTotal.WithLabelValues("create_ngo_partner", "error").Inc()
		return admin.NGOPartner{}, r.handleError(err, "create ngo partner")
	}

	ngoPartnerDBQueryTotal.WithLabelValues("create_ngo_partner", "success").Inc()
	return r.mapToNGOPartner(created), nil
}

func (r *ngoPartnerRepository) GetNGOPartnerByUserID(ctx context.Context, userID uuid.UUID) (admin.NGOPartner, error) {
	start := time.Now()
	defer func() {
		ngoPartnerDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetNGOPartnerByUserID(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		ngoPartnerDBQueryTotal.WithLabelValues("get_ngo_partner_by_user_id", "error").Inc()
		return admin.NGOPartner{}, r.handleError(err, "get ngo partner by user id")
	}

	ngoPartnerDBQueryTotal.WithLabelValues("get_ngo_partner_by_user_id", "success").Inc()
	return r.mapToNGOPartner(row), nil
}

// ===== Helper Functions =====

func (r *ngoPartnerRepository) mapToNGOPartner(row sqlc.NgoPartner) admin.NGOPartner {
	return admin.NGOPartner{
		ID:                   pgtypeUUIDToUUID(row.ID),
		UserID:               pgtypeUUIDToUUID(row.UserID),
		OrganizationName:     row.OrganizationName,
		OrganizationType:     pgtypeTextToStringPtr(row.OrganizationType),
		RegistrationNumber:   pgtypeTextToStringPtr(row.RegistrationNumber),
		TaxID:                pgtypeTextToStringPtr(row.TaxID),
		OrganizationAddress:  pgtypeTextToStringPtr(row.OrganizationAddress),
		OrganizationPhone:    pgtypeTextToStringPtr(row.OrganizationPhone),
		OrganizationEmail:    pgtypeTextToStringPtr(row.OrganizationEmail),
		Website:              pgtypeTextToStringPtr(row.Website),
		ContactPersonName:    pgtypeTextToStringPtr(row.ContactPersonName),
		ContactPersonRole:    pgtypeTextToStringPtr(row.ContactPersonRole),
		ContactPersonPhone:   pgtypeTextToStringPtr(row.ContactPersonPhone),
		ContactPersonEmail:   pgtypeTextToStringPtr(row.ContactPersonEmail),
		PartnershipType:      pgtypeTextToStringPtr(row.PartnershipType),
		PartnershipStartDate: pgtypeDateToTimePtr(row.PartnershipStartDate),
		PartnershipEndDate:   pgtypeDateToTimePtr(row.PartnershipEndDate),
		PartnershipStatus:    pgtypeTextToString(row.PartnershipStatus),
		OperatingRegions:     row.OperatingRegions,
		FocusAreas:           row.FocusAreas,
		CanAccessReports:     pgtypeBoolToBool(row.CanAccessReports),
		ReportAccessLevel:    pgtypeTextToStringPtr(row.ReportAccessLevel),
		CustomReportFilters:  pgtypeJSONToInterface(row.CustomReportFilters),
		LogoURL:              pgtypeTextToStringPtr(row.LogoUrl),
		BrandingColor:        pgtypeTextToStringPtr(row.BrandingColor),
		CreatedAt:            row.CreatedAt.Time,
		UpdatedAt:            row.UpdatedAt.Time,
	}
}

func (r *ngoPartnerRepository) handleError(err error, operation string) error {
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	return fmt.Errorf("%s: %w", operation, err)
}
