package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	consentDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "consent_db_query_duration_seconds",
			Help:    "Consent database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	consentDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "consent_db_query_total",
			Help: "Total number of consent database queries",
		},
		[]string{"operation", "status"},
	)
)

type consentRepository struct {
	querier sqlc.Querier
}

// NewConsentRepository creates a new consent repository using a pool
func NewConsentRepository(pool *pgxpool.Pool) repository.ConsentRepository {
	return NewConsentRepositoryWithQuerier(sqlc.New(pool))
}

// NewConsentRepositoryWithQuerier creates a new consent repository using a provided querier (for transactions)
func NewConsentRepositoryWithQuerier(querier sqlc.Querier) repository.ConsentRepository {
	return &consentRepository{
		querier: querier,
	}
}

func (r *consentRepository) CreatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) (core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var ipAddr *netip.Addr
	if consent.IPAddress != nil {
		addr, err := netip.ParseAddr(*consent.IPAddress)
		if err == nil {
			ipAddr = &addr
		}
	}

	created, err := r.querier.CreatePrivacyConsent(ctx, sqlc.CreatePrivacyConsentParams{
		UserID:                    uuidToPgtypeUUID(consent.UserID),
		HealthDataConsent:         pgtype.Bool{Bool: consent.HealthDataConsent, Valid: true},
		HealthDataConsentDate:     timePtrToPgtypeTimestamp(consent.HealthDataConsentDate),
		HealthDataConsentVersion:  pgtypeTextFromStringPtr(consent.HealthDataConsentVersion),
		EmergencyAccessConsent:    pgtype.Bool{Bool: consent.EmergencyAccessConsent, Valid: true},
		SmsCommunicationConsent:   pgtype.Bool{Bool: consent.SMSCommunicationConsent, Valid: true},
		EmailCommunicationConsent: pgtype.Bool{Bool: consent.EmailCommunicationConsent, Valid: true},
		IpAddress:                 ipAddr,
		UserAgent:                 pgtypeTextFromStringPtr(consent.UserAgent), // This should be *string
	})
	if err != nil {
		consentDBQueryTotal.WithLabelValues("create_privacy_consent", "error").Inc()
		return core.PrivacyConsent{}, r.handleError(err, "create privacy consent")
	}

	consentDBQueryTotal.WithLabelValues("create_privacy_consent", "success").Inc()
	return r.mapToPrivacyConsentFromCreate(created), nil
}

func (r *consentRepository) GetPrivacyConsent(ctx context.Context, userID uuid.UUID) (core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	consent, err := r.querier.GetPrivacyConsent(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			consentDBQueryTotal.WithLabelValues("get_privacy_consent", "not_found").Inc()
			return core.PrivacyConsent{}, domain.ErrNotFound
		}
		consentDBQueryTotal.WithLabelValues("get_privacy_consent", "error").Inc()
		return core.PrivacyConsent{}, r.handleError(err, "get privacy consent")
	}

	consentDBQueryTotal.WithLabelValues("get_privacy_consent", "success").Inc()
	return r.mapToPrivacyConsent(consent), nil
}

func (r *consentRepository) UpdatePrivacyConsent(ctx context.Context, consent core.PrivacyConsent) error {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Convert data_sharing_consent and special_categories_consent to []byte
	dataSharingBytes, err := mapToJSONB(consent.DataSharingConsent)
	if err != nil {
		consentDBQueryTotal.WithLabelValues("update_privacy_consent", "error").Inc()
		return fmt.Errorf("convert data sharing consent: %w", err)
	}

	err = r.querier.UpdatePrivacyConsent(ctx, sqlc.UpdatePrivacyConsentParams{
		UserID:                    uuidToPgtypeUUID(consent.UserID),
		HealthDataConsent:         boolToPgtypeBool(consent.HealthDataConsent),
		ResearchConsent:           boolToPgtypeBool(consent.ResearchConsent),
		SmsCommunicationConsent:   boolToPgtypeBool(consent.SMSCommunicationConsent),
		EmailCommunicationConsent: boolToPgtypeBool(consent.EmailCommunicationConsent),
		DataSharingConsent:        dataSharingBytes,
	})
	if err != nil {
		consentDBQueryTotal.WithLabelValues("update_privacy_consent", "error").Inc()
		return r.handleError(err, "update privacy consent")
	}

	consentDBQueryTotal.WithLabelValues("update_privacy_consent", "success").Inc()
	return nil
}

// handleError converts database errors to domain errors
func (r *consentRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return fmt.Errorf("consent record already exists: %w", err)
		case "23503": // foreign_key_violation
			return fmt.Errorf("foreign key violation: %w", err)
		case "23514": // check_violation
			return fmt.Errorf("check constraint violation: %w", err)
		}
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

// Helper mapping functions
func (r *consentRepository) mapToPrivacyConsentFromCreate(row sqlc.CreatePrivacyConsentRow) core.PrivacyConsent {
	return core.PrivacyConsent{
		ID:                pgtypeUUIDToUUID(row.ID),
		UserID:            pgtypeUUIDToUUID(row.UserID),
		HealthDataConsent: pgtypeBoolToBool(row.HealthDataConsent),
		CreatedAt:         row.CreatedAt.Time,
	}
}

func (r *consentRepository) mapToPrivacyConsent(row sqlc.PrivacyConsent) core.PrivacyConsent {
	var ipAddr *string
	if row.IpAddress != nil {
		addrStr := row.IpAddress.String()
		ipAddr = &addrStr
	}
	return core.PrivacyConsent{
		ID:                         pgtypeUUIDToUUID(row.ID),
		UserID:                     pgtypeUUIDToUUID(row.UserID),
		HealthDataConsent:          pgtypeBoolToBool(row.HealthDataConsent),
		HealthDataConsentDate:      pgtypeTimestampToTimePtr(row.HealthDataConsentDate),
		HealthDataConsentVersion:   pgtypeTextToStringPtr(row.HealthDataConsentVersion),
		ResearchConsent:            pgtypeBoolToBool(row.ResearchConsent),
		ResearchConsentDate:        pgtypeTimestampToTimePtr(row.ResearchConsentDate),
		EmergencyAccessConsent:     pgtypeBoolToBool(row.EmergencyAccessConsent),
		EmergencyAccessConsentDate: pgtypeTimestampToTimePtr(row.EmergencyAccessConsentDate),
		SMSCommunicationConsent:    pgtypeBoolToBool(row.SmsCommunicationConsent),
		EmailCommunicationConsent:  pgtypeBoolToBool(row.EmailCommunicationConsent),
		DataSharingConsent:         jsonbToMap(row.DataSharingConsent),
		SpecialCategoriesConsent:   jsonbToMap(row.SpecialCategoriesConsent),
		ConsentWithdrawn:           pgtypeBoolToBool(row.ConsentWithdrawn),
		ConsentWithdrawnDate:       pgtypeTimestampToTimePtr(row.ConsentWithdrawnDate),
		WithdrawalReason:           pgtypeTextToStringPtr(row.WithdrawalReason),
		IPAddress:                  ipAddr,
		UserAgent:                  pgtypeTextToStringPtr(row.UserAgent),
		CreatedAt:                  row.CreatedAt.Time,
		UpdatedAt:                  row.UpdatedAt.Time,
	}
}
