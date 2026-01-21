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

func (r *consentRepository) WithdrawConsent(ctx context.Context, userID uuid.UUID, reason string) error {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.WithdrawConsent(ctx, sqlc.WithdrawConsentParams{
		UserID:           uuidToPgtypeUUID(userID),
		WithdrawalReason: pgtypeTextFromString(reason),
	})
	if err != nil {
		consentDBQueryTotal.WithLabelValues("withdraw_consent", "error").Inc()
		return r.handleError(err, "withdraw consent")
	}

	consentDBQueryTotal.WithLabelValues("withdraw_consent", "success").Inc()
	return nil
}

func (r *consentRepository) UpdateHealthDataConsent(ctx context.Context, userID uuid.UUID, consent bool, version string) error {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	now := time.Now()
	err := r.querier.UpdateHealthDataConsent(ctx, sqlc.UpdateHealthDataConsentParams{
		UserID:                   uuidToPgtypeUUID(userID),
		HealthDataConsent:        boolToPgtypeBool(consent),
		HealthDataConsentDate:    timeToPgtypeTimestamp(now),
		HealthDataConsentVersion: pgtypeTextFromString(version),
	})
	if err != nil {
		consentDBQueryTotal.WithLabelValues("update_health_data_consent", "error").Inc()
		return r.handleError(err, "update health data consent")
	}

	consentDBQueryTotal.WithLabelValues("update_health_data_consent", "success").Inc()
	return nil
}

func (r *consentRepository) UpdateResearchConsent(ctx context.Context, userID uuid.UUID, consent bool) error {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	now := time.Now()
	err := r.querier.UpdateResearchConsent(ctx, sqlc.UpdateResearchConsentParams{
		UserID:              uuidToPgtypeUUID(userID),
		ResearchConsent:     boolToPgtypeBool(consent),
		ResearchConsentDate: timeToPgtypeTimestamp(now),
	})
	if err != nil {
		consentDBQueryTotal.WithLabelValues("update_research_consent", "error").Inc()
		return r.handleError(err, "update research consent")
	}

	consentDBQueryTotal.WithLabelValues("update_research_consent", "success").Inc()
	return nil
}

func (r *consentRepository) UpdateEmergencyAccessConsent(ctx context.Context, userID uuid.UUID, consent bool) error {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	now := time.Now()
	err := r.querier.UpdateEmergencyAccessConsent(ctx, sqlc.UpdateEmergencyAccessConsentParams{
		UserID:                     uuidToPgtypeUUID(userID),
		EmergencyAccessConsent:     boolToPgtypeBool(consent),
		EmergencyAccessConsentDate: timeToPgtypeTimestamp(now),
	})
	if err != nil {
		consentDBQueryTotal.WithLabelValues("update_emergency_access_consent", "error").Inc()
		return r.handleError(err, "update emergency access consent")
	}

	consentDBQueryTotal.WithLabelValues("update_emergency_access_consent", "success").Inc()
	return nil
}

func (r *consentRepository) UpdateCommunicationConsents(ctx context.Context, userID uuid.UUID, sms, email bool) error {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.UpdateCommunicationConsents(ctx, sqlc.UpdateCommunicationConsentsParams{
		UserID:                    uuidToPgtypeUUID(userID),
		SmsCommunicationConsent:   boolToPgtypeBool(sms),
		EmailCommunicationConsent: boolToPgtypeBool(email),
	})
	if err != nil {
		consentDBQueryTotal.WithLabelValues("update_communication_consents", "error").Inc()
		return r.handleError(err, "update communication consents")
	}

	consentDBQueryTotal.WithLabelValues("update_communication_consents", "success").Inc()
	return nil
}

func (r *consentRepository) UpdateDataSharingConsent(ctx context.Context, userID uuid.UUID, sharingPrefs map[string]interface{}) error {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	dataSharingBytes, err := mapToJSONB(sharingPrefs)
	if err != nil {
		consentDBQueryTotal.WithLabelValues("update_data_sharing_consent", "error").Inc()
		return fmt.Errorf("convert data sharing preferences: %w", err)
	}

	err = r.querier.UpdateDataSharingConsent(ctx, sqlc.UpdateDataSharingConsentParams{
		UserID:             uuidToPgtypeUUID(userID),
		DataSharingConsent: dataSharingBytes,
	})
	if err != nil {
		consentDBQueryTotal.WithLabelValues("update_data_sharing_consent", "error").Inc()
		return r.handleError(err, "update data sharing consent")
	}

	consentDBQueryTotal.WithLabelValues("update_data_sharing_consent", "success").Inc()
	return nil
}

func (r *consentRepository) GetConsentHistory(ctx context.Context, userID uuid.UUID) ([]core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	consents, err := r.querier.GetConsentHistory(ctx, uuidToPgtypeUUID(userID))
	if err != nil {
		consentDBQueryTotal.WithLabelValues("get_consent_history", "error").Inc()
		return nil, r.handleError(err, "get consent history")
	}

	consentDBQueryTotal.WithLabelValues("get_consent_history", "success").Inc()

	result := make([]core.PrivacyConsent, len(consents))
	for i, c := range consents {
		result[i] = r.mapToPrivacyConsent(c)
	}

	return result, nil
}

func (r *consentRepository) GetActiveConsentsByType(ctx context.Context, consentType string) ([]core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var consents []sqlc.PrivacyConsent
	var err error

	switch consentType {
	case "health_data":
		consents, err = r.querier.GetActiveHealthDataConsents(ctx)
	case "research":
		consents, err = r.querier.GetActiveResearchConsents(ctx)
	case "emergency_access":
		consents, err = r.querier.GetActiveEmergencyAccessConsents(ctx)
	default:
		consentDBQueryTotal.WithLabelValues("get_active_consents_by_type", "error").Inc()
		return nil, fmt.Errorf("invalid consent type: %s", consentType)
	}

	if err != nil {
		consentDBQueryTotal.WithLabelValues("get_active_consents_by_type", "error").Inc()
		return nil, r.handleError(err, "get active consents by type")
	}

	consentDBQueryTotal.WithLabelValues("get_active_consents_by_type", "success").Inc()

	result := make([]core.PrivacyConsent, len(consents))
	for i, c := range consents {
		result[i] = r.mapToPrivacyConsent(c)
	}

	return result, nil
}

func (r *consentRepository) GetExpiredConsents(ctx context.Context) ([]core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	consents, err := r.querier.GetExpiredConsents(ctx)
	if err != nil {
		consentDBQueryTotal.WithLabelValues("get_expired_consents", "error").Inc()
		return nil, r.handleError(err, "get expired consents")
	}

	consentDBQueryTotal.WithLabelValues("get_expired_consents", "success").Inc()

	result := make([]core.PrivacyConsent, len(consents))
	for i, c := range consents {
		result[i] = r.mapToPrivacyConsent(c)
	}

	return result, nil
}

func (r *consentRepository) GetWithdrawnConsents(ctx context.Context, startDate, endDate time.Time) ([]core.PrivacyConsent, error) {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	consents, err := r.querier.GetWithdrawnConsents(ctx, sqlc.GetWithdrawnConsentsParams{
		ConsentWithdrawnDate:   timeToPgtypeTimestamp(startDate),
		ConsentWithdrawnDate_2: timeToPgtypeTimestamp(endDate),
	})
	if err != nil {
		consentDBQueryTotal.WithLabelValues("get_withdrawn_consents", "error").Inc()
		return nil, r.handleError(err, "get withdrawn consents")
	}

	consentDBQueryTotal.WithLabelValues("get_withdrawn_consents", "success").Inc()

	result := make([]core.PrivacyConsent, len(consents))
	for i, c := range consents {
		result[i] = r.mapToPrivacyConsent(c)
	}

	return result, nil
}

func (r *consentRepository) ExportConsentData(ctx context.Context, userID uuid.UUID) ([]byte, error) {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	consent, err := r.GetPrivacyConsent(ctx, userID)
	if err != nil {
		consentDBQueryTotal.WithLabelValues("export_consent_data", "error").Inc()
		return nil, err
	}

	consentDBQueryTotal.WithLabelValues("export_consent_data", "success").Inc()
	return jsonbToBytes(consent)
}

func (r *consentRepository) NotifyConsentExpirations(ctx context.Context, daysBefore int) ([]uuid.UUID, error) {
	start := time.Now()
	defer func() {
		consentDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	expirationDate := time.Now().AddDate(0, 0, daysBefore)
	userIDs, err := r.querier.GetConsentsExpiringBefore(ctx, timeToPgtypeTimestamp(expirationDate))
	if err != nil {
		consentDBQueryTotal.WithLabelValues("notify_consent_expirations", "error").Inc()
		return nil, r.handleError(err, "notify consent expirations")
	}

	consentDBQueryTotal.WithLabelValues("notify_consent_expirations", "success").Inc()

	result := make([]uuid.UUID, len(userIDs))
	for i, id := range userIDs {
		result[i] = pgtypeUUIDToUUID(id)
	}

	return result, nil
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
