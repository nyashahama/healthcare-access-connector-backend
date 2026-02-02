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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// ============================================
// METRICS
// ============================================

var (
	credentialDBQueryDuration = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "credential_db_query_duration_seconds",
			Help:    "Credential database query latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
	)

	credentialDBQueryTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "credential_db_query_total",
			Help: "Total number of credential database queries",
		},
		[]string{"operation", "status"},
	)
)

// ============================================
// REPOSITORY IMPLEMENTATION
// ============================================

type credentialRepository struct {
	querier sqlc.Querier
}

// NewCredentialRepository creates a new credential repository using a pool
func NewCredentialRepository(pool *pgxpool.Pool) repository.CredentialRepository {
	return NewCredentialRepositoryWithQuerier(sqlc.New(pool))
}

// NewCredentialRepositoryWithQuerier creates a new credential repository using a provided querier (for transactions)
func NewCredentialRepositoryWithQuerier(querier sqlc.Querier) repository.CredentialRepository {
	return &credentialRepository{
		querier: querier,
	}
}

// ============================================
// CORE CRUD OPERATIONS
// ============================================

func (r *credentialRepository) CreateCredential(ctx context.Context, credential providers.ProfessionalCredential) (providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CreateCredentialParams{
		StaffID:          uuidToPgtypeUUID(credential.StaffID),
		CredentialType:   credential.CredentialType,
		CredentialNumber: pgtypeTextFromStringPtr(credential.CredentialNumber),
		IssuingAuthority: credential.IssuingAuthority,
		IssueDate:        datePtrToPgtypeDate(credential.IssueDate),
		ExpiryDate:       datePtrToPgtypeDate(credential.ExpiryDate),
		Status:           pgtypeTextFromString(credential.Status),
		VerifiedBy:       uuidPtrToPgtypeUUID(credential.VerifiedBy),
		VerificationDate: timePtrToPgtypeTimestamp(credential.VerificationDate),
		DocumentUrl:      pgtypeTextFromStringPtr(credential.DocumentURL),
		Notes:            pgtypeTextFromStringPtr(credential.Notes),
	}

	created, err := r.querier.CreateCredential(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("create_credential", "error").Inc()
		return providers.ProfessionalCredential{}, r.handleError(err, "create credential")
	}

	credentialDBQueryTotal.WithLabelValues("create_credential", "success").Inc()
	return r.mapToProfessionalCredential(created), nil
}

// ============================================
// QUERYING BY STAFF MEMBER
// ============================================

func (r *credentialRepository) GetStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaffCredentials(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_staff_credentials", "error").Inc()
		return nil, r.handleError(err, "get staff credentials")
	}

	credentials := make([]providers.ProfessionalCredential, len(rows))
	for i, row := range rows {
		credentials[i] = r.mapToProfessionalCredential(row)
	}

	credentialDBQueryTotal.WithLabelValues("get_staff_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) DeleteCredential(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteCredential(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("delete_credential", "error").Inc()
		return r.handleError(err, "delete credential")
	}

	credentialDBQueryTotal.WithLabelValues("delete_credential", "success").Inc()
	return nil
}

// ============================================
// ERROR HANDLING
// ============================================

func (r *credentialRepository) handleError(err error, operation string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			if strings.Contains(pgErr.ConstraintName, "credential_number") {
				return domain.ErrDuplicate
			}
			return fmt.Errorf("duplicate constraint violation: %w", err)
		case "23503": // foreign_key_violation
			return fmt.Errorf("foreign key violation: %w", err)
		case "23514": // check_violation
			return fmt.Errorf("check constraint violation: %w", err)
		}
	}

	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrCredentialNotFound
	}

	return fmt.Errorf("%s failed: %w", operation, err)
}

// ============================================
// MAPPING FUNCTIONS
// ============================================

func (r *credentialRepository) mapToProfessionalCredential(row sqlc.ProfessionalCredential) providers.ProfessionalCredential {
	return providers.ProfessionalCredential{
		ID:               pgtypeUUIDToUUID(row.ID),
		StaffID:          pgtypeUUIDToUUID(row.StaffID),
		CredentialType:   row.CredentialType,
		CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
		IssuingAuthority: row.IssuingAuthority,
		IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
		ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
		Status:           pgtypeTextToString(row.Status),
		VerifiedBy:       uuidPtrToUUID(row.VerifiedBy),
		VerificationDate: pgtypeTimestampToTimePtr(row.VerificationDate),
		DocumentURL:      pgtypeTextToStringPtr(row.DocumentUrl),
		Notes:            pgtypeTextToStringPtr(row.Notes),
		CreatedAt:        row.CreatedAt.Time,
		UpdatedAt:        row.UpdatedAt.Time,
	}
}
