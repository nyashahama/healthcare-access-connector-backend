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
	pool    *pgxpool.Pool
}

// NewCredentialRepository creates a new credential repository using a pool
func NewCredentialRepository(pool *pgxpool.Pool) repository.CredentialRepository {
	return &credentialRepository{
		querier: sqlc.New(pool),
		pool:    pool,
	}
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
		Status:           credential.Status,
		VerifiedBy:       uuidPtrToPgtypeUUID(credential.VerifiedBy),
		VerificationDate: timePtrToPgtypeTimestamp(credential.VerificationDate),
		DocumentURL:      pgtypeTextFromStringPtr(credential.DocumentURL),
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

func (r *credentialRepository) GetCredentialByID(ctx context.Context, id uuid.UUID) (providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	c, err := r.querier.GetCredentialByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows) {
			credentialDBQueryTotal.WithLabelValues("get_credential_by_id", "not_found").Inc()
			return providers.ProfessionalCredential{}, domain.ErrCredentialNotFound
		}
		credentialDBQueryTotal.WithLabelValues("get_credential_by_id", "error").Inc()
		return providers.ProfessionalCredential{}, err
	}

	credentialDBQueryTotal.WithLabelValues("get_credential_by_id", "success").Inc()
	return r.mapToProfessionalCredential(c), nil
}

func (r *credentialRepository) UpdateCredential(ctx context.Context, credential providers.ProfessionalCredential) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateCredentialParams{
		ID:               uuidToPgtypeUUID(credential.ID),
		CredentialType:   pgtypeTextFromString(&credential.CredentialType),
		CredentialNumber: pgtypeTextFromStringPtr(credential.CredentialNumber),
		IssuingAuthority: pgtypeTextFromString(&credential.IssuingAuthority),
		IssueDate:        datePtrToPgtypeDate(credential.IssueDate),
		ExpiryDate:       datePtrToPgtypeDate(credential.ExpiryDate),
		Status:           pgtypeTextFromString(&credential.Status),
		DocumentURL:      pgtypeTextFromStringPtr(credential.DocumentURL),
		Notes:            pgtypeTextFromStringPtr(credential.Notes),
	}

	err := r.querier.UpdateCredential(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("update_credential", "error").Inc()
		return r.handleError(err, "update credential")
	}

	credentialDBQueryTotal.WithLabelValues("update_credential", "success").Inc()
	return nil
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
// VERIFICATION & STATUS MANAGEMENT
// ============================================

func (r *credentialRepository) VerifyCredential(ctx context.Context, id, verifiedBy uuid.UUID, notes *string) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.VerifyCredentialParams{
		ID:         uuidToPgtypeUUID(id),
		VerifiedBy: uuidToPgtypeUUID(verifiedBy),
		Notes:      pgtypeTextFromStringPtr(notes),
	}

	err := r.querier.VerifyCredential(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("verify_credential", "error").Inc()
		return r.handleError(err, "verify credential")
	}

	credentialDBQueryTotal.WithLabelValues("verify_credential", "success").Inc()
	return nil
}

func (r *credentialRepository) RejectCredential(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.RejectCredentialParams{
		ID:         uuidToPgtypeUUID(id),
		VerifiedBy: uuidToPgtypeUUID(verifiedBy),
		Notes:      pgtypeTextFromString(&notes),
	}

	err := r.querier.RejectCredential(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("reject_credential", "error").Inc()
		return r.handleError(err, "reject credential")
	}

	credentialDBQueryTotal.WithLabelValues("reject_credential", "success").Inc()
	return nil
}

func (r *credentialRepository) RevokeCredential(ctx context.Context, id uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.RevokeCredentialParams{
		ID:    uuidToPgtypeUUID(id),
		Notes: pgtypeTextFromString(&notes),
	}

	err := r.querier.RevokeCredential(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("revoke_credential", "error").Inc()
		return r.handleError(err, "revoke credential")
	}

	credentialDBQueryTotal.WithLabelValues("revoke_credential", "success").Inc()
	return nil
}

func (r *credentialRepository) MarkCredentialExpired(ctx context.Context, id uuid.UUID) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.MarkCredentialExpired(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("mark_credential_expired", "error").Inc()
		return r.handleError(err, "mark credential expired")
	}

	credentialDBQueryTotal.WithLabelValues("mark_credential_expired", "success").Inc()
	return nil
}

func (r *credentialRepository) UpdateCredentialStatus(ctx context.Context, id uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateCredentialStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtypeTextFromString(status),
	}

	err := r.querier.UpdateCredentialStatus(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("update_credential_status", "error").Inc()
		return r.handleError(err, "update credential status")
	}

	credentialDBQueryTotal.WithLabelValues("update_credential_status", "success").Inc()
	return nil
}

func (r *credentialRepository) RenewCredential(ctx context.Context, id uuid.UUID, expiryDate time.Time) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.RenewCredentialParams{
		ID:         uuidToPgtypeUUID(id),
		ExpiryDate: pgtype.Date{Time: expiryDate, Valid: true},
	}

	err := r.querier.RenewCredential(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("renew_credential", "error").Inc()
		return r.handleError(err, "renew credential")
	}

	credentialDBQueryTotal.WithLabelValues("renew_credential", "success").Inc()
	return nil
}

// ============================================
// CREDENTIAL DETAILS MANAGEMENT
// ============================================

func (r *credentialRepository) UpdateCredentialNumber(ctx context.Context, id uuid.UUID, credentialNumber string) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateCredentialNumberParams{
		ID:               uuidToPgtypeUUID(id),
		CredentialNumber: pgtypeTextFromString(credentialNumber),
	}

	err := r.querier.UpdateCredentialNumber(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("update_credential_number", "error").Inc()
		return r.handleError(err, "update credential number")
	}

	credentialDBQueryTotal.WithLabelValues("update_credential_number", "success").Inc()
	return nil
}

func (r *credentialRepository) UpdateCredentialExpiry(ctx context.Context, id uuid.UUID, expiryDate time.Time) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateCredentialExpiryParams{
		ID:         uuidToPgtypeUUID(id),
		ExpiryDate: pgtype.Date{Time: expiryDate, Valid: true},
	}

	err := r.querier.UpdateCredentialExpiry(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("update_credential_expiry", "error").Inc()
		return r.handleError(err, "update credential expiry")
	}

	credentialDBQueryTotal.WithLabelValues("update_credential_expiry", "success").Inc()
	return nil
}

func (r *credentialRepository) UpdateCredentialDocument(ctx context.Context, id uuid.UUID, documentURL string) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateCredentialDocumentParams{
		ID:          uuidToPgtypeUUID(id),
		DocumentURL: pgtypeTextFromString(documentURL),
	}

	err := r.querier.UpdateCredentialDocument(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("update_credential_document", "error").Inc()
		return r.handleError(err, "update credential document")
	}

	credentialDBQueryTotal.WithLabelValues("update_credential_document", "success").Inc()
	return nil
}

func (r *credentialRepository) UpdateCredentialNotes(ctx context.Context, id uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateCredentialNotesParams{
		ID:    uuidToPgtypeUUID(id),
		Notes: pgtypeTextFromString(notes),
	}

	err := r.querier.UpdateCredentialNotes(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("update_credential_notes", "error").Inc()
		return r.handleError(err, "update credential notes")
	}

	credentialDBQueryTotal.WithLabelValues("update_credential_notes", "success").Inc()
	return nil
}

func (r *credentialRepository) UpdateCredentialDates(ctx context.Context, id uuid.UUID, issueDate, expiryDate time.Time) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.UpdateCredentialDatesParams{
		ID:         uuidToPgtypeUUID(id),
		IssueDate:  pgtype.Date{Time: issueDate, Valid: true},
		ExpiryDate: pgtype.Date{Time: expiryDate, Valid: true},
	}

	err := r.querier.UpdateCredentialDates(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("update_credential_dates", "error").Inc()
		return r.handleError(err, "update credential dates")
	}

	credentialDBQueryTotal.WithLabelValues("update_credential_dates", "success").Inc()
	return nil
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

func (r *credentialRepository) GetVerifiedStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetVerifiedStaffCredentials(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_verified_staff_credentials", "error").Inc()
		return nil, r.handleError(err, "get verified staff credentials")
	}

	credentials := make([]providers.ProfessionalCredential, len(rows))
	for i, row := range rows {
		credentials[i] = r.mapToProfessionalCredential(row)
	}

	credentialDBQueryTotal.WithLabelValues("get_verified_staff_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetActiveStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetActiveStaffCredentials(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_active_staff_credentials", "error").Inc()
		return nil, r.handleError(err, "get active staff credentials")
	}

	credentials := make([]providers.ProfessionalCredential, len(rows))
	for i, row := range rows {
		credentials[i] = providers.ProfessionalCredential{
			ID:               pgtypeUUIDToUUID(row.ID),
			StaffID:          staffID,
			CredentialType:   row.CredentialType,
			CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
			IssuingAuthority: row.IssuingAuthority,
			ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_active_staff_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetStaffCredentialsByType(ctx context.Context, staffID uuid.UUID, credentialType string) ([]providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetStaffCredentialsByTypeParams{
		StaffID:        uuidToPgtypeUUID(staffID),
		CredentialType: credentialType,
	}

	rows, err := r.querier.GetStaffCredentialsByType(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_staff_credentials_by_type", "error").Inc()
		return nil, r.handleError(err, "get staff credentials by type")
	}

	credentials := make([]providers.ProfessionalCredential, len(rows))
	for i, row := range rows {
		credentials[i] = providers.ProfessionalCredential{
			ID:               pgtypeUUIDToUUID(row.ID),
			StaffID:          staffID,
			CredentialType:   credentialType,
			CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
			IssuingAuthority: row.IssuingAuthority,
			IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
			ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
			Status:           row.Status,
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_staff_credentials_by_type", "success").Inc()
	return credentials, nil
}

// ============================================
// CREDENTIAL TYPE QUERIES
// ============================================

func (r *credentialRepository) GetCredentialsByType(ctx context.Context, credentialType string) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetCredentialsByType(ctx, credentialType)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_credentials_by_type", "error").Inc()
		return nil, r.handleError(err, "get credentials by type")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   credentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
				ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
				Status:           row.Status,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
				ClinicID:  pgtypeUUIDToUUID(row.ClinicID),
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_credentials_by_type", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetLicenseCredentials(ctx context.Context, clinicID *uuid.UUID) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	var pgtypeClinicID pgtype.UUID
	if clinicID != nil {
		pgtypeClinicID = uuidToPgtypeUUID(*clinicID)
	}

	rows, err := r.querier.GetLicenseCredentials(ctx, pgtypeClinicID)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_license_credentials", "error").Inc()
		return nil, r.handleError(err, "get license credentials")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   "professional_license",
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
				Status:           row.Status,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
				ClinicID:  pgtypeUUIDToUUID(row.ClinicID),
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_license_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetSpecializationCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetSpecializationCredentials(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_specialization_credentials", "error").Inc()
		return nil, r.handleError(err, "get specialization credentials")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   "specialization",
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
				Status:           row.Status,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_specialization_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetDegreeCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetDegreeCredentials(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_degree_credentials", "error").Inc()
		return nil, r.handleError(err, "get degree credentials")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   "degree",
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_degree_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetCertificationCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetCertificationCredentials(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_certification_credentials", "error").Inc()
		return nil, r.handleError(err, "get certification credentials")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   "certification",
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
				ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
				Status:           row.Status,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_certification_credentials", "success").Inc()
	return credentials, nil
}

// ============================================
// VERIFICATION WORKFLOWS
// ============================================

func (r *credentialRepository) GetPendingCredentialVerifications(ctx context.Context) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPendingCredentialVerifications(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_pending_credential_verifications", "error").Inc()
		return nil, r.handleError(err, "get pending credential verifications")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   row.CredentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
				ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
				DocumentURL:      pgtypeTextToStringPtr(row.DocumentUrl),
				Notes:            pgtypeTextToStringPtr(row.Notes),
				CreatedAt:        row.CreatedAt.Time,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
				ClinicID:  pgtypeUUIDToUUID(row.ClinicID),
				WorkEmail: pgtypeTextToStringPtr(row.WorkEmail),
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_pending_credential_verifications", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetPendingCredentialsByClinic(ctx context.Context, clinicID uuid.UUID) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetPendingCredentialsByClinic(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_pending_credentials_by_clinic", "error").Inc()
		return nil, r.handleError(err, "get pending credentials by clinic")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   row.CredentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				CreatedAt:        row.CreatedAt.Time,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
				WorkEmail: pgtypeTextToStringPtr(row.WorkEmail),
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_pending_credentials_by_clinic", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetVerifiedCredentialsByDateRange(ctx context.Context, startDate, endDate time.Time) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	// Since there's no direct query for date range, we'll get all recently verified and filter
	rows, err := r.querier.GetRecentlyVerifiedCredentials(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_verified_credentials_by_date_range", "error").Inc()
		return nil, r.handleError(err, "get verified credentials by date range")
	}

	// Filter by date range
	var filtered []providers.CredentialWithStaff
	for _, row := range rows {
		if row.VerificationDate.Valid {
			verificationDate := row.VerificationDate.Time
			if (verificationDate.After(startDate) || verificationDate.Equal(startDate)) &&
				(verificationDate.Before(endDate) || verificationDate.Equal(endDate)) {
				filtered = append(filtered, providers.CredentialWithStaff{
					Credential: providers.ProfessionalCredential{
						ID:               pgtypeUUIDToUUID(row.ID),
						StaffID:          pgtypeUUIDToUUID(row.StaffID),
						CredentialType:   row.CredentialType,
						CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
						VerifiedBy:       uuidPtrToUUID(row.VerifiedBy),
						VerificationDate: &verificationDate,
					},
					StaffInfo: providers.StaffBasicInfo{
						ID:        pgtypeUUIDToUUID(row.StaffID),
						FirstName: row.FirstName,
						LastName:  row.LastName,
						ClinicID:  pgtypeUUIDToUUID(row.ClinicID),
					},
				})
			}
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_verified_credentials_by_date_range", "success").Inc()
	return filtered, nil
}

// ============================================
// EXPIRATION MANAGEMENT
// ============================================

func (r *credentialRepository) GetExpiringCredentials(ctx context.Context, daysUntilExpiry int) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetCredentialsExpiringWithinDays(ctx, int32(daysUntilExpiry))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_expiring_credentials", "error").Inc()
		return nil, r.handleError(err, "get expiring credentials")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   row.CredentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
				ClinicID:  pgtypeUUIDToUUID(row.ClinicID),
				WorkEmail: pgtypeTextToStringPtr(row.WorkEmail),
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_expiring_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetExpiredCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetExpiredCredentials(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_expired_credentials", "error").Inc()
		return nil, r.handleError(err, "get expired credentials")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   row.CredentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
				ClinicID:  pgtypeUUIDToUUID(row.ClinicID),
				WorkEmail: pgtypeTextToStringPtr(row.WorkEmail),
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_expired_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetClinicExpiredCredentials(ctx context.Context, clinicID uuid.UUID) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetExpiredCredentialsByClinic(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_clinic_expired_credentials", "error").Inc()
		return nil, r.handleError(err, "get clinic expired credentials")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   row.CredentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
				WorkEmail: pgtypeTextToStringPtr(row.WorkEmail),
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_clinic_expired_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) AutoExpireCredentials(ctx context.Context) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.AutoExpireCredentials(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("auto_expire_credentials", "error").Inc()
		return r.handleError(err, "auto expire credentials")
	}

	credentialDBQueryTotal.WithLabelValues("auto_expire_credentials", "success").Inc()
	return nil
}

// ============================================
// ISSUING AUTHORITY QUERIES
// ============================================

func (r *credentialRepository) GetCredentialsByAuthority(ctx context.Context, issuingAuthority string) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetCredentialsByAuthority(ctx, issuingAuthority)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_credentials_by_authority", "error").Inc()
		return nil, r.handleError(err, "get credentials by authority")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   row.CredentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
				ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
				Status:           row.Status,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_credentials_by_authority", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetCredentialsByAuthorityAndType(ctx context.Context, issuingAuthority, credentialType string) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetCredentialsByAuthorityAndTypeParams{
		IssuingAuthority: issuingAuthority,
		CredentialType:   credentialType,
	}

	rows, err := r.querier.GetCredentialsByAuthorityAndType(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_credentials_by_authority_and_type", "error").Inc()
		return nil, r.handleError(err, "get credentials by authority and type")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   credentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
				ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
				Status:           row.Status,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_credentials_by_authority_and_type", "success").Inc()
	return credentials, nil
}

// ============================================
// STATISTICS & ANALYTICS
// ============================================

func (r *credentialRepository) GetCredentialStatistics(ctx context.Context, staffID uuid.UUID) (providers.CredentialStatistics, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetCredentialStatistics(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_credential_statistics", "error").Inc()
		return providers.CredentialStatistics{}, r.handleError(err, "get credential statistics")
	}

	stats := providers.CredentialStatistics{
		TotalCredentials: row.TotalCredentials,
		VerifiedCount:    row.VerifiedCount,
		PendingCount:     row.PendingCount,
		ExpiredCount:     row.ExpiredCount,
		RevokedCount:     row.RevokedCount,
		RejectedCount:    row.RejectedCount,
		OverdueRenewals:  row.OverdueRenewals,
	}

	credentialDBQueryTotal.WithLabelValues("get_credential_statistics", "success").Inc()
	return stats, nil
}

func (r *credentialRepository) GetClinicCredentialMetrics(ctx context.Context, clinicID uuid.UUID) (providers.ClinicCredentialMetrics, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetClinicCredentialMetrics(ctx, uuidToPgtypeUUID(clinicID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_clinic_credential_metrics", "error").Inc()
		return providers.ClinicCredentialMetrics{}, r.handleError(err, "get clinic credential metrics")
	}

	var avgDuration *float64
	if row.AvgCredentialDuration.Valid {
		avgDuration = &row.AvgCredentialDuration.Float64
	}

	metrics := providers.ClinicCredentialMetrics{
		TotalCredentials:      row.TotalCredentials,
		VerifiedCredentials:   row.VerifiedCredentials,
		PendingCredentials:    row.PendingCredentials,
		ExpiredCredentials:    row.ExpiredCredentials,
		StaffWithCredentials:  row.StaffWithCredentials,
		AvgCredentialDuration: avgDuration,
	}

	credentialDBQueryTotal.WithLabelValues("get_clinic_credential_metrics", "success").Inc()
	return metrics, nil
}

func (r *credentialRepository) GetCredentialTypeDistribution(ctx context.Context, staffID uuid.UUID) ([]providers.CredentialTypeDistribution, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetCredentialTypeDistribution(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_credential_type_distribution", "error").Inc()
		return nil, r.handleError(err, "get credential type distribution")
	}

	distributions := make([]providers.CredentialTypeDistribution, len(rows))
	for i, row := range rows {
		distributions[i] = providers.CredentialTypeDistribution{
			CredentialType: row.CredentialType,
			Count:          row.Count,
			VerifiedCount:  row.VerifiedCount,
			ExpiredCount:   row.ExpiredCount,
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_credential_type_distribution", "success").Inc()
	return distributions, nil
}

func (r *credentialRepository) GetCredentialStatusDistribution(ctx context.Context, staffID uuid.UUID) ([]providers.CredentialStatusDistribution, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetCredentialStatusDistribution(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_credential_status_distribution", "error").Inc()
		return nil, r.handleError(err, "get credential status distribution")
	}

	distributions := make([]providers.CredentialStatusDistribution, len(rows))
	for i, row := range rows {
		distributions[i] = providers.CredentialStatusDistribution{
			Status:     row.Status,
			Count:      row.Count,
			WithExpiry: row.WithExpiry,
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_credential_status_distribution", "success").Inc()
	return distributions, nil
}

func (r *credentialRepository) GetSystemCredentialMetrics(ctx context.Context) (providers.SystemCredentialMetrics, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	row, err := r.querier.GetSystemCredentialMetrics(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_system_credential_metrics", "error").Inc()
		return providers.SystemCredentialMetrics{}, r.handleError(err, "get system credential metrics")
	}

	var avgVerificationTime *float64
	if row.AvgVerificationTimeDays.Valid {
		avgVerificationTime = &row.AvgVerificationTimeDays.Float64
	}

	metrics := providers.SystemCredentialMetrics{
		TotalCredentials:          row.TotalCredentials,
		TotalStaffWithCredentials: row.TotalStaffWithCredentials,
		VerifiedCredentials:       row.VerifiedCredentials,
		PendingVerifications:      row.PendingVerifications,
		ExpiredCredentials:        row.ExpiredCredentials,
		ExpiringSoon:              row.ExpiringSoon,
		UniqueAuthorities:         row.UniqueAuthorities,
		AvgVerificationTimeDays:   avgVerificationTime,
	}

	credentialDBQueryTotal.WithLabelValues("get_system_credential_metrics", "success").Inc()
	return metrics, nil
}

// ============================================
// COUNTING & EXISTENCE CHECKS
// ============================================

func (r *credentialRepository) CountStaffCredentials(ctx context.Context, staffID uuid.UUID, status *string) (int64, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CountStaffCredentialsParams{
		StaffID: uuidToPgtypeUUID(staffID),
		Status:  pgtypeTextFromStringPtr(status),
	}

	count, err := r.querier.CountStaffCredentials(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("count_staff_credentials", "error").Inc()
		return 0, r.handleError(err, "count staff credentials")
	}

	credentialDBQueryTotal.WithLabelValues("count_staff_credentials", "success").Inc()
	return count, nil
}

func (r *credentialRepository) CountCredentialsByType(ctx context.Context, staffID uuid.UUID, credentialType string) (int64, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CountCredentialsByTypeParams{
		StaffID:        uuidToPgtypeUUID(staffID),
		CredentialType: credentialType,
	}

	count, err := r.querier.CountCredentialsByType(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("count_credentials_by_type", "error").Inc()
		return 0, r.handleError(err, "count credentials by type")
	}

	credentialDBQueryTotal.WithLabelValues("count_credentials_by_type", "success").Inc()
	return count, nil
}

func (r *credentialRepository) CredentialExists(ctx context.Context, id uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	exists, err := r.querier.CredentialExists(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("credential_exists", "error").Inc()
		return false, r.handleError(err, "check credential exists")
	}

	credentialDBQueryTotal.WithLabelValues("credential_exists", "success").Inc()
	return exists, nil
}

func (r *credentialRepository) CheckCredentialNumberExists(ctx context.Context, credentialNumber, issuingAuthority string, excludeID *uuid.UUID) (bool, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.CheckCredentialNumberExistsParams{
		CredentialNumber: pgtypeTextFromString(credentialNumber),
		IssuingAuthority: issuingAuthority,
		ID:               uuidPtrToPgtypeUUID(excludeID),
	}

	exists, err := r.querier.CheckCredentialNumberExists(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("check_credential_number_exists", "error").Inc()
		return false, r.handleError(err, "check credential number exists")
	}

	credentialDBQueryTotal.WithLabelValues("check_credential_number_exists", "success").Inc()
	return exists, nil
}

func (r *credentialRepository) HasVerifiedCredentialOfType(ctx context.Context, staffID uuid.UUID, credentialType string) (bool, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	exists, err := r.querier.HasVerifiedCredentialOfType(ctx, uuidToPgtypeUUID(staffID), credentialType)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("has_verified_credential_of_type", "error").Inc()
		return false, r.handleError(err, "check has verified credential of type")
	}

	credentialDBQueryTotal.WithLabelValues("has_verified_credential_of_type", "success").Inc()
	return exists, nil
}

// ============================================
// BULK OPERATIONS
// ============================================

func (r *credentialRepository) GetCredentialsByIDs(ctx context.Context, ids []uuid.UUID) ([]providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	rows, err := r.querier.GetCredentialsByIDs(ctx, pgtypeIDs)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_credentials_by_ids", "error").Inc()
		return nil, r.handleError(err, "get credentials by ids")
	}

	credentials := make([]providers.ProfessionalCredential, len(rows))
	for i, row := range rows {
		credentials[i] = r.mapToProfessionalCredential(row)
	}

	credentialDBQueryTotal.WithLabelValues("get_credentials_by_ids", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) BulkVerifyCredentials(ctx context.Context, ids []uuid.UUID, verifiedBy uuid.UUID) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	params := sqlc.BulkVerifyCredentialsParams{
		IDs:        pgtypeIDs,
		VerifiedBy: uuidToPgtypeUUID(verifiedBy),
	}

	err := r.querier.BulkVerifyCredentials(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("bulk_verify_credentials", "error").Inc()
		return r.handleError(err, "bulk verify credentials")
	}

	credentialDBQueryTotal.WithLabelValues("bulk_verify_credentials", "success").Inc()
	return nil
}

func (r *credentialRepository) BulkRejectCredentials(ctx context.Context, ids []uuid.UUID, verifiedBy uuid.UUID, notes string) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	params := sqlc.BulkRejectCredentialsParams{
		IDs:        pgtypeIDs,
		VerifiedBy: uuidToPgtypeUUID(verifiedBy),
		Notes:      pgtypeTextFromString(notes),
	}

	err := r.querier.BulkRejectCredentials(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("bulk_reject_credentials", "error").Inc()
		return r.handleError(err, "bulk reject credentials")
	}

	credentialDBQueryTotal.WithLabelValues("bulk_reject_credentials", "success").Inc()
	return nil
}

func (r *credentialRepository) BulkUpdateCredentialStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	pgtypeIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgtypeIDs[i] = uuidToPgtypeUUID(id)
	}

	params := sqlc.BulkUpdateCredentialStatusParams{
		IDs:    pgtypeIDs,
		Status: status,
	}

	err := r.querier.BulkUpdateCredentialStatus(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("bulk_update_credential_status", "error").Inc()
		return r.handleError(err, "bulk update credential status")
	}

	credentialDBQueryTotal.WithLabelValues("bulk_update_credential_status", "success").Inc()
	return nil
}

func (r *credentialRepository) DeleteStaffCredentials(ctx context.Context, staffID uuid.UUID) error {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	err := r.querier.DeleteStaffCredentials(ctx, uuidToPgtypeUUID(staffID))
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("delete_staff_credentials", "error").Inc()
		return r.handleError(err, "delete staff credentials")
	}

	credentialDBQueryTotal.WithLabelValues("delete_staff_credentials", "success").Inc()
	return nil
}

// ============================================
// COMPLIANCE & REPORTING
// ============================================

func (r *credentialRepository) GetStaffWithoutRequiredCredentials(ctx context.Context) ([]providers.ClinicStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetStaffWithoutRequiredCredentials(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_staff_without_required_credentials", "error").Inc()
		return nil, r.handleError(err, "get staff without required credentials")
	}

	staffList := make([]providers.ClinicStaff, len(rows))
	for i, row := range rows {
		staffList[i] = providers.ClinicStaff{
			ID:                pgtypeUUIDToUUID(row.ID),
			ClinicID:          pgtypeUUIDToUUID(row.ClinicID),
			FirstName:         row.FirstName,
			LastName:          row.LastName,
			ProfessionalTitle: row.ProfessionalTitle,
			StaffRole:         row.StaffRole,
			WorkEmail:         pgtypeTextToStringPtr(row.WorkEmail),
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_staff_without_required_credentials", "success").Inc()
	return staffList, nil
}

func (r *credentialRepository) GetVerificationBacklog(ctx context.Context) ([]providers.VerificationBacklog, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetVerificationBacklog(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_verification_backlog", "error").Inc()
		return nil, r.handleError(err, "get verification backlog")
	}

	backlog := make([]providers.VerificationBacklog, len(rows))
	for i, row := range rows {
		var avgDaysPending *float64
		if row.AvgDaysPending.Valid {
			avgDaysPending = &row.AvgDaysPending.Float64
		}

		backlog[i] = providers.VerificationBacklog{
			SubmissionDate: row.SubmissionDate.Time,
			PendingCount:   row.PendingCount,
			AvgDaysPending: avgDaysPending,
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_verification_backlog", "success").Inc()
	return backlog, nil
}

func (r *credentialRepository) GetVerifierWorkload(ctx context.Context, startDate, endDate time.Time) ([]providers.VerifierWorkload, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetVerifierWorkloadParams{
		StartDate: pgtype.Timestamp{Time: startDate, Valid: true},
		EndDate:   pgtype.Timestamp{Time: endDate, Valid: true},
	}

	rows, err := r.querier.GetVerifierWorkload(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_verifier_workload", "error").Inc()
		return nil, r.handleError(err, "get verifier workload")
	}

	workloads := make([]providers.VerifierWorkload, len(rows))
	for i, row := range rows {
		workloads[i] = providers.VerifierWorkload{
			VerifierID:        pgtypeUUIDToUUID(row.VerifierID),
			VerifierEmail:     row.VerifierEmail,
			VerifiedCount:     row.VerifiedCount,
			FirstVerification: pgtypeTimestampToTimePtr(row.FirstVerification),
			LastVerification:  pgtypeTimestampToTimePtr(row.LastVerification),
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_verifier_workload", "success").Inc()
	return workloads, nil
}

func (r *credentialRepository) GetCredentialsByDateRange(ctx context.Context, startDate, endDate time.Time) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetCredentialsByDateRangeParams{
		StartDate: pgtype.Timestamp{Time: startDate, Valid: true},
		EndDate:   pgtype.Timestamp{Time: endDate, Valid: true},
	}

	rows, err := r.querier.GetCredentialsByDateRange(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_credentials_by_date_range", "error").Inc()
		return nil, r.handleError(err, "get credentials by date range")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   row.CredentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				Status:           row.Status,
				CreatedAt:        row.CreatedAt.Time,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
				ClinicID:  pgtypeUUIDToUUID(row.ClinicID),
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_credentials_by_date_range", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetRevokedCredentials(ctx context.Context) ([]providers.CredentialWithStaff, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	rows, err := r.querier.GetRevokedCredentials(ctx)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_revoked_credentials", "error").Inc()
		return nil, r.handleError(err, "get revoked credentials")
	}

	credentials := make([]providers.CredentialWithStaff, len(rows))
	for i, row := range rows {
		credentials[i] = providers.CredentialWithStaff{
			Credential: providers.ProfessionalCredential{
				ID:               pgtypeUUIDToUUID(row.ID),
				StaffID:          pgtypeUUIDToUUID(row.StaffID),
				CredentialType:   row.CredentialType,
				CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
				IssuingAuthority: row.IssuingAuthority,
				Notes:            pgtypeTextToStringPtr(row.Notes),
				UpdatedAt:        row.UpdatedAt.Time,
			},
			StaffInfo: providers.StaffBasicInfo{
				ID:        pgtypeUUIDToUUID(row.StaffID),
				FirstName: row.FirstName,
				LastName:  row.LastName,
				ClinicID:  pgtypeUUIDToUUID(row.ClinicID),
				WorkEmail: pgtypeTextToStringPtr(row.WorkEmail),
			},
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_revoked_credentials", "success").Inc()
	return credentials, nil
}

func (r *credentialRepository) GetCredentialRenewalHistory(ctx context.Context, staffID uuid.UUID, credentialType string) ([]providers.ProfessionalCredential, error) {
	start := time.Now()
	defer func() {
		credentialDBQueryDuration.Observe(time.Since(start).Seconds())
	}()

	params := sqlc.GetCredentialRenewalHistoryParams{
		StaffID:        uuidToPgtypeUUID(staffID),
		CredentialType: credentialType,
	}

	rows, err := r.querier.GetCredentialRenewalHistory(ctx, params)
	if err != nil {
		credentialDBQueryTotal.WithLabelValues("get_credential_renewal_history", "error").Inc()
		return nil, r.handleError(err, "get credential renewal history")
	}

	credentials := make([]providers.ProfessionalCredential, len(rows))
	for i, row := range rows {
		credentials[i] = providers.ProfessionalCredential{
			ID:               pgtypeUUIDToUUID(row.ID),
			StaffID:          staffID,
			CredentialType:   credentialType,
			CredentialNumber: pgtypeTextToStringPtr(row.CredentialNumber),
			IssueDate:        pgtypeDateToTimePtr(row.IssueDate),
			ExpiryDate:       pgtypeDateToTimePtr(row.ExpiryDate),
			Status:           row.Status,
			UpdatedAt:        row.UpdatedAt.Time,
		}
	}

	credentialDBQueryTotal.WithLabelValues("get_credential_renewal_history", "success").Inc()
	return credentials, nil
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
		Status:           row.Status,
		VerifiedBy:       uuidPtrToUUID(row.VerifiedBy),
		VerificationDate: pgtypeTimestampToTimePtr(row.VerificationDate),
		DocumentURL:      pgtypeTextToStringPtr(row.DocumentUrl),
		Notes:            pgtypeTextToStringPtr(row.Notes),
		CreatedAt:        row.CreatedAt.Time,
		UpdatedAt:        row.UpdatedAt.Time,
	}
}
