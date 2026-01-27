-- ============================================
-- PROFESSIONAL CREDENTIALS REPOSITORY QUERIES
-- Maps to: Part of StaffRepository interface (credential methods)
-- Domain: Professional Licensing & Certification Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreateCredential :one
INSERT INTO professional_credentials (
    staff_id, credential_type, credential_number, issuing_authority,
    issue_date, expiry_date, status, verified_by, verification_date,
    document_url, notes
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: GetCredentialByID :one
SELECT * FROM professional_credentials
WHERE id = $1;

-- name: UpdateCredential :exec
UPDATE professional_credentials
SET 
    credential_type = COALESCE($2, credential_type),
    credential_number = COALESCE($3, credential_number),
    issuing_authority = COALESCE($4, issuing_authority),
    issue_date = COALESCE($5, issue_date),
    expiry_date = COALESCE($6, expiry_date),
    status = COALESCE($7, status),
    document_url = COALESCE($8, document_url),
    notes = COALESCE($9, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteCredential :exec
DELETE FROM professional_credentials 
WHERE id = $1;

-- ============================================
-- VERIFICATION & STATUS MANAGEMENT
-- ============================================

-- name: VerifyCredential :exec
UPDATE professional_credentials
SET 
    status = 'verified',
    verified_by = $2,
    verification_date = NOW(),
    notes = COALESCE($3, notes),
    updated_at = NOW()
WHERE id = $1;

-- name: RejectCredential :exec
UPDATE professional_credentials
SET 
    status = 'rejected',
    verified_by = $2,
    verification_date = NOW(),
    notes = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: RevokeCredential :exec
UPDATE professional_credentials
SET 
    status = 'revoked',
    notes = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: MarkCredentialExpired :exec
UPDATE professional_credentials
SET 
    status = 'expired',
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateCredentialStatus :exec
UPDATE professional_credentials
SET 
    status = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: RenewCredential :exec
UPDATE professional_credentials
SET 
    expiry_date = $2,
    status = 'verified',
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- CREDENTIAL DETAILS MANAGEMENT
-- ============================================

-- name: UpdateCredentialNumber :exec
UPDATE professional_credentials
SET 
    credential_number = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateCredentialExpiry :exec
UPDATE professional_credentials
SET 
    expiry_date = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateCredentialDocument :exec
UPDATE professional_credentials
SET 
    document_url = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateCredentialNotes :exec
UPDATE professional_credentials
SET 
    notes = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateCredentialDates :exec
UPDATE professional_credentials
SET 
    issue_date = $2,
    expiry_date = $3,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- QUERYING BY STAFF MEMBER
-- ============================================

-- name: GetStaffCredentials :many
SELECT 
    id, staff_id, credential_type, credential_number,
    issuing_authority, issue_date, expiry_date, status,
    verified_by, verification_date, document_url, notes,
    created_at, updated_at
FROM professional_credentials
WHERE staff_id = $1
ORDER BY 
    CASE status
        WHEN 'verified' THEN 1
        WHEN 'pending' THEN 2
        WHEN 'expired' THEN 3
        WHEN 'revoked' THEN 4
        WHEN 'rejected' THEN 5
        ELSE 6
    END,
    expiry_date ASC NULLS LAST,
    issue_date DESC;

-- name: GetVerifiedStaffCredentials :many
SELECT 
    id, credential_type, credential_number,
    issuing_authority, issue_date, expiry_date,
    verification_date, verified_by
FROM professional_credentials
WHERE 
    staff_id = $1
    AND status = 'verified'
ORDER BY issue_date DESC;

-- name: GetActiveStaffCredentials :many
SELECT 
    id, credential_type, credential_number,
    issuing_authority, expiry_date
FROM professional_credentials
WHERE 
    staff_id = $1
    AND status = 'verified'
    AND (expiry_date IS NULL OR expiry_date >= CURRENT_DATE)
ORDER BY credential_type;

-- name: GetStaffCredentialsByType :many
SELECT 
    id, credential_number, issuing_authority,
    issue_date, expiry_date, status
FROM professional_credentials
WHERE 
    staff_id = $1
    AND credential_type = $2
ORDER BY issue_date DESC;

-- ============================================
-- CREDENTIAL TYPE QUERIES
-- ============================================

-- name: GetCredentialsByType :many
SELECT 
    pc.id, pc.staff_id, pc.credential_number,
    pc.issuing_authority, pc.issue_date, pc.expiry_date, pc.status,
    cs.first_name, cs.last_name, cs.clinic_id
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE pc.credential_type = $1
ORDER BY pc.expiry_date ASC NULLS LAST;

-- name: GetLicenseCredentials :many
SELECT 
    pc.id, pc.staff_id, pc.credential_number,
    pc.issuing_authority, pc.expiry_date, pc.status,
    cs.first_name, cs.last_name, cs.clinic_id
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE 
    pc.credential_type = 'professional_license'
    AND ($1::uuid IS NULL OR cs.clinic_id = $1)
ORDER BY pc.expiry_date ASC NULLS LAST;

-- name: GetSpecializationCredentials :many
SELECT 
    pc.id, pc.staff_id, pc.credential_number,
    pc.issuing_authority, pc.issue_date, pc.status,
    cs.first_name, cs.last_name
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE pc.credential_type = 'specialization'
ORDER BY pc.issue_date DESC;

-- name: GetDegreeCredentials :many
SELECT 
    pc.id, pc.staff_id, pc.credential_number,
    pc.issuing_authority, pc.issue_date,
    cs.first_name, cs.last_name
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE pc.credential_type = 'degree'
ORDER BY pc.issue_date DESC;

-- name: GetCertificationCredentials :many
SELECT 
    pc.id, pc.staff_id, pc.credential_number,
    pc.issuing_authority, pc.issue_date, pc.expiry_date, pc.status,
    cs.first_name, cs.last_name
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE pc.credential_type = 'certification'
ORDER BY pc.expiry_date ASC NULLS LAST;

-- ============================================
-- VERIFICATION WORKFLOWS
-- ============================================

-- name: GetPendingCredentialVerifications :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type, pc.credential_number,
    pc.issuing_authority, pc.issue_date, pc.expiry_date,
    pc.document_url, pc.notes, pc.created_at,
    cs.first_name, cs.last_name, cs.clinic_id, cs.work_email
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE pc.status = 'pending'
ORDER BY pc.created_at ASC;

-- name: GetPendingCredentialsByClinic :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type, pc.credential_number,
    pc.issuing_authority, pc.created_at,
    cs.first_name, cs.last_name, cs.work_email
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE 
    cs.clinic_id = $1
    AND pc.status = 'pending'
ORDER BY pc.created_at ASC;

-- name: GetRejectedCredentials :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type,
    pc.verified_by, pc.verification_date, pc.notes,
    cs.first_name, cs.last_name, cs.work_email
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE pc.status = 'rejected'
ORDER BY pc.verification_date DESC;

-- name: GetRecentlyVerifiedCredentials :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type, pc.credential_number,
    pc.verified_by, pc.verification_date,
    cs.first_name, cs.last_name, cs.clinic_id
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE 
    pc.status = 'verified'
    AND pc.verification_date >= CURRENT_DATE - INTERVAL '30 days'
ORDER BY pc.verification_date DESC;

-- ============================================
-- EXPIRATION & RENEWAL MANAGEMENT
-- ============================================

-- name: GetExpiredCredentials :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type, pc.credential_number,
    pc.issuing_authority, pc.expiry_date,
    cs.first_name, cs.last_name, cs.clinic_id, cs.work_email
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE 
    pc.expiry_date < CURRENT_DATE
    AND pc.status = 'verified'
ORDER BY pc.expiry_date ASC;

-- name: GetCredentialsExpiringWithinDays :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type, pc.credential_number,
    pc.issuing_authority, pc.expiry_date,
    cs.first_name, cs.last_name, cs.clinic_id, cs.work_email,
    CURRENT_DATE - pc.expiry_date as days_until_expiry
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE 
    pc.expiry_date <= CURRENT_DATE + ($1 || ' days')::INTERVAL
    AND pc.expiry_date >= CURRENT_DATE
    AND pc.status = 'verified'
ORDER BY pc.expiry_date ASC;

-- name: GetCredentialsNeedingRenewal :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type, pc.credential_number,
    pc.issuing_authority, pc.expiry_date,
    cs.first_name, cs.last_name, cs.work_email
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE 
    pc.expiry_date <= CURRENT_DATE + INTERVAL '30 days'
    AND pc.expiry_date >= CURRENT_DATE
    AND pc.status = 'verified'
ORDER BY pc.expiry_date ASC;

-- name: GetExpiredCredentialsByClinic :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type,
    pc.credential_number, pc.expiry_date,
    cs.first_name, cs.last_name, cs.work_email
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE 
    cs.clinic_id = $1
    AND pc.expiry_date < CURRENT_DATE
    AND pc.status = 'verified'
ORDER BY pc.expiry_date ASC;

-- name: AutoExpireCredentials :exec
UPDATE professional_credentials
SET 
    status = 'expired',
    updated_at = NOW()
WHERE 
    expiry_date < CURRENT_DATE
    AND status = 'verified';

-- ============================================
-- ISSUING AUTHORITY QUERIES
-- ============================================

-- name: GetCredentialsByAuthority :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type, pc.credential_number,
    pc.issue_date, pc.expiry_date, pc.status,
    cs.first_name, cs.last_name
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE pc.issuing_authority = $1
ORDER BY pc.issue_date DESC;

-- name: GetCredentialsByAuthorityAndType :many
SELECT 
    pc.id, pc.staff_id, pc.credential_number,
    pc.issue_date, pc.expiry_date, pc.status,
    cs.first_name, cs.last_name
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE 
    pc.issuing_authority = $1
    AND pc.credential_type = $2
ORDER BY pc.issue_date DESC;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: GetCredentialStatistics :one
SELECT 
    COUNT(*) as total_credentials,
    COUNT(*) FILTER (WHERE status = 'verified') as verified_count,
    COUNT(*) FILTER (WHERE status = 'pending') as pending_count,
    COUNT(*) FILTER (WHERE status = 'expired') as expired_count,
    COUNT(*) FILTER (WHERE status = 'revoked') as revoked_count,
    COUNT(*) FILTER (WHERE status = 'rejected') as rejected_count,
    COUNT(*) FILTER (WHERE expiry_date < CURRENT_DATE AND status = 'verified') as overdue_renewals
FROM professional_credentials
WHERE staff_id = $1;

-- name: GetClinicCredentialMetrics :one
SELECT 
    COUNT(DISTINCT pc.id) as total_credentials,
    COUNT(DISTINCT pc.id) FILTER (WHERE pc.status = 'verified') as verified_credentials,
    COUNT(DISTINCT pc.id) FILTER (WHERE pc.status = 'pending') as pending_credentials,
    COUNT(DISTINCT pc.id) FILTER (WHERE pc.expiry_date < CURRENT_DATE AND pc.status = 'verified') as expired_credentials,
    COUNT(DISTINCT pc.staff_id) as staff_with_credentials,
    AVG(EXTRACT(YEAR FROM AGE(pc.expiry_date, pc.issue_date))) FILTER (WHERE pc.expiry_date IS NOT NULL) as avg_credential_duration
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE cs.clinic_id = $1;

-- name: GetCredentialTypeDistribution :many
SELECT 
    credential_type,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE status = 'verified') as verified_count,
    COUNT(*) FILTER (WHERE expiry_date < CURRENT_DATE AND status = 'verified') as expired_count
FROM professional_credentials
WHERE staff_id = $1
GROUP BY credential_type
ORDER BY count DESC;

-- name: GetCredentialStatusDistribution :many
SELECT 
    status,
    COUNT(*) as count,
    COUNT(*) FILTER (WHERE expiry_date IS NOT NULL) as with_expiry
FROM professional_credentials
WHERE staff_id = $1
GROUP BY status
ORDER BY 
    CASE status
        WHEN 'verified' THEN 1
        WHEN 'pending' THEN 2
        WHEN 'expired' THEN 3
        ELSE 4
    END;

-- name: GetSystemCredentialMetrics :one
SELECT 
    COUNT(*) as total_credentials,
    COUNT(DISTINCT staff_id) as total_staff_with_credentials,
    COUNT(*) FILTER (WHERE status = 'verified') as verified_credentials,
    COUNT(*) FILTER (WHERE status = 'pending') as pending_verifications,
    COUNT(*) FILTER (WHERE expiry_date < CURRENT_DATE AND status = 'verified') as expired_credentials,
    COUNT(*) FILTER (WHERE expiry_date <= CURRENT_DATE + INTERVAL '30 days' AND expiry_date >= CURRENT_DATE) as expiring_soon,
    COUNT(DISTINCT issuing_authority) as unique_authorities,
    AVG(EXTRACT(DAY FROM AGE(verification_date, created_at))) FILTER (WHERE verification_date IS NOT NULL) as avg_verification_time_days
FROM professional_credentials;

-- ============================================
-- COUNTING & EXISTENCE CHECKS
-- ============================================

-- name: CountStaffCredentials :one
SELECT COUNT(*) 
FROM professional_credentials
WHERE 
    staff_id = $1
    AND ($2::VARCHAR IS NULL OR status = $2);

-- name: CountCredentialsByType :one
SELECT COUNT(*)
FROM professional_credentials
WHERE 
    staff_id = $1
    AND credential_type = $2
    AND status = 'verified';

-- name: CredentialExists :one
SELECT EXISTS(
    SELECT 1 FROM professional_credentials 
    WHERE id = $1
) as exists;

-- name: CheckCredentialNumberExists :one
SELECT EXISTS(
    SELECT 1 FROM professional_credentials
    WHERE 
        credential_number = $1
        AND issuing_authority = $2
        AND ($3::uuid IS NULL OR id != $3)
) as exists;

-- name: HasVerifiedCredentialOfType :one
SELECT EXISTS(
    SELECT 1 FROM professional_credentials
    WHERE 
        staff_id = $1
        AND credential_type = $2
        AND status = 'verified'
        AND (expiry_date IS NULL OR expiry_date >= CURRENT_DATE)
) as exists;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetCredentialsByIDs :many
SELECT * FROM professional_credentials
WHERE id = ANY($1::uuid[])
ORDER BY created_at DESC;

-- name: BulkVerifyCredentials :exec
UPDATE professional_credentials
SET 
    status = 'verified',
    verified_by = $2,
    verification_date = NOW(),
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkRejectCredentials :exec
UPDATE professional_credentials
SET 
    status = 'rejected',
    verified_by = $2,
    verification_date = NOW(),
    notes = $3,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkUpdateCredentialStatus :exec
UPDATE professional_credentials
SET 
    status = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: DeleteStaffCredentials :exec
DELETE FROM professional_credentials
WHERE staff_id = $1;

-- ============================================
-- COMPLIANCE & REPORTING
-- ============================================

-- name: GetStaffWithoutRequiredCredentials :many
SELECT DISTINCT
    cs.id, cs.clinic_id, cs.first_name, cs.last_name,
    cs.professional_title, cs.staff_role, cs.work_email
FROM clinic_staff cs
LEFT JOIN professional_credentials pc ON cs.id = pc.staff_id 
    AND pc.credential_type = 'professional_license'
    AND pc.status = 'verified'
    AND (pc.expiry_date IS NULL OR pc.expiry_date >= CURRENT_DATE)
WHERE 
    cs.employment_status = 'active'
    AND cs.staff_role IN ('doctor', 'nurse')
    AND pc.id IS NULL
ORDER BY cs.clinic_id, cs.last_name;

-- name: GetVerificationBacklog :many
SELECT 
    DATE(pc.created_at) as submission_date,
    COUNT(*) as pending_count,
    AVG(EXTRACT(DAY FROM AGE(CURRENT_TIMESTAMP, pc.created_at))) as avg_days_pending
FROM professional_credentials pc
WHERE pc.status = 'pending'
GROUP BY DATE(pc.created_at)
ORDER BY submission_date DESC;

-- name: GetVerifierWorkload :many
SELECT 
    u.id as verifier_id,
    u.email as verifier_email,
    COUNT(*) as verified_count,
    MIN(pc.verification_date) as first_verification,
    MAX(pc.verification_date) as last_verification
FROM professional_credentials pc
JOIN users u ON pc.verified_by = u.id
WHERE 
    pc.verification_date >= $1
    AND pc.verification_date <= $2
GROUP BY u.id, u.email
ORDER BY verified_count DESC;

-- name: GetCredentialsByDateRange :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type, pc.credential_number,
    pc.status, pc.created_at,
    cs.first_name, cs.last_name, cs.clinic_id
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE 
    pc.created_at >= $1
    AND pc.created_at <= $2
ORDER BY pc.created_at DESC;

-- name: GetRevokedCredentials :many
SELECT 
    pc.id, pc.staff_id, pc.credential_type, pc.credential_number,
    pc.issuing_authority, pc.notes, pc.updated_at,
    cs.first_name, cs.last_name, cs.clinic_id, cs.work_email
FROM professional_credentials pc
JOIN clinic_staff cs ON pc.staff_id = cs.id
WHERE pc.status = 'revoked'
ORDER BY pc.updated_at DESC;

-- name: GetCredentialRenewalHistory :many
SELECT 
    id, credential_type, credential_number,
    issue_date, expiry_date, status, updated_at
FROM professional_credentials
WHERE 
    staff_id = $1
    AND credential_type = $2
ORDER BY issue_date DESC;
