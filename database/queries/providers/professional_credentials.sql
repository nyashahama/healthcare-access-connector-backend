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
