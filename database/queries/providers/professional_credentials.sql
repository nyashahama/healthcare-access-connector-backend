-- ============================================
-- Professional Credentials Queries
-- ============================================

-- name: AddProfessionalCredential :one
INSERT INTO professional_credentials (
    staff_id, credential_type, credential_number, issuing_authority,
    issue_date, expiry_date, status, document_url
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, staff_id, credential_type, issuing_authority, 
    status, created_at;

-- name: GetStaffCredentials :many
SELECT id, staff_id, credential_type, credential_number, 
    issuing_authority, issue_date, expiry_date, status,
    verified_by, verification_date, document_url, notes
FROM professional_credentials
WHERE staff_id = $1
ORDER BY issue_date DESC;


-- name: VerifyCredential :exec
UPDATE professional_credentials
SET status = 'verified', verified_by = $2, verification_date = NOW()
WHERE id = $1;


-- name: UpdateCredential :exec
UPDATE professional_credentials
SET credential_number = $2, expiry_date = $3, 
    status = $4, notes = $5
WHERE id = $1;

