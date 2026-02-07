-- ============================================
-- EMERGENCY CONTACTS REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Emergency Contact & Medical Access Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddEmergencyContact :one
INSERT INTO emergency_contacts (
    patient_id, contact_name, relationship, phone_number, email,
    address, is_primary, can_access_medical_info, access_level,
    relationship_verified, verification_notes
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
RETURNING *;

-- name: GetEmergencyContact :one
SELECT * FROM emergency_contacts
WHERE id = $1;

-- name: UpdateEmergencyContact :exec
UPDATE emergency_contacts
SET 
    contact_name = COALESCE($2, contact_name),
    relationship = COALESCE($3, relationship),
    phone_number = COALESCE($4, phone_number),
    email = COALESCE($5, email),
    address = COALESCE($6, address),
    can_access_medical_info = COALESCE($7, can_access_medical_info),
    access_level = COALESCE($8, access_level),
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteEmergencyContact :exec
DELETE FROM emergency_contacts WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientEmergencyContacts :many
SELECT 
    id, patient_id, contact_name, relationship, phone_number,
    email, address, is_primary, can_access_medical_info,
    access_level, relationship_verified, created_at, updated_at
FROM emergency_contacts
WHERE patient_id = $1
ORDER BY 
    CASE WHEN is_primary THEN 0 ELSE 1 END,
    contact_name;

-- name: GetPrimaryEmergencyContact :one
SELECT 
    id, contact_name, relationship, phone_number, email,
    can_access_medical_info, access_level
FROM emergency_contacts
WHERE 
    patient_id = $1
    AND is_primary = true
LIMIT 1;

