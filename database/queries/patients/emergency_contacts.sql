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

-- name: GetEmergencyContactsByRelationship :many
SELECT 
    id, contact_name, phone_number, email, is_primary, access_level
FROM emergency_contacts
WHERE 
    patient_id = $1
    AND relationship = $2
ORDER BY is_primary DESC, contact_name;

-- ============================================
-- PRIMARY CONTACT MANAGEMENT
-- ============================================

-- name: SetPrimaryPatientContact :exec
UPDATE emergency_contacts
SET 
    is_primary = CASE WHEN id = $2 THEN true ELSE false END,
    updated_at = NOW()
WHERE patient_id = $1;

-- name: UpdatePrimaryContact :exec
UPDATE emergency_contacts
SET 
    is_primary = true,
    updated_at = NOW()
WHERE id = $1;

-- name: ClearPrimaryContacts :exec
UPDATE emergency_contacts
SET 
    is_primary = false,
    updated_at = NOW()
WHERE patient_id = $1;

-- ============================================
-- ACCESS LEVEL MANAGEMENT
-- ============================================

-- name: UpdateAccessLevel :exec
UPDATE emergency_contacts
SET 
    can_access_medical_info = $2,
    access_level = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: GrantMedicalAccess :exec
UPDATE emergency_contacts
SET 
    can_access_medical_info = true,
    access_level = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: RevokeMedicalAccess :exec
UPDATE emergency_contacts
SET 
    can_access_medical_info = false,
    access_level = 'emergency_only',
    updated_at = NOW()
WHERE id = $1;

-- name: GetContactsWithMedicalAccess :many
SELECT 
    ec.id,
    ec.patient_id,
    pp.first_name as patient_first_name,
    pp.last_name as patient_last_name,
    ec.contact_name,
    ec.relationship,
    ec.access_level,
    ec.phone_number
FROM emergency_contacts ec
JOIN patient_profiles pp ON ec.patient_id = pp.id
WHERE 
    ec.can_access_medical_info = true
    AND ($1::VARCHAR IS NULL OR ec.access_level = $1)
ORDER BY pp.last_name, ec.contact_name;

-- name: GetFullAccessContacts :many
SELECT 
    id, contact_name, relationship, phone_number, email
FROM emergency_contacts
WHERE 
    patient_id = $1
    AND can_access_medical_info = true
    AND access_level = 'full'
ORDER BY is_primary DESC, contact_name;

-- ============================================
-- VERIFICATION MANAGEMENT
-- ============================================

-- name: VerifyRelationship :exec
UPDATE emergency_contacts
SET 
    relationship_verified = true,
    verification_notes = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateVerificationNotes :exec
UPDATE emergency_contacts
SET 
    verification_notes = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetUnverifiedContacts :many
SELECT 
    ec.id,
    ec.patient_id,
    pp.first_name as patient_first_name,
    pp.last_name as patient_last_name,
    ec.contact_name,
    ec.relationship,
    ec.phone_number,
    ec.created_at
FROM emergency_contacts ec
JOIN patient_profiles pp ON ec.patient_id = pp.id
WHERE ec.relationship_verified = false
ORDER BY ec.created_at ASC;

-- ============================================
-- CONTACT INFORMATION UPDATES
-- ============================================

-- name: UpdateContactPhone :exec
UPDATE emergency_contacts
SET 
    phone_number = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateContactEmail :exec
UPDATE emergency_contacts
SET 
    email = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateContactAddress :exec
UPDATE emergency_contacts
SET 
    address = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateContactDetails :exec
UPDATE emergency_contacts
SET 
    phone_number = COALESCE($2, phone_number),
    email = COALESCE($3, email),
    address = COALESCE($4, address),
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- SEARCH & FILTERING
-- ============================================

-- name: SearchEmergencyContacts :many
SELECT 
    ec.id,
    ec.patient_id,
    pp.first_name as patient_first_name,
    pp.last_name as patient_last_name,
    ec.contact_name,
    ec.relationship,
    ec.phone_number,
    ec.is_primary
FROM emergency_contacts ec
JOIN patient_profiles pp ON ec.patient_id = pp.id
WHERE ec.contact_name ILIKE '%' || $1 || '%'
ORDER BY pp.last_name, ec.contact_name;

-- name: GetContactsByPhone :many
SELECT 
    ec.id,
    ec.patient_id,
    pp.first_name as patient_first_name,
    pp.last_name as patient_last_name,
    ec.contact_name,
    ec.relationship
FROM emergency_contacts ec
JOIN patient_profiles pp ON ec.patient_id = pp.id
WHERE ec.phone_number = $1;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountPatientEmergencyContacts :one
SELECT 
    COUNT(*) as total_contacts,
    COUNT(*) FILTER (WHERE is_primary = true) as primary_contacts,
    COUNT(*) FILTER (WHERE can_access_medical_info = true) as with_medical_access,
    COUNT(*) FILTER (WHERE relationship_verified = true) as verified_contacts,
    COUNT(*) FILTER (WHERE access_level = 'full') as full_access_contacts
FROM emergency_contacts
WHERE patient_id = $1;

-- name: GetEmergencyContactStatistics :one
SELECT 
    COUNT(DISTINCT patient_id) as patients_with_contacts,
    COUNT(*) as total_contacts,
    COUNT(*) FILTER (WHERE is_primary = true) as primary_contacts,
    COUNT(*) FILTER (WHERE can_access_medical_info = true) as with_medical_access,
    COUNT(*) FILTER (WHERE relationship_verified = false) as unverified_contacts,
    AVG((SELECT COUNT(*) FROM emergency_contacts ec2 WHERE ec2.patient_id = emergency_contacts.patient_id)) as avg_contacts_per_patient
FROM emergency_contacts;

-- name: GetRelationshipDistribution :many
SELECT 
    relationship,
    COUNT(*) as contact_count,
    COUNT(*) FILTER (WHERE is_primary = true) as primary_count,
    COUNT(*) FILTER (WHERE can_access_medical_info = true) as with_access
FROM emergency_contacts
GROUP BY relationship
ORDER BY contact_count DESC;

-- name: GetAccessLevelDistribution :many
SELECT 
    access_level,
    COUNT(*) as contact_count,
    COUNT(DISTINCT patient_id) as patient_count
FROM emergency_contacts
WHERE can_access_medical_info = true
GROUP BY access_level
ORDER BY contact_count DESC;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetEmergencyContactsByPatientIDs :many
SELECT 
    patient_id, contact_name, relationship, phone_number,
    is_primary, can_access_medical_info
FROM emergency_contacts
WHERE patient_id = ANY($1::uuid[])
ORDER BY patient_id, is_primary DESC, contact_name;

-- name: DeletePatientEmergencyContacts :exec
DELETE FROM emergency_contacts
WHERE patient_id = $1;

-- name: BulkVerifyContacts :exec
UPDATE emergency_contacts
SET 
    relationship_verified = true,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: HasEmergencyContacts :one
SELECT EXISTS(
    SELECT 1 FROM emergency_contacts
    WHERE patient_id = $1
) as has_contacts;

-- name: HasPrimaryContact :one
SELECT EXISTS(
    SELECT 1 FROM emergency_contacts
    WHERE 
        patient_id = $1
        AND is_primary = true
) as has_primary;

-- name: CheckPhonePatientExists :one
SELECT EXISTS(
    SELECT 1 FROM emergency_contacts
    WHERE 
        patient_id = $1
        AND phone_number = $2
        AND ($3::uuid IS NULL OR id != $3)
) as phone_exists;

-- ============================================
-- REPORTING QUERIES
-- ============================================

-- name: GetPatientsWithoutEmergencyContacts :many
SELECT 
    pp.id as patient_id,
    pp.user_id,
    pp.first_name,
    pp.last_name,
    pp.primary_address,
    pp.city,
    pp.province
FROM patient_profiles pp
LEFT JOIN emergency_contacts ec ON pp.id = ec.patient_id
WHERE ec.id IS NULL
ORDER BY pp.last_name, pp.first_name
LIMIT $1 OFFSET $2;

-- name: GetPatientsWithoutPrimaryContact :many
SELECT 
    pp.id as patient_id,
    pp.first_name,
    pp.last_name,
    COUNT(ec.id) as contact_count
FROM patient_profiles pp
LEFT JOIN emergency_contacts ec ON pp.id = ec.patient_id AND ec.is_primary = true
WHERE ec.id IS NULL
GROUP BY pp.id, pp.first_name, pp.last_name
HAVING COUNT(ec.id) = 0
ORDER BY pp.last_name
LIMIT $1 OFFSET $2;

-- name: GetContactsNeedingVerification :many
SELECT 
    ec.id,
    ec.patient_id,
    pp.first_name as patient_first_name,
    pp.last_name as patient_last_name,
    ec.contact_name,
    ec.relationship,
    ec.phone_number,
    ec.created_at,
    EXTRACT(DAY FROM AGE(CURRENT_TIMESTAMP, ec.created_at))::INTEGER as days_unverified
FROM emergency_contacts ec
JOIN patient_profiles pp ON ec.patient_id = pp.id
WHERE 
    ec.relationship_verified = false
    AND ec.created_at < CURRENT_TIMESTAMP - INTERVAL '7 days'
ORDER BY ec.created_at ASC;

-- ============================================
-- EMERGENCY ACCESS
-- ============================================

-- name: GetEmergencyContactInfo :many
SELECT 
    contact_name,
    relationship,
    phone_number,
    email,
    is_primary,
    can_access_medical_info,
    access_level
FROM emergency_contacts
WHERE patient_id = $1
ORDER BY is_primary DESC, contact_name;

-- name: GetEmergencyNotificationList :many
SELECT 
    contact_name,
    phone_number,
    email,
    relationship
FROM emergency_contacts
WHERE 
    patient_id = $1
    AND (is_primary = true OR can_access_medical_info = true)
ORDER BY is_primary DESC;