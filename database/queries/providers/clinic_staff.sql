-- ============================================
-- CLINIC STAFF REPOSITORY QUERIES
-- Maps to: StaffRepository interface
-- Domain: Healthcare Staff Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreateStaffMember :one
INSERT INTO clinic_staff (
    clinic_id, user_id, title, first_name, last_name,
    professional_title, specialization,
    work_email, work_phone, personal_phone,
    hpcs_number, other_license_numbers, qualifications, years_experience, bio,
    staff_role, department, is_primary_contact,
    working_hours, available_days, is_accepting_new_patients,
    employment_status, start_date, end_date,
    profile_picture_url, languages_spoken
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26
)
RETURNING *;

-- name: GetStaffByID :one
SELECT * FROM clinic_staff
WHERE id = $1;

-- name: GetStaffByUserID :one
SELECT * FROM clinic_staff
WHERE user_id = $1;

-- name: UpdateStaffMember :exec
UPDATE clinic_staff
SET 
    title = COALESCE($2, title),
    first_name = COALESCE($3, first_name),
    last_name = COALESCE($4, last_name),
    professional_title = COALESCE($5, professional_title),
    specialization = COALESCE($6, specialization),
    work_email = COALESCE($7, work_email),
    work_phone = COALESCE($8, work_phone),
    bio = COALESCE($9, bio),
    years_experience = COALESCE($10, years_experience),
    is_accepting_new_patients = COALESCE($11, is_accepting_new_patients),
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteStaffMember :exec
DELETE FROM clinic_staff 
WHERE id = $1;

-- ============================================
-- CLINIC STAFF MANAGEMENT
-- ============================================

-- name: GetClinicStaff :many
SELECT 
    id, clinic_id, user_id, title, first_name, last_name,
    professional_title, specialization, staff_role,
    employment_status, is_accepting_new_patients,
    work_email, work_phone, created_at
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND ($2::VARCHAR IS NULL OR staff_role = $2)
    AND employment_status = 'active'
ORDER BY 
    CASE staff_role
        WHEN 'manager' THEN 1
        WHEN 'doctor' THEN 2
        WHEN 'nurse' THEN 3
        ELSE 4
    END,
    first_name, last_name;

-- name: GetAllClinicStaff :many
SELECT 
    id, clinic_id, user_id, title, first_name, last_name,
    professional_title, specialization, staff_role,
    employment_status, is_accepting_new_patients,
    start_date, end_date, created_at
FROM clinic_staff
WHERE clinic_id = $1
ORDER BY employment_status, first_name, last_name;

-- name: GetActiveClinicStaff :many
SELECT 
    id, user_id, title, first_name, last_name,
    professional_title, specialization, staff_role,
    work_email, work_phone, is_accepting_new_patients
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND employment_status = 'active'
ORDER BY staff_role, first_name, last_name;

-- name: StaffExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_staff 
    WHERE id = $1
) as exists;


