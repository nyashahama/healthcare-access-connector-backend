-- ============================================
-- Clinic Staff Queries
-- ============================================

-- name: CreateClinicStaff :one
INSERT INTO clinic_staff (
    clinic_id, user_id, title, first_name, last_name, 
    professional_title, specialization, work_email, work_phone,
    hpcs_number, staff_role, employment_status, 
    is_accepting_new_patients
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
RETURNING id, clinic_id, user_id, first_name, last_name, 
    staff_role, employment_status, created_at;


-- name: GetClinicStaffByID :one
SELECT * FROM clinic_staff WHERE id = $1;

-- name: GetClinicStaffByUserID :one
SELECT * FROM clinic_staff WHERE user_id = $1;

-- name: ListClinicStaff :many
SELECT id, clinic_id, user_id, title, first_name, last_name,
    professional_title, specialization, staff_role, 
    employment_status, is_accepting_new_patients, created_at
FROM clinic_staff
WHERE clinic_id = $1 
    AND ($2::VARCHAR IS NULL OR staff_role = $2)
    AND employment_status = 'active'
ORDER BY first_name, last_name;


-- name: UpdateClinicStaff :exec
UPDATE clinic_staff
SET professional_title = $2, specialization = $3, 
    work_email = $4, work_phone = $5, bio = $6,
    is_accepting_new_patients = $7
WHERE id = $1;


-- name: UpdateStaffStatus :exec
UPDATE clinic_staff
SET employment_status = $2, end_date = $3
WHERE id = $1;

