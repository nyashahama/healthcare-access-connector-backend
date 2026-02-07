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
    profile_picture_url, languages_spoken,
    invitation_status, can_manage_staff, can_approve_appointments, can_edit_clinic_info
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
    $27, $28, $29, $30
)
RETURNING *;

-- name: GetStaffByID :one
SELECT * FROM clinic_staff
WHERE id = $1;

-- name: GetStaffByUserID :one
SELECT * FROM clinic_staff
WHERE user_id = $1
LIMIT 1;

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
    work_email, work_phone, invitation_status,
    can_manage_staff, can_approve_appointments, can_edit_clinic_info,
    created_at
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND ($2::VARCHAR IS NULL OR staff_role = $2)
    AND employment_status = 'active'
ORDER BY 
    CASE staff_role
        WHEN 'owner' THEN 1
        WHEN 'admin' THEN 2
        WHEN 'manager' THEN 3
        WHEN 'doctor' THEN 4
        WHEN 'nurse' THEN 5
        ELSE 6
    END,
    first_name, last_name;

-- name: GetAllClinicStaff :many
SELECT 
    id, clinic_id, user_id, title, first_name, last_name,
    professional_title, specialization, staff_role,
    employment_status, is_accepting_new_patients,
    start_date, end_date, invitation_status, created_at
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
    AND invitation_status = 'accepted'
ORDER BY staff_role, first_name, last_name;

-- name: StaffExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_staff 
    WHERE id = $1
) as exists;

-- ============================================
-- STAFF INVITATION FLOW 
-- ============================================

-- name: CreateStaffInvitation :one
INSERT INTO clinic_staff (
    clinic_id, work_email, first_name, last_name,
    staff_role, professional_title,
    invitation_token, invitation_status, invited_by,
    invited_at, invitation_expires,
    can_manage_staff, can_approve_appointments, can_edit_clinic_info,
    employment_status
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, 'pending', $8,
    NOW(), $9, $10, $11, $12, 'invited'
)
RETURNING *;

-- name: GetStaffInvitationByToken :one
SELECT 
    cs.*,
    c.clinic_name,
    c.city,
    c.province,
    u.email as inviter_email,
    u.phone as inviter_phone
FROM clinic_staff cs
INNER JOIN clinics c ON cs.clinic_id = c.id
LEFT JOIN users u ON cs.invited_by = u.id
WHERE cs.invitation_token = $1
    AND cs.invitation_status = 'pending'
    AND cs.invitation_expires > NOW();

-- name: AcceptStaffInvitation :exec
UPDATE clinic_staff
SET 
    user_id = $2,
    invitation_status = 'accepted',
    employment_status = 'active',
    start_date = CURRENT_DATE,
    updated_at = NOW()
WHERE invitation_token = $1
    AND invitation_status = 'pending'
    AND invitation_expires > NOW();

-- name: DeclineStaffInvitation :exec
UPDATE clinic_staff
SET 
    invitation_status = 'declined',
    employment_status = 'terminated',
    updated_at = NOW()
WHERE invitation_token = $1
    AND invitation_status = 'pending';

-- name: ExpireStaffInvitations :exec
UPDATE clinic_staff
SET 
    invitation_status = 'expired',
    employment_status = 'terminated',
    updated_at = NOW()
WHERE invitation_status = 'pending'
    AND invitation_expires < NOW();

-- name: GetPendingInvitationsByClinic :many
SELECT 
    id, work_email, first_name, last_name,
    staff_role, professional_title,
    invitation_token, invited_at, invitation_expires,
    invited_by
FROM clinic_staff
WHERE clinic_id = $1
    AND invitation_status = 'pending'
    AND employment_status = 'invited'
ORDER BY invited_at DESC;

-- name: GetStaffInvitationsByEmail :many
SELECT 
    cs.*,
    c.clinic_name,
    c.city,
    c.province
FROM clinic_staff cs
INNER JOIN clinics c ON cs.clinic_id = c.id
WHERE cs.work_email = $1
    AND cs.invitation_status = 'pending'
    AND cs.invitation_expires > NOW()
ORDER BY cs.invited_at DESC;

-- name: CancelStaffInvitation :exec
DELETE FROM clinic_staff
WHERE invitation_token = $1
    AND invitation_status = 'pending';

-- name: ResendStaffInvitation :exec
UPDATE clinic_staff
SET 
    invitation_token = $2,
    invitation_expires = $3,
    invited_at = NOW(),
    updated_at = NOW()
WHERE id = $1
    AND invitation_status = 'pending';

-- name: CheckStaffEmailExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_staff 
    WHERE clinic_id = $1 
        AND work_email = $2
        AND (
            employment_status = 'active' 
            OR (invitation_status = 'pending' AND invitation_expires > NOW())
        )
) as exists;

-- name: GetStaffByUserAndClinic :one
SELECT * FROM clinic_staff
WHERE user_id = $1 
    AND clinic_id = $2
LIMIT 1;

-- name: UpdateStaffPermissions :exec
UPDATE clinic_staff
SET 
    can_manage_staff = $2,
    can_approve_appointments = $3,
    can_edit_clinic_info = $4,
    permissions = $5,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateStaffRole :exec
UPDATE clinic_staff
SET 
    staff_role = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetStaffWithPermissions :one
SELECT 
    id, clinic_id, user_id, staff_role,
    can_manage_staff, can_approve_appointments, can_edit_clinic_info,
    permissions, is_primary_contact
FROM clinic_staff
WHERE id = $1;

-- name: TerminateStaffMember :exec
UPDATE clinic_staff
SET 
    employment_status = 'terminated',
    end_date = CURRENT_DATE,
    updated_at = NOW()
WHERE id = $1;

-- name: ReactivateStaffMember :exec
UPDATE clinic_staff
SET 
    employment_status = 'active',
    end_date = NULL,
    updated_at = NOW()
WHERE id = $1;
