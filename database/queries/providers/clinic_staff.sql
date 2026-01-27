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
-- PROFESSIONAL INFORMATION
-- ============================================

-- name: UpdateStaffProfessionalInfo :exec
UPDATE clinic_staff
SET 
    professional_title = $2,
    specialization = $3,
    qualifications = $4,
    years_experience = $5,
    bio = $6,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateStaffLicenses :exec
UPDATE clinic_staff
SET 
    hpcs_number = $2,
    other_license_numbers = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateStaffQualifications :exec
UPDATE clinic_staff
SET 
    qualifications = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: AddStaffQualification :exec
UPDATE clinic_staff
SET 
    qualifications = array_append(qualifications, $2),
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- CONTACT INFORMATION
-- ============================================

-- name: UpdateStaffContact :exec
UPDATE clinic_staff
SET 
    work_email = $2,
    work_phone = $3,
    personal_phone = $4,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateStaffProfile :exec
UPDATE clinic_staff
SET 
    bio = $2,
    profile_picture_url = $3,
    languages_spoken = $4,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- ROLE & EMPLOYMENT
-- ============================================

-- name: UpdateStaffRole :exec
UPDATE clinic_staff
SET 
    staff_role = $2,
    department = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateStaffStatus :exec
UPDATE clinic_staff
SET 
    employment_status = $2,
    end_date = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateStaffEmploymentDates :exec
UPDATE clinic_staff
SET 
    start_date = COALESCE($2, start_date),
    end_date = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: SetPrimaryContact :exec
UPDATE clinic_staff
SET 
    is_primary_contact = CASE WHEN id = $2 THEN TRUE ELSE FALSE END,
    updated_at = NOW()
WHERE clinic_id = $1;

-- name: ActivateStaff :exec
UPDATE clinic_staff
SET 
    employment_status = 'active',
    updated_at = NOW()
WHERE id = $1;

-- name: DeactivateStaff :exec
UPDATE clinic_staff
SET 
    employment_status = 'terminated',
    end_date = CURRENT_DATE,
    updated_at = NOW()
WHERE id = $1;

-- name: SetStaffOnLeave :exec
UPDATE clinic_staff
SET 
    employment_status = 'on_leave',
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- AVAILABILITY & SCHEDULING
-- ============================================

-- name: UpdateStaffAvailability :exec
UPDATE clinic_staff
SET 
    working_hours = $2,
    available_days = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdatePatientAcceptanceStatus :exec
UPDATE clinic_staff
SET 
    is_accepting_new_patients = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: SetAcceptingPatients :exec
UPDATE clinic_staff
SET 
    is_accepting_new_patients = TRUE,
    updated_at = NOW()
WHERE id = $1;

-- name: SetNotAcceptingPatients :exec
UPDATE clinic_staff
SET 
    is_accepting_new_patients = FALSE,
    updated_at = NOW()
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

-- name: GetClinicStaffByRole :many
SELECT 
    id, user_id, title, first_name, last_name,
    professional_title, specialization,
    work_email, work_phone, employment_status
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND staff_role = $2
ORDER BY first_name, last_name;

-- name: GetClinicDoctors :many
SELECT 
    id, user_id, title, first_name, last_name,
    professional_title, specialization, hpcs_number,
    is_accepting_new_patients, years_experience
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND staff_role = 'doctor'
    AND employment_status = 'active'
ORDER BY is_accepting_new_patients DESC, years_experience DESC;

-- name: GetClinicNurses :many
SELECT 
    id, user_id, title, first_name, last_name,
    professional_title, specialization,
    is_accepting_new_patients
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND staff_role = 'nurse'
    AND employment_status = 'active'
ORDER BY first_name, last_name;

-- name: GetClinicPrimaryContact :one
SELECT 
    id, user_id, title, first_name, last_name,
    staff_role, work_email, work_phone
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND is_primary_contact = TRUE
    AND employment_status = 'active'
LIMIT 1;

-- ============================================
-- STAFF SEARCH & FILTERING
-- ============================================

-- name: SearchStaffByName :many
SELECT 
    id, clinic_id, title, first_name, last_name,
    professional_title, specialization, staff_role
FROM clinic_staff
WHERE 
    (first_name ILIKE '%' || $1 || '%' 
     OR last_name ILIKE '%' || $1 || '%')
    AND ($2::uuid IS NULL OR clinic_id = $2)
    AND employment_status = 'active'
ORDER BY first_name, last_name
LIMIT $3 OFFSET $4;

-- name: GetStaffBySpecialization :many
SELECT 
    id, clinic_id, title, first_name, last_name,
    professional_title, specialization,
    is_accepting_new_patients
FROM clinic_staff
WHERE 
    specialization ILIKE '%' || $1 || '%'
    AND ($2::uuid IS NULL OR clinic_id = $2)
    AND employment_status = 'active'
ORDER BY years_experience DESC;

-- name: GetAcceptingNewPatientsStaff :many
SELECT 
    id, clinic_id, title, first_name, last_name,
    professional_title, specialization, staff_role
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND is_accepting_new_patients = TRUE
    AND employment_status = 'active'
ORDER BY staff_role, first_name;

-- name: GetStaffByDepartment :many
SELECT 
    id, title, first_name, last_name,
    professional_title, staff_role, department
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND department = $2
    AND employment_status = 'active'
ORDER BY first_name, last_name;

-- ============================================
-- STAFF AVAILABILITY QUERIES
-- ============================================

-- name: GetStaffAvailableOnDay :many
SELECT 
    id, title, first_name, last_name,
    professional_title, staff_role,
    working_hours, available_days
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND $2 = ANY(available_days)
    AND employment_status = 'active'
ORDER BY staff_role, first_name;

-- name: GetStaffWorkingHours :one
SELECT 
    id, first_name, last_name,
    working_hours, available_days
FROM clinic_staff
WHERE id = $1;

-- ============================================
-- LICENSING & CREDENTIALS
-- ============================================

-- name: GetStaffByHPCSNumber :one
SELECT * FROM clinic_staff
WHERE hpcs_number = $1
LIMIT 1;

-- name: CheckHPCSNumberExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_staff
    WHERE 
        hpcs_number = $1
        AND ($2::uuid IS NULL OR id != $2)
) as exists;

-- name: GetStaffWithExpiredLicenses :many
SELECT 
    cs.id, cs.clinic_id, cs.first_name, cs.last_name,
    cs.hpcs_number, cs.work_email
FROM clinic_staff cs
WHERE 
    cs.employment_status = 'active'
    AND EXISTS (
        SELECT 1 FROM professional_credentials pc
        WHERE pc.staff_id = cs.id
        AND pc.expiry_date < CURRENT_DATE
        AND pc.status = 'verified'
    )
ORDER BY cs.clinic_id, cs.last_name;

-- name: GetStaffNeedingCredentialRenewal :many
SELECT 
    cs.id, cs.clinic_id, cs.first_name, cs.last_name,
    cs.work_email, pc.credential_type, pc.expiry_date
FROM clinic_staff cs
JOIN professional_credentials pc ON cs.id = pc.staff_id
WHERE 
    cs.employment_status = 'active'
    AND pc.expiry_date <= CURRENT_DATE + INTERVAL '30 days'
    AND pc.expiry_date >= CURRENT_DATE
    AND pc.status = 'verified'
ORDER BY pc.expiry_date ASC;

-- ============================================
-- TRANSFER & REASSIGNMENT
-- ============================================

-- name: TransferStaffToClinic :exec
UPDATE clinic_staff
SET 
    clinic_id = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetStaffTransferHistory :many
SELECT 
    id, clinic_id, first_name, last_name,
    staff_role, start_date, end_date
FROM clinic_staff
WHERE user_id = $1
ORDER BY start_date DESC;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: GetStaffStatistics :one
SELECT 
    id,
    CONCAT(first_name, ' ', last_name) as full_name,
    professional_title,
    specialization,
    years_experience,
    employment_status,
    is_accepting_new_patients,
    created_at
FROM clinic_staff
WHERE id = $1;

-- name: GetClinicStaffMetrics :one
SELECT 
    COUNT(*) as total_staff,
    COUNT(*) FILTER (WHERE employment_status = 'active') as active_staff,
    COUNT(*) FILTER (WHERE employment_status = 'on_leave') as on_leave_staff,
    COUNT(*) FILTER (WHERE employment_status = 'terminated') as terminated_staff,
    COUNT(*) FILTER (WHERE staff_role = 'doctor') as doctor_count,
    COUNT(*) FILTER (WHERE staff_role = 'nurse') as nurse_count,
    COUNT(*) FILTER (WHERE staff_role = 'administrator') as admin_count,
    COUNT(*) FILTER (WHERE is_accepting_new_patients = TRUE AND employment_status = 'active') as accepting_patients_count,
    AVG(years_experience) FILTER (WHERE years_experience IS NOT NULL) as avg_experience
FROM clinic_staff
WHERE clinic_id = $1;

-- name: GetStaffRoleDistribution :many
SELECT 
    staff_role,
    COUNT(*) as count,
    AVG(years_experience) FILTER (WHERE years_experience IS NOT NULL) as avg_experience
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND employment_status = 'active'
GROUP BY staff_role
ORDER BY count DESC;

-- name: GetStaffByExperience :many
SELECT 
    id, title, first_name, last_name,
    professional_title, years_experience
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND employment_status = 'active'
    AND years_experience >= $2
ORDER BY years_experience DESC;

-- name: GetStaffDemographics :one
SELECT 
    COUNT(*) as total_staff,
    COUNT(DISTINCT specialization) FILTER (WHERE specialization IS NOT NULL) as unique_specializations,
    COUNT(DISTINCT staff_role) as unique_roles,
    AVG(array_length(languages_spoken, 1)) as avg_languages_spoken
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND employment_status = 'active';

-- ============================================
-- COUNTING & EXISTENCE CHECKS
-- ============================================

-- name: CountClinicStaff :one
SELECT COUNT(*) 
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND ($2::VARCHAR IS NULL OR employment_status = $2);

-- name: CountStaffByRole :one
SELECT COUNT(*)
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND staff_role = $2
    AND employment_status = 'active';

-- name: StaffExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_staff 
    WHERE id = $1
) as exists;

-- name: CheckStaffEmailExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_staff
    WHERE 
        work_email = $1
        AND ($2::uuid IS NULL OR id != $2)
) as exists;

-- name: CheckUserStaffExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_staff
    WHERE user_id = $1
) as exists;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetStaffByIDs :many
SELECT * FROM clinic_staff
WHERE id = ANY($1::uuid[])
ORDER BY first_name, last_name;

-- name: BulkUpdateStaffStatus :exec
UPDATE clinic_staff
SET 
    employment_status = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkSetAcceptingPatients :exec
UPDATE clinic_staff
SET 
    is_accepting_new_patients = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: DeactivateClinicStaff :exec
UPDATE clinic_staff
SET 
    employment_status = 'terminated',
    end_date = CURRENT_DATE,
    updated_at = NOW()
WHERE clinic_id = $1;

-- ============================================
-- LANGUAGE & COMMUNICATION
-- ============================================

-- name: GetStaffByLanguage :many
SELECT 
    id, title, first_name, last_name,
    professional_title, staff_role, languages_spoken
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND $2 = ANY(languages_spoken)
    AND employment_status = 'active'
ORDER BY staff_role, first_name;

-- name: GetMultilingualStaff :many
SELECT 
    id, first_name, last_name,
    professional_title, languages_spoken,
    array_length(languages_spoken, 1) as language_count
FROM clinic_staff
WHERE 
    clinic_id = $1
    AND employment_status = 'active'
    AND array_length(languages_spoken, 1) >= $2
ORDER BY language_count DESC;

-- ============================================
-- REPORTING & COMPLIANCE
-- ============================================

-- name: GetStaffWithoutHPCSNumber :many
SELECT 
    id, clinic_id, first_name, last_name,
    professional_title, staff_role, work_email
FROM clinic_staff
WHERE 
    staff_role IN ('doctor', 'nurse')
    AND (hpcs_number IS NULL OR hpcs_number = '')
    AND employment_status = 'active'
ORDER BY clinic_id, last_name;

-- name: GetStaffWithIncompleteProfiles :many
SELECT 
    id, clinic_id, first_name, last_name,
    professional_title, work_email
FROM clinic_staff
WHERE 
    employment_status = 'active'
    AND (
        bio IS NULL 
        OR profile_picture_url IS NULL
        OR qualifications IS NULL
        OR array_length(qualifications, 1) = 0
    )
ORDER BY clinic_id, last_name;

-- name: GetStaffHiredBetweenDates :many
SELECT 
    id, clinic_id, first_name, last_name,
    professional_title, staff_role, start_date
FROM clinic_staff
WHERE 
    start_date >= $1
    AND start_date <= $2
ORDER BY start_date DESC;

-- name: GetStaffTerminatedBetweenDates :many
SELECT 
    id, clinic_id, first_name, last_name,
    professional_title, staff_role, end_date
FROM clinic_staff
WHERE 
    employment_status = 'terminated'
    AND end_date >= $1
    AND end_date <= $2
ORDER BY end_date DESC;
