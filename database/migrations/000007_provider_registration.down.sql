
-- Rollback: Provider Registration & Staff Invitation Flow
BEGIN;

-- =========================================================
-- 1. Drop indexes
-- =========================================================
DROP INDEX IF EXISTS idx_clinic_staff_invited_by;
DROP INDEX IF EXISTS idx_clinic_staff_invitation_status;
DROP INDEX IF EXISTS idx_clinic_staff_invitation_token;
DROP INDEX IF EXISTS idx_clinics_verification_status;
DROP INDEX IF EXISTS idx_clinics_owner_user_id;
DROP INDEX IF EXISTS idx_clinics_created_by;
DROP INDEX IF EXISTS idx_users_onboarding_step;
DROP INDEX IF EXISTS idx_users_primary_clinic_id;
DROP INDEX IF EXISTS idx_clinic_staff_user_clinic;

-- =========================================================
-- 2. CLINIC_STAFF table
-- =========================================================

-- Restore NOT NULL constraint
ALTER TABLE clinic_staff
ALTER COLUMN user_id SET NOT NULL;

-- Remove invitation & permission columns
ALTER TABLE clinic_staff
DROP COLUMN IF EXISTS invitation_token,
DROP COLUMN IF EXISTS invitation_status,
DROP COLUMN IF EXISTS invited_by,
DROP COLUMN IF EXISTS invited_at,
DROP COLUMN IF EXISTS invitation_expires,
DROP COLUMN IF EXISTS permissions,
DROP COLUMN IF EXISTS can_manage_staff,
DROP COLUMN IF EXISTS can_approve_appointments,
DROP COLUMN IF EXISTS can_edit_clinic_info;

-- Restore original uniqueness constraint
ALTER TABLE clinic_staff
ADD CONSTRAINT clinic_staff_user_id_key UNIQUE (user_id);

-- =========================================================
-- 3. CLINICS table
-- =========================================================
ALTER TABLE clinics
DROP COLUMN IF EXISTS created_by,
DROP COLUMN IF EXISTS owner_user_id;

-- =========================================================
-- 4. USERS table
-- =========================================================
ALTER TABLE users
DROP COLUMN IF EXISTS primary_clinic_id,
DROP COLUMN IF EXISTS onboarding_completed,
DROP COLUMN IF EXISTS onboarding_step;

COMMIT;
