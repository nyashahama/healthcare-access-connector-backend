-- Migration: Provider Registration & Staff Invitation Flow
BEGIN;

-- =========================================================
-- 1. USERS table
-- =========================================================
ALTER TABLE users
ADD COLUMN IF NOT EXISTS primary_clinic_id UUID REFERENCES clinics(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS onboarding_completed BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS onboarding_step VARCHAR(50);
-- 'account_created', 'clinic_registered', 'clinic_approved', 'completed'

-- =========================================================
-- 2. CLINICS table
-- =========================================================
ALTER TABLE clinics
ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS owner_user_id UUID REFERENCES users(id) ON DELETE SET NULL;

-- =========================================================
-- 3. CLINIC_STAFF table – invitation flow
-- =========================================================

-- 3a. Remove old uniqueness constraint (1 user → 1 clinic)
ALTER TABLE clinic_staff
DROP CONSTRAINT IF EXISTS clinic_staff_user_id_key;

-- 3b. Add invitation & permission columns
ALTER TABLE clinic_staff
ADD COLUMN IF NOT EXISTS invitation_token VARCHAR(100) UNIQUE,
ADD COLUMN IF NOT EXISTS invitation_status VARCHAR(20) DEFAULT 'accepted',
ADD COLUMN IF NOT EXISTS invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS invited_at TIMESTAMP,
ADD COLUMN IF NOT EXISTS invitation_expires TIMESTAMP,
ADD COLUMN IF NOT EXISTS permissions JSONB DEFAULT '{}',
ADD COLUMN IF NOT EXISTS can_manage_staff BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS can_approve_appointments BOOLEAN DEFAULT false,
ADD COLUMN IF NOT EXISTS can_edit_clinic_info BOOLEAN DEFAULT false;

-- 3c. Allow pending invitations without a user
ALTER TABLE clinic_staff
ALTER COLUMN user_id DROP NOT NULL;

-- =========================================================
-- 4. Constraints & indexes
-- =========================================================

-- User can belong to multiple clinics (but only once per clinic)
CREATE UNIQUE INDEX IF NOT EXISTS idx_clinic_staff_user_clinic
ON clinic_staff(user_id, clinic_id)
WHERE user_id IS NOT NULL;

-- =========================================================
-- 5. Performance indexes
-- =========================================================
CREATE INDEX IF NOT EXISTS idx_users_primary_clinic_id
ON users(primary_clinic_id);

CREATE INDEX IF NOT EXISTS idx_users_onboarding_step
ON users(onboarding_step);

CREATE INDEX IF NOT EXISTS idx_clinics_created_by
ON clinics(created_by);

CREATE INDEX IF NOT EXISTS idx_clinics_owner_user_id
ON clinics(owner_user_id);

CREATE INDEX IF NOT EXISTS idx_clinics_verification_status
ON clinics(verification_status);

CREATE INDEX IF NOT EXISTS idx_clinic_staff_invitation_token
ON clinic_staff(invitation_token);

CREATE INDEX IF NOT EXISTS idx_clinic_staff_invitation_status
ON clinic_staff(invitation_status);

CREATE INDEX IF NOT EXISTS idx_clinic_staff_invited_by
ON clinic_staff(invited_by);

COMMIT;
