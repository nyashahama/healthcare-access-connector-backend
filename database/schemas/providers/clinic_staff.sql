CREATE TABLE clinic_staff (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE, -- Remove UNIQUE constraint here
    
    -- Professional Information
    title VARCHAR(50),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    professional_title VARCHAR(255),
    specialization VARCHAR(255),
    
    -- Contact Information
    work_email VARCHAR(255),
    work_phone VARCHAR(20),
    personal_phone VARCHAR(20),
    
    -- Professional Details
    hpcs_number VARCHAR(50),
    other_license_numbers JSONB,
    qualifications TEXT[],
    years_experience INTEGER,
    bio TEXT,
    
    -- Role at Clinic
    staff_role VARCHAR(100) NOT NULL,
    department VARCHAR(100),
    is_primary_contact BOOLEAN DEFAULT false,
    
    -- NEW: Invitation flow fields
    invitation_token VARCHAR(100) UNIQUE,
    invitation_status VARCHAR(20) DEFAULT 'accepted',
    invited_by UUID REFERENCES users(id) ON DELETE SET NULL,
    invited_at TIMESTAMP,
    invitation_expires TIMESTAMP,
    
    -- NEW: Permission fields
    permissions JSONB DEFAULT '{}',
    can_manage_staff BOOLEAN DEFAULT false,
    can_approve_appointments BOOLEAN DEFAULT false,
    can_edit_clinic_info BOOLEAN DEFAULT false,
    
    -- Availability
    working_hours JSONB,
    available_days VARCHAR(50)[],
    is_accepting_new_patients BOOLEAN DEFAULT true,
    
    -- Status
    employment_status VARCHAR(20) DEFAULT 'active',
    start_date DATE,
    end_date DATE,
    
    -- Profile
    profile_picture_url TEXT,
    languages_spoken VARCHAR(50)[],
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add unique constraint for user-clinic combination
CREATE UNIQUE INDEX idx_clinic_staff_user_clinic 
ON clinic_staff(user_id, clinic_id) 
WHERE user_id IS NOT NULL;
