-- Clinic staff/healthcare workers
CREATE TABLE clinic_staff (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE,
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Professional Information
    title VARCHAR(50), -- 'Dr', 'Nurse', 'Sr', 'Mr', 'Ms'
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    professional_title VARCHAR(255), -- 'General Practitioner', 'Registered Nurse'
    specialization VARCHAR(255),
    
    -- Contact Information
    work_email VARCHAR(255),
    work_phone VARCHAR(20),
    personal_phone VARCHAR(20), -- For emergency contact
    
    -- Professional Details
    hpcs_number VARCHAR(50), -- Health Professions Council of South Africa
    other_license_numbers JSONB,
    qualifications TEXT[],
    years_experience INTEGER,
    bio TEXT,
    
    -- Role at Clinic
    staff_role VARCHAR(100) NOT NULL, -- 'doctor', 'nurse', 'administrator', 'receptionist', 'manager'
    department VARCHAR(100),
    is_primary_contact BOOLEAN DEFAULT false,
    
    -- Availability
    working_hours JSONB,
    available_days VARCHAR(50)[], -- ['monday', 'tuesday', ...]
    is_accepting_new_patients BOOLEAN DEFAULT true,
    
    -- Status
    employment_status VARCHAR(20) DEFAULT 'active', -- 'active', 'on_leave', 'terminated'
    start_date DATE,
    end_date DATE,
    
    -- Profile
    profile_picture_url TEXT,
    languages_spoken VARCHAR(50)[],
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
