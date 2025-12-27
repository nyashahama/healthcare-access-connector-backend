-- ============================================
-- Provider (Clinic/Healthcare Worker) Tables
-- ============================================

CREATE TABLE clinics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Basic Information
    clinic_name VARCHAR(255) NOT NULL,
    clinic_type VARCHAR(100) NOT NULL, -- 'public_health_clinic', 'private_clinic', 'community_health_center', 'mobile_clinic'
    registration_number VARCHAR(100),
    accreditation_number VARCHAR(100),
    
    -- Contact Information
    primary_phone VARCHAR(20),
    secondary_phone VARCHAR(20),
    emergency_phone VARCHAR(20),
    email VARCHAR(255),
    website VARCHAR(255),
    
    -- Location
    physical_address TEXT NOT NULL,
    city VARCHAR(100),
    province VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100) DEFAULT 'South Africa',
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    google_place_id VARCHAR(255),
    
    -- Clinic Details
    description TEXT,
    year_established INTEGER,
    ownership_type VARCHAR(50), -- 'government', 'private', 'ngo', 'religious'
    bed_count INTEGER,
    operating_hours JSONB, -- Store structured hours per day
    
    -- Services Offered
    services JSONB, -- Array of services
    specialties JSONB, -- Array of specialties
    languages_spoken VARCHAR(255)[],
    facilities JSONB, -- Array of facilities
    
    -- Payment & Insurance
    accepts_medical_aid BOOLEAN DEFAULT false,
    medical_aid_providers JSONB,
    payment_methods JSONB,
    fee_structure VARCHAR(50), -- 'free', 'sliding_scale', 'fixed_fees'
    
    -- Accreditation & Certifications
    accreditation_body VARCHAR(255),
    accreditation_expiry DATE,
    certifications JSONB,
    
    -- Status
    is_verified BOOLEAN DEFAULT false,
    verification_status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'verified', 'rejected'
    verification_notes TEXT,
    verified_by UUID REFERENCES users(id),
    verification_date TIMESTAMP,
    
    -- Metrics
    patient_capacity INTEGER,
    average_wait_time_minutes INTEGER,
    rating DECIMAL(3,2),
    review_count INTEGER DEFAULT 0,
    
    -- Contact Person
    contact_person_name VARCHAR(255),
    contact_person_role VARCHAR(100),
    contact_person_phone VARCHAR(20),
    contact_person_email VARCHAR(255),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

