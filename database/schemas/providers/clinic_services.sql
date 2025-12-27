-- Clinic services with detailed information
CREATE TABLE clinic_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE,
    
    service_name VARCHAR(255) NOT NULL,
    service_category VARCHAR(100), -- 'preventive', 'pediatric', 'adult', 'testing', 'women_health'
    description TEXT,
    
    -- Operational Details
    duration_minutes INTEGER,
    preparation_instructions TEXT,
    follow_up_required BOOLEAN DEFAULT false,
    follow_up_days INTEGER,
    
    -- Eligibility
    minimum_age INTEGER,
    maximum_age INTEGER,
    gender_restriction VARCHAR(20), -- 'male', 'female', 'none'
    prerequisites TEXT[],
    
    -- Cost & Insurance
    cost DECIMAL(10,2),
    cost_currency VARCHAR(3) DEFAULT 'ZAR',
    is_covered_by_medical_aid BOOLEAN,
    medical_aid_codes JSONB,
    
    -- Availability
    is_active BOOLEAN DEFAULT true,
    available_days VARCHAR(20)[],
    requires_appointment BOOLEAN DEFAULT true,
    walk_in_allowed BOOLEAN DEFAULT false,
    
    -- Staff
    provided_by_staff_ids UUID[],
    
    -- Metrics
    popularity_score INTEGER DEFAULT 0,
    average_rating DECIMAL(3,2),
    review_count INTEGER DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

