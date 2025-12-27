-- Patient medical information
CREATE TABLE patient_medical_info (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    
    -- Vital Information
    blood_type VARCHAR(10), -- 'A+', 'O-', etc.
    blood_type_last_tested DATE,
    height_cm DECIMAL(5,2),
    weight_kg DECIMAL(5,2),
    bmi DECIMAL(4,2),
    last_measured_date DATE,
    
    -- Health Summary
    overall_health_status VARCHAR(50), -- 'excellent', 'good', 'fair', 'poor'
    health_summary TEXT,
    primary_care_physician VARCHAR(255),
    primary_clinic_id UUID, -- References clinics table
    
    -- Important Notes
    organ_donor BOOLEAN DEFAULT false,
    advance_directive_exists BOOLEAN DEFAULT false,
    advance_directive_url TEXT,
    dnr_status BOOLEAN DEFAULT false,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
