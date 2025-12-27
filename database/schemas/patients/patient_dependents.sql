-- Dependents (Children)
CREATE TABLE patient_dependents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE NOT NULL,
    gender VARCHAR(20),
    relationship VARCHAR(50) NOT NULL, -- 'child', 'ward', 'dependent_adult'
    
    -- Health Information
    blood_type VARCHAR(10),
    health_status VARCHAR(50), -- 'excellent', 'good', 'fair', 'poor'
    primary_pediatrician VARCHAR(255),
    clinic_id UUID, -- References clinics table
    
    -- Growth tracking
    birth_weight_kg DECIMAL(4,2),
    birth_height_cm DECIMAL(4,1),
    
    -- School/Childcare
    school_name VARCHAR(255),
    grade VARCHAR(50),
    
    -- Guardianship
    has_legal_guardianship BOOLEAN DEFAULT true,
    guardianship_document_url TEXT,
    
    -- Flags
    has_special_needs BOOLEAN DEFAULT false,
    special_needs_description TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

