-- Dependent-specific health records
CREATE TABLE dependent_health_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dependent_id UUID REFERENCES patient_dependents(id) ON DELETE CASCADE,
    record_type VARCHAR(50), -- 'growth_check', 'vaccination', 'checkup', 'emergency'
    record_date DATE NOT NULL,
    weight_kg DECIMAL(4,2),
    height_cm DECIMAL(4,1),
    head_circumference_cm DECIMAL(4,1),
    temperature_c DECIMAL(3,1),
    notes TEXT,
    provider_name VARCHAR(255),
    clinic_name VARCHAR(255),
    next_appointment_date DATE,
    documents JSONB, -- Store URLs to documents
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

