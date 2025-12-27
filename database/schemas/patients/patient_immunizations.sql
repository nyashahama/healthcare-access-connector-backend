-- Immunization records
CREATE TABLE patient_immunizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    vaccine_name VARCHAR(255) NOT NULL,
    vaccine_type VARCHAR(100), -- 'routine', 'travel', 'covid', 'flu'
    administration_date DATE NOT NULL,
    next_due_date DATE,
    administered_by VARCHAR(255),
    clinic_name VARCHAR(255),
    lot_number VARCHAR(100),
    manufacturer VARCHAR(255),
    dose_number INTEGER,
    total_doses INTEGER,
    notes TEXT,
    documented_by UUID REFERENCES users(id),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

