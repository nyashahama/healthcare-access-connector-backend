-- Medications
CREATE TABLE patient_medications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    medication_name VARCHAR(255) NOT NULL,
    generic_name VARCHAR(255),
    dosage VARCHAR(100), -- "2 puffs", "500mg", etc.
    frequency VARCHAR(100), -- "daily", "twice daily", "as needed"
    route VARCHAR(50), -- "oral", "inhalation", "topical", "injection"
    prescribing_doctor VARCHAR(255),
    pharmacy_name VARCHAR(255),
    prescription_date DATE,
    start_date DATE,
    end_date DATE,
    reason_for_medication TEXT, -- "For asthma management"
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'completed', 'discontinued'
    side_effects TEXT,
    instructions TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
