-- Surgical history
CREATE TABLE patient_surgeries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    procedure_name VARCHAR(255) NOT NULL,
    procedure_date DATE NOT NULL,
    hospital_name VARCHAR(255),
    surgeon_name VARCHAR(255),
    anesthesia_type VARCHAR(100),
    complications TEXT,
    recovery_notes TEXT,
    outcome VARCHAR(50), -- 'successful', 'partial_success', 'complications'
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

