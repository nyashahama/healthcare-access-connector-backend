-- Medical conditions
CREATE TABLE patient_conditions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    condition_name VARCHAR(255) NOT NULL,
    icd10_code VARCHAR(20),
    type VARCHAR(50), -- 'chronic', 'acute', 'genetic', 'mental_health'
    diagnosed_date DATE,
    diagnosed_by VARCHAR(255),
    severity VARCHAR(20), -- 'mild', 'moderate', 'severe'
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'resolved', 'remission', 'managed'
    notes TEXT,
    last_flare_up DATE,
    next_checkup_date DATE,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

