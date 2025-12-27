-- Family medical history
CREATE TABLE patient_family_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    relative VARCHAR(50) NOT NULL, -- 'mother', 'father', 'sibling', 'grandparent'
    relative_age_at_diagnosis INTEGER,
    condition_name VARCHAR(255) NOT NULL,
    notes TEXT,
    is_alive BOOLEAN,
    cause_of_death VARCHAR(255),
    age_at_death INTEGER,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

