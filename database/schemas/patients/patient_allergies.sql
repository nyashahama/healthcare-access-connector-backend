-- Allergies
CREATE TABLE patient_allergies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    allergy_name VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- 'mild', 'moderate', 'severe', 'life_threatening'
    reaction_description TEXT,
    first_identified_date DATE,
    last_occurrence_date DATE,
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'resolved', 'inactive'
    notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

