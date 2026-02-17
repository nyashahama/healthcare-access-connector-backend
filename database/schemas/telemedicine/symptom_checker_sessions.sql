-- ============================================
-- SYMPTOM CHECKER SESSIONS REPOSITORY QUERIES
-- Maps to: SymptomCheckerRepository interface
-- Domain: Telemedicine / Triage
-- ============================================

-- ============================================
-- SCHEMA
-- ============================================

CREATE TABLE symptom_checker_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id     UUID NOT NULL REFERENCES patient_profiles(id) ON DELETE CASCADE,
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dependent_id   UUID REFERENCES patient_dependents(id) ON DELETE SET NULL,

    -- Chief complaint & triage
    chief_complaint         TEXT NOT NULL,
    symptom_duration        VARCHAR(100),
    symptoms_reported       JSONB NOT NULL DEFAULT '[]',
    body_systems_affected   VARCHAR(50)[],
    severity_score          INTEGER CHECK (severity_score BETWEEN 1 AND 10),
    triage_level            VARCHAR(20) NOT NULL DEFAULT 'low',
        -- 'low' | 'medium' | 'high' | 'emergency'
    is_for_dependent        BOOLEAN NOT NULL DEFAULT false,

    -- AI-generated output
    ai_summary              TEXT,
    recommended_action      VARCHAR(100),
        -- 'telemedicine' | 'visit_clinic' | 'emergency' | 'self_care'

    -- Session lifecycle
    status                  VARCHAR(30) NOT NULL DEFAULT 'completed',
        -- 'completed' | 'abandoned' | 'converted_to_consult'
    raw_answers             JSONB,

    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_triage_level CHECK (
        triage_level IN ('low', 'medium', 'high', 'emergency')
    ),
    CONSTRAINT valid_recommended_action CHECK (
        recommended_action IN ('telemedicine', 'visit_clinic', 'emergency', 'self_care')
    ),
    CONSTRAINT valid_session_status CHECK (
        status IN ('completed', 'abandoned', 'converted_to_consult')
    )
);

CREATE INDEX idx_symptom_sessions_patient   ON symptom_checker_sessions(patient_id);
CREATE INDEX idx_symptom_sessions_user      ON symptom_checker_sessions(user_id);
CREATE INDEX idx_symptom_sessions_triage    ON symptom_checker_sessions(triage_level);
CREATE INDEX idx_symptom_sessions_status    ON symptom_checker_sessions(status);
CREATE INDEX idx_symptom_sessions_created   ON symptom_checker_sessions(created_at DESC);
CREATE INDEX idx_symptom_sessions_dependent ON symptom_checker_sessions(dependent_id)
    WHERE dependent_id IS NOT NULL;



