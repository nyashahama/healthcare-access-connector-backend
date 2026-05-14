-- ============================================
-- CONSULTATIONS REPOSITORY QUERIES
-- Maps to: ConsultationRepository interface
-- Domain: Telemedicine / Provider-Patient Sessions
-- ============================================

-- ============================================
-- SCHEMA
-- ============================================

CREATE TABLE consultations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Required gate: must come from a completed symptom session
    symptom_session_id   UUID NOT NULL REFERENCES symptom_checker_sessions(id) ON DELETE RESTRICT,
    patient_id           UUID NOT NULL REFERENCES patient_profiles(id) ON DELETE CASCADE,
    provider_staff_id    UUID REFERENCES clinic_staff(id) ON DELETE SET NULL,
    clinic_id            UUID REFERENCES clinics(id) ON DELETE SET NULL,

    -- Channel: 'chat' now, extensible to 'video' | 'phone' later
    channel              VARCHAR(20) NOT NULL DEFAULT 'chat',

    -- Lifecycle timestamps
    requested_at         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    accepted_at          TIMESTAMP,
    started_at           TIMESTAMP,
    ended_at             TIMESTAMP,
    duration_seconds     INTEGER,

    -- Status
    status               VARCHAR(30) NOT NULL DEFAULT 'pending_acceptance',
        -- 'pending_acceptance' | 'accepted' | 'in_progress'
        -- | 'completed' | 'cancelled' | 'no_show' | 'escalated' | 'declined'
    triage_level_at_start VARCHAR(20),   -- copied from session at creation
    ended_by             UUID REFERENCES users(id) ON DELETE SET NULL,
    end_reason           VARCHAR(50),
        -- 'completed' | 'no_show' | 'cancelled' | 'escalated'

    -- Billing
    consultation_fee     DECIMAL(10,2),
    fee_currency         VARCHAR(3) NOT NULL DEFAULT 'ZAR',
    payment_status       VARCHAR(20) NOT NULL DEFAULT 'pending',
        -- 'pending' | 'paid' | 'waived' | 'failed'
    payment_reference    VARCHAR(100),

    -- Post-consultation rating (from patient)
    patient_rating       INTEGER CHECK (patient_rating BETWEEN 1 AND 5),
    patient_feedback     TEXT,
    rated_at             TIMESTAMP,

    -- Optional: follow-up appointment booked in the same flow
    follow_up_appointment_id UUID REFERENCES appointments(id) ON DELETE SET NULL,

    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_consultation_status CHECK (status IN (
        'pending_acceptance', 'accepted', 'in_progress',
        'completed', 'cancelled', 'no_show', 'escalated', 'declined'
    )),
    CONSTRAINT valid_channel CHECK (channel IN ('chat', 'video', 'phone')),
    CONSTRAINT valid_payment_status CHECK (payment_status IN ('pending', 'paid', 'waived', 'failed'))
);

CREATE INDEX idx_consultations_patient         ON consultations(patient_id);
CREATE INDEX idx_consultations_provider        ON consultations(provider_staff_id);
CREATE INDEX idx_consultations_status          ON consultations(status);
CREATE INDEX idx_consultations_triage          ON consultations(triage_level_at_start);
CREATE INDEX idx_consultations_requested_at    ON consultations(requested_at DESC);
CREATE INDEX idx_consultations_symptom_session ON consultations(symptom_session_id);
CREATE INDEX idx_consultations_provider_open   ON consultations(provider_staff_id, status)
    WHERE status IN ('accepted', 'in_progress', 'pending_acceptance');
