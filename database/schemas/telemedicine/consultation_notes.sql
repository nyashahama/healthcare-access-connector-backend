-- ============================================
-- CONSULTATION NOTES REPOSITORY QUERIES
-- Maps to: ConsultationNotesRepository interface
-- Domain: Telemedicine / Clinical Records
-- ============================================

-- ============================================
-- SCHEMA
-- ============================================

CREATE TABLE consultation_notes (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Strict 1-to-1 with a consultation
    consultation_id     UUID NOT NULL UNIQUE REFERENCES consultations(id) ON DELETE CASCADE,
    authored_by_staff_id UUID NOT NULL REFERENCES clinic_staff(id) ON DELETE RESTRICT,

    -- SOAP format (standard clinical note structure)
    subjective  TEXT,   -- Patient's reported symptoms in provider's words  (S)
    objective   TEXT,   -- Observations, vitals where available             (O)
    assessment  TEXT,   -- Clinical impression / working diagnosis           (A)
    plan        TEXT,   -- Treatment plan, advice, next steps               (P)

    -- Diagnosis
    diagnosis_codes     VARCHAR(20)[],  -- ICD-10 codes, e.g. '{J06.9, R50.9}'

    -- Prescription
    prescription_issued  BOOLEAN NOT NULL DEFAULT false,
    prescription_details JSONB,
    -- e.g. [{"name":"Amoxicillin","dosage":"500mg","frequency":"3x daily","duration":"5 days"}]

    -- Referral
    referral_required   BOOLEAN NOT NULL DEFAULT false,
    referral_type       VARCHAR(100),
        -- 'specialist' | 'emergency' | 'in_person_clinic'
    referral_notes      TEXT,

    -- Follow-up flag — drives "Book Follow-up" CTA in frontend
    follow_up_recommended BOOLEAN NOT NULL DEFAULT false,
    follow_up_timeframe   VARCHAR(100),  -- e.g. 'within 48 hours', 'in 1 week'

    -- Locking: provider finalises note → no more edits
    is_finalised    BOOLEAN   NOT NULL DEFAULT false,
    finalised_at    TIMESTAMP,

    created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_referral_type CHECK (
        referral_type IS NULL OR referral_type IN ('specialist', 'emergency', 'in_person_clinic')
    )
);

CREATE INDEX idx_notes_consultation ON consultation_notes(consultation_id);
CREATE INDEX idx_notes_provider     ON consultation_notes(authored_by_staff_id);
CREATE INDEX idx_notes_finalised    ON consultation_notes(is_finalised);



