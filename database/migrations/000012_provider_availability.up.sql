
-- ============================================
-- PROVIDER AVAILABILITY REPOSITORY QUERIES
-- Maps to: ProviderAvailabilityRepository interface
-- Domain: Telemedicine / Provider Status Management
-- ============================================

-- ============================================
-- SCHEMA
-- ============================================

CREATE TABLE provider_availability (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staff_id    UUID NOT NULL UNIQUE REFERENCES clinic_staff(id) ON DELETE CASCADE,

    -- Online / accepting state
    is_online                    BOOLEAN NOT NULL DEFAULT false,
    is_accepting                 BOOLEAN NOT NULL DEFAULT false,
    status                       VARCHAR(20) NOT NULL DEFAULT 'offline',
        -- 'available' | 'busy' | 'away' | 'offline'

    -- Concurrency control
    active_consultation_count    INTEGER NOT NULL DEFAULT 0,
    max_concurrent_consultations INTEGER NOT NULL DEFAULT 1,

    -- Patient-facing display
    estimated_wait_minutes  INTEGER,
    status_message          VARCHAR(255),   -- e.g. 'Back in 10 min'

    -- Fee override for this session (overrides clinic default)
    consultation_fee_override DECIMAL(10,2),

    -- Heartbeat: provider dashboard pings this
    last_seen_at    TIMESTAMP,
    shift_start     TIMESTAMP,

    updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT valid_availability_status CHECK (
        status IN ('available', 'busy', 'away', 'offline')
    ),
    CONSTRAINT non_negative_count CHECK (
        active_consultation_count >= 0
    ),
    CONSTRAINT valid_max_concurrent CHECK (
        max_concurrent_consultations BETWEEN 1 AND 10
    )
);

CREATE INDEX idx_availability_staff   ON provider_availability(staff_id);
-- Fast lookup: all providers currently accepting (drives ProvidersList.jsx)
CREATE INDEX idx_availability_accepting ON provider_availability(is_accepting, status)
    WHERE is_accepting = true;


