
-- ============================================
-- Appointments Table
-- ============================================

CREATE TABLE appointments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- References
    clinic_id UUID NOT NULL REFERENCES clinics(id) ON DELETE CASCADE,
    patient_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    
    -- Appointment Details
    appointment_date DATE NOT NULL,
    appointment_time DATE NOT NULL,
    appointment_datetime TIMESTAMP NOT NULL, -- Computed field for easier querying
    
    -- Patient Information (denormalized for convenience)
    patient_name VARCHAR(255) NOT NULL,
    patient_phone VARCHAR(20) NOT NULL,
    patient_email VARCHAR(255),
    
    -- Appointment Details
    reason_for_visit TEXT NOT NULL,
    notes TEXT, -- Additional notes from patient
    
    -- Status Management
    status VARCHAR(50) NOT NULL DEFAULT 'pending', -- 'pending', 'confirmed', 'cancelled', 'completed', 'no_show'
    cancellation_reason TEXT,
    cancelled_by UUID REFERENCES users(id),
    cancelled_at TIMESTAMP,
    
    -- Confirmation
    confirmed_by UUID REFERENCES users(id), -- Clinic staff who confirmed
    confirmed_at TIMESTAMP,
    
    -- Reminders
    reminder_preferences JSONB, -- SMS and additional reminder preferences
    reminder_sent JSONB, -- Track which reminders have been sent
    
    -- Metadata
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT valid_status CHECK (status IN ('pending', 'confirmed', 'cancelled', 'completed', 'no_show')),
    CONSTRAINT valid_appointment_datetime CHECK (appointment_datetime >= CURRENT_TIMESTAMP)
);

-- Indexes for better query performance
CREATE INDEX idx_appointments_clinic_id ON appointments(clinic_id);
CREATE INDEX idx_appointments_patient_id ON appointments(patient_id);
CREATE INDEX idx_appointments_date ON appointments(appointment_date);
CREATE INDEX idx_appointments_datetime ON appointments(appointment_datetime);
CREATE INDEX idx_appointments_status ON appointments(status);
CREATE INDEX idx_appointments_clinic_date_status ON appointments(clinic_id, appointment_date, status);
