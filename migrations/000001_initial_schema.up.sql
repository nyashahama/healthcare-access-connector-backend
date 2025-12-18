
-- Migration: 000001_initial_schema.up.sql
-- Description: Create initial database schema with all tables

-- ============================================
-- Core User & Authentication Tables
-- ============================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255),  -- Made nullable
    phone VARCHAR(20),
    password_hash VARCHAR(255),
    role VARCHAR(50) NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    is_verified BOOLEAN DEFAULT false,
    verification_token VARCHAR(100),
    verification_expires TIMESTAMP,
    reset_password_token VARCHAR(100),
    reset_password_expires TIMESTAMP,
    last_login TIMESTAMP,
    login_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- SMS-only user tracking
    is_sms_only BOOLEAN DEFAULT false,
    sms_consent_given BOOLEAN DEFAULT false,
    popia_consent_given BOOLEAN DEFAULT false,
    consent_date TIMESTAMP,
    
    -- Profile completion tracking
    profile_completion_percentage INTEGER DEFAULT 0,
    
    -- Ensure at least one identifier is provided
    CONSTRAINT check_email_or_phone CHECK (
        (email IS NOT NULL AND email != '') OR 
        (phone IS NOT NULL AND phone != '')
    )
);

-- Create unique indexes that handle NULLs properly
CREATE UNIQUE INDEX idx_user_email ON users(email) 
    WHERE email IS NOT NULL AND email != '';

CREATE UNIQUE INDEX idx_user_phone ON users(phone) 
    WHERE phone IS NOT NULL AND phone != '';

CREATE INDEX idx_user_role_status ON users(role, status);

COMMENT ON CONSTRAINT check_email_or_phone ON users IS 
    'Ensures at least one contact method (email or phone) is provided for each user';

-- User sessions for web/mobile
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    device_type VARCHAR(50),
    device_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX idx_user_sessions_user ON user_sessions(user_id);


-- ============================================
-- Patient/Caregiver Specific Tables
-- ============================================

CREATE TABLE patient_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Personal Information
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    preferred_name VARCHAR(100),
    date_of_birth DATE,
    gender VARCHAR(20),
    preferred_gender_pronouns VARCHAR(50),
    
    -- Contact Information
    primary_address TEXT,
    city VARCHAR(100),
    province VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100) DEFAULT 'South Africa',
    
    -- Demographic Information
    language_preferences VARCHAR(255)[] DEFAULT '{"English"}',
    home_language VARCHAR(50),
    requires_interpreter BOOLEAN DEFAULT false,
    preferred_communication_method VARCHAR(50) DEFAULT 'sms',
    
    -- Health System Identifiers
    medical_aid_number VARCHAR(50),
    medical_aid_provider VARCHAR(100),
    has_medical_aid BOOLEAN DEFAULT false,
    national_id_number VARCHAR(50),
    
    -- Employment/Education
    employment_status VARCHAR(50),
    education_level VARCHAR(50),
    household_income_range VARCHAR(50),
    
    -- Profile Settings
    profile_picture_url TEXT,
    timezone VARCHAR(50) DEFAULT 'Africa/Johannesburg',
    last_profile_update TIMESTAMP,
    
    -- Additional Metadata
    referred_by UUID REFERENCES users(id),
    referral_code VARCHAR(50),
    accepts_marketing_emails BOOLEAN DEFAULT false,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_patient_user ON patient_profiles(user_id);
CREATE INDEX idx_patient_location ON patient_profiles(province, city);


-- Patient medical information
CREATE TABLE patient_medical_info (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    
    -- Vital Information
    blood_type VARCHAR(10),
    blood_type_last_tested DATE,
    height_cm DECIMAL(5,2),
    weight_kg DECIMAL(5,2),
    bmi DECIMAL(4,2),
    last_measured_date DATE,
    
    -- Health Summary
    overall_health_status VARCHAR(50),
    health_summary TEXT,
    primary_care_physician VARCHAR(255),
    primary_clinic_id UUID,
    
    -- Important Notes
    organ_donor BOOLEAN DEFAULT false,
    advance_directive_exists BOOLEAN DEFAULT false,
    advance_directive_url TEXT,
    dnr_status BOOLEAN DEFAULT false,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_medical_patient ON patient_medical_info(patient_id);


-- Allergies
CREATE TABLE patient_allergies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    allergy_name VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    reaction_description TEXT,
    first_identified_date DATE,
    last_occurrence_date DATE,
    status VARCHAR(20) DEFAULT 'active',
    notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_allergy_patient ON patient_allergies(patient_id);
CREATE INDEX idx_allergy_status ON patient_allergies(status);


-- Medications
CREATE TABLE patient_medications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    medication_name VARCHAR(255) NOT NULL,
    generic_name VARCHAR(255),
    dosage VARCHAR(100),
    frequency VARCHAR(100),
    route VARCHAR(50),
    prescribing_doctor VARCHAR(255),
    pharmacy_name VARCHAR(255),
    prescription_date DATE,
    start_date DATE,
    end_date DATE,
    reason_for_medication TEXT,
    status VARCHAR(20) DEFAULT 'active',
    side_effects TEXT,
    instructions TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_medication_patient ON patient_medications(patient_id);
CREATE INDEX idx_medication_status ON patient_medications(status);


-- Medical conditions
CREATE TABLE patient_conditions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    condition_name VARCHAR(255) NOT NULL,
    icd10_code VARCHAR(20),
    type VARCHAR(50),
    diagnosed_date DATE,
    diagnosed_by VARCHAR(255),
    severity VARCHAR(20),
    status VARCHAR(20) DEFAULT 'active',
    notes TEXT,
    last_flare_up DATE,
    next_checkup_date DATE,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_condition_patient ON patient_conditions(patient_id);
CREATE INDEX idx_condition_status ON patient_conditions(status);


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
    outcome VARCHAR(50),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_surgery_date ON patient_surgeries(procedure_date);
CREATE INDEX idx_surgery_patient ON patient_surgeries(patient_id);


-- Immunization records
CREATE TABLE patient_immunizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    vaccine_name VARCHAR(255) NOT NULL,
    vaccine_type VARCHAR(100),
    administration_date DATE NOT NULL,
    next_due_date DATE,
    administered_by VARCHAR(255),
    clinic_name VARCHAR(255),
    lot_number VARCHAR(100),
    manufacturer VARCHAR(255),
    dose_number INTEGER,
    total_doses INTEGER,
    notes TEXT,
    documented_by UUID REFERENCES users(id),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_immunization_patient ON patient_immunizations(patient_id);
CREATE INDEX idx_immunization_dates ON patient_immunizations(administration_date, next_due_date);


-- Family medical history
CREATE TABLE patient_family_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    relative VARCHAR(50) NOT NULL,
    relative_age_at_diagnosis INTEGER,
    condition_name VARCHAR(255) NOT NULL,
    notes TEXT,
    is_alive BOOLEAN,
    cause_of_death VARCHAR(255),
    age_at_death INTEGER,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_family_patient ON patient_family_history(patient_id);


-- Dependents (Children)
CREATE TABLE patient_dependents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE NOT NULL,
    gender VARCHAR(20),
    relationship VARCHAR(50) NOT NULL,
    
    -- Health Information
    blood_type VARCHAR(10),
    health_status VARCHAR(50),
    primary_pediatrician VARCHAR(255),
    clinic_id UUID,
    
    -- Growth tracking
    birth_weight_kg DECIMAL(4,2),
    birth_height_cm DECIMAL(4,1),
    
    -- School/Childcare
    school_name VARCHAR(255),
    grade VARCHAR(50),
    
    -- Guardianship
    has_legal_guardianship BOOLEAN DEFAULT true,
    guardianship_document_url TEXT,
    
    -- Flags
    has_special_needs BOOLEAN DEFAULT false,
    special_needs_description TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dependent_patient ON patient_dependents(patient_id);
CREATE INDEX idx_dependent_birthdate ON patient_dependents(date_of_birth);


-- Dependent-specific health records
CREATE TABLE dependent_health_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dependent_id UUID REFERENCES patient_dependents(id) ON DELETE CASCADE,
    record_type VARCHAR(50),
    record_date DATE NOT NULL,
    weight_kg DECIMAL(4,2),
    height_cm DECIMAL(4,1),
    head_circumference_cm DECIMAL(4,1),
    temperature_c DECIMAL(3,1),
    notes TEXT,
    provider_name VARCHAR(255),
    clinic_name VARCHAR(255),
    next_appointment_date DATE,
    documents JSONB,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_dependent_records ON dependent_health_records(dependent_id, record_date);

-- ============================================
-- Emergency Contacts & Consent Management
-- ============================================

CREATE TABLE emergency_contacts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    contact_name VARCHAR(255) NOT NULL,
    relationship VARCHAR(100) NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    email VARCHAR(255),
    address TEXT,
    is_primary BOOLEAN DEFAULT false,
    can_access_medical_info BOOLEAN DEFAULT false,
    access_level VARCHAR(50),
    relationship_verified BOOLEAN DEFAULT false,
    verification_notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_emergency_patient ON emergency_contacts(patient_id);
CREATE INDEX idx_emergency_primary ON emergency_contacts(patient_id, is_primary);


-- Privacy consents (POPIA compliance)
CREATE TABLE privacy_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    
    -- Consent Types
    health_data_consent BOOLEAN DEFAULT false,
    health_data_consent_date TIMESTAMP,
    health_data_consent_version VARCHAR(20),
    
    research_consent BOOLEAN DEFAULT false,
    research_consent_date TIMESTAMP,
    
    emergency_access_consent BOOLEAN DEFAULT true,
    emergency_access_consent_date TIMESTAMP,
    
    sms_communication_consent BOOLEAN DEFAULT false,
    email_communication_consent BOOLEAN DEFAULT false,
    
    data_sharing_consent JSONB,
    special_categories_consent JSONB,
    
    -- Withdrawal Information
    consent_withdrawn BOOLEAN DEFAULT false,
    consent_withdrawn_date TIMESTAMP,
    withdrawal_reason TEXT,
    
    -- Audit
    ip_address INET,
    user_agent TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_consent_user ON privacy_consents(user_id);

-- ============================================
-- Provider (Clinic/Healthcare Worker) Tables
-- ============================================

CREATE TABLE clinics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Basic Information
    clinic_name VARCHAR(255) NOT NULL,
    clinic_type VARCHAR(100) NOT NULL,
    registration_number VARCHAR(100),
    accreditation_number VARCHAR(100),
    
    -- Contact Information
    primary_phone VARCHAR(20),
    secondary_phone VARCHAR(20),
    emergency_phone VARCHAR(20),
    email VARCHAR(255),
    website VARCHAR(255),
    
    -- Location
    physical_address TEXT NOT NULL,
    city VARCHAR(100),
    province VARCHAR(100),
    postal_code VARCHAR(20),
    country VARCHAR(100) DEFAULT 'South Africa',
    latitude DECIMAL(10,8),
    longitude DECIMAL(11,8),
    google_place_id VARCHAR(255),
    
    -- Clinic Details
    description TEXT,
    year_established INTEGER,
    ownership_type VARCHAR(50),
    bed_count INTEGER,
    operating_hours JSONB,
    
    -- Services Offered
    services JSONB,
    specialties JSONB,
    languages_spoken VARCHAR(255)[],
    facilities JSONB,
    
    -- Payment & Insurance
    accepts_medical_aid BOOLEAN DEFAULT false,
    medical_aid_providers JSONB,
    payment_methods JSONB,
    fee_structure VARCHAR(50),
    
    -- Accreditation & Certifications
    accreditation_body VARCHAR(255),
    accreditation_expiry DATE,
    certifications JSONB,
    
    -- Status
    is_verified BOOLEAN DEFAULT false,
    verification_status VARCHAR(50) DEFAULT 'pending',
    verification_notes TEXT,
    verified_by UUID REFERENCES users(id),
    verification_date TIMESTAMP,
    
    -- Metrics
    patient_capacity INTEGER,
    average_wait_time_minutes INTEGER,
    rating DECIMAL(3,2),
    review_count INTEGER DEFAULT 0,
    
    -- Contact Person
    contact_person_name VARCHAR(255),
    contact_person_role VARCHAR(100),
    contact_person_phone VARCHAR(20),
    contact_person_email VARCHAR(255),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_clinic_location ON clinics(province, city);
CREATE INDEX idx_clinic_type_status ON clinics(clinic_type, verification_status);
CREATE INDEX idx_clinic_coordinates ON clinics(latitude, longitude);


-- Clinic staff/healthcare workers
CREATE TABLE clinic_staff (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE,
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Professional Information
    title VARCHAR(50),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    professional_title VARCHAR(255),
    specialization VARCHAR(255),
    
    -- Contact Information
    work_email VARCHAR(255),
    work_phone VARCHAR(20),
    personal_phone VARCHAR(20),
    
    -- Professional Details
    hpcs_number VARCHAR(50),
    other_license_numbers JSONB,
    qualifications TEXT[],
    years_experience INTEGER,
    bio TEXT,
    
    -- Role at Clinic
    staff_role VARCHAR(100) NOT NULL,
    department VARCHAR(100),
    is_primary_contact BOOLEAN DEFAULT false,
    
    -- Availability
    working_hours JSONB,
    available_days VARCHAR(50)[],
    is_accepting_new_patients BOOLEAN DEFAULT true,
    
    -- Status
    employment_status VARCHAR(20) DEFAULT 'active',
    start_date DATE,
    end_date DATE,
    
    -- Profile
    profile_picture_url TEXT,
    languages_spoken VARCHAR(50)[],
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_staff_clinic ON clinic_staff(clinic_id);
CREATE INDEX idx_staff_role ON clinic_staff(staff_role, employment_status);
CREATE INDEX idx_staff_hpcs ON clinic_staff(hpcs_number);


-- Professional credentials
CREATE TABLE professional_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    staff_id UUID REFERENCES clinic_staff(id) ON DELETE CASCADE,
    credential_type VARCHAR(100) NOT NULL,
    credential_number VARCHAR(100),
    issuing_authority VARCHAR(255) NOT NULL,
    issue_date DATE,
    expiry_date DATE,
    status VARCHAR(20) DEFAULT 'pending',
    verified_by UUID REFERENCES users(id),
    verification_date TIMESTAMP,
    document_url TEXT,
    notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_credentials_status ON professional_credentials(status, expiry_date);
CREATE INDEX idx_credentials_staff ON professional_credentials(staff_id);


-- Clinic services with detailed information
CREATE TABLE clinic_services (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE,
    
    service_name VARCHAR(255) NOT NULL,
    service_category VARCHAR(100),
    description TEXT,
    
    -- Operational Details
    duration_minutes INTEGER,
    preparation_instructions TEXT,
    follow_up_required BOOLEAN DEFAULT false,
    follow_up_days INTEGER,
    
    -- Eligibility
    minimum_age INTEGER,
    maximum_age INTEGER,
    gender_restriction VARCHAR(20),
    prerequisites TEXT[],
    
    -- Cost & Insurance
    cost DECIMAL(10,2),
    cost_currency VARCHAR(3) DEFAULT 'ZAR',
    is_covered_by_medical_aid BOOLEAN,
    medical_aid_codes JSONB,
    
    -- Availability
    is_active BOOLEAN DEFAULT true,
    available_days VARCHAR(20)[],
    requires_appointment BOOLEAN DEFAULT true,
    walk_in_allowed BOOLEAN DEFAULT false,
    
    -- Staff
    provided_by_staff_ids UUID[],
    
    -- Metrics
    popularity_score INTEGER DEFAULT 0,
    average_rating DECIMAL(3,2),
    review_count INTEGER DEFAULT 0,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_services_clinic ON clinic_services(clinic_id, is_active);
CREATE INDEX idx_services_category ON clinic_services(service_category);


-- ============================================
-- System Administration & NGO Partners
-- ============================================

CREATE TABLE system_admins (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Admin Details
    admin_level VARCHAR(50) NOT NULL,
    assigned_regions VARCHAR(255)[],
    department VARCHAR(100),
    
    -- Permissions
    permissions JSONB NOT NULL,
    can_manage_users BOOLEAN DEFAULT false,
    can_manage_clinics BOOLEAN DEFAULT false,
    can_manage_content BOOLEAN DEFAULT false,
    can_view_analytics BOOLEAN DEFAULT false,
    can_manage_system BOOLEAN DEFAULT false,
    
    -- Contact
    work_phone VARCHAR(20),
    extension VARCHAR(20),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_admin_level ON system_admins(admin_level);


CREATE TABLE ngo_partners (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Organization Details
    organization_name VARCHAR(255) NOT NULL,
    organization_type VARCHAR(100),
    registration_number VARCHAR(100),
    tax_id VARCHAR(100),
    
    -- Contact Information
    organization_address TEXT,
    organization_phone VARCHAR(20),
    organization_email VARCHAR(255),
    website VARCHAR(255),
    
    -- Primary Contact
    contact_person_name VARCHAR(255),
    contact_person_role VARCHAR(100),
    contact_person_phone VARCHAR(20),
    contact_person_email VARCHAR(255),
    
    -- Partnership Details
    partnership_type VARCHAR(50),
    partnership_start_date DATE,
    partnership_end_date DATE,
    partnership_status VARCHAR(20) DEFAULT 'active',
    
    -- Regions of Operation
    operating_regions VARCHAR(255)[],
    focus_areas VARCHAR(255)[],
    
    -- Reporting Access
    can_access_reports BOOLEAN DEFAULT false,
    report_access_level VARCHAR(50),
    custom_report_filters JSONB,
    
    -- Logo & Branding
    logo_url TEXT,
    branding_color VARCHAR(20),
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ngo_status ON ngo_partners(partnership_status);
CREATE INDEX idx_ngo_regions ON ngo_partners(operating_regions);


-- ============================================
-- Activity & Audit Logging
-- ============================================

CREATE TABLE user_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    
    activity_type VARCHAR(100) NOT NULL,
    activity_details JSONB,
    
    -- Device & Location
    ip_address INET,
    user_agent TEXT,
    device_type VARCHAR(50),
    device_id VARCHAR(255),
    location JSONB,
    
    -- Resource
    resource_type VARCHAR(100),
    resource_id UUID,
    
    -- Timestamps
    performed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_activity_user ON user_activities(user_id, performed_at);
CREATE INDEX idx_activity_type ON user_activities(activity_type, performed_at);


-- Data access audit log (POPIA compliance)
CREATE TABLE data_access_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Who accessed
    accessed_by_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    accessed_by_role VARCHAR(50),
    
    -- What was accessed
    accessed_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    accessed_resource_type VARCHAR(100),
    accessed_resource_id UUID,
    
    -- Access Details
    access_type VARCHAR(50),
    access_reason TEXT,
    is_emergency_access BOOLEAN DEFAULT false,
    
    -- Context
    ip_address INET,
    user_agent TEXT,
    location JSONB,
    
    accessed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_access_log_accessed ON data_access_logs(accessed_user_id, accessed_at);
CREATE INDEX idx_access_log_accessor ON data_access_logs(accessed_by_user_id, accessed_at);


-- ============================================
-- Notification Preferences
-- ============================================

CREATE TABLE notification_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Channels
    sms_enabled BOOLEAN DEFAULT true,
    email_enabled BOOLEAN DEFAULT true,
    push_enabled BOOLEAN DEFAULT true,
    whatsapp_enabled BOOLEAN DEFAULT false,
    
    -- Notification Types
    appointment_reminders BOOLEAN DEFAULT true,
    appointment_reminder_hours_before INTEGER DEFAULT 24,
    
    health_tips BOOLEAN DEFAULT true,
    health_tips_frequency VARCHAR(20) DEFAULT 'weekly',
    
    medication_reminders BOOLEAN DEFAULT false,
    prescription_updates BOOLEAN DEFAULT true,
    
    clinic_updates BOOLEAN DEFAULT true,
    newsletter BOOLEAN DEFAULT false,
    
    emergency_alerts BOOLEAN DEFAULT true,
    system_maintenance BOOLEAN DEFAULT true,
    
    -- Language Preferences
    notification_language VARCHAR(50) DEFAULT 'English',
    
    -- Quiet Hours
    quiet_hours_start TIME,
    quiet_hours_end TIME,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_notif_pref_user ON notification_preferences(user_id);


-- ============================================
-- SMS Communication Tracking
-- ============================================

CREATE TABLE sms_conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    phone_number VARCHAR(20) NOT NULL,
    
    -- Conversation State
    current_menu VARCHAR(50),
    conversation_state JSONB,
    
    -- Last Interaction
    last_message_sent TEXT,
    last_message_received TEXT,
    last_interaction_at TIMESTAMP,
    
    -- Context
    last_location JSONB,
    last_search_query TEXT,
    callback_scheduled TIMESTAMP,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sms_phone ON sms_conversations(phone_number);
CREATE INDEX idx_sms_user ON sms_conversations(user_id);


CREATE TABLE sms_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES sms_conversations(id) ON DELETE CASCADE,
    
    direction VARCHAR(10) NOT NULL,
    message_body TEXT NOT NULL,
    twilio_message_id VARCHAR(100),
    twilio_status VARCHAR(50),
    
    -- Timing
    sent_at TIMESTAMP,
    delivered_at TIMESTAMP,
    
    -- Cost
    segments INTEGER DEFAULT 1,
    cost DECIMAL(5,4),
    cost_currency VARCHAR(3) DEFAULT 'USD',
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sms_conversation ON sms_messages(conversation_id, created_at);
CREATE INDEX idx_sms_twilio_id ON sms_messages(twilio_message_id);


-- ============================================
-- Performance Indexes
-- ============================================

-- Composite indexes for common queries
CREATE INDEX idx_users_composite ON users(role, status, created_at);
CREATE INDEX idx_patients_search ON patient_profiles(first_name, last_name, province, city);
CREATE INDEX idx_clinics_search ON clinics(clinic_name, province, city, clinic_type, is_verified);
CREATE INDEX idx_staff_search ON clinic_staff(first_name, last_name, specialization, clinic_id);


-- Full-text search indexes
CREATE INDEX idx_patients_ftsearch ON patient_profiles 
    USING GIN(to_tsvector('english', COALESCE(first_name, '') || ' ' || COALESCE(last_name, '') || ' ' || COALESCE(primary_address, '')));

CREATE INDEX idx_clinics_ftsearch ON clinics 
    USING GIN(to_tsvector('english', clinic_name || ' ' || COALESCE(description, '') || ' ' || physical_address));


-- ============================================
-- Functions & Triggers
-- ============================================

-- Update updated_at timestamp automatically
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply triggers to all tables with updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_patient_profiles_updated_at BEFORE UPDATE ON patient_profiles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_patient_medical_info_updated_at BEFORE UPDATE ON patient_medical_info
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clinics_updated_at BEFORE UPDATE ON clinics
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clinic_staff_updated_at BEFORE UPDATE ON clinic_staff
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_professional_credentials_updated_at BEFORE UPDATE ON professional_credentials
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_emergency_contacts_updated_at BEFORE UPDATE ON emergency_contacts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_privacy_consents_updated_at BEFORE UPDATE ON privacy_consents
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notification_preferences_updated_at BEFORE UPDATE ON notification_preferences
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_admins_updated_at BEFORE UPDATE ON system_admins
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_ngo_partners_updated_at BEFORE UPDATE ON ngo_partners
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_clinic_services_updated_at BEFORE UPDATE ON clinic_services
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


-- Function to calculate age from date of birth
CREATE OR REPLACE FUNCTION calculate_age(birth_date DATE)
RETURNS INTEGER AS $$
BEGIN
    RETURN DATE_PART('year', AGE(birth_date));
END;
$$ LANGUAGE plpgsql IMMUTABLE;


-- View for patient demographics
CREATE VIEW patient_demographics AS
SELECT 
    p.id,
    p.first_name,
    p.last_name,
    calculate_age(p.date_of_birth) as age,
    p.gender,
    p.province,
    p.city,
    p.language_preferences,
    p.requires_interpreter,
    m.blood_type,
    m.overall_health_status,
    COUNT(DISTINCT d.id) as number_of_dependents,
    u.created_at as registration_date
FROM patient_profiles p
LEFT JOIN patient_medical_info m ON p.id = m.patient_id
LEFT JOIN patient_dependents d ON p.id = d.patient_id
LEFT JOIN users u ON p.user_id = u.id
GROUP BY p.id, m.id, u.id;
