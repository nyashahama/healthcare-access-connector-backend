-- ============================================
-- Core User & Authentication Tables
-- ============================================

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    phone VARCHAR(20) UNIQUE,
    password_hash VARCHAR(255),
    role VARCHAR(50) NOT NULL, -- 'patient', 'caregiver', 'provider_staff', 'clinic_admin', 'system_admin', 'ngo_partner'
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'inactive', 'pending_verification', 'suspended'
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
    
    INDEX idx_user_email (email),
    INDEX idx_user_phone (phone),
    INDEX idx_user_role_status (role, status)
);

-- User sessions for web/mobile
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    session_token VARCHAR(255) UNIQUE NOT NULL,
    device_type VARCHAR(50), -- 'web', 'mobile_ios', 'mobile_android', 'sms'
    device_id VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_user_sessions_token (session_token),
    INDEX idx_user_sessions_user (user_id)
);

-- ============================================
-- Patient/Caregiver Specific Tables
-- ============================================

CREATE TABLE patient_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Personal Information
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    preferred_name VARCHAR(100),
    date_of_birth DATE,
    gender VARCHAR(20), -- 'male', 'female', 'other', 'prefer_not_to_say'
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
    preferred_communication_method VARCHAR(50) DEFAULT 'sms', -- 'sms', 'email', 'whatsapp', 'call'
    
    -- Health System Identifiers
    medical_aid_number VARCHAR(50),
    medical_aid_provider VARCHAR(100),
    has_medical_aid BOOLEAN DEFAULT false,
    national_id_number VARCHAR(50),
    
    -- Employment/Education
    employment_status VARCHAR(50),
    education_level VARCHAR(50),
    household_income_range VARCHAR(50), -- 'low', 'medium', 'high', 'prefer_not_to_say'
    
    -- Profile Settings
    profile_picture_url TEXT,
    timezone VARCHAR(50) DEFAULT 'Africa/Johannesburg',
    last_profile_update TIMESTAMP,
    
    -- Additional Metadata
    referred_by UUID REFERENCES users(id),
    referral_code VARCHAR(50),
    accepts_marketing_emails BOOLEAN DEFAULT false,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_patient_user (user_id),
    INDEX idx_patient_location (province, city)
);


-- Patient medical information
CREATE TABLE patient_medical_info (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    
    -- Vital Information
    blood_type VARCHAR(10), -- 'A+', 'O-', etc.
    blood_type_last_tested DATE,
    height_cm DECIMAL(5,2),
    weight_kg DECIMAL(5,2),
    bmi DECIMAL(4,2),
    last_measured_date DATE,
    
    -- Health Summary
    overall_health_status VARCHAR(50), -- 'excellent', 'good', 'fair', 'poor'
    health_summary TEXT,
    primary_care_physician VARCHAR(255),
    primary_clinic_id UUID, -- References clinics table
    
    -- Important Notes
    organ_donor BOOLEAN DEFAULT false,
    advance_directive_exists BOOLEAN DEFAULT false,
    advance_directive_url TEXT,
    dnr_status BOOLEAN DEFAULT false,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_medical_patient (patient_id)
);

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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_allergy_patient (patient_id),
    INDEX idx_allergy_status (status)
);


-- Medications
CREATE TABLE patient_medications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    medication_name VARCHAR(255) NOT NULL,
    generic_name VARCHAR(255),
    dosage VARCHAR(100), -- "2 puffs", "500mg", etc.
    frequency VARCHAR(100), -- "daily", "twice daily", "as needed"
    route VARCHAR(50), -- "oral", "inhalation", "topical", "injection"
    prescribing_doctor VARCHAR(255),
    pharmacy_name VARCHAR(255),
    prescription_date DATE,
    start_date DATE,
    end_date DATE,
    reason_for_medication TEXT, -- "For asthma management"
    status VARCHAR(20) DEFAULT 'active', -- 'active', 'completed', 'discontinued'
    side_effects TEXT,
    instructions TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_medication_patient (patient_id),
    INDEX idx_medication_status (status)
);


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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_condition_patient (patient_id),
    INDEX idx_condition_status (status)
);


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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_surgery_patient (patient_id),
    INDEX idx_surgery_date (procedure_date)
);


-- Immunization records
CREATE TABLE patient_immunizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    vaccine_name VARCHAR(255) NOT NULL,
    vaccine_type VARCHAR(100), -- 'routine', 'travel', 'covid', 'flu'
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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_immunization_patient (patient_id),
    INDEX idx_immunization_dates (administration_date, next_due_date)
);


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
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_family_patient (patient_id)
);


-- Dependents (Children)
CREATE TABLE patient_dependents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patient_id UUID REFERENCES patient_profiles(id) ON DELETE CASCADE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    date_of_birth DATE NOT NULL,
    gender VARCHAR(20),
    relationship VARCHAR(50) NOT NULL, -- 'child', 'ward', 'dependent_adult'
    
    -- Health Information
    blood_type VARCHAR(10),
    health_status VARCHAR(50), -- 'excellent', 'good', 'fair', 'poor'
    primary_pediatrician VARCHAR(255),
    clinic_id UUID, -- References clinics table
    
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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_dependent_patient (patient_id),
    INDEX idx_dependent_birthdate (date_of_birth)
);


-- Dependent-specific health records
CREATE TABLE dependent_health_records (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    dependent_id UUID REFERENCES patient_dependents(id) ON DELETE CASCADE,
    record_type VARCHAR(50), -- 'growth_check', 'vaccination', 'checkup', 'emergency'
    record_date DATE NOT NULL,
    weight_kg DECIMAL(4,2),
    height_cm DECIMAL(4,1),
    head_circumference_cm DECIMAL(4,1),
    temperature_c DECIMAL(3,1),
    notes TEXT,
    provider_name VARCHAR(255),
    clinic_name VARCHAR(255),
    next_appointment_date DATE,
    documents JSONB, -- Store URLs to documents
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_dependent_records (dependent_id, record_date)
);


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
    access_level VARCHAR(50), -- 'full', 'limited', 'emergency_only'
    relationship_verified BOOLEAN DEFAULT false,
    verification_notes TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_emergency_patient (patient_id),
    INDEX idx_emergency_primary (patient_id, is_primary)
);


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
    
    data_sharing_consent JSONB, -- Store specific sharing preferences
    special_categories_consent JSONB, -- For sensitive data
    
    -- Withdrawal Information
    consent_withdrawn BOOLEAN DEFAULT false,
    consent_withdrawn_date TIMESTAMP,
    withdrawal_reason TEXT,
    
    -- Audit
    ip_address INET,
    user_agent TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_consent_user (user_id)
);


-- ============================================
-- Provider (Clinic/Healthcare Worker) Tables
-- ============================================

CREATE TABLE clinics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Basic Information
    clinic_name VARCHAR(255) NOT NULL,
    clinic_type VARCHAR(100) NOT NULL, -- 'public_health_clinic', 'private_clinic', 'community_health_center', 'mobile_clinic'
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
    ownership_type VARCHAR(50), -- 'government', 'private', 'ngo', 'religious'
    bed_count INTEGER,
    operating_hours JSONB, -- Store structured hours per day
    
    -- Services Offered
    services JSONB, -- Array of services
    specialties JSONB, -- Array of specialties
    languages_spoken VARCHAR(255)[],
    facilities JSONB, -- Array of facilities
    
    -- Payment & Insurance
    accepts_medical_aid BOOLEAN DEFAULT false,
    medical_aid_providers JSONB,
    payment_methods JSONB,
    fee_structure VARCHAR(50), -- 'free', 'sliding_scale', 'fixed_fees'
    
    -- Accreditation & Certifications
    accreditation_body VARCHAR(255),
    accreditation_expiry DATE,
    certifications JSONB,
    
    -- Status
    is_verified BOOLEAN DEFAULT false,
    verification_status VARCHAR(50) DEFAULT 'pending', -- 'pending', 'verified', 'rejected'
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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_clinic_location (province, city),
    INDEX idx_clinic_type_status (clinic_type, verification_status),
    INDEX idx_clinic_coordinates (latitude, longitude)
);



-- Clinic staff/healthcare workers
CREATE TABLE clinic_staff (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    clinic_id UUID REFERENCES clinics(id) ON DELETE CASCADE,
    user_id UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    
    -- Professional Information
    title VARCHAR(50), -- 'Dr', 'Nurse', 'Sr', 'Mr', 'Ms'
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    professional_title VARCHAR(255), -- 'General Practitioner', 'Registered Nurse'
    specialization VARCHAR(255),
    
    -- Contact Information
    work_email VARCHAR(255),
    work_phone VARCHAR(20),
    personal_phone VARCHAR(20), -- For emergency contact
    
    -- Professional Details
    hpcs_number VARCHAR(50), -- Health Professions Council of South Africa
    other_license_numbers JSONB,
    qualifications TEXT[],
    years_experience INTEGER,
    bio TEXT,
    
    -- Role at Clinic
    staff_role VARCHAR(100) NOT NULL, -- 'doctor', 'nurse', 'administrator', 'receptionist', 'manager'
    department VARCHAR(100),
    is_primary_contact BOOLEAN DEFAULT false,
    
    -- Availability
    working_hours JSONB,
    available_days VARCHAR(50)[], -- ['monday', 'tuesday', ...]
    is_accepting_new_patients BOOLEAN DEFAULT true,
    
    -- Status
    employment_status VARCHAR(20) DEFAULT 'active', -- 'active', 'on_leave', 'terminated'
    start_date DATE,
    end_date DATE,
    
    -- Profile
    profile_picture_url TEXT,
    languages_spoken VARCHAR(50)[],
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_staff_clinic (clinic_id),
    INDEX idx_staff_role (staff_role, employment_status),
    INDEX idx_staff_hpcs (hpcs_number)
);
