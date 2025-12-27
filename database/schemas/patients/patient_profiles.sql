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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

