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
