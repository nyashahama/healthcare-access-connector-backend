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
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

