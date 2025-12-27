-- ============================================
-- OTP Verification Table
-- ============================================

CREATE TABLE otp_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    otp VARCHAR(6) NOT NULL,
    type VARCHAR(50) NOT NULL, -- 'password_reset', 'email_verification'
    channel VARCHAR(20) NOT NULL, -- 'email', 'sms'
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    CONSTRAINT otp_length_check CHECK (length(otp) = 6),
    CONSTRAINT otp_type_check CHECK (type IN ('password_reset', 'email_verification', 'phone_verification')),
    CONSTRAINT otp_channel_check CHECK (channel IN ('email', 'sms'))
);

