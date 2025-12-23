BEGIN;

-- Create OTP verifications table
CREATE TABLE IF NOT EXISTS otp_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp VARCHAR(6) NOT NULL,
    type VARCHAR(50) NOT NULL,
    channel VARCHAR(20) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Constraints
    CONSTRAINT otp_length_check CHECK (length(otp) = 6),
    CONSTRAINT otp_type_check CHECK (type IN ('password_reset', 'email_verification', 'phone_verification')),
    CONSTRAINT otp_channel_check CHECK (channel IN ('email', 'sms'))
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_otp_user ON otp_verifications(user_id);
CREATE INDEX IF NOT EXISTS idx_otp_expires ON otp_verifications(expires_at);
CREATE INDEX IF NOT EXISTS idx_otp_used ON otp_verifications(used_at);
CREATE INDEX IF NOT EXISTS idx_otp_lookup ON otp_verifications(user_id, otp, type) WHERE used_at IS NULL;

-- Function to cleanup expired OTPs
CREATE OR REPLACE FUNCTION cleanup_expired_otps()
RETURNS void AS $$
BEGIN
    DELETE FROM otp_verifications
    WHERE expires_at < NOW() OR created_at < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;

-- Optional: Create a cron job to cleanup expired OTPs
-- Uncomment if you have pg_cron extension installed
-- SELECT cron.schedule('cleanup-expired-otps', '0 */6 * * *', 'SELECT cleanup_expired_otps()');

COMMIT;
