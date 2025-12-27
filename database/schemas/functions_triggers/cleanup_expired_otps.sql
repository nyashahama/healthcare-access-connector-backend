-- Add cleanup function for expired OTPs
CREATE OR REPLACE FUNCTION cleanup_expired_otps()
RETURNS void AS $$
BEGIN
    DELETE FROM otp_verifications
    WHERE expires_at < NOW() OR created_at < NOW() - INTERVAL '24 hours';
END;
$$ LANGUAGE plpgsql;