-- Core Indexes
CREATE INDEX idx_user_email ON users(email);
CREATE INDEX idx_user_phone ON users(phone);
CREATE INDEX idx_user_role_status ON users(role, status);

CREATE INDEX idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX idx_user_sessions_user ON user_sessions(user_id);

CREATE INDEX idx_otp_user ON otp_verifications(user_id);
CREATE INDEX idx_otp_expires ON otp_verifications(expires_at);
CREATE INDEX idx_otp_used ON otp_verifications(used_at);
CREATE INDEX idx_otp_lookup ON otp_verifications(user_id, otp, type) WHERE used_at IS NULL;

CREATE INDEX idx_notif_pref_user ON notification_preferences(user_id);
CREATE INDEX idx_consent_user ON privacy_consents(user_id);
CREATE INDEX idx_activity_user ON user_activities(user_id, performed_at);
CREATE INDEX idx_activity_type ON user_activities(activity_type, performed_at);
CREATE INDEX idx_access_log_accessed ON data_access_logs(accessed_user_id, accessed_at);
CREATE INDEX idx_access_log_accessor ON data_access_logs(accessed_by_user_id, accessed_at);