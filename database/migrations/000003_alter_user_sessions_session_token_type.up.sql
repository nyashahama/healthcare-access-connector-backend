-- Increase session_token column length to accommodate JWT tokens
ALTER TABLE user_sessions ALTER COLUMN session_token TYPE TEXT;
