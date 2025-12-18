-- Migration: 000001_initial_schema.down.sql
-- Description: Rollback initial schema

-- Drop views first
DROP VIEW IF EXISTS patient_demographics;

-- Drop functions
DROP FUNCTION IF EXISTS calculate_age(DATE);
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop tables in reverse order (respecting foreign key dependencies)
DROP TABLE IF EXISTS sms_messages CASCADE;
DROP TABLE IF EXISTS sms_conversations CASCADE;
DROP TABLE IF EXISTS notification_preferences CASCADE;
DROP TABLE IF EXISTS data_access_logs CASCADE;
DROP TABLE IF EXISTS user_activities CASCADE;
DROP TABLE IF EXISTS ngo_partners CASCADE;
DROP TABLE IF EXISTS system_admins CASCADE;
DROP TABLE IF EXISTS clinic_services CASCADE;
DROP TABLE IF EXISTS professional_credentials CASCADE;
DROP TABLE IF EXISTS clinic_staff CASCADE;
DROP TABLE IF EXISTS clinics CASCADE;
DROP TABLE IF EXISTS privacy_consents CASCADE;
DROP TABLE IF EXISTS emergency_contacts CASCADE;
DROP TABLE IF EXISTS dependent_health_records CASCADE;
DROP TABLE IF EXISTS patient_dependents CASCADE;
DROP TABLE IF EXISTS patient_family_history CASCADE;
DROP TABLE IF EXISTS patient_immunizations CASCADE;
DROP TABLE IF EXISTS patient_surgeries CASCADE;
DROP TABLE IF EXISTS patient_conditions CASCADE;
DROP TABLE IF EXISTS patient_medications CASCADE;
DROP TABLE IF EXISTS patient_allergies CASCADE;
DROP TABLE IF EXISTS patient_medical_info CASCADE;
DROP TABLE IF EXISTS patient_profiles CASCADE;
DROP TABLE IF EXISTS user_sessions CASCADE;
DROP TABLE IF EXISTS users CASCADE;



