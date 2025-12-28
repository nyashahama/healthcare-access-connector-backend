-- ============================================
-- Database Initialization Script
-- ============================================

-- Core tables first (due to foreign key dependencies)
\i schemas/core/users.sql
\i schemas/core/user_sessions.sql
\i schemas/core/otp_verifications.sql
\i schemas/core/notification_preferences.sql
\i schemas/core/privacy_consents.sql
\i schemas/core/user_activities.sql
\i schemas/core/data_access_logs.sql

-- Patient tables
\i schemas/patients/patient_profiles.sql
\i schemas/patients/patient_medical_info.sql
\i schemas/patients/patient_allergies.sql
\i schemas/patients/patient_medications.sql
\i schemas/patients/patient_conditions.sql
\i schemas/patients/patient_surgeries.sql
\i schemas/patients/patient_immunizations.sql
\i schemas/patients/patient_family_history.sql
\i schemas/patients/patient_dependents.sql
\i schemas/patients/dependent_health_records.sql
\i schemas/patients/emergency_contacts.sql

-- Provider tables
\i schemas/providers/clinics.sql
\i schemas/providers/clinic_staff.sql
\i schemas/providers/professional_credentials.sql
\i schemas/providers/clinic_services.sql

-- Admin tables
\i schemas/admin/system_admins.sql
\i schemas/admin/ngo_partners.sql

-- SMS tables
\i schemas/sms/sms_conversations.sql
\i schemas/sms/sms_messages.sql

-- Indexes
\i schemas/indexes/core_indexes.sql
\i schemas/indexes/patients_indexes.sql
\i schemas/indexes/providers_indexes.sql
\i schemas/indexes/admin_indexes.sql
\i schemas/indexes/sms_indexes.sql
\i schemas/indexes/composite_indexes.sql
\i schemas/indexes/full_text_indexes.sql

-- Functions & Triggers
\i schemas/functions_triggers/update_updated_at.sql
\i schemas/functions_triggers/calculate_age.sql
\i schemas/functions_triggers/cleanup_expired_otps.sql

-- Views
\i schemas/views/patient_demographics.sql