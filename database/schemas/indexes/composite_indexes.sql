-- Composite Indexes for Performance
CREATE INDEX idx_users_composite ON users(role, status, created_at);
CREATE INDEX idx_patients_search ON patient_profiles(first_name, last_name, province, city);
CREATE INDEX idx_clinics_search ON clinics(clinic_name, province, city, clinic_type, is_verified);
CREATE INDEX idx_staff_search ON clinic_staff(first_name, last_name, specialization, clinic_id);