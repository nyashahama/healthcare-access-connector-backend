
-- Provider Indexes
CREATE INDEX idx_clinic_location ON clinics(province, city);
CREATE INDEX idx_clinic_type_status ON clinics(clinic_type, verification_status);
CREATE INDEX idx_clinic_coordinates ON clinics(latitude, longitude);

CREATE INDEX idx_staff_clinic ON clinic_staff(clinic_id);
CREATE INDEX idx_staff_role ON clinic_staff(staff_role, employment_status);
CREATE INDEX idx_staff_hpcs ON clinic_staff(hpcs_number);

CREATE INDEX idx_credentials_status ON professional_credentials(status, expiry_date);
CREATE INDEX idx_credentials_staff ON professional_credentials(staff_id);

CREATE INDEX idx_services_clinic ON clinic_services(clinic_id, is_active);
CREATE INDEX idx_services_category ON clinic_services(service_category);