-- Patient Indexes
CREATE INDEX idx_patient_user ON patient_profiles(user_id);
CREATE INDEX idx_patient_location ON patient_profiles(province, city);

CREATE INDEX idx_medical_patient ON patient_medical_info(patient_id);

CREATE INDEX idx_allergy_patient ON patient_allergies(patient_id);
CREATE INDEX idx_allergy_status ON patient_allergies(status);

CREATE INDEX idx_medication_patient ON patient_medications(patient_id);
CREATE INDEX idx_medication_status ON patient_medications(status);

CREATE INDEX idx_condition_patient ON patient_conditions(patient_id);
CREATE INDEX idx_condition_status ON patient_conditions(status);

CREATE INDEX idx_surgery_date ON patient_surgeries(procedure_date);
CREATE INDEX idx_surgery_patient ON patient_surgeries(patient_id);

CREATE INDEX idx_immunization_patient ON patient_immunizations(patient_id);
CREATE INDEX idx_immunization_dates ON patient_immunizations(administration_date, next_due_date);

CREATE INDEX idx_family_patient ON patient_family_history(patient_id);

CREATE INDEX idx_dependent_patient ON patient_dependents(patient_id);
CREATE INDEX idx_dependent_birthdate ON patient_dependents(date_of_birth);

CREATE INDEX idx_dependent_records ON dependent_health_records(dependent_id, record_date);

CREATE INDEX idx_emergency_patient ON emergency_contacts(patient_id);
CREATE INDEX idx_emergency_primary ON emergency_contacts(patient_id, is_primary);