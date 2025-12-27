-- Full-text search indexes
CREATE INDEX idx_patients_ftsearch ON patient_profiles 
USING GIN(to_tsvector('english', first_name || ' ' || last_name || ' ' || primary_address));

CREATE INDEX idx_clinics_ftsearch ON clinics 
USING GIN(to_tsvector('english', clinic_name || ' ' || description || ' ' || physical_address));