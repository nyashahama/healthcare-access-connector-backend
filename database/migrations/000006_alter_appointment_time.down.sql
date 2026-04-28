-- Rollback: restore appointments.appointment_time as DATE
ALTER TABLE appointments ADD COLUMN appointment_time_new DATE;

UPDATE appointments
SET appointment_time_new = appointment_datetime::DATE;

ALTER TABLE appointments DROP COLUMN appointment_time;

ALTER TABLE appointments RENAME COLUMN appointment_time_new TO appointment_time;

ALTER TABLE appointments ALTER COLUMN appointment_time SET NOT NULL;
