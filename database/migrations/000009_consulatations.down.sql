-- Rollback: remove consultation schema
DROP TABLE IF EXISTS consultation_messages CASCADE;
DROP TABLE IF EXISTS consultation_notes CASCADE;
DROP TABLE IF EXISTS consultations CASCADE;
