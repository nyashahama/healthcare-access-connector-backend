-- ============================================
-- PATIENT MEDICATIONS REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Patient Medication Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddPatientMedication :one
INSERT INTO patient_medications (
    patient_id, medication_name, generic_name, dosage, frequency,
    route, prescribing_doctor, pharmacy_name, prescription_date,
    start_date, end_date, reason_for_medication, status,
    side_effects, instructions
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
RETURNING *;

-- name: GetPatientMedication :one
SELECT * FROM patient_medications
WHERE id = $1;

-- name: UpdatePatientMedication :exec
UPDATE patient_medications
SET 
    medication_name = COALESCE($2, medication_name),
    generic_name = COALESCE($3, generic_name),
    dosage = COALESCE($4, dosage),
    frequency = COALESCE($5, frequency),
    route = COALESCE($6, route),
    end_date = COALESCE($7, end_date),
    status = COALESCE($8, status),
    side_effects = COALESCE($9, side_effects),
    instructions = COALESCE($10, instructions),
    updated_at = NOW()
WHERE id = $1;

-- name: DeletePatientMedication :exec
DELETE FROM patient_medications WHERE id = $1;

-- ============================================
-- QUERYING BY PATIENT
-- ============================================

-- name: GetPatientMedications :many
SELECT 
    id, patient_id, medication_name, generic_name, dosage,
    frequency, route, prescribing_doctor, start_date, end_date,
    reason_for_medication, status, instructions, side_effects,
    created_at, updated_at
FROM patient_medications
WHERE 
    patient_id = $1
    AND ($2::VARCHAR IS NULL OR status = $2)
ORDER BY 
    CASE status
        WHEN 'active' THEN 1
        WHEN 'completed' THEN 2
        WHEN 'discontinued' THEN 3
        ELSE 4
    END,
    start_date DESC;

-- name: GetActiveMedications :many
SELECT 
    id, medication_name, generic_name, dosage, frequency,
    route, prescribing_doctor, start_date, reason_for_medication, instructions
FROM patient_medications
WHERE 
    patient_id = $1
    AND status = 'active'
ORDER BY start_date DESC;

-- name: GetCurrentMedications :many
SELECT 
    id, medication_name, dosage, frequency, route, instructions
FROM patient_medications
WHERE 
    patient_id = $1
    AND status = 'active'
    AND (end_date IS NULL OR end_date >= CURRENT_DATE)
ORDER BY medication_name;

-- name: GetMedicationHistory :many
SELECT 
    id, medication_name, dosage, frequency, start_date, end_date,
    status, reason_for_medication
FROM patient_medications
WHERE patient_id = $1
ORDER BY start_date DESC;

-- ============================================
-- STATUS MANAGEMENT
-- ============================================

-- name: UpdateMedicationStatus :exec
UPDATE patient_medications
SET 
    status = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: DiscontinueMedication :exec
UPDATE patient_medications
SET 
    status = 'discontinued',
    end_date = COALESCE($2, CURRENT_DATE),
    instructions = COALESCE($3, instructions),
    updated_at = NOW()
WHERE id = $1;

-- name: CompleteMedication :exec
UPDATE patient_medications
SET 
    status = 'completed',
    end_date = CURRENT_DATE,
    updated_at = NOW()
WHERE id = $1;

-- name: ReactivateMedication :exec
UPDATE patient_medications
SET 
    status = 'active',
    start_date = CURRENT_DATE,
    end_date = NULL,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- SIDE EFFECTS & MONITORING
-- ============================================

-- name: RecordSideEffects :exec
UPDATE patient_medications
SET 
    side_effects = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetMedicationsWithSideEffects :many
SELECT 
    pm.id,
    pm.patient_id,
    pp.first_name,
    pp.last_name,
    pm.medication_name,
    pm.side_effects,
    pm.start_date
FROM patient_medications pm
JOIN patient_profiles pp ON pm.patient_id = pp.id
WHERE 
    pm.side_effects IS NOT NULL
    AND pm.status = 'active'
ORDER BY pm.start_date DESC;

-- name: GetMedicationsByRoute :many
SELECT 
    id, medication_name, dosage, frequency, route, start_date
FROM patient_medications
WHERE 
    patient_id = $1
    AND route = $2
    AND status = 'active'
ORDER BY start_date DESC;

-- ============================================
-- PRESCRIBER & PHARMACY QUERIES
-- ============================================

-- name: GetMedicationsByPrescriber :many
SELECT 
    pm.patient_id,
    pp.first_name,
    pp.last_name,
    pm.medication_name,
    pm.prescription_date,
    pm.status
FROM patient_medications pm
JOIN patient_profiles pp ON pm.patient_id = pp.id
WHERE pm.prescribing_doctor = $1
ORDER BY pm.prescription_date DESC;

-- name: GetMedicationsByPharmacy :many
SELECT 
    pm.patient_id,
    pp.first_name,
    pp.last_name,
    pm.medication_name,
    pm.prescription_date,
    pm.status
FROM patient_medications pm
JOIN patient_profiles pp ON pm.patient_id = pp.id
WHERE pm.pharmacy_name = $1
ORDER BY pm.prescription_date DESC;

-- name: UpdatePharmacy :exec
UPDATE patient_medications
SET 
    pharmacy_name = $2,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- EXPIRATION & REFILL MANAGEMENT
-- ============================================

-- name: GetExpiringMedications :many
SELECT 
    pm.id,
    pm.patient_id,
    pp.first_name,
    pp.last_name,
    pm.medication_name,
    pm.end_date,
    pm.prescribing_doctor
FROM patient_medications pm
JOIN patient_profiles pp ON pm.patient_id = pp.id
WHERE 
    pm.status = 'active'
    AND pm.end_date BETWEEN CURRENT_DATE AND $1
ORDER BY pm.end_date ASC;

-- name: GetExpiredMedications :many
SELECT 
    pm.id,
    pm.patient_id,
    pp.first_name,
    pp.last_name,
    pm.medication_name,
    pm.end_date
FROM patient_medications pm
JOIN patient_profiles pp ON pm.patient_id = pp.id
WHERE 
    pm.status = 'active'
    AND pm.end_date < CURRENT_DATE
ORDER BY pm.end_date ASC;

-- name: UpdateMedicationEndDate :exec
UPDATE patient_medications
SET 
    end_date = $2,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- SEARCH & FILTERING
-- ============================================

-- name: SearchMedicationsByName :many
SELECT 
    id, medication_name, generic_name, dosage, frequency, status
FROM patient_medications
WHERE 
    patient_id = $1
    AND (medication_name ILIKE '%' || $2 || '%' 
         OR generic_name ILIKE '%' || $2 || '%')
ORDER BY start_date DESC;

-- name: GetPatientsByMedication :many
SELECT 
    pm.patient_id,
    pp.first_name,
    pp.last_name,
    pm.dosage,
    pm.frequency,
    pm.start_date,
    pp.city,
    pp.province
FROM patient_medications pm
JOIN patient_profiles pp ON pm.patient_id = pp.id
WHERE 
    (pm.medication_name ILIKE '%' || $1 || '%'
     OR pm.generic_name ILIKE '%' || $1 || '%')
    AND pm.status = 'active'
ORDER BY pp.last_name;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountPatientMedications :one
SELECT 
    COUNT(*) as total_medications,
    COUNT(*) FILTER (WHERE status = 'active') as active_medications,
    COUNT(*) FILTER (WHERE side_effects IS NOT NULL) as with_side_effects,
    COUNT(DISTINCT prescribing_doctor) FILTER (WHERE prescribing_doctor IS NOT NULL) as prescriber_count
FROM patient_medications
WHERE patient_id = $1;

-- name: GetMedicationStatistics :one
SELECT 
    COUNT(DISTINCT patient_id) as patients_on_medication,
    COUNT(*) as total_prescriptions,
    COUNT(*) FILTER (WHERE status = 'active') as active_prescriptions,
    COUNT(*) FILTER (WHERE side_effects IS NOT NULL) as with_side_effects,
    COUNT(DISTINCT medication_name) as unique_medications,
    AVG(EXTRACT(DAY FROM AGE(COALESCE(end_date, CURRENT_DATE), start_date))) FILTER (WHERE start_date IS NOT NULL) as avg_duration_days
FROM patient_medications;

-- name: GetMostPrescribedMedications :many
SELECT 
    medication_name,
    COUNT(DISTINCT patient_id) as patient_count,
    COUNT(*) FILTER (WHERE status = 'active') as active_prescriptions,
    COUNT(*) FILTER (WHERE side_effects IS NOT NULL) as reported_side_effects
FROM patient_medications
GROUP BY medication_name
ORDER BY patient_count DESC
LIMIT $1;

-- name: GetPrescriptionTrends :many
SELECT 
    DATE_TRUNC('month', prescription_date) as month,
    COUNT(*) as prescription_count,
    COUNT(DISTINCT patient_id) as unique_patients,
    COUNT(DISTINCT medication_name) as unique_medications
FROM patient_medications
WHERE prescription_date >= $1
GROUP BY DATE_TRUNC('month', prescription_date)
ORDER BY month DESC;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetMedicationsByPatientIDs :many
SELECT 
    patient_id, medication_name, dosage, frequency, status
FROM patient_medications
WHERE 
    patient_id = ANY($1::uuid[])
    AND status = 'active'
ORDER BY patient_id, medication_name;

-- name: BulkUpdateMedicationStatus :exec
UPDATE patient_medications
SET 
    status = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: DeletePatientMedications :exec
DELETE FROM patient_medications
WHERE patient_id = $1;

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: CheckMedicationConflict :one
SELECT EXISTS(
    SELECT 1 FROM patient_medications
    WHERE 
        patient_id = $1
        AND (medication_name = $2 OR generic_name = $2)
        AND status = 'active'
        AND id != COALESCE($3, '00000000-0000-0000-0000-000000000000'::uuid)
) as has_conflict;

-- name: GetActiveMedicationCount :one
SELECT COUNT(*) as active_count
FROM patient_medications
WHERE 
    patient_id = $1
    AND status = 'active';

-- ============================================
-- REPORTING QUERIES
-- ============================================

-- name: GetPatientsOnMultipleMedications :many
SELECT 
    pm.patient_id,
    pp.first_name,
    pp.last_name,
    COUNT(*) as medication_count,
    STRING_AGG(pm.medication_name, ', ' ORDER BY pm.medication_name) as medications
FROM patient_medications pm
JOIN patient_profiles pp ON pm.patient_id = pp.id
WHERE pm.status = 'active'
GROUP BY pm.patient_id, pp.first_name, pp.last_name
HAVING COUNT(*) >= $1
ORDER BY medication_count DESC;

-- name: GetLongTermMedications :many
SELECT 
    pm.id,
    pm.patient_id,
    pp.first_name,
    pp.last_name,
    pm.medication_name,
    pm.start_date,
    EXTRACT(YEAR FROM AGE(CURRENT_DATE, pm.start_date))::INTEGER as years_on_medication
FROM patient_medications pm
JOIN patient_profiles pp ON pm.patient_id = pp.id
WHERE 
    pm.status = 'active'
    AND pm.start_date < CURRENT_DATE - INTERVAL '1 year'
ORDER BY pm.start_date ASC;

-- name: GetEmergencyMedicationInfo :many
SELECT 
    medication_name,
    dosage,
    frequency,
    route,
    reason_for_medication,
    prescribing_doctor
FROM patient_medications
WHERE 
    patient_id = $1
    AND status = 'active'
ORDER BY medication_name;
