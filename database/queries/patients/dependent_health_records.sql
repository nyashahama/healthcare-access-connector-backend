-- ============================================
-- DEPENDENT HEALTH RECORDS REPOSITORY QUERIES
-- Maps to: Part of PatientRepository interface
-- Domain: Dependent Health Records & Growth Tracking
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: AddDependentHealthRecord :one
INSERT INTO dependent_health_records (
    dependent_id, record_type, record_date, weight_kg, height_cm,
    head_circumference_cm, temperature_c, notes, provider_name,
    clinic_name, next_appointment_date, documents
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
RETURNING *;

-- name: GetDependentHealthRecord :one
SELECT * FROM dependent_health_records
WHERE id = $1;

-- name: UpdateDependentHealthRecord :exec
UPDATE dependent_health_records
SET 
    record_type = COALESCE($2, record_type),
    weight_kg = COALESCE($3, weight_kg),
    height_cm = COALESCE($4, height_cm),
    head_circumference_cm = COALESCE($5, head_circumference_cm),
    temperature_c = COALESCE($6, temperature_c),
    notes = COALESCE($7, notes),
    next_appointment_date = COALESCE($8, next_appointment_date)
WHERE id = $1;

-- name: DeleteDependentHealthRecord :exec
DELETE FROM dependent_health_records WHERE id = $1;

-- ============================================
-- QUERYING BY DEPENDENT
-- ============================================

-- name: GetDependentHealthRecords :many
SELECT 
    id, dependent_id, record_type, record_date, weight_kg,
    height_cm, head_circumference_cm, temperature_c, notes,
    provider_name, clinic_name, next_appointment_date, created_at
FROM dependent_health_records
WHERE dependent_id = $1
ORDER BY record_date DESC;

-- name: GetHealthRecordsByType :many
SELECT 
    id, record_date, weight_kg, height_cm, temperature_c,
    provider_name, clinic_name, notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_type = $2
ORDER BY record_date DESC;

-- name: GetGrowthRecords :many
SELECT 
    id, record_date, weight_kg, height_cm, head_circumference_cm, notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_type = 'growth_check'
ORDER BY record_date DESC;

-- name: GetVaccinationRecords :many
SELECT 
    id, record_date, provider_name, clinic_name, notes, documents
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_type = 'vaccination'
ORDER BY record_date DESC;

-- name: GetCheckupRecords :many
SELECT 
    id, record_date, weight_kg, height_cm, temperature_c,
    provider_name, clinic_name, notes, next_appointment_date
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_type = 'checkup'
ORDER BY record_date DESC;

-- name: GetEmergencyRecords :many
SELECT 
    id, record_date, temperature_c, provider_name,
    clinic_name, notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_type = 'emergency'
ORDER BY record_date DESC;

-- ============================================
-- GROWTH TRACKING
-- ============================================

-- name: GetLatestGrowthMeasurements :one
SELECT 
    weight_kg,
    height_cm,
    head_circumference_cm,
    record_date
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND (weight_kg IS NOT NULL OR height_cm IS NOT NULL OR head_circumference_cm IS NOT NULL)
ORDER BY record_date DESC
LIMIT 1;

-- name: GetWeightHistory :many
SELECT 
    record_date,
    weight_kg,
    record_type
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND weight_kg IS NOT NULL
ORDER BY record_date ASC;

-- name: GetHeightHistory :many
SELECT 
    record_date,
    height_cm,
    record_type
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND height_cm IS NOT NULL
ORDER BY record_date ASC;

-- name: GetHeadCircumferenceHistory :many
SELECT 
    record_date,
    head_circumference_cm,
    record_type
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND head_circumference_cm IS NOT NULL
ORDER BY record_date ASC;

-- name: GetGrowthTrend :many
SELECT 
    record_date,
    weight_kg,
    height_cm,
    head_circumference_cm
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND (weight_kg IS NOT NULL OR height_cm IS NOT NULL OR head_circumference_cm IS NOT NULL)
ORDER BY record_date ASC;

-- ============================================
-- VITAL SIGNS TRACKING
-- ============================================

-- name: GetTemperatureHistory :many
SELECT 
    record_date,
    temperature_c,
    record_type,
    notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND temperature_c IS NOT NULL
ORDER BY record_date DESC;

-- name: GetAbnormalTemperatures :many
SELECT 
    id, record_date, temperature_c, record_type, notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND temperature_c IS NOT NULL
    AND (temperature_c < 36.0 OR temperature_c > 38.0)
ORDER BY record_date DESC;

-- ============================================
-- APPOINTMENT MANAGEMENT
-- ============================================

-- name: GetUpcomingAppointments :many
SELECT 
    dhr.id,
    dhr.dependent_id,
    pd.first_name,
    pd.last_name,
    dhr.next_appointment_date,
    dhr.record_type,
    dhr.provider_name,
    dhr.clinic_name
FROM dependent_health_records dhr
JOIN patient_dependents pd ON dhr.dependent_id = pd.id
WHERE 
    dhr.next_appointment_date >= CURRENT_DATE
ORDER BY dhr.next_appointment_date ASC;

-- name: UpdateNextAppointment :exec
UPDATE dependent_health_records
SET 
    next_appointment_date = $2
WHERE id = $1;

-- ============================================
-- PROVIDER & CLINIC QUERIES
-- ============================================

-- name: GetRecordsByProvider :many
SELECT 
    id, record_date, record_type, weight_kg, height_cm, notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND provider_name = $2
ORDER BY record_date DESC;

-- name: GetRecordsByClinic :many
SELECT 
    id, record_date, record_type, provider_name, notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND clinic_name = $2
ORDER BY record_date DESC;

-- name: GetProviderList :many
SELECT DISTINCT provider_name
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND provider_name IS NOT NULL
ORDER BY provider_name;

-- name: GetClinicList :many
SELECT DISTINCT clinic_name
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND clinic_name IS NOT NULL
ORDER BY clinic_name;

-- ============================================
-- DOCUMENT MANAGEMENT
-- ============================================

-- name: UpdateRecordDocuments :exec
UPDATE dependent_health_records
SET 
    documents = $2
WHERE id = $1;

-- name: AddRecordDocument :exec
UPDATE dependent_health_records
SET 
    documents = COALESCE(documents, '[]'::jsonb) || $2::jsonb
WHERE id = $1;

-- name: GetRecordsWithDocuments :many
SELECT 
    id, record_date, record_type, documents, provider_name
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND documents IS NOT NULL
    AND jsonb_array_length(documents) > 0
ORDER BY record_date DESC;

-- ============================================
-- DATE RANGE QUERIES
-- ============================================

-- name: GetRecordsByDateRange :many
SELECT 
    id, record_type, record_date, weight_kg, height_cm,
    temperature_c, provider_name, clinic_name, notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_date BETWEEN $2 AND $3
ORDER BY record_date DESC;

-- name: GetRecentRecords :many
SELECT 
    id, record_type, record_date, weight_kg, height_cm,
    provider_name, notes
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_date >= CURRENT_DATE - INTERVAL '6 months'
ORDER BY record_date DESC;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountHealthRecords :one
SELECT 
    COUNT(*) as total_records,
    COUNT(*) FILTER (WHERE record_type = 'growth_check') as growth_checks,
    COUNT(*) FILTER (WHERE record_type = 'vaccination') as vaccinations,
    COUNT(*) FILTER (WHERE record_type = 'checkup') as checkups,
    COUNT(*) FILTER (WHERE record_type = 'emergency') as emergency_visits,
    MAX(record_date) as last_record_date
FROM dependent_health_records
WHERE dependent_id = $1;

-- name: GetRecordTypeDistribution :many
SELECT 
    record_type,
    COUNT(*) as record_count,
    MAX(record_date) as last_record_date
FROM dependent_health_records
WHERE dependent_id = $1
GROUP BY record_type
ORDER BY record_count DESC;

-- name: GetGrowthStatistics :one
SELECT 
    MIN(weight_kg) FILTER (WHERE weight_kg IS NOT NULL) as min_weight,
    MAX(weight_kg) FILTER (WHERE weight_kg IS NOT NULL) as max_weight,
    MIN(height_cm) FILTER (WHERE height_cm IS NOT NULL) as min_height,
    MAX(height_cm) FILTER (WHERE height_cm IS NOT NULL) as max_height,
    COUNT(*) FILTER (WHERE weight_kg IS NOT NULL OR height_cm IS NOT NULL) as measurements_count
FROM dependent_health_records
WHERE dependent_id = $1;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetRecordsByDependentIDs :many
SELECT 
    dependent_id, record_type, record_date, provider_name
FROM dependent_health_records
WHERE dependent_id = ANY($1::uuid[])
ORDER BY dependent_id, record_date DESC;

-- name: DeleteDependentHealthRecords :exec
DELETE FROM dependent_health_records
WHERE dependent_id = $1;

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: HasHealthRecords :one
SELECT EXISTS(
    SELECT 1 FROM dependent_health_records
    WHERE dependent_id = $1
) as has_records;

-- name: GetLastCheckupDate :one
SELECT MAX(record_date) as last_checkup_date
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_type = 'checkup';

-- name: GetLastGrowthCheckDate :one
SELECT MAX(record_date) as last_growth_check_date
FROM dependent_health_records
WHERE 
    dependent_id = $1
    AND record_type = 'growth_check';