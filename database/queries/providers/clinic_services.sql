-- ============================================
-- CLINIC SERVICES REPOSITORY QUERIES
-- Maps to: Part of ClinicRepository interface (service-related methods)
-- Domain: Healthcare Service Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreateClinicService :one
INSERT INTO clinic_services (
    clinic_id, service_name, service_category, description,
    duration_minutes, preparation_instructions, follow_up_required, follow_up_days,
    minimum_age, maximum_age, gender_restriction, prerequisites,
    cost, cost_currency, is_covered_by_medical_aid, medical_aid_codes,
    is_active, available_days, requires_appointment, walk_in_allowed,
    provided_by_staff_ids
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
    $13, $14, $15, $16, $17, $18, $19, $20, $21
)
RETURNING *;

-- name: GetServiceByID :one
SELECT * FROM clinic_services
WHERE id = $1;

-- name: UpdateClinicService :exec
UPDATE clinic_services
SET 
    service_name = COALESCE($2, service_name),
    service_category = COALESCE($3, service_category),
    description = COALESCE($4, description),
    duration_minutes = COALESCE($5, duration_minutes),
    cost = COALESCE($6, cost),
    is_covered_by_medical_aid = COALESCE($7, is_covered_by_medical_aid),
    requires_appointment = COALESCE($8, requires_appointment),
    walk_in_allowed = COALESCE($9, walk_in_allowed),
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteClinicService :exec
DELETE FROM clinic_services 
WHERE id = $1;

-- ============================================
-- SERVICE STATUS MANAGEMENT
-- ============================================

-- name: ActivateService :exec
UPDATE clinic_services
SET 
    is_active = TRUE,
    updated_at = NOW()
WHERE id = $1;

-- name: DeactivateService :exec
UPDATE clinic_services
SET 
    is_active = FALSE,
    updated_at = NOW()
WHERE id = $1;

-- name: ToggleServiceStatus :exec
UPDATE clinic_services
SET 
    is_active = NOT is_active,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- SERVICE DETAILS MANAGEMENT
-- ============================================

-- name: UpdateServiceDetails :exec
UPDATE clinic_services
SET 
    description = $2,
    duration_minutes = $3,
    preparation_instructions = $4,
    follow_up_required = $5,
    follow_up_days = $6,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateServiceEligibility :exec
UPDATE clinic_services
SET 
    minimum_age = $2,
    maximum_age = $3,
    gender_restriction = $4,
    prerequisites = $5,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateServiceCost :exec
UPDATE clinic_services
SET 
    cost = $2,
    cost_currency = COALESCE($3, cost_currency),
    is_covered_by_medical_aid = $4,
    medical_aid_codes = $5,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateServiceAvailability :exec
UPDATE clinic_services
SET 
    available_days = $2,
    requires_appointment = $3,
    walk_in_allowed = $4,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateServiceStaff :exec
UPDATE clinic_services
SET 
    provided_by_staff_ids = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: AddStaffToService :exec
UPDATE clinic_services
SET 
    provided_by_staff_ids = array_append(provided_by_staff_ids, $2),
    updated_at = NOW()
WHERE id = $1
AND NOT ($2 = ANY(provided_by_staff_ids));

-- name: RemoveStaffFromService :exec
UPDATE clinic_services
SET 
    provided_by_staff_ids = array_remove(provided_by_staff_ids, $2),
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- SERVICE METRICS & RATINGS
-- ============================================

-- name: UpdateServiceRating :exec
UPDATE clinic_services
SET 
    average_rating = $2,
    review_count = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: IncrementServiceReviewCount :exec
UPDATE clinic_services
SET 
    review_count = review_count + 1,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateServicePopularity :exec
UPDATE clinic_services
SET 
    popularity_score = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: IncrementPopularityScore :exec
UPDATE clinic_services
SET 
    popularity_score = popularity_score + 1,
    updated_at = NOW()
WHERE id = $1;

-- ============================================
-- QUERYING BY CLINIC
-- ============================================

-- name: GetClinicServices :many
SELECT 
    id, clinic_id, service_name, service_category, description,
    duration_minutes, cost, cost_currency, is_covered_by_medical_aid,
    is_active, requires_appointment, walk_in_allowed,
    average_rating, review_count, popularity_score
FROM clinic_services
WHERE clinic_id = $1 
ORDER BY popularity_score DESC, service_name ASC;

-- name: GetActiveClinicServices :many
SELECT 
    id, clinic_id, service_name, service_category, description,
    duration_minutes, cost, cost_currency, is_covered_by_medical_aid,
    requires_appointment, walk_in_allowed,
    average_rating, review_count, popularity_score
FROM clinic_services
WHERE 
    clinic_id = $1 
    AND is_active = TRUE
ORDER BY popularity_score DESC, service_name ASC;

-- name: GetClinicServicesByCategory :many
SELECT 
    id, service_name, service_category, description,
    cost, duration_minutes, is_active, average_rating
FROM clinic_services
WHERE 
    clinic_id = $1
    AND service_category = $2
    AND is_active = TRUE
ORDER BY popularity_score DESC;

-- name: GetClinicServicesByStaff :many
SELECT 
    cs.id, cs.service_name, cs.service_category,
    cs.cost, cs.duration_minutes, cs.is_active
FROM clinic_services cs
WHERE 
    cs.clinic_id = $1
    AND $2 = ANY(cs.provided_by_staff_ids)
    AND cs.is_active = TRUE
ORDER BY cs.service_name;

-- ============================================
-- SEARCH & FILTERING
-- ============================================

-- name: SearchServices :many
SELECT 
    id, clinic_id, service_name, service_category,
    description, cost, duration_minutes,
    is_covered_by_medical_aid, average_rating
FROM clinic_services
WHERE 
    service_name ILIKE '%' || $1 || '%'
    AND is_active = TRUE
    AND ($2::uuid IS NULL OR clinic_id = $2)
ORDER BY popularity_score DESC
LIMIT $3 OFFSET $4;

-- name: SearchServicesByCategory :many
SELECT 
    id, clinic_id, service_name, description,
    cost, duration_minutes, average_rating
FROM clinic_services
WHERE 
    service_category = $1
    AND is_active = TRUE
    AND ($2::uuid IS NULL OR clinic_id = $2)
ORDER BY average_rating DESC NULLS LAST, popularity_score DESC
LIMIT $3 OFFSET $4;

-- name: GetServicesByPriceRange :many
SELECT 
    id, clinic_id, service_name, service_category,
    cost, cost_currency, duration_minutes
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND cost >= $2
    AND cost <= $3
ORDER BY cost ASC;

-- name: GetFreeServices :many
SELECT 
    id, clinic_id, service_name, service_category, description
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND (cost = 0 OR cost IS NULL)
ORDER BY service_name;

-- name: GetWalkInServices :many
SELECT 
    id, clinic_id, service_name, service_category,
    cost, duration_minutes
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND walk_in_allowed = TRUE
ORDER BY popularity_score DESC;

-- name: GetAppointmentOnlyServices :many
SELECT 
    id, clinic_id, service_name, service_category,
    cost, duration_minutes, requires_appointment
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND requires_appointment = TRUE
    AND walk_in_allowed = FALSE
ORDER BY service_name;

-- ============================================
-- MEDICAL AID COVERAGE
-- ============================================

-- name: GetMedicalAidCoveredServices :many
SELECT 
    id, clinic_id, service_name, service_category,
    cost, is_covered_by_medical_aid, medical_aid_codes
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND is_covered_by_medical_aid = TRUE
ORDER BY service_name;

-- name: GetServicesByMedicalAidCode :many
SELECT 
    id, clinic_id, service_name, service_category,
    cost, medical_aid_codes
FROM clinic_services
WHERE 
    is_active = TRUE
    AND medical_aid_codes @> $1::jsonb
ORDER BY clinic_id, service_name;

-- ============================================
-- AGE & ELIGIBILITY FILTERING
-- ============================================

-- name: GetServicesForAge :many
SELECT 
    id, clinic_id, service_name, service_category,
    minimum_age, maximum_age, cost
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND (minimum_age IS NULL OR minimum_age <= $2)
    AND (maximum_age IS NULL OR maximum_age >= $2)
ORDER BY service_name;

-- name: GetServicesForGender :many
SELECT 
    id, clinic_id, service_name, service_category,
    gender_restriction, cost
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND (gender_restriction = 'none' OR gender_restriction = $2)
ORDER BY service_name;

-- name: GetPediatricServices :many
SELECT 
    id, clinic_id, service_name, service_category,
    minimum_age, maximum_age, cost
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND service_category = 'pediatric'
    AND (maximum_age IS NOT NULL AND maximum_age <= 18)
ORDER BY service_name;

-- name: GetPreventiveServices :many
SELECT 
    id, clinic_id, service_name, description,
    cost, duration_minutes
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND service_category = 'preventive'
ORDER BY service_name;

-- ============================================
-- POPULAR & RECOMMENDED SERVICES
-- ============================================

-- name: GetTopRatedServices :many
SELECT 
    id, clinic_id, service_name, service_category,
    average_rating, review_count, cost
FROM clinic_services
WHERE 
    is_active = TRUE
    AND average_rating IS NOT NULL
    AND review_count >= $1
    AND ($2::uuid IS NULL OR clinic_id = $2)
ORDER BY average_rating DESC, review_count DESC
LIMIT $3;

-- name: GetMostPopularServices :many
SELECT 
    id, clinic_id, service_name, service_category,
    popularity_score, average_rating, cost
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
ORDER BY popularity_score DESC, average_rating DESC NULLS LAST
LIMIT $2;

-- name: GetRecentlyAddedServices :many
SELECT 
    id, clinic_id, service_name, service_category,
    cost, created_at
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
ORDER BY created_at DESC
LIMIT $2;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: GetServiceStatistics :one
SELECT 
    id,
    service_name,
    average_rating,
    review_count,
    popularity_score,
    cost,
    created_at
FROM clinic_services
WHERE id = $1;

-- name: GetClinicServiceMetrics :one
SELECT 
    COUNT(*) as total_services,
    COUNT(*) FILTER (WHERE is_active = TRUE) as active_services,
    COUNT(*) FILTER (WHERE is_active = FALSE) as inactive_services,
    AVG(cost) FILTER (WHERE cost > 0) as average_cost,
    AVG(duration_minutes) FILTER (WHERE duration_minutes IS NOT NULL) as avg_duration,
    AVG(average_rating) FILTER (WHERE average_rating IS NOT NULL) as overall_rating,
    SUM(review_count) as total_reviews,
    COUNT(*) FILTER (WHERE is_covered_by_medical_aid = TRUE) as medical_aid_services,
    COUNT(*) FILTER (WHERE walk_in_allowed = TRUE) as walk_in_services
FROM clinic_services
WHERE clinic_id = $1;

-- name: GetServiceCategoryDistribution :many
SELECT 
    service_category,
    COUNT(*) as count,
    AVG(cost) FILTER (WHERE cost > 0) as avg_cost,
    AVG(average_rating) FILTER (WHERE average_rating IS NOT NULL) as avg_rating
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
GROUP BY service_category
ORDER BY count DESC;

-- name: GetServicePriceDistribution :many
SELECT 
    CASE
        WHEN cost = 0 OR cost IS NULL THEN 'Free'
        WHEN cost < 500 THEN 'Under R500'
        WHEN cost < 1000 THEN 'R500-R1000'
        WHEN cost < 2000 THEN 'R1000-R2000'
        ELSE 'Over R2000'
    END as price_range,
    COUNT(*) as count,
    AVG(average_rating) FILTER (WHERE average_rating IS NOT NULL) as avg_rating
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
GROUP BY price_range
ORDER BY 
    CASE price_range
        WHEN 'Free' THEN 1
        WHEN 'Under R500' THEN 2
        WHEN 'R500-R1000' THEN 3
        WHEN 'R1000-R2000' THEN 4
        ELSE 5
    END;

-- ============================================
-- COUNTING & EXISTENCE CHECKS
-- ============================================

-- name: CountClinicServices :one
SELECT COUNT(*) 
FROM clinic_services
WHERE 
    clinic_id = $1
    AND ($2::BOOLEAN IS NULL OR is_active = $2);

-- name: CountServicesByCategory :one
SELECT COUNT(*)
FROM clinic_services
WHERE 
    clinic_id = $1
    AND service_category = $2
    AND is_active = TRUE;

-- name: ServiceExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_services 
    WHERE id = $1
) as exists;

-- name: CheckServiceNameExists :one
SELECT EXISTS(
    SELECT 1 FROM clinic_services
    WHERE 
        clinic_id = $1
        AND service_name = $2
        AND ($3::uuid IS NULL OR id != $3)
) as exists;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetServicesByIDs :many
SELECT * FROM clinic_services
WHERE id = ANY($1::uuid[])
ORDER BY service_name;

-- name: BulkActivateServices :exec
UPDATE clinic_services
SET 
    is_active = TRUE,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkDeactivateServices :exec
UPDATE clinic_services
SET 
    is_active = FALSE,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkUpdateServiceCategory :exec
UPDATE clinic_services
SET 
    service_category = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: DeactivateClinicServices :exec
UPDATE clinic_services
SET 
    is_active = FALSE,
    updated_at = NOW()
WHERE clinic_id = $1;

-- ============================================
-- AVAILABILITY & SCHEDULING
-- ============================================

-- name: GetServicesAvailableOnDay :many
SELECT 
    id, service_name, service_category, cost,
    duration_minutes, available_days
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND $2 = ANY(available_days)
ORDER BY service_name;

-- name: GetServicesRequiringFollowUp :many
SELECT 
    id, clinic_id, service_name,
    follow_up_required, follow_up_days,
    cost
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND follow_up_required = TRUE
ORDER BY service_name;

-- name: GetQuickServices :many
SELECT 
    id, clinic_id, service_name,
    duration_minutes, cost
FROM clinic_services
WHERE 
    clinic_id = $1
    AND is_active = TRUE
    AND duration_minutes <= $2
ORDER BY duration_minutes ASC;

-- ============================================
-- COMPARISON & CROSS-CLINIC QUERIES
-- ============================================

-- name: CompareServiceAcrossClinics :many
SELECT 
    cs.clinic_id,
    c.clinic_name,
    cs.cost,
    cs.duration_minutes,
    cs.average_rating,
    cs.is_covered_by_medical_aid
FROM clinic_services cs
JOIN clinics c ON cs.clinic_id = c.id
WHERE 
    cs.service_name = $1
    AND cs.is_active = TRUE
    AND c.verification_status = 'verified'
ORDER BY cs.cost ASC;

-- name: GetCheapestServiceProviders :many
SELECT 
    cs.clinic_id,
    c.clinic_name,
    cs.service_name,
    cs.cost,
    c.city,
    c.province
FROM clinic_services cs
JOIN clinics c ON cs.clinic_id = c.id
WHERE 
    cs.service_name ILIKE '%' || $1 || '%'
    AND cs.is_active = TRUE
    AND c.verification_status = 'verified'
    AND cs.cost > 0
ORDER BY cs.cost ASC
LIMIT $2;
