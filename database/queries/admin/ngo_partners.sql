-- ============================================
-- NGO PARTNERS REPOSITORY QUERIES
-- Maps to: NGOPartnerRepository interface
-- Domain: NGO Partner & Stakeholder Management
-- ============================================

-- ============================================
-- CORE CRUD OPERATIONS
-- ============================================

-- name: CreateNGOPartner :one
INSERT INTO ngo_partners (
    user_id, organization_name, organization_type, registration_number,
    tax_id, organization_address, organization_phone, organization_email,
    website, contact_person_name, contact_person_role, contact_person_phone,
    contact_person_email, partnership_type, partnership_start_date,
    partnership_end_date, partnership_status, operating_regions,
    focus_areas, can_access_reports, report_access_level,
    custom_report_filters, logo_url, branding_color
)
VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
    $16, $17, $18, $19, $20, $21, $22, $23, $24
)
RETURNING *;

-- name: GetNGOPartner :one
SELECT * FROM ngo_partners
WHERE id = $1;

-- name: GetNGOPartnerByUserID :one
SELECT * FROM ngo_partners
WHERE user_id = $1;

-- name: UpdateNGOPartner :exec
UPDATE ngo_partners
SET 
    organization_name = COALESCE($2, organization_name),
    organization_type = COALESCE($3, organization_type),
    organization_address = COALESCE($4, organization_address),
    organization_phone = COALESCE($5, organization_phone),
    organization_email = COALESCE($6, organization_email),
    website = COALESCE($7, website),
    partnership_status = COALESCE($8, partnership_status),
    updated_at = NOW()
WHERE id = $1;

-- name: DeleteNGOPartner :exec
DELETE FROM ngo_partners WHERE id = $1;

-- ============================================
-- ORGANIZATION DETAILS
-- ============================================

-- name: UpdateOrganizationInfo :exec
UPDATE ngo_partners
SET 
    organization_name = COALESCE($2, organization_name),
    organization_type = COALESCE($3, organization_type),
    registration_number = COALESCE($4, registration_number),
    tax_id = COALESCE($5, tax_id),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateOrganizationContact :exec
UPDATE ngo_partners
SET 
    organization_address = COALESCE($2, organization_address),
    organization_phone = COALESCE($3, organization_phone),
    organization_email = COALESCE($4, organization_email),
    website = COALESCE($5, website),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateRegistrationInfo :exec
UPDATE ngo_partners
SET 
    registration_number = $2,
    tax_id = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: GetNGOsByType :many
SELECT 
    np.id,
    np.organization_name,
    np.registration_number,
    np.partnership_type,
    np.partnership_status,
    np.operating_regions,
    np.created_at
FROM ngo_partners np
WHERE np.organization_type = $1
ORDER BY np.organization_name;

-- ============================================
-- CONTACT PERSON MANAGEMENT
-- ============================================

-- name: UpdateContactPerson :exec
UPDATE ngo_partners
SET 
    contact_person_name = COALESCE($2, contact_person_name),
    contact_person_role = COALESCE($3, contact_person_role),
    contact_person_phone = COALESCE($4, contact_person_phone),
    contact_person_email = COALESCE($5, contact_person_email),
    updated_at = NOW()
WHERE id = $1;

-- name: GetContactPersonInfo :one
SELECT 
    contact_person_name,
    contact_person_role,
    contact_person_phone,
    contact_person_email,
    organization_name
FROM ngo_partners
WHERE id = $1;

-- name: FindNGOByContactEmail :one
SELECT 
    np.id,
    np.organization_name,
    np.contact_person_name,
    np.partnership_status
FROM ngo_partners np
WHERE np.contact_person_email = $1;

-- name: FindNGOByContactPhone :one
SELECT 
    np.id,
    np.organization_name,
    np.contact_person_name,
    np.partnership_status
FROM ngo_partners np
WHERE np.contact_person_phone = $1;

-- ============================================
-- PARTNERSHIP MANAGEMENT
-- ============================================

-- name: UpdatePartnershipDetails :exec
UPDATE ngo_partners
SET 
    partnership_type = COALESCE($2, partnership_type),
    partnership_start_date = COALESCE($3, partnership_start_date),
    partnership_end_date = COALESCE($4, partnership_end_date),
    partnership_status = COALESCE($5, partnership_status),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdatePartnershipStatus :exec
UPDATE ngo_partners
SET 
    partnership_status = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: ActivatePartnership :exec
UPDATE ngo_partners
SET 
    partnership_status = 'active',
    partnership_start_date = COALESCE(partnership_start_date, CURRENT_DATE),
    updated_at = NOW()
WHERE id = $1;

-- name: SuspendPartnership :exec
UPDATE ngo_partners
SET 
    partnership_status = 'suspended',
    updated_at = NOW()
WHERE id = $1;

-- name: TerminatePartnership :exec
UPDATE ngo_partners
SET 
    partnership_status = 'terminated',
    partnership_end_date = COALESCE($2, CURRENT_DATE),
    updated_at = NOW()
WHERE id = $1;

-- name: RenewPartnership :exec
UPDATE ngo_partners
SET 
    partnership_status = 'active',
    partnership_start_date = $2,
    partnership_end_date = $3,
    updated_at = NOW()
WHERE id = $1;

-- name: GetActivePartnerships :many
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.partnership_type,
    np.partnership_start_date,
    np.operating_regions,
    np.focus_areas
FROM ngo_partners np
WHERE np.partnership_status = 'active'
ORDER BY np.partnership_start_date DESC;

-- name: GetPartnershipsByStatus :many
SELECT 
    np.id,
    np.organization_name,
    np.partnership_type,
    np.partnership_start_date,
    np.partnership_end_date,
    np.contact_person_name
FROM ngo_partners np
WHERE np.partnership_status = $1
ORDER BY np.partnership_start_date DESC;

-- name: GetPartnershipsByType :many
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.partnership_status,
    np.operating_regions,
    np.focus_areas
FROM ngo_partners np
WHERE np.partnership_type = $1
ORDER BY np.organization_name;

-- name: GetExpiringPartnerships :many
SELECT 
    np.id,
    np.organization_name,
    np.partnership_type,
    np.partnership_end_date,
    np.contact_person_name,
    np.contact_person_email
FROM ngo_partners np
WHERE 
    np.partnership_status = 'active'
    AND np.partnership_end_date BETWEEN CURRENT_DATE AND $1
ORDER BY np.partnership_end_date ASC;

-- name: GetExpiredPartnerships :many
SELECT 
    np.id,
    np.organization_name,
    np.partnership_type,
    np.partnership_end_date,
    np.contact_person_email
FROM ngo_partners np
WHERE 
    np.partnership_status = 'active'
    AND np.partnership_end_date < CURRENT_DATE
ORDER BY np.partnership_end_date ASC;

-- ============================================
-- REGIONAL OPERATIONS
-- ============================================

-- name: UpdateOperatingRegions :exec
UPDATE ngo_partners
SET 
    operating_regions = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: AddOperatingRegion :exec
UPDATE ngo_partners
SET 
    operating_regions = array_append(operating_regions, $2),
    updated_at = NOW()
WHERE id = $1 AND NOT ($2 = ANY(operating_regions));

-- name: RemoveOperatingRegion :exec
UPDATE ngo_partners
SET 
    operating_regions = array_remove(operating_regions, $2),
    updated_at = NOW()
WHERE id = $1;

-- name: GetNGOsByRegion :many
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.partnership_type,
    np.partnership_status,
    np.focus_areas,
    np.contact_person_name
FROM ngo_partners np
WHERE 
    $1 = ANY(np.operating_regions)
    AND np.partnership_status = 'active'
ORDER BY np.organization_name;

-- name: GetNGORegionCoverage :many
SELECT 
    unnest(operating_regions) as region,
    COUNT(*) as ngo_count,
    COUNT(*) FILTER (WHERE partnership_status = 'active') as active_count
FROM ngo_partners
WHERE operating_regions IS NOT NULL
GROUP BY region
ORDER BY ngo_count DESC;
-- name: CheckNGOOperatesInRegion :one
SELECT EXISTS(
    SELECT 1 FROM ngo_partners
    WHERE id = $1 AND $2 = ANY(operating_regions)
) as operates_in_region;

-- ============================================
-- FOCUS AREAS MANAGEMENT
-- ============================================

-- name: UpdateFocusAreas :exec
UPDATE ngo_partners
SET 
    focus_areas = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: AddFocusArea :exec
UPDATE ngo_partners
SET 
    focus_areas = array_append(focus_areas, $2),
    updated_at = NOW()
WHERE id = $1 AND NOT ($2 = ANY(focus_areas));

-- name: RemoveFocusArea :exec
UPDATE ngo_partners
SET 
    focus_areas = array_remove(focus_areas, $2),
    updated_at = NOW()
WHERE id = $1;

-- name: GetNGOsByFocusArea :many
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.partnership_type,
    np.operating_regions,
    np.contact_person_name
FROM ngo_partners np
WHERE 
    $1 = ANY(np.focus_areas)
    AND np.partnership_status = 'active'
ORDER BY np.organization_name;

-- name: GetFocusAreaDistribution :many
SELECT 
    unnest(focus_areas) as focus_area,
    COUNT(*) as ngo_count,
    COUNT(*) FILTER (WHERE partnership_status = 'active') as active_count
FROM ngo_partners
WHERE focus_areas IS NOT NULL
GROUP BY focus_area
ORDER BY ngo_count DESC;

-- name: CheckNGOHasFocusArea :one
SELECT EXISTS(
    SELECT 1 FROM ngo_partners
    WHERE id = $1 AND $2 = ANY(focus_areas)
) as has_focus_area;

-- ============================================
-- REPORT ACCESS MANAGEMENT
-- ============================================

-- name: UpdateReportAccess :exec
UPDATE ngo_partners
SET 
    can_access_reports = $2,
    report_access_level = $3,
    custom_report_filters = COALESCE($4, custom_report_filters),
    updated_at = NOW()
WHERE id = $1;

-- name: GrantReportAccess :exec
UPDATE ngo_partners
SET 
    can_access_reports = true,
    report_access_level = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: RevokeReportAccess :exec
UPDATE ngo_partners
SET 
    can_access_reports = false,
    report_access_level = NULL,
    custom_report_filters = NULL,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateReportAccessLevel :exec
UPDATE ngo_partners
SET 
    report_access_level = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateCustomReportFilters :exec
UPDATE ngo_partners
SET 
    custom_report_filters = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetNGOsWithReportAccess :many
SELECT 
    np.id,
    np.organization_name,
    np.report_access_level,
    np.custom_report_filters,
    np.operating_regions
FROM ngo_partners np
WHERE 
    np.can_access_reports = true
    AND np.partnership_status = 'active'
ORDER BY np.organization_name;

-- name: GetNGOsByAccessLevel :many
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.operating_regions,
    np.focus_areas
FROM ngo_partners np
WHERE 
    np.can_access_reports = true
    AND np.report_access_level = $1
    AND np.partnership_status = 'active'
ORDER BY np.organization_name;

-- name: GetReportAccessInfo :one
SELECT 
    can_access_reports,
    report_access_level,
    custom_report_filters,
    operating_regions,
    focus_areas
FROM ngo_partners
WHERE id = $1;

-- ============================================
-- BRANDING & ASSETS
-- ============================================

-- name: UpdateBranding :exec
UPDATE ngo_partners
SET 
    logo_url = COALESCE($2, logo_url),
    branding_color = COALESCE($3, branding_color),
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateLogo :exec
UPDATE ngo_partners
SET 
    logo_url = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: UpdateBrandingColor :exec
UPDATE ngo_partners
SET 
    branding_color = $2,
    updated_at = NOW()
WHERE id = $1;

-- name: GetNGOBranding :one
SELECT 
    organization_name,
    logo_url,
    branding_color
FROM ngo_partners
WHERE id = $1;

-- ============================================
-- SEARCH & FILTERING
-- ============================================

-- name: SearchNGOPartners :many
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.partnership_type,
    np.partnership_status,
    np.operating_regions,
    np.focus_areas,
    np.contact_person_name
FROM ngo_partners np
WHERE 
    ($1::VARCHAR IS NULL OR np.organization_name ILIKE '%' || $1 || '%')
    AND ($2::VARCHAR IS NULL OR np.organization_type = $2)
    AND ($3::VARCHAR IS NULL OR np.partnership_type = $3)
    AND ($4::VARCHAR IS NULL OR np.partnership_status = $4)
ORDER BY np.organization_name;

-- name: FindNGOByName :one
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.partnership_status,
    np.contact_person_email
FROM ngo_partners np
WHERE np.organization_name ILIKE $1;

-- name: FindNGOByRegistration :one
SELECT 
    np.id,
    np.organization_name,
    np.partnership_status
FROM ngo_partners np
WHERE np.registration_number = $1;

-- name: FindNGOByTaxID :one
SELECT 
    np.id,
    np.organization_name,
    np.partnership_status
FROM ngo_partners np
WHERE np.tax_id = $1;

-- name: FindNGOByEmail :one
SELECT 
    np.id,
    np.organization_name,
    np.contact_person_name
FROM ngo_partners np
WHERE np.organization_email = $1 OR np.contact_person_email = $1;

-- ============================================
-- STATISTICS & ANALYTICS
-- ============================================

-- name: CountNGOPartners :one
SELECT 
    COUNT(*) as total_partners,
    COUNT(*) FILTER (WHERE partnership_status = 'active') as active_partners,
    COUNT(*) FILTER (WHERE partnership_status = 'suspended') as suspended_partners,
    COUNT(*) FILTER (WHERE partnership_status = 'terminated') as terminated_partners,
    COUNT(*) FILTER (WHERE can_access_reports = true) as with_report_access,
    COUNT(DISTINCT organization_type) as unique_org_types,
    COUNT(DISTINCT partnership_type) as unique_partnership_types
FROM ngo_partners;

-- name: GetPartnershipStatistics :one
SELECT 
    COUNT(*) FILTER (WHERE partnership_status = 'active') as active_count,
    COUNT(*) FILTER (WHERE partnership_type = 'funding') as funding_partners,
    COUNT(*) FILTER (WHERE partnership_type = 'implementation') as implementation_partners,
    COUNT(*) FILTER (WHERE partnership_type = 'technical') as technical_partners,
    AVG(EXTRACT(YEAR FROM AGE(COALESCE(partnership_end_date, CURRENT_DATE), partnership_start_date))) 
        FILTER (WHERE partnership_start_date IS NOT NULL) as avg_partnership_duration_years
FROM ngo_partners;

-- name: GetOrganizationTypeDistribution :many
SELECT 
    organization_type,
    COUNT(*) as partner_count,
    COUNT(*) FILTER (WHERE partnership_status = 'active') as active_count
FROM ngo_partners
GROUP BY organization_type
ORDER BY partner_count DESC;

-- name: GetPartnershipTypeDistribution :many
SELECT 
    partnership_type,
    COUNT(*) as partner_count,
    COUNT(*) FILTER (WHERE partnership_status = 'active') as active_count,
    AVG(EXTRACT(YEAR FROM AGE(COALESCE(partnership_end_date, CURRENT_DATE), partnership_start_date)))
        FILTER (WHERE partnership_start_date IS NOT NULL) as avg_duration_years
FROM ngo_partners
GROUP BY partnership_type
ORDER BY partner_count DESC;

-- name: GetReportAccessStatistics :one
SELECT 
    COUNT(*) FILTER (WHERE can_access_reports = true) as with_access,
    COUNT(*) FILTER (WHERE report_access_level = 'summary') as summary_level,
    COUNT(*) FILTER (WHERE report_access_level = 'detailed') as detailed_level,
    COUNT(*) FILTER (WHERE report_access_level = 'custom') as custom_level,
    COUNT(*) FILTER (WHERE custom_report_filters IS NOT NULL) as with_custom_filters
FROM ngo_partners
WHERE partnership_status = 'active';

-- ============================================
-- LISTING & PAGINATION
-- ============================================

-- name: ListNGOPartners :many
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.partnership_type,
    np.partnership_status,
    np.partnership_start_date,
    np.operating_regions,
    np.focus_areas,
    np.contact_person_name,
    np.contact_person_email,
    np.created_at
FROM ngo_partners np
ORDER BY 
    CASE np.partnership_status
        WHEN 'active' THEN 1
        WHEN 'suspended' THEN 2
        WHEN 'terminated' THEN 3
        ELSE 4
    END,
    np.organization_name
LIMIT $1 OFFSET $2;

-- name: GetAllNGOPartners :many
SELECT 
    np.id,
    np.organization_name,
    np.partnership_status,
    np.contact_person_email
FROM ngo_partners np
ORDER BY np.organization_name;

-- ============================================
-- BULK OPERATIONS
-- ============================================

-- name: GetNGOsByIDs :many
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.partnership_status,
    np.operating_regions
FROM ngo_partners np
WHERE np.id = ANY($1::uuid[])
ORDER BY np.organization_name;

-- name: GetNGOsByUserIDs :many
SELECT 
    np.id,
    np.user_id,
    np.organization_name,
    np.partnership_status
FROM ngo_partners np
WHERE np.user_id = ANY($1::uuid[])
ORDER BY np.organization_name;

-- name: BulkUpdatePartnershipStatus :exec
UPDATE ngo_partners
SET 
    partnership_status = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkGrantReportAccess :exec
UPDATE ngo_partners
SET 
    can_access_reports = true,
    report_access_level = $2,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkRevokeReportAccess :exec
UPDATE ngo_partners
SET 
    can_access_reports = false,
    report_access_level = NULL,
    updated_at = NOW()
WHERE id = ANY($1::uuid[]);

-- name: BulkAddOperatingRegion :exec
UPDATE ngo_partners
SET 
    operating_regions = array_append(operating_regions, $2),
    updated_at = NOW()
WHERE 
    id = ANY($1::uuid[])
    AND NOT ($2 = ANY(operating_regions));

-- name: BulkAddFocusArea :exec
UPDATE ngo_partners
SET 
    focus_areas = array_append(focus_areas, $2),
    updated_at = NOW()
WHERE 
    id = ANY($1::uuid[])
    AND NOT ($2 = ANY(focus_areas));

-- ============================================
-- VALIDATION & UTILITIES
-- ============================================

-- name: CheckNGOExists :one
SELECT EXISTS(
    SELECT 1 FROM ngo_partners
    WHERE user_id = $1
) as exists;

-- name: CheckRegistrationExists :one
SELECT EXISTS(
    SELECT 1 FROM ngo_partners
    WHERE registration_number = $1
) as exists;

-- name: CheckTaxIDExists :one
SELECT EXISTS(
    SELECT 1 FROM ngo_partners
    WHERE tax_id = $1
) as exists;

-- name: IsPartnershipActive :one
SELECT partnership_status = 'active' as is_active
FROM ngo_partners
WHERE id = $1;

-- name: GetPartnershipDuration :one
SELECT 
    partnership_start_date,
    partnership_end_date,
    EXTRACT(YEAR FROM AGE(
        COALESCE(partnership_end_date, CURRENT_DATE),
        partnership_start_date
    ))::INTEGER as years_active
FROM ngo_partners
WHERE id = $1;

-- ============================================
-- REPORTING QUERIES
-- ============================================

-- name: GetRecentlyAddedPartners :many
SELECT 
    np.id,
    np.organization_name,
    np.organization_type,
    np.partnership_type,
    np.contact_person_email,
    np.created_at
FROM ngo_partners np
WHERE np.created_at >= $1
ORDER BY np.created_at DESC;

-- name: GetRecentlyUpdatedPartners :many
SELECT 
    np.id,
    np.organization_name,
    np.partnership_status,
    np.updated_at
FROM ngo_partners np
WHERE np.updated_at >= $1
ORDER BY np.updated_at DESC;

-- name: GetLongTermPartners :many
SELECT 
    np.id,
    np.organization_name,
    np.partnership_type,
    np.partnership_start_date,
    EXTRACT(YEAR FROM AGE(CURRENT_DATE, np.partnership_start_date))::INTEGER as years_partnered
FROM ngo_partners np
WHERE 
    np.partnership_status = 'active'
    AND np.partnership_start_date < CURRENT_DATE - INTERVAL '1 year'
ORDER BY np.partnership_start_date ASC;

-- name: GetPartnersNeedingRenewal :many
SELECT 
    np.id,
    np.organization_name,
    np.partnership_end_date,
    np.contact_person_name,
    np.contact_person_email,
    np.contact_person_phone
FROM ngo_partners np
WHERE 
    np.partnership_status = 'active'
    AND np.partnership_end_date BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL '90 days'
ORDER BY np.partnership_end_date ASC;

-- name: GetMultiRegionalPartners :many
SELECT 
    np.id,
    np.organization_name,
    np.operating_regions,
    array_length(np.operating_regions, 1) as region_count,
    np.focus_areas
FROM ngo_partners np
WHERE 
    np.partnership_status = 'active'
    AND array_length(np.operating_regions, 1) >= $1
ORDER BY array_length(np.operating_regions, 1) DESC;

-- name: GetPartnersByRegionAndFocus :many
SELECT 
    np.id,
    np.organization_name,
    np.partnership_type,
    np.contact_person_name,
    np.contact_person_email
FROM ngo_partners np
WHERE 
    np.partnership_status = 'active'
    AND $1 = ANY(np.operating_regions)
    AND $2 = ANY(np.focus_areas)
ORDER BY np.organization_name;

-- name: GetPartnerContactDirectory :many
SELECT 
    np.organization_name,
    np.contact_person_name,
    np.contact_person_role,
    np.contact_person_email,
    np.contact_person_phone,
    np.organization_phone,
    np.organization_email
FROM ngo_partners np
WHERE np.partnership_status = 'active'
ORDER BY np.organization_name;

-- name: GetPartnersWithIncompleteInfo :many
SELECT 
    np.id,
    np.organization_name,
    CASE 
        WHEN np.registration_number IS NULL THEN 'Missing registration number'
        WHEN np.tax_id IS NULL THEN 'Missing tax ID'
        WHEN np.organization_address IS NULL THEN 'Missing address'
        WHEN np.contact_person_email IS NULL THEN 'Missing contact email'
        WHEN array_length(np.operating_regions, 1) IS NULL THEN 'No operating regions'
        WHEN array_length(np.focus_areas, 1) IS NULL THEN 'No focus areas'
        ELSE 'Other'
    END as missing_info
FROM ngo_partners np
WHERE 
    np.partnership_status = 'active'
    AND (
        np.registration_number IS NULL OR
        np.tax_id IS NULL OR
        np.organization_address IS NULL OR
        np.contact_person_email IS NULL OR
        array_length(np.operating_regions, 1) IS NULL OR
        array_length(np.focus_areas, 1) IS NULL
    )
ORDER BY np.organization_name;
