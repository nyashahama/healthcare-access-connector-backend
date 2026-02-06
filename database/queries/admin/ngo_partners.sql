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

