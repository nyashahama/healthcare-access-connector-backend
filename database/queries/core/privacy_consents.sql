-- ============================================
-- Privacy Consent Queries (POPIA Compliance)
-- ============================================

-- name: CreatePrivacyConsent :one
INSERT INTO privacy_consents (
    user_id, health_data_consent, health_data_consent_date,
    health_data_consent_version, emergency_access_consent,
    sms_communication_consent, email_communication_consent,
    ip_address, user_agent
)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING id, user_id, health_data_consent, created_at;

-- name: GetPrivacyConsent :one
SELECT * FROM privacy_consents 
WHERE user_id = $1 
AND consent_withdrawn = false
ORDER BY created_at DESC
LIMIT 1;

-- name: UpdatePrivacyConsent :exec
UPDATE privacy_consents
SET health_data_consent = $2, 
    research_consent = $3,
    sms_communication_consent = $4, 
    email_communication_consent = $5,
    data_sharing_consent = $6,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: WithdrawConsent :exec
UPDATE privacy_consents
SET consent_withdrawn = TRUE, 
    consent_withdrawn_date = CURRENT_TIMESTAMP,
    withdrawal_reason = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateHealthDataConsent :exec
UPDATE privacy_consents
SET health_data_consent = $2,
    health_data_consent_date = $3,
    health_data_consent_version = $4,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateResearchConsent :exec
UPDATE privacy_consents
SET research_consent = $2,
    research_consent_date = $3,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateEmergencyAccessConsent :exec
UPDATE privacy_consents
SET emergency_access_consent = $2,
    emergency_access_consent_date = $3,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateCommunicationConsents :exec
UPDATE privacy_consents
SET sms_communication_consent = $2,
    email_communication_consent = $3,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: UpdateDataSharingConsent :exec
UPDATE privacy_consents
SET data_sharing_consent = $2,
    updated_at = CURRENT_TIMESTAMP
WHERE user_id = $1;

-- name: GetConsentHistory :many
SELECT * FROM privacy_consents
WHERE user_id = $1
ORDER BY created_at DESC;

-- name: GetActiveHealthDataConsents :many
SELECT * FROM privacy_consents
WHERE health_data_consent = true
AND consent_withdrawn = false
ORDER BY created_at DESC;

-- name: GetActiveResearchConsents :many
SELECT * FROM privacy_consents
WHERE research_consent = true
AND consent_withdrawn = false
ORDER BY created_at DESC;

-- name: GetActiveEmergencyAccessConsents :many
SELECT * FROM privacy_consents
WHERE emergency_access_consent = true
AND consent_withdrawn = false
ORDER BY created_at DESC;

-- name: GetExpiredConsents :many
SELECT * FROM privacy_consents
WHERE health_data_consent_date < CURRENT_TIMESTAMP - INTERVAL '2 years'
AND consent_withdrawn = false
ORDER BY health_data_consent_date ASC;

-- name: GetWithdrawnConsents :many
SELECT * FROM privacy_consents
WHERE consent_withdrawn = true
AND consent_withdrawn_date >= $1
AND consent_withdrawn_date <= $2
ORDER BY consent_withdrawn_date DESC;

-- name: GetConsentsExpiringBefore :many
SELECT user_id FROM privacy_consents
WHERE health_data_consent = true
AND consent_withdrawn = false
AND health_data_consent_date < $1
ORDER BY health_data_consent_date ASC;

-- name: CountActiveConsents :one
SELECT COUNT(*) FROM privacy_consents
WHERE consent_withdrawn = false;

-- name: CountConsentsByType :one
SELECT 
    COUNT(*) FILTER (WHERE health_data_consent = true) as health_data_count,
    COUNT(*) FILTER (WHERE research_consent = true) as research_count,
    COUNT(*) FILTER (WHERE emergency_access_consent = true) as emergency_access_count,
    COUNT(*) FILTER (WHERE sms_communication_consent = true) as sms_count,
    COUNT(*) FILTER (WHERE email_communication_consent = true) as email_count
FROM privacy_consents
WHERE consent_withdrawn = false;

-- name: GetConsentByID :one
SELECT * FROM privacy_consents
WHERE id = $1;

-- name: DeletePrivacyConsent :exec
DELETE FROM privacy_consents
WHERE user_id = $1;
