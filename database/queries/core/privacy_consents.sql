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
SELECT * FROM privacy_consents WHERE user_id = $1;


-- name: UpdatePrivacyConsent :exec
UPDATE privacy_consents
SET health_data_consent = $2, research_consent = $3,
    sms_communication_consent = $4, email_communication_consent = $5,
    data_sharing_consent = $6
WHERE user_id = $1;

-- name: WithdrawConsent :exec
UPDATE privacy_consents
SET consent_withdrawn = TRUE, consent_withdrawn_date = NOW(),
    withdrawal_reason = $2
WHERE user_id = $1;

