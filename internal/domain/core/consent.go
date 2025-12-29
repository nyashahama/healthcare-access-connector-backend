package core

import (
	"time"

	"github.com/google/uuid"
)

// PrivacyConsent represents user consent for POPIA compliance
type PrivacyConsent struct {
	ID                         uuid.UUID      `json:"id"`
	UserID                     uuid.UUID      `json:"user_id"`
	HealthDataConsent          bool           `json:"health_data_consent"`
	HealthDataConsentDate      *time.Time     `json:"health_data_consent_date,omitempty"`
	HealthDataConsentVersion   *string        `json:"health_data_consent_version,omitempty"`
	ResearchConsent            bool           `json:"research_consent"`
	ResearchConsentDate        *time.Time     `json:"research_consent_date,omitempty"`
	EmergencyAccessConsent     bool           `json:"emergency_access_consent"`
	EmergencyAccessConsentDate *time.Time     `json:"emergency_access_consent_date,omitempty"`
	SMSCommunicationConsent    bool           `json:"sms_communication_consent"`
	EmailCommunicationConsent  bool           `json:"email_communication_consent"`
	DataSharingConsent         map[string]any `json:"data_sharing_consent,omitempty"`
	SpecialCategoriesConsent   map[string]any `json:"special_categories_consent,omitempty"`
	ConsentWithdrawn           bool           `json:"consent_withdrawn"`
	ConsentWithdrawnDate       *time.Time     `json:"consent_withdrawn_date,omitempty"`
	WithdrawalReason           *string        `json:"withdrawal_reason,omitempty"`
	IPAddress                  *string        `json:"ip_address,omitempty"`
	UserAgent                  *string        `json:"user_agent,omitempty"`
	CreatedAt                  time.Time      `json:"created_at"`
	UpdatedAt                  time.Time      `json:"updated_at"`
}