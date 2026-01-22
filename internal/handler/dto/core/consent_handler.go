package core

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
)

// PrivacyConsentResponse represents privacy consent in responses
type PrivacyConsentResponse struct {
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

// PrivacyConsentRequest represents request to create/update privacy consent
type PrivacyConsentRequest struct {
	HealthDataConsent         bool           `json:"health_data_consent"`
	HealthDataConsentVersion  string         `json:"health_data_consent_version,omitempty"`
	ResearchConsent           bool           `json:"research_consent"`
	EmergencyAccessConsent    bool           `json:"emergency_access_consent"`
	SMSCommunicationConsent   bool           `json:"sms_communication_consent"`
	EmailCommunicationConsent bool           `json:"email_communication_consent"`
	DataSharingConsent        map[string]any `json:"data_sharing_consent,omitempty"`
	SpecialCategoriesConsent  map[string]any `json:"special_categories_consent,omitempty"`
	IPAddress                 *string        `json:"ip_address,omitempty"`
	UserAgent                 *string        `json:"user_agent,omitempty"`
}

// WithdrawConsentRequest represents request to withdraw consent
type WithdrawConsentRequest struct {
	Reason string `json:"reason" validate:"required"`
}

// UpdateHealthDataConsentRequest represents request to update health data consent
type UpdateHealthDataConsentRequest struct {
	Consent bool   `json:"consent"`
	Version string `json:"version" validate:"required"`
}

// UpdateResearchConsentRequest represents request to update research consent
type UpdateResearchConsentRequest struct {
	Consent bool `json:"consent"`
}

// UpdateEmergencyAccessConsentRequest represents request to update emergency access consent
type UpdateEmergencyAccessConsentRequest struct {
	Consent bool `json:"consent"`
}

// UpdateCommunicationConsentsRequest represents request to update communication consents
type UpdateCommunicationConsentsRequest struct {
	SMS   bool `json:"sms"`
	Email bool `json:"email"`
}

// UpdateDataSharingConsentRequest represents request to update data sharing consent
type UpdateDataSharingConsentRequest struct {
	SharingPreferences map[string]interface{} `json:"sharing_preferences"`
}

// ConsentHistoryResponse represents consent history list response
type ConsentHistoryResponse struct {
	ConsentHistory []PrivacyConsentResponse `json:"consent_history"`
	Count          int                      `json:"count"`
	UserID         uuid.UUID                `json:"user_id"`
}

// ActiveConsentsByTypeResponse represents active consents by type response
type ActiveConsentsByTypeResponse struct {
	Consents    []PrivacyConsentResponse `json:"consents"`
	Count       int                      `json:"count"`
	ConsentType string                   `json:"consent_type"`
}

// ExpiredConsentsResponse represents expired consents response
type ExpiredConsentsResponse struct {
	ExpiredConsents []PrivacyConsentResponse `json:"expired_consents"`
	Count           int                      `json:"count"`
}

// WithdrawnConsentsResponse represents withdrawn consents response
type WithdrawnConsentsResponse struct {
	WithdrawnConsents []PrivacyConsentResponse `json:"withdrawn_consents"`
	Count             int                      `json:"count"`
	StartDate         time.Time                `json:"start_date"`
	EndDate           time.Time                `json:"end_date"`
}

// ConsentExpirationNotificationResponse represents consent expiration notification response
type ConsentExpirationNotificationResponse struct {
	UserIDs    []string `json:"user_ids"`
	Count      int      `json:"count"`
	DaysBefore int      `json:"days_before"`
	Message    string   `json:"message"`
}

// ToPrivacyConsentResponse converts domain.PrivacyConsent to PrivacyConsentResponse
func ToPrivacyConsentResponse(consent core.PrivacyConsent) PrivacyConsentResponse {
	return PrivacyConsentResponse{
		ID:                         consent.ID,
		UserID:                     consent.UserID,
		HealthDataConsent:          consent.HealthDataConsent,
		HealthDataConsentDate:      consent.HealthDataConsentDate,
		HealthDataConsentVersion:   consent.HealthDataConsentVersion,
		ResearchConsent:            consent.ResearchConsent,
		ResearchConsentDate:        consent.ResearchConsentDate,
		EmergencyAccessConsent:     consent.EmergencyAccessConsent,
		EmergencyAccessConsentDate: consent.EmergencyAccessConsentDate,
		SMSCommunicationConsent:    consent.SMSCommunicationConsent,
		EmailCommunicationConsent:  consent.EmailCommunicationConsent,
		DataSharingConsent:         consent.DataSharingConsent,
		SpecialCategoriesConsent:   consent.SpecialCategoriesConsent,
		ConsentWithdrawn:           consent.ConsentWithdrawn,
		ConsentWithdrawnDate:       consent.ConsentWithdrawnDate,
		WithdrawalReason:           consent.WithdrawalReason,
		IPAddress:                  consent.IPAddress,
		UserAgent:                  consent.UserAgent,
		CreatedAt:                  consent.CreatedAt,
		UpdatedAt:                  consent.UpdatedAt,
	}
}

// ToPrivacyConsent converts PrivacyConsentRequest to domain.PrivacyConsent
func ToPrivacyConsent(req PrivacyConsentRequest) core.PrivacyConsent {
	now := time.Now()
	var healthDataConsentDate *time.Time
	var healthDataConsentVersion *string

	if req.HealthDataConsent {
		healthDataConsentDate = &now
		if req.HealthDataConsentVersion != "" {
			healthDataConsentVersion = &req.HealthDataConsentVersion
		}
	}

	var emergencyAccessConsentDate *time.Time
	if req.EmergencyAccessConsent {
		emergencyAccessConsentDate = &now
	}

	var researchConsentDate *time.Time
	if req.ResearchConsent {
		researchConsentDate = &now
	}

	return core.PrivacyConsent{
		HealthDataConsent:          req.HealthDataConsent,
		HealthDataConsentDate:      healthDataConsentDate,
		HealthDataConsentVersion:   healthDataConsentVersion,
		ResearchConsent:            req.ResearchConsent,
		ResearchConsentDate:        researchConsentDate,
		EmergencyAccessConsent:     req.EmergencyAccessConsent,
		EmergencyAccessConsentDate: emergencyAccessConsentDate,
		SMSCommunicationConsent:    req.SMSCommunicationConsent,
		EmailCommunicationConsent:  req.EmailCommunicationConsent,
		DataSharingConsent:         req.DataSharingConsent,
		SpecialCategoriesConsent:   req.SpecialCategoriesConsent,
		IPAddress:                  req.IPAddress,
		UserAgent:                  req.UserAgent,
		CreatedAt:                  now,
		UpdatedAt:                  now,
	}
}

// ToConsentHistoryResponse converts list of consents to ConsentHistoryResponse
func ToConsentHistoryResponse(consents []core.PrivacyConsent, userID uuid.UUID) ConsentHistoryResponse {
	consentResponses := make([]PrivacyConsentResponse, len(consents))
	for i, consent := range consents {
		consentResponses[i] = ToPrivacyConsentResponse(consent)
	}

	return ConsentHistoryResponse{
		ConsentHistory: consentResponses,
		Count:          len(consentResponses),
		UserID:         userID,
	}
}

// ToActiveConsentsByTypeResponse converts list of consents to ActiveConsentsByTypeResponse
func ToActiveConsentsByTypeResponse(consents []core.PrivacyConsent, consentType string) ActiveConsentsByTypeResponse {
	consentResponses := make([]PrivacyConsentResponse, len(consents))
	for i, consent := range consents {
		consentResponses[i] = ToPrivacyConsentResponse(consent)
	}

	return ActiveConsentsByTypeResponse{
		Consents:    consentResponses,
		Count:       len(consentResponses),
		ConsentType: consentType,
	}
}

// ToExpiredConsentsResponse converts list of consents to ExpiredConsentsResponse
func ToExpiredConsentsResponse(consents []core.PrivacyConsent) ExpiredConsentsResponse {
	consentResponses := make([]PrivacyConsentResponse, len(consents))
	for i, consent := range consents {
		consentResponses[i] = ToPrivacyConsentResponse(consent)
	}

	return ExpiredConsentsResponse{
		ExpiredConsents: consentResponses,
		Count:           len(consentResponses),
	}
}

// ToWithdrawnConsentsResponse converts list of consents to WithdrawnConsentsResponse
func ToWithdrawnConsentsResponse(consents []core.PrivacyConsent, startDate, endDate time.Time) WithdrawnConsentsResponse {
	consentResponses := make([]PrivacyConsentResponse, len(consents))
	for i, consent := range consents {
		consentResponses[i] = ToPrivacyConsentResponse(consent)
	}

	return WithdrawnConsentsResponse{
		WithdrawnConsents: consentResponses,
		Count:             len(consentResponses),
		StartDate:         startDate,
		EndDate:           endDate,
	}
}

// ToConsentExpirationNotificationResponse converts user IDs to notification response
func ToConsentExpirationNotificationResponse(userIDs []uuid.UUID, daysBefore int) ConsentExpirationNotificationResponse {
	userIDStrings := make([]string, len(userIDs))
	for i, id := range userIDs {
		userIDStrings[i] = id.String()
	}

	return ConsentExpirationNotificationResponse{
		UserIDs:    userIDStrings,
		Count:      len(userIDs),
		DaysBefore: daysBefore,
		Message:    "Consent expiration notifications processed",
	}
}
