// Package domain contains domain models and errors
package domain

import (
	"errors"
	"fmt"
	"net/http"
)

// Common domain errors
var (
	// General errors
	ErrNotFound     = errors.New("resource not found")
	ErrUnauthorized = errors.New("unauthorized")
	ErrForbidden    = errors.New("forbidden")
	ErrValidation   = errors.New("validation failed")
	ErrInternal     = errors.New("internal server error")

	// User errors
	ErrDuplicateEmail     = errors.New("email already exists")
	ErrDuplicatePhone     = errors.New("phone number already exists")
	ErrDuplicateUsername  = errors.New("username already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("token expired")
	ErrUserNotFound       = errors.New("user not found")
	ErrPasswordTooWeak    = errors.New("password too weak")
	ErrUserNotVerified    = errors.New("user email/phone not verified")
	ErrUserInactive       = errors.New("user account is inactive")
	ErrUserSuspended      = errors.New("user account is suspended")

	// Patient errors
	ErrPatientNotFound      = errors.New("patient profile not found")
	ErrPatientProfileExists = errors.New("patient profile already exists")
	ErrMedicalInfoNotFound  = errors.New("medical information not found")
	ErrAllergyNotFound      = errors.New("allergy record not found")
	ErrMedicationNotFound   = errors.New("medication record not found")
	ErrConditionNotFound    = errors.New("condition record not found")
	ErrImmunizationNotFound = errors.New("immunization record not found")

	// Clinic errors
	ErrClinicNotFound        = errors.New("clinic not found")
	ErrClinicNotVerified     = errors.New("clinic is not verified")
	ErrClinicAlreadyVerified = errors.New("clinic is already verified")
	ErrServiceNotFound       = errors.New("clinic service not found")
	ErrServiceNotAvailable   = errors.New("service is not available")

	// Staff errors
	ErrStaffNotFound         = errors.New("staff member not found")
	ErrStaffNotActive        = errors.New("staff member is not active")
	ErrCredentialNotFound    = errors.New("credential not found")
	ErrCredentialExpired     = errors.New("credential has expired")
	ErrCredentialNotVerified = errors.New("credential not verified")
	ErrInvalidHPCSNumber     = errors.New("invalid HPCS number")

	// Session errors
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session has expired")
	ErrInvalidSession  = errors.New("invalid session")

	// Consent errors (POPIA compliance)
	ErrConsentRequired           = errors.New("user consent is required")
	ErrConsentWithdrawn          = errors.New("user consent has been withdrawn")
	ErrHealthDataConsentRequired = errors.New("health data consent is required")
	ErrInvalidConsentVersion     = errors.New("invalid consent version")

	// SMS errors
	ErrSMSDeliveryFailed    = errors.New("SMS delivery failed")
	ErrInvalidPhoneNumber   = errors.New("invalid phone number")
	ErrSMSConsentRequired   = errors.New("SMS consent is required")
	ErrConversationNotFound = errors.New("SMS conversation not found")

	// Access control errors
	ErrInsufficientPermissions = errors.New("insufficient permissions")
	ErrEmergencyAccessOnly     = errors.New("only emergency access allowed")
	ErrAccessDenied            = errors.New("access denied")
	ErrDataAccessNotAuthorized = errors.New("data access not authorized")

	// Appointment errors (for future use)
	ErrAppointmentNotFound  = errors.New("appointment not found")
	ErrAppointmentConflict  = errors.New("appointment time conflict")
	ErrAppointmentCancelled = errors.New("appointment has been cancelled")

	// Notification errors
	ErrNotificationFailed  = errors.New("notification delivery failed")
	ErrPreferencesNotFound = errors.New("notification preferences not found")

	ErrRateLimited = errors.New("rate limited")
)

// AppError represents an application-specific error with additional context
type AppError struct {
	Err        error
	Message    string
	StatusCode int
	Fields     map[string]string
	Internal   error // Internal error for logging, not exposed to users
}

// Error implements the error interface
func (e *AppError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return "unknown error"
}

// Unwrap returns the underlying error
func (e *AppError) Unwrap() error {
	return e.Err
}

// NewAppError creates a new AppError
func NewAppError(err error, message string, statusCode int) *AppError {
	return &AppError{
		Err:        err,
		Message:    message,
		StatusCode: statusCode,
	}
}

// NewValidationError creates a validation error with field details
func NewValidationError(fields map[string]string) *AppError {
	return &AppError{
		Err:        ErrValidation,
		Message:    "validation failed",
		StatusCode: http.StatusBadRequest,
		Fields:     fields,
	}
}

// WrapInternal wraps an error with an internal error for logging
func (e *AppError) WrapInternal(internal error) *AppError {
	e.Internal = internal
	return e
}

// HTTPStatusCode returns the appropriate HTTP status code for an error
func HTTPStatusCode(err error) int {
	if err == nil {
		return http.StatusOK
	}

	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr.StatusCode
	}

	switch {
	// 404 Not Found
	case errors.Is(err, ErrNotFound),
		errors.Is(err, ErrUserNotFound),
		errors.Is(err, ErrPatientNotFound),
		errors.Is(err, ErrClinicNotFound),
		errors.Is(err, ErrStaffNotFound),
		errors.Is(err, ErrSessionNotFound),
		errors.Is(err, ErrAppointmentNotFound),
		errors.Is(err, ErrMedicalInfoNotFound),
		errors.Is(err, ErrAllergyNotFound),
		errors.Is(err, ErrMedicationNotFound),
		errors.Is(err, ErrConditionNotFound),
		errors.Is(err, ErrImmunizationNotFound),
		errors.Is(err, ErrServiceNotFound),
		errors.Is(err, ErrCredentialNotFound),
		errors.Is(err, ErrConversationNotFound),
		errors.Is(err, ErrPreferencesNotFound):
		return http.StatusNotFound

	// 401 Unauthorized
	case errors.Is(err, ErrUnauthorized),
		errors.Is(err, ErrInvalidCredentials),
		errors.Is(err, ErrInvalidToken),
		errors.Is(err, ErrExpiredToken),
		errors.Is(err, ErrSessionExpired),
		errors.Is(err, ErrInvalidSession),
		errors.Is(err, ErrUserNotVerified):
		return http.StatusUnauthorized

	// 403 Forbidden
	case errors.Is(err, ErrForbidden),
		errors.Is(err, ErrInsufficientPermissions),
		errors.Is(err, ErrAccessDenied),
		errors.Is(err, ErrDataAccessNotAuthorized),
		errors.Is(err, ErrConsentRequired),
		errors.Is(err, ErrConsentWithdrawn),
		errors.Is(err, ErrHealthDataConsentRequired),
		errors.Is(err, ErrSMSConsentRequired),
		errors.Is(err, ErrUserInactive),
		errors.Is(err, ErrUserSuspended),
		errors.Is(err, ErrClinicNotVerified),
		errors.Is(err, ErrStaffNotActive),
		errors.Is(err, ErrCredentialNotVerified),
		errors.Is(err, ErrCredentialExpired):
		return http.StatusForbidden

	// 400 Bad Request
	case errors.Is(err, ErrValidation),
		errors.Is(err, ErrPasswordTooWeak),
		errors.Is(err, ErrInvalidPhoneNumber),
		errors.Is(err, ErrInvalidHPCSNumber),
		errors.Is(err, ErrInvalidConsentVersion):
		return http.StatusBadRequest

	// 409 Conflict
	case errors.Is(err, ErrDuplicateEmail),
		errors.Is(err, ErrDuplicatePhone),
		errors.Is(err, ErrDuplicateUsername),
		errors.Is(err, ErrPatientProfileExists),
		errors.Is(err, ErrClinicAlreadyVerified),
		errors.Is(err, ErrAppointmentConflict):
		return http.StatusConflict

	// 410 Gone
	case errors.Is(err, ErrAppointmentCancelled):
		return http.StatusGone

	// 503 Service Unavailable
	case errors.Is(err, ErrServiceNotAvailable),
		errors.Is(err, ErrSMSDeliveryFailed),
		errors.Is(err, ErrNotificationFailed):
		return http.StatusServiceUnavailable

	case errors.Is(err, ErrRateLimited):
		return http.StatusTooManyRequests

	// 500 Internal Server Error (default)
	default:
		return http.StatusInternalServerError
	}
}

// ErrorMessage returns a user-friendly error message
func ErrorMessage(err error) string {
	if err == nil {
		return ""
	}

	var appErr *AppError
	if errors.As(err, &appErr) && appErr.Message != "" {
		return appErr.Message
	}

	// Return safe messages for known errors
	switch {
	// User errors
	case errors.Is(err, ErrUserNotFound):
		return "User not found"
	case errors.Is(err, ErrInvalidCredentials):
		return "Invalid email/phone or password"
	case errors.Is(err, ErrInvalidToken), errors.Is(err, ErrExpiredToken):
		return "Invalid or expired token"
	case errors.Is(err, ErrDuplicateEmail):
		return "Email address is already registered"
	case errors.Is(err, ErrDuplicatePhone):
		return "Phone number is already registered"
	case errors.Is(err, ErrPasswordTooWeak):
		return "Password does not meet security requirements"
	case errors.Is(err, ErrUserNotVerified):
		return "Please verify your email or phone number"
	case errors.Is(err, ErrUserInactive):
		return "Your account is inactive"
	case errors.Is(err, ErrUserSuspended):
		return "Your account has been suspended"

	// Patient errors
	case errors.Is(err, ErrPatientNotFound):
		return "Patient profile not found"
	case errors.Is(err, ErrPatientProfileExists):
		return "Patient profile already exists"

	// Clinic errors
	case errors.Is(err, ErrClinicNotFound):
		return "Clinic not found"
	case errors.Is(err, ErrClinicNotVerified):
		return "This clinic has not been verified yet"
	case errors.Is(err, ErrServiceNotAvailable):
		return "This service is currently not available"

	// Staff errors
	case errors.Is(err, ErrStaffNotFound):
		return "Staff member not found"
	case errors.Is(err, ErrStaffNotActive):
		return "This staff member is not currently active"
	case errors.Is(err, ErrCredentialExpired):
		return "Professional credential has expired"

	// Session errors
	case errors.Is(err, ErrSessionExpired):
		return "Your session has expired. Please log in again"
	case errors.Is(err, ErrInvalidSession):
		return "Invalid session"

	// Consent errors
	case errors.Is(err, ErrConsentRequired):
		return "You must provide consent to continue"
	case errors.Is(err, ErrConsentWithdrawn):
		return "Consent has been withdrawn"
	case errors.Is(err, ErrHealthDataConsentRequired):
		return "Health data consent is required to access this information"
	case errors.Is(err, ErrSMSConsentRequired):
		return "SMS consent is required for this service"

	// Access errors
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrAccessDenied):
		return "You don't have permission to access this resource"
	case errors.Is(err, ErrInsufficientPermissions):
		return "You don't have sufficient permissions for this action"
	case errors.Is(err, ErrDataAccessNotAuthorized):
		return "You are not authorized to access this data"

	// SMS errors
	case errors.Is(err, ErrInvalidPhoneNumber):
		return "Invalid phone number format"
	case errors.Is(err, ErrSMSDeliveryFailed):
		return "Failed to send SMS. Please try again later"

	// Appointment errors
	case errors.Is(err, ErrAppointmentNotFound):
		return "Appointment not found"
	case errors.Is(err, ErrAppointmentConflict):
		return "This appointment time is not available"
	case errors.Is(err, ErrAppointmentCancelled):
		return "This appointment has been cancelled"

	// Validation errors
	case errors.Is(err, ErrValidation):
		return "Please check your input and try again"

	// Generic errors
	case errors.Is(err, ErrNotFound):
		return "Resource not found"
	case errors.Is(err, ErrUnauthorized):
		return "Authentication required"

	case errors.Is(err, ErrRateLimited):
		return "Too many requests. Please try again later"

	// Default
	default:
		return "An error occurred. Please try again later"
	}
}

// WrapError wraps an error with a message
func WrapError(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}

// IsNotFoundError checks if an error is a "not found" type error
func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrNotFound) ||
		errors.Is(err, ErrUserNotFound) ||
		errors.Is(err, ErrPatientNotFound) ||
		errors.Is(err, ErrClinicNotFound) ||
		errors.Is(err, ErrStaffNotFound) ||
		errors.Is(err, ErrSessionNotFound)
}

// IsAuthError checks if an error is an authentication error
func IsAuthError(err error) bool {
	return errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrInvalidCredentials) ||
		errors.Is(err, ErrInvalidToken) ||
		errors.Is(err, ErrExpiredToken) ||
		errors.Is(err, ErrSessionExpired)
}

// IsConsentError checks if an error is related to consent (POPIA)
func IsConsentError(err error) bool {
	return errors.Is(err, ErrConsentRequired) ||
		errors.Is(err, ErrConsentWithdrawn) ||
		errors.Is(err, ErrHealthDataConsentRequired) ||
		errors.Is(err, ErrSMSConsentRequired)
}
