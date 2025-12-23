// Package validator
package validator

import (
	"fmt"
	"net/mail"
	"regexp"
	"strings"
)

var (
	// Username: 3-50 chars, alphanumeric + underscore
	usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_]{3,50}$`)
	// Password: min 8 chars
	minPasswordLength = 8
)

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

type Validator struct {
	errors []ValidationError
}

func New() *Validator {
	return &Validator{errors: []ValidationError{}}
}

func (v *Validator) AddError(field, message string) {
	v.errors = append(v.errors, ValidationError{Field: field, Message: message})
}

func (v *Validator) Valid() bool {
	return len(v.errors) == 0
}

func (v *Validator) Errors() []ValidationError {
	return v.errors
}

func (v *Validator) ValidateEmail(field, email string) {
	email = strings.TrimSpace(email)
	if email == "" {
		v.AddError(field, "is required")
		return
	}
	if _, err := mail.ParseAddress(email); err != nil {
		v.AddError(field, "is not a valid email address")
	}
}

// ValidatePhone checks if a phone number is valid
func (v *Validator) ValidatePhone(field, phone string) {
	if phone == "" {
		return
	}
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	if !phoneRegex.MatchString(phone) {
		v.AddError(field, "must be a valid phone number")
	}
}

func (v *Validator) ValidateUsername(field, username string) {
	username = strings.TrimSpace(username)
	if username == "" {
		v.AddError(field, "is required")
		return
	}
	if !usernameRegex.MatchString(username) {
		v.AddError(field, "must be 3-50 characters and contain only letters, numbers, and underscores")
	}
}

func (v *Validator) ValidatePassword(field, password string) {
	if len(password) < minPasswordLength {
		v.AddError(field, fmt.Sprintf("must be at least %d characters long", minPasswordLength))
	}
}

func (v *Validator) ValidateRole(field, role string) {
	allowedRoles := map[string]bool{
		"patient":        true,
		"caregiver":      true,
		"provider_staff": true,
		"clinic_admin":   true,
		"system_admin":   true,
		"ngo_partner":    true,
	}

	if role == "" {
		// Empty role is allowed - service will default to "patient"
		return
	}

	if !allowedRoles[role] {
		v.AddError(field, "must be one of: patient, caregiver, provider_staff, clinic_admin, system_admin, ngo_partner")
	}
}

func (v *Validator) ValidateRequired(field, value string) {
	if strings.TrimSpace(value) == "" {
		v.AddError(field, "is required")
	}
}

// ValidateLength validates string length
func (v *Validator) ValidateLength(field, value string, min, max int) {
	length := len(strings.TrimSpace(value))
	if length < min || length > max {
		if min == max {
			v.AddError(field, fmt.Sprintf("must be exactly %d characters", min))
		} else {
			v.AddError(field, fmt.Sprintf("must be between %d and %d characters", min, max))
		}
	}
}

// ValidateNumeric validates that string contains only digits
func (v *Validator) ValidateNumeric(field, value string) {
	numericRegex := regexp.MustCompile(`^[0-9]+$`)
	if !numericRegex.MatchString(value) {
		v.AddError(field, "must contain only numbers")
	}
}

// ValidateOTP validates OTP format
func (v *Validator) ValidateOTP(field, otp string) {
	otp = strings.TrimSpace(otp)
	if otp == "" {
		v.AddError(field, "is required")
		return
	}

	if len(otp) != 6 {
		v.AddError(field, "must be exactly 6 digits")
		return
	}

	v.ValidateNumeric(field, otp)
}
