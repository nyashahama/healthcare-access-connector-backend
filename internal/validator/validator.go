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
		// Email is optional (can use phone instead), so don't add error if empty
		return
	}
	if _, err := mail.ParseAddress(email); err != nil {
		v.AddError(field, "is not a valid email address")
	}
}

func (v *Validator) ValidatePhone(field, phone string) {
	phone = strings.TrimSpace(phone)
	if phone == "" {
		// Phone is optional (can use email instead), so don't add error if empty
		return
	}
	// Basic phone validation - you might want to adjust this for your needs
	// This regex allows international format: + followed by 1-15 digits
	phoneRegex := regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	if !phoneRegex.MatchString(phone) {
		v.AddError(field, "is not a valid phone number")
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
	// Updated to match your application's roles from auth_service.go
	validRoles := map[string]bool{
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
	if !validRoles[role] {
		v.AddError(field, "must be one of: patient, caregiver, provider_staff, clinic_admin, system_admin, ngo_partner")
	}
}

func (v *Validator) ValidateRequired(field, value string) {
	if strings.TrimSpace(value) == "" {
		v.AddError(field, "is required")
	}
}
