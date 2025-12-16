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
	validRoles := map[string]bool{"user": true, "admin": true, "moderator": true}
	if role == "" {
		role = "user" // default
		return
	}
	if !validRoles[role] {
		v.AddError(field, "must be one of: user, admin, moderator")
	}
}

func (v *Validator) ValidateRequired(field, value string) {
	if strings.TrimSpace(value) == "" {
		v.AddError(field, "is required")
	}
}
