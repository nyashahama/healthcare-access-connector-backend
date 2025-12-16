// Package domain contains domain models and errors
package domain

import (
	"errors"
	"fmt"
	"net/http"
)

// Common domain errors
var (
	ErrNotFound           = errors.New("resource not found")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrForbidden          = errors.New("forbidden")
	ErrValidation         = errors.New("validation failed")
	ErrInternal           = errors.New("internal server error")
	ErrDuplicateEmail     = errors.New("email already exists")
	ErrDuplicateUsername  = errors.New("username already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("token expired")
	ErrUserNotFound       = errors.New("user not found")
	ErrPasswordTooWeak    = errors.New("password too weak")
)

// AppError represents an application-specific error with additional context
type AppError struct {
	Err        error
	Message    string
	StatusCode int
	Fields     map[string]string
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
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrUserNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrInvalidCredentials),
		errors.Is(err, ErrInvalidToken), errors.Is(err, ErrExpiredToken):
		return http.StatusUnauthorized
	case errors.Is(err, ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, ErrValidation), errors.Is(err, ErrPasswordTooWeak):
		return http.StatusBadRequest
	case errors.Is(err, ErrDuplicateEmail), errors.Is(err, ErrDuplicateUsername):
		return http.StatusConflict
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
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrUserNotFound):
		return "Resource not found"
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrInvalidCredentials):
		return "Invalid credentials"
	case errors.Is(err, ErrInvalidToken), errors.Is(err, ErrExpiredToken):
		return "Invalid or expired token"
	case errors.Is(err, ErrForbidden):
		return "Access denied"
	case errors.Is(err, ErrValidation):
		return "Validation failed"
	case errors.Is(err, ErrDuplicateEmail):
		return "Email already exists"
	case errors.Is(err, ErrDuplicateUsername):
		return "Username already exists"
	case errors.Is(err, ErrPasswordTooWeak):
		return "Password does not meet requirements"
	default:
		return "An error occurred"
	}
}

// WrapError wraps an error with a message
func WrapError(err error, message string) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", message, err)
}
