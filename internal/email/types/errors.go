// Package types defines core email types
package types

import "errors"

// Common email errors
var (
	ErrNoRecipients      = errors.New("no recipients specified")
	ErrInvalidProvider   = errors.New("invalid email provider")
	ErrServiceUnavailable = errors.New("email service unavailable")
	ErrTemplateNotFound  = errors.New("email template not found")
	ErrTemplateParsing   = errors.New("failed to parse email template")
	ErrSendFailed        = errors.New("failed to send email")
	ErrCircuitOpen       = errors.New("circuit breaker is open")
	ErrQueueFull         = errors.New("email queue is full")
	ErrTimeout           = errors.New("email send timeout")
)