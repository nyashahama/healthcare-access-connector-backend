// Package ai defines sentinel errors for the AI client
package ai

import "errors"

var (
	// ErrAIUnavailable is returned when the AI service is not configured or unreachable
	ErrAIUnavailable = errors.New("ai: service unavailable")

	// ErrInvalidRequest is returned when the request payload is malformed
	ErrInvalidRequest = errors.New("ai: invalid request")
)
