package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/core"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// respondJSON sends a JSON response
func RespondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if data == nil {
		w.WriteHeader(status)
		return
	}

	payload, err := json.Marshal(data)
	if err != nil {
		log.Error().Err(err).Msg("failed to marshal response payload")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(status)
	if _, err := w.Write(payload); err != nil {
		log.Error().Err(err).Int("status", status).Msg("failed to write JSON response")
		return
	}
}

// respondError sends an error response
func RespondError(w http.ResponseWriter, logger *zerolog.Logger, err error) {
	statusCode := domain.HTTPStatusCode(err)
	message := domain.ErrorMessage(err)

	// Log internal errors
	if statusCode == http.StatusInternalServerError {
		logger.Error().Err(err).Msg("Internal server error")
		message = "An internal error occurred"
	}

	var appErr *domain.AppError
	var response core.ErrorResponse

	if errors.As(err, &appErr) && len(appErr.Fields) > 0 {
		response = core.ErrorResponse{
			Error:  message,
			Fields: appErr.Fields,
			Code:   domainErrorCode(err),
		}
	} else {
		response = core.ErrorResponse{
			Error: message,
			Code:  domainErrorCode(err),
		}
	}

	RespondJSON(w, statusCode, response)
}

// respondValidationError sends a validation error response
func RespondValidationError(w http.ResponseWriter, errors []validator.ValidationError) {
	fields := make(map[string]string, len(errors))
	for _, err := range errors {
		fields[err.Field] = err.Message
	}

	response := core.ErrorResponse{
		Error:  "validation failed",
		Fields: fields,
		Code:   "VALIDATION_ERROR",
	}

	RespondJSON(w, http.StatusBadRequest, response)
}

// domainErrorCode extracts error code from domain error
func domainErrorCode(err error) string {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return "NOT_FOUND"
	case errors.Is(err, domain.ErrUnauthorized):
		return "UNAUTHORIZED"
	case errors.Is(err, domain.ErrForbidden):
		return "FORBIDDEN"
	case errors.Is(err, domain.ErrValidation):
		return "VALIDATION_ERROR"
	case errors.Is(err, domain.ErrDuplicateEmail):
		return "DUPLICATE_EMAIL"
	case errors.Is(err, domain.ErrDuplicatePhone):
		return "DUPLICATE_PHONE"
	case errors.Is(err, domain.ErrInvalidCredentials):
		return "INVALID_CREDENTIALS"
	case errors.Is(err, domain.ErrInvalidToken):
		return "INVALID_TOKEN"
	case errors.Is(err, domain.ErrExpiredToken):
		return "EXPIRED_TOKEN"
	case errors.Is(err, domain.ErrUserNotFound):
		return "USER_NOT_FOUND"
	case errors.Is(err, domain.ErrUserNotVerified):
		return "USER_NOT_VERIFIED"
	case errors.Is(err, domain.ErrUserInactive):
		return "USER_INACTIVE"
	case errors.Is(err, domain.ErrUserSuspended):
		return "USER_SUSPENDED"
	case errors.Is(err, domain.ErrConsentRequired):
		return "CONSENT_REQUIRED"
	default:
		return "INTERNAL_ERROR"
	}
}
