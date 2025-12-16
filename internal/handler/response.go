// Package handler provides HTTP response utilities
package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"

	"github.com/rs/zerolog"
)

// respondJSON sends a JSON response
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data != nil {
		json.NewEncoder(w).Encode(data)
	}
}

// respondError sends an error response
func respondError(w http.ResponseWriter, logger *zerolog.Logger, err error) {
	statusCode := domain.HTTPStatusCode(err)
	message := domain.ErrorMessage(err)

	// Log internal errors
	if statusCode == http.StatusInternalServerError {
		logger.Error().Err(err).Msg("Internal server error")
		message = "An internal error occurred"
	}

	var appErr *domain.AppError
	var response dto.ErrorResponse

	if errors.As(err, &appErr) && len(appErr.Fields) > 0 {
		response = dto.ErrorResponse{
			Error:  message,
			Fields: appErr.Fields,
		}
	} else {
		response = dto.ErrorResponse{
			Error: message,
		}
	}

	respondJSON(w, statusCode, response)
}

// respondValidationError sends a validation error response
func respondValidationError(w http.ResponseWriter, errors []validator.ValidationError) {
	fields := make(map[string]string, len(errors))
	for _, err := range errors {
		fields[err.Field] = err.Message
	}

	response := dto.ErrorResponse{
		Error:  "validation failed",
		Fields: fields,
	}

	respondJSON(w, http.StatusBadRequest, response)
}