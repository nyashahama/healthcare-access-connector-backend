package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type OTPHandler struct {
	otpService service.OTPService
	logger     *zerolog.Logger
	timeout    time.Duration
}

// NewOTPHandler creates a new OTP handler
func NewOTPHandler(
	otpService service.OTPService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *OTPHandler {
	return &OTPHandler{
		otpService: otpService,
		logger:     logger,
		timeout:    timeout,
	}
}

// GenerateOTP generates and sends OTP to user
func (h *OTPHandler) GenerateOTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req core.OTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("identifier", req.Identifier)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Generate OTP
	err := h.otpService.GenerateOTP(ctx, req.Identifier)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Always return success message for security
	response := core.OTPResponse{
		Message:   "If your account exists, a verification code has been sent",
		ExpiresIn: 10, // 10 minutes
	}

	// Determine channel for user feedback
	if strings.Contains(req.Identifier, "@") {
		response.Channel = "email"
	} else {
		response.Channel = "sms"
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// VerifyOTP verifies OTP and returns reset token
func (h *OTPHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req core.OTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("identifier", req.Identifier)
	v.ValidateRequired("otp", req.OTP)
	v.ValidateLength("otp", req.OTP, 6, 6)
	v.ValidateNumeric("otp", req.OTP)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Verify OTP
	resetToken, err := h.otpService.VerifyOTP(ctx, req.Identifier, req.OTP)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message":  "OTP verified successfully",
		"token":    resetToken, // For backward compatibility
		"verified": "true",
	})
}

// ResetPasswordWithOTP resets password using OTP verification
func (h *OTPHandler) ResetPasswordWithOTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req core.PasswordResetWithOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("identifier", req.Identifier)
	v.ValidateRequired("otp", req.OTP)
	v.ValidateRequired("new_password", req.NewPassword)
	v.ValidateLength("otp", req.OTP, 6, 6)
	v.ValidateNumeric("otp", req.OTP)
	v.ValidatePassword("new_password", req.NewPassword)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Reset password with OTP
	err := h.otpService.ResetPasswordWithOTP(ctx, req.Identifier, req.OTP, req.NewPassword)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully",
	})
}