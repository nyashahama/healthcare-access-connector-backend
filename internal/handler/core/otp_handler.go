package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
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

// GetLatestActiveOTP gets the latest active OTP for a user
func (h *OTPHandler) GetLatestActiveOTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Extract query parameters
	userIDStr := r.URL.Query().Get("user_id")
	otpType := r.URL.Query().Get("type")

	if userIDStr == "" || otpType == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "user_id and type parameters are required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	// Get latest active OTP
	otp, err := h.otpService.GetLatestActiveOTP(ctx, userID, otpType)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"otp": map[string]interface{}{
			"id":         otp.ID,
			"user_id":    otp.UserID,
			"otp":        otp.OTP,
			"type":       otp.Type,
			"channel":    otp.Channel,
			"expires_at": otp.ExpiresAt,
			"used_at":    otp.UsedAt,
			"created_at": otp.CreatedAt,
		},
	})
}

// InvalidateUserOTPs invalidates all OTPs for a user
func (h *OTPHandler) InvalidateUserOTPs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := r.URL.Query().Get("user_id")
	otpType := r.URL.Query().Get("type")

	if userIDStr == "" || otpType == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "user_id and type parameters are required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	// Invalidate OTPs
	err = h.otpService.InvalidateUserOTPs(ctx, userID, otpType)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "User OTPs invalidated successfully",
	})
}

// DeleteExpiredOTPs deletes all expired OTPs
func (h *OTPHandler) DeleteExpiredOTPs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Delete expired OTPs
	err := h.otpService.DeleteExpiredOTPs(ctx)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Expired OTPs deleted successfully",
	})
}

// GetOTPAttemptCount gets OTP attempt count for a user
func (h *OTPHandler) GetOTPAttemptCount(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := r.URL.Query().Get("user_id")
	otpType := r.URL.Query().Get("type")

	if userIDStr == "" || otpType == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "user_id and type parameters are required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	// Get attempt count
	count, err := h.otpService.GetOTPAttemptCount(ctx, userID, otpType)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":     userID,
		"type":        otpType,
		"attempts":    count,
		"max_allowed": 5,
	})
}

// GetRecentOTPs gets recent OTPs for a user
func (h *OTPHandler) GetRecentOTPs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := r.URL.Query().Get("user_id")
	withinStr := r.URL.Query().Get("within")

	if userIDStr == "" || withinStr == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "user_id and within parameters are required",
		})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	withinMinutes, err := strconv.Atoi(withinStr)
	if err != nil || withinMinutes <= 0 {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid within parameter. Must be a positive number of minutes",
		})
		return
	}

	// Get recent OTPs
	otps, err := h.otpService.GetRecentOTPs(ctx, userID, time.Duration(withinMinutes)*time.Minute)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	otpResponses := make([]map[string]interface{}, len(otps))
	for i, otp := range otps {
		otpResponses[i] = map[string]interface{}{
			"id":         otp.ID,
			"user_id":    otp.UserID,
			"otp":        otp.OTP,
			"type":       otp.Type,
			"channel":    otp.Channel,
			"expires_at": otp.ExpiresAt,
			"used_at":    otp.UsedAt,
			"created_at": otp.CreatedAt,
		}
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"user_id":        userID,
		"within_minutes": withinMinutes,
		"otps":           otpResponses,
		"count":          len(otps),
	})
}
