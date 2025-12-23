// Package handler implements HTTP handlers for health project
package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/docker/distribution/uuid"
	"github.com/go-chi/chi/v5"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type AuthHandler struct {
	authService service.AuthService
	userService service.UserService
	logger      *zerolog.Logger
	timeout     time.Duration
}

// NewAuthHandler creates a new authentication handler for health project
func NewAuthHandler(
	authService service.AuthService,
	userService service.UserService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		userService: userService,
		logger:      logger,
		timeout:     timeout,
	}
}

// Register handles user registration
// @Summary Register a new user
// @Description Register with email or phone
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RegisterRequest true "Registration data"
// @Success 201 {object} dto.UserResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 409 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/auth/register [post]
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req dto.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()

	if req.Email != "" {
		v.ValidateEmail("email", req.Email)
	}
	if req.Phone != "" {
		v.ValidatePhone("phone", req.Phone)
	}
	v.ValidatePassword("password", req.Password)
	if req.Role != "" {
		v.ValidateRole("role", req.Role)
	}

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	// Register user
	user, err := h.authService.Register(ctx, req.Email, req.Phone, req.Password, req.Role)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusCreated, dto.ToUserResponse(user))
}

// Login handles user login
// @Summary Login user
// @Description Login with email or phone
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Login credentials"
// @Success 200 {object} dto.LoginResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 403 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/auth/login [post]
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req dto.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("identifier", req.Identifier)
	v.ValidateRequired("password", req.Password)

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	// Authenticate user
	token, expiresAt, user, err := h.authService.Login(ctx, req.Identifier, req.Password)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	response := dto.LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      dto.ToUserResponse(user),
	}

	respondJSON(w, http.StatusOK, response)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	tokenString := extractToken(r)
	if tokenString == "" {
		respondJSON(w, http.StatusUnauthorized, dto.ErrorResponse{
			Error: "Missing authorization token",
		})
		return
	}

	claims, err := h.authService.ValidateToken(ctx, tokenString)
	if err != nil {
		respondJSON(w, http.StatusOK, map[string]string{
			"message": "Logged out successfully",
		})
		return
	}

	if err := h.authService.Logout(ctx, tokenString, claims.UserID); err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

// GetProfile retrieves user's profile
// @Summary Get user profile
// @Description Get user profile with patient information if applicable
// @Tags users
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} dto.ProfileResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users/{id}/profile [get]
func (h *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	// Get user profile using user service
	user, patientProfile, err := h.userService.GetProfile(ctx, userID)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusOK, dto.ToProfileResponse(user, patientProfile))
}

// RefreshToken refreshes an access token
// @Summary Refresh access token
// @Description Refresh expired access token
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} dto.LoginResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/auth/refresh [post]
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Get token from Authorization header
	tokenString := extractToken(r)
	if tokenString == "" {
		respondJSON(w, http.StatusUnauthorized, dto.ErrorResponse{
			Error: "Missing authorization token",
		})
		return
	}

	// Refresh token
	newToken, expiresAt, user, err := h.authService.RefreshToken(ctx, tokenString)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	response := dto.LoginResponse{
		Token:     newToken,
		ExpiresAt: expiresAt,
		User:      dto.ToUserResponse(user),
	}

	respondJSON(w, http.StatusOK, response)
}

// VerifyEmail handles email verification
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	token := r.URL.Query().Get("token")
	if token == "" {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Verification token is required",
		})
		return
	}

	if err := h.authService.VerifyEmail(ctx, token); err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Email verified successfully",
	})
}

// ResetPassword resets password with token
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req dto.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	v := validator.New()
	v.ValidateRequired("token", req.Token)
	v.ValidateRequired("new_password", req.NewPassword)
	v.ValidatePassword("new_password", req.NewPassword)

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	if err := h.authService.ResetPassword(ctx, req.Token, req.NewPassword); err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully",
	})
}

// RequestPasswordReset requests password reset
// @Summary Request password reset
// @Description Send password reset link to email or SMS to phone
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.PasswordResetRequest true "Reset request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/auth/password/reset [post]
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req dto.PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("identifier", req.Identifier)

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	// Request password reset
	err := h.authService.RequestPasswordReset(ctx, req.Identifier)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	// Always return success for security (don't reveal if user exists)
	respondJSON(w, http.StatusOK, map[string]string{
		"message": "If your account exists, you will receive reset instructions",
	})
}

// ResendVerificationEmail resends verification email
// @Summary Resend verification email
// @Description Resend verification email to user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.ResendVerificationRequest true "Email address"
// @Success 200 {object} map[string]string
// @Failure 400 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/auth/resend-verification [post]
func (h *AuthHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req dto.ResendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateEmail("email", req.Email)

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	// Resend verification email
	if err := h.authService.ResendVerificationEmail(ctx, req.Email); err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "If your account exists, a verification email has been sent",
	})
}

// UpdatePassword updates user password
// @Summary Update password
// @Description Update user password with current password verification
// @Tags users
// @Accept json
// @Produce json
// @Param id path string true "User ID"
// @Param request body dto.PasswordUpdateRequest true "Password update data"
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users/{id}/password [put]
func (h *AuthHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	var req dto.PasswordUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	v := validator.New()
	v.ValidateRequired("current_password", req.CurrentPassword)
	v.ValidateRequired("new_password", req.NewPassword)
	v.ValidatePassword("new_password", req.NewPassword)

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	err = h.userService.UpdatePassword(ctx, userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Password updated successfully",
	})
}

// GetConsent retrieves user consent settings
// @Summary Get consent settings
// @Description Get user privacy consent settings (POPIA compliance)
// @Tags users
// @Produce json
// @Param id path string true "User ID"
// @Security BearerAuth
// @Success 200 {object} dto.ConsentResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/users/{id}/consent [get]
func (h *AuthHandler) GetConsent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	// Get consent
	consent, err := h.userService.GetConsent(ctx, userID)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	response := dto.ConsentResponse{
		HealthDataConsent:         consent.HealthDataConsent,
		ResearchConsent:           consent.ResearchConsent,
		EmergencyAccessConsent:    consent.EmergencyAccessConsent,
		SMSCommunicationConsent:   consent.SMSCommunicationConsent,
		EmailCommunicationConsent: consent.EmailCommunicationConsent,
		ConsentWithdrawn:          consent.ConsentWithdrawn,
		ConsentDate:               consent.HealthDataConsentDate,
		CreatedAt:                 consent.CreatedAt,
		UpdatedAt:                 consent.UpdatedAt,
	}

	respondJSON(w, http.StatusOK, response)
}

// GenerateOTP generates and sends OTP to user
// @Summary Generate OTP for password reset
// @Description Generate and send 6-digit OTP via email/SMS
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.OTPRequest true "OTP request"
// @Success 200 {object} dto.OTPResponse
// @Failure 400 {object} dto.ErrorResponse
// @Failure 429 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/auth/otp/generate [post]
func (h *AuthHandler) GenerateOTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req dto.OTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("identifier", req.Identifier)

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	// Generate OTP
	err := h.authService.GenerateOTP(ctx, req.Identifier)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	// Always return success message for security
	response := dto.OTPResponse{
		Message:   "If your account exists, a verification code has been sent",
		ExpiresIn: 10, // 10 minutes
	}

	// Determine channel for user feedback
	if strings.Contains(req.Identifier, "@") {
		response.Channel = "email"
	} else {
		response.Channel = "sms"
	}

	respondJSON(w, http.StatusOK, response)
}

// VerifyOTP verifies OTP and returns reset token
// @Summary Verify OTP code
// @Description Verify 6-digit OTP code for password reset
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.OTPVerifyRequest true "OTP verification"
// @Success 200 {object} map[string]string
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 404 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/auth/otp/verify [post]
func (h *AuthHandler) VerifyOTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req dto.OTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
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
		respondValidationError(w, v.Errors())
		return
	}

	// Verify OTP
	resetToken, err := h.authService.VerifyOTP(ctx, req.Identifier, req.OTP)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message":  "OTP verified successfully",
		"token":    resetToken, // For backward compatibility
		"verified": "true",
	})
}

// ResetPasswordWithOTP resets password using OTP verification
// @Summary Reset password with OTP
// @Description Reset password using OTP verification (two-step process)
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.PasswordResetWithOTPRequest true "Reset with OTP"
// @Success 200 {object} map[string]string
// @Failure 400 {object} dto.ErrorResponse
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/auth/password/reset-with-otp [post]
func (h *AuthHandler) ResetPasswordWithOTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req dto.PasswordResetWithOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
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
		respondValidationError(w, v.Errors())
		return
	}

	// Reset password with OTP
	// This uses the new combined method (or you can call VerifyOTP then ResetPassword)
	err := h.authService.ResetPasswordWithOTP(ctx, req.Identifier, req.OTP, req.NewPassword)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully",
	})
}

// extractToken extracts JWT token from Authorization header
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}
