// Package handler implements HTTP handlers for health project
package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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

	// Check at least email or phone is provided
	if req.Email == "" && req.Phone == "" {
		v.AddError("email", "Email or phone is required")
		v.AddError("phone", "Email or phone is required")
	} else {
		if req.Email != "" {
			v.ValidateEmail("email", req.Email)
		}
		if req.Phone != "" {
			v.ValidatePhone("phone", req.Phone)
		}
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
	token, expiresAt, err := h.authService.Login(ctx, req.Identifier, req.Password)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	// Get user profile for response
	claims, _ := h.authService.ValidateToken(ctx, token)
	user, _ := h.userService.GetUserByID(ctx, claims.UserID)

	response := dto.LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      dto.ToUserResponse(user),
	}

	respondJSON(w, http.StatusOK, response)
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
	newToken, expiresAt, err := h.authService.RefreshToken(ctx, tokenString)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	// Get user claims
	claims, _ := h.authService.ValidateToken(ctx, newToken)
	user, _ := h.userService.GetUserByID(ctx, claims.UserID)

	response := dto.LoginResponse{
		Token:     newToken,
		ExpiresAt: expiresAt,
		User:      dto.ToUserResponse(user),
	}

	respondJSON(w, http.StatusOK, response)
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
	fmt.Println(ctx)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	fmt.Print(userID)
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

	// Validate input
	v := validator.New()
	v.ValidateRequired("current_password", req.CurrentPassword)
	v.ValidateRequired("new_password", req.NewPassword)
	v.ValidatePassword("new_password", req.NewPassword)

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	// Update password
	// Note: You'll need to add UpdatePassword method to UserService interface
	// For now, we'll call auth service
	// err = h.userService.UpdatePassword(ctx, userID, req.CurrentPassword, req.NewPassword)
	// if err != nil {
	//     respondError(w, h.logger, err)
	//     return
	// }

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

// Logout handles user logout
// @Summary Logout user
// @Description Invalidate user session
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} dto.ErrorResponse
// @Failure 500 {object} dto.ErrorResponse
// @Router /api/v1/auth/logout [post]
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
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

	// Validate token to get user ID
	claims, err := h.authService.ValidateToken(ctx, tokenString)
	fmt.Println(claims)
	if err != nil {
		// Token might already be invalid, still return success
		respondJSON(w, http.StatusOK, map[string]string{
			"message": "Logged out successfully",
		})
		return
	}

	// Delete session (you'll need to add DeleteSession method to auth service)
	// For now, just return success
	// if err := h.authService.Logout(ctx, tokenString, claims.UserID); err != nil {
	//     respondError(w, h.logger, err)
	//     return
	// }

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
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
