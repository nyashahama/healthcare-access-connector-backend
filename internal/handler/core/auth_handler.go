package core

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
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

// NewAuthHandler creates a new authentication handler
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
func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req core.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
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
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Register user
	user, err := h.authService.Register(ctx, req.Email, req.Phone, req.Password, req.Role)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, core.ToUserResponse(user))
}

// RegisterInvitedStaff handles staff member registration via invitation
// POST /api/v1/auth/register/staff
func (h *AuthHandler) RegisterInvitedStaff(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req core.StaffRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("invitation_token", req.InvitationToken)
	v.ValidateRequired("email", req.Email)
	v.ValidateEmail("email", req.Email)
	v.ValidateRequired("password", req.Password)
	v.ValidatePassword("password", req.Password)

	if req.Phone != "" {
		v.ValidatePhone("phone", req.Phone)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Register user with invitation token
	user, err := h.authService.RegisterInvitedStaff(ctx, req.InvitationToken, req.Email, req.Password, req.Phone)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Auto-login the user after successful registration
	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	token, expiresAt, _, err := h.authService.Login(ctx, req.Email, req.Password, ipAddress, userAgent)
	if err != nil {
		// Registration succeeded but login failed - still return success
		h.logger.Warn().Err(err).Msg("Staff registered but auto-login failed")
		handler.RespondJSON(w, http.StatusCreated, map[string]interface{}{
			"message": "Registration successful. Please login.",
			"user":    core.ToUserResponse(user),
		})
		return
	}

	response := core.LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      core.ToUserResponse(user),
	}

	handler.RespondJSON(w, http.StatusCreated, response)
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req core.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateRequired("identifier", req.Identifier)
	v.ValidateRequired("password", req.Password)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	// Authenticate user
	token, expiresAt, user, err := h.authService.Login(ctx, req.Identifier, req.Password, ipAddress, userAgent)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	h.logger.Debug().Str("ip_address", ipAddress).Msg("login completed")

	response := core.LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      core.ToUserResponse(user),
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	tokenString := extractToken(r)
	if tokenString == "" {
		handler.RespondJSON(w, http.StatusUnauthorized, core.ErrorResponse{
			Error: "Missing authorization token",
		})
		return
	}

	claims, err := h.authService.ValidateToken(ctx, tokenString)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	if err := h.authService.Logout(ctx, tokenString, claims.UserID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Logged out successfully",
	})
}

// RefreshToken refreshes an access token
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Get token from Authorization header
	tokenString := extractToken(r)
	if tokenString == "" {
		handler.RespondJSON(w, http.StatusUnauthorized, core.ErrorResponse{
			Error: "Missing authorization token",
		})
		return
	}

	ipAddress := getIPAddress(r)
	userAgent := r.UserAgent()

	// Refresh token
	newToken, expiresAt, user, err := h.authService.RefreshToken(ctx, tokenString, ipAddress, userAgent)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := core.LoginResponse{
		Token:     newToken,
		ExpiresAt: expiresAt,
		User:      core.ToUserResponse(user),
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// VerifyEmail handles email verification
func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var token string

	if r.Method == http.MethodGet {
		token = r.URL.Query().Get("token")
	} else {
		var req struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
				Error: "Invalid request body",
			})
			return
		}
		token = req.Token
	}

	if token == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Verification token is required",
		})
		return
	}

	if err := h.authService.VerifyEmail(ctx, token); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Email verified successfully",
	})
}

// ResetPassword resets password with token
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req core.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	v := validator.New()
	v.ValidateRequired("token", req.Token)
	v.ValidateRequired("new_password", req.NewPassword)
	v.ValidatePassword("new_password", req.NewPassword)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.authService.ResetPassword(ctx, req.Token, req.NewPassword); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Password reset successfully",
	})
}

// RequestPasswordReset requests password reset
func (h *AuthHandler) RequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req core.PasswordResetRequest
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

	// Request password reset
	err := h.authService.RequestPasswordReset(ctx, req.Identifier)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Always return success for security
	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "If your account exists, you will receive reset instructions",
	})
}

// ResendVerificationEmail resends verification email
func (h *AuthHandler) ResendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req core.ResendVerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateEmail("email", req.Email)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Resend verification email
	if err := h.authService.ResendVerificationEmail(ctx, req.Email); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "If your account exists, a verification email has been sent",
	})
}

// UpdatePassword updates user password
func (h *AuthHandler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	var req core.PasswordUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	v := validator.New()
	v.ValidateRequired("current_password", req.CurrentPassword)
	v.ValidateRequired("new_password", req.NewPassword)
	v.ValidatePassword("new_password", req.NewPassword)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	err = h.userService.UpdatePassword(ctx, userID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Password updated successfully",
	})
}

// GetProviderWithClinic retrieves provider user with their clinic information
func (h *AuthHandler) GetProviderWithClinic(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	provider, err := h.authService.GetProviderWithClinic(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	if provider == nil {
		handler.RespondJSON(w, http.StatusNotFound, core.ErrorResponse{
			Error: "Provider not found",
		})
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToProviderWithClinicResponse(*provider))
}

// GetUserClinics retrieves all clinics associated with a user
func (h *AuthHandler) GetUserClinics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid user ID format",
		})
		return
	}

	clinics, err := h.authService.GetUserClinics(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response DTOs
	clinicResponses := make([]core.UserClinicResponse, len(clinics))
	for i, clinic := range clinics {
		clinicResponses[i] = core.ToUserClinicResponse(clinic)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"clinics": clinicResponses,
		"total":   len(clinicResponses),
	})
}

// GetProviderDashboard returns provider dashboard information
func (h *AuthHandler) GetProviderDashboard(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Get claims from context
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		handler.RespondJSON(w, http.StatusUnauthorized, core.ErrorResponse{
			Error: "User not authenticated",
		})
		return
	}

	// Extract user ID from claims
	userID := claims.UserID

	// Get provider with clinic info
	provider, err := h.authService.GetProviderWithClinic(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := map[string]interface{}{
		"user_id":              provider.UserID,
		"role":                 provider.Role,
		"onboarding_completed": provider.OnboardingCompleted,
		"onboarding_step":      provider.OnboardingStep,
	}

	// If user has a clinic, add clinic info
	if provider.ClinicID != nil {
		response["has_clinic"] = true
		response["clinic_id"] = provider.ClinicID
		response["clinic_name"] = provider.ClinicName
		response["clinic_is_verified"] = provider.ClinicIsVerified
		response["clinic_verification_status"] = provider.ClinicVerificationStatus

		// Determine dashboard status based on clinic verification
		if provider.ClinicIsVerified != nil && *provider.ClinicIsVerified {
			response["clinic_status"] = "verified"
			response["message"] = "Your clinic is verified and ready"
			response["can_invite_staff"] = true
			response["can_manage_services"] = true
		} else {
			response["clinic_status"] = "pending_approval"
			response["message"] = "Your clinic is under review"
			response["estimated_time"] = "2-3 business days"
			response["can_invite_staff"] = false
			response["can_manage_services"] = false
		}
	} else {
		response["has_clinic"] = false
		response["message"] = "No clinic registered yet"
		response["can_register_clinic"] = true
	}

	handler.RespondJSON(w, http.StatusOK, response)
}

// extractToken extracts JWT token from Authorization header
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}

func getIPAddress(r *http.Request) string {
	// Check for X-Forwarded-For header (if behind proxy)
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// Get the first IP in the chain
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// Fall back to RemoteAddr
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}
