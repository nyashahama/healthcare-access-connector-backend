package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/core"
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

	fmt.Println("the ip addresss is", ipAddress)

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
		handler.RespondJSON(w, http.StatusOK, map[string]string{
			"message": "Logged out successfully",
		})
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

	token := r.URL.Query().Get("token")
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
