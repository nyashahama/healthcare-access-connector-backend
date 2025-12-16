// Package handler implements HTTP handlers
package handler

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"

	"github.com/go-chi/chi/v5"
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

	var req dto.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	v.ValidateUsername("username", req.Username)
	v.ValidateEmail("email", req.Email)
	v.ValidatePassword("password", req.Password)
	v.ValidateRole("role", req.Role)

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	// Register user
	user, err := h.authService.Register(ctx, req.Username, req.Email, req.Password, req.Role)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusCreated, dto.ToUserResponse(user))
}

// Login handles user login
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
	v.ValidateRequired("email", req.Email)
	v.ValidateRequired("password", req.Password)

	if !v.Valid() {
		respondValidationError(w, v.Errors())
		return
	}

	// Authenticate user
	token, expiresAt, err := h.authService.Login(ctx, req.Email, req.Password)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	// Get user profile for response
	claims, _ := h.authService.ValidateToken(ctx, token)
	user := dto.UserResponse{
		ID:    claims.UserID,
		Email: claims.Email,
		Role:  claims.Role,
	}

	response := dto.LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User:      user,
	}

	respondJSON(w, http.StatusOK, response)
}

// GetProfile retrieves a user's profile
func (h *AuthHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	userIDStr := chi.URLParam(r, "id")
	userID64, err := strconv.ParseInt(userIDStr, 10, 32)
	if err != nil {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "Invalid user ID",
		})
		return
	}

	if userID64 < math.MinInt32 || userID64 > math.MaxInt32 {
		respondJSON(w, http.StatusBadRequest, dto.ErrorResponse{
			Error: "User ID out of range",
		})
		return
	}

	userID := int32(userID64)

	// Get user profile using user service
	user, err := h.userService.GetProfile(ctx, userID)
	if err != nil {
		respondError(w, h.logger, err)
		return
	}

	respondJSON(w, http.StatusOK, dto.ToUserResponse(user))
}

// RefreshToken refreshes an access token
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
	user := dto.UserResponse{
		ID:    claims.UserID,
		Email: claims.Email,
		Role:  claims.Role,
	}

	response := dto.LoginResponse{
		Token:     newToken,
		ExpiresAt: expiresAt,
		User:      user,
	}

	respondJSON(w, http.StatusOK, response)
}

// extractToken extracts JWT token from Authorization header
func extractToken(r *http.Request) string {
	bearerToken := r.Header.Get("Authorization")
	if len(bearerToken) > 7 && bearerToken[:7] == "Bearer " {
		return bearerToken[7:]
	}
	return ""
}