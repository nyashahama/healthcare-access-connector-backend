package core

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

type UserHandler struct {
	userService service.UserService
	logger      *zerolog.Logger
	timeout     time.Duration
}

// NewUserHandler creates a new user handler
func NewUserHandler(
	userService service.UserService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *UserHandler {
	return &UserHandler{
		userService: userService,
		logger:      logger,
		timeout:     timeout,
	}
}

// GetProfile retrieves user's profile
func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
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

	// Get user profile using user service
	user, patientProfile, err := h.userService.GetProfile(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToProfileResponse(user, patientProfile))
}

// GetUser retrieves a specific user by ID
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
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

	user, err := h.userService.GetUserByID(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToUserResponse(user))
}

// UpdateProfile updates user profile
func (h *UserHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
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

	var updates map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate updates
	v := validator.New()

	if email, ok := updates["email"].(string); ok && email != "" {
		v.ValidateEmail("email", email)
	}

	if phone, ok := updates["phone"].(string); ok && phone != "" {
		v.ValidatePhone("phone", phone)
	}

	if role, ok := updates["role"].(string); ok && role != "" {
		v.ValidateRole("role", role)
	}

	if status, ok := updates["status"].(string); ok && status != "" {
		validStatuses := []string{"active", "inactive", "pending_verification", "suspended"}
		v.ValidateEnum("status", status, validStatuses)
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Update profile
	if err := h.userService.UpdateProfile(ctx, userID, updates); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Get updated profile
	user, patientProfile, err := h.userService.GetProfile(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, core.ToProfileResponse(user, patientProfile))
}

// DeleteProfile deactivates user profile
func (h *UserHandler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
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

	if err := h.userService.DeleteProfile(ctx, userID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Profile deactivated successfully",
	})
}

// ListUsers lists users with filtering
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Parse query parameters
	role := r.URL.Query().Get("role")
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 50 // Default limit
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 {
			limit = parsedLimit
			if limit > 100 {
				limit = 100 // Max limit
			}
		}
	}

	offset := 0
	if offsetStr != "" {
		if parsedOffset, err := strconv.Atoi(offsetStr); err == nil && parsedOffset >= 0 {
			offset = parsedOffset
		}
	}

	users, err := h.userService.ListUsers(ctx, role, limit, offset)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	userResponses := make([]core.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = core.ToUserResponse(user)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"users":  userResponses,
		"count":  len(userResponses),
		"limit":  limit,
		"offset": offset,
	})
}

// SearchUsers searches users with query, role, and status filters
func (h *UserHandler) SearchUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Parse query parameters
	query := r.URL.Query().Get("q")
	role := r.URL.Query().Get("role")
	status := r.URL.Query().Get("status")

	if query == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Search query 'q' parameter is required",
		})
		return
	}

	users, err := h.userService.SearchUsers(ctx, query, role, status)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	userResponses := make([]core.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = core.ToUserResponse(user)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"users": userResponses,
		"count": len(userResponses),
		"query": query,
	})
}

// GetConsent retrieves user consent settings
func (h *UserHandler) GetConsent(w http.ResponseWriter, r *http.Request) {
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

	// Get consent
	consent, err := h.userService.GetConsent(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := core.ConsentResponse{
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

	handler.RespondJSON(w, http.StatusOK, response)
}

// UpdateConsent updates user consent settings
func (h *UserHandler) UpdateConsent(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		HealthDataConsent         bool `json:"health_data_consent"`
		ResearchConsent           bool `json:"research_consent"`
		EmergencyAccessConsent    bool `json:"emergency_access_consent"`
		SMSCommunicationConsent   bool `json:"sms_communication_consent"`
		EmailCommunicationConsent bool `json:"email_communication_consent"`
		ConsentWithdrawn          bool `json:"consent_withdrawn"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Get existing consent to update
	consent, err := h.userService.GetConsent(ctx, userID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Update consent fields
	now := time.Now()
	consent.HealthDataConsent = req.HealthDataConsent
	if req.HealthDataConsent {
		consent.HealthDataConsentDate = &now
	}
	consent.ResearchConsent = req.ResearchConsent
	if req.ResearchConsent {
		consent.ResearchConsentDate = &now
	}
	consent.EmergencyAccessConsent = req.EmergencyAccessConsent
	if req.EmergencyAccessConsent {
		consent.EmergencyAccessConsentDate = &now
	}
	consent.SMSCommunicationConsent = req.SMSCommunicationConsent
	consent.EmailCommunicationConsent = req.EmailCommunicationConsent
	consent.ConsentWithdrawn = req.ConsentWithdrawn
	if req.ConsentWithdrawn {
		consent.ConsentWithdrawnDate = &now
	}

	if err := h.userService.UpdateConsent(ctx, userID, consent); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	response := core.ConsentResponse{
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

	handler.RespondJSON(w, http.StatusOK, response)
}

// UpdateUserEmail updates user email
func (h *UserHandler) UpdateUserEmail(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate email
	v := validator.New()
	v.ValidateEmail("email", req.Email)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.userService.UpdateUserEmail(ctx, userID, req.Email); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Email updated successfully",
	})
}

// UpdateUserPhone updates user phone
func (h *UserHandler) UpdateUserPhone(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		Phone string `json:"phone"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate phone
	v := validator.New()
	v.ValidatePhone("phone", req.Phone)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.userService.UpdateUserPhone(ctx, userID, req.Phone); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Phone updated successfully",
	})
}

// UpdateUserRole updates user role (admin only)
func (h *UserHandler) UpdateUserRole(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		Role string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate role
	v := validator.New()
	v.ValidateRole("role", req.Role)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.userService.UpdateUserRole(ctx, userID, req.Role); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Role updated successfully",
	})
}

// UpdateUserStatus updates user status (admin only)
func (h *UserHandler) UpdateUserStatus(w http.ResponseWriter, r *http.Request) {
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

	var req struct {
		Status string `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate status
	v := validator.New()
	validStatuses := []string{"active", "inactive", "pending_verification", "suspended"}
	v.ValidateEnum("status", req.Status, validStatuses)

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	if err := h.userService.UpdateUserStatus(ctx, userID, req.Status); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Status updated successfully",
	})
}

// BulkUpdateStatus updates status for multiple users (admin only)
func (h *UserHandler) BulkUpdateStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	var req struct {
		UserIDs []string `json:"user_ids"`
		Status  string   `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "Invalid request body",
		})
		return
	}

	// Validate input
	v := validator.New()
	validStatuses := []string{"active", "inactive", "pending_verification", "suspended"}
	v.ValidateEnum("status", req.Status, validStatuses)

	if len(req.UserIDs) == 0 {
		v.AddError("user_ids", "At least one user ID is required")
	}

	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	// Parse user IDs
	userIDs := make([]uuid.UUID, 0, len(req.UserIDs))
	for _, idStr := range req.UserIDs {
		id, err := uuid.Parse(idStr)
		if err != nil {
			handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
				Error: "Invalid user ID format: " + idStr,
			})
			return
		}
		userIDs = append(userIDs, id)
	}

	if err := h.userService.BulkUpdateStatus(ctx, userIDs, req.Status); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"message": "Status updated successfully",
		"count":   len(userIDs),
	})
}

// GetUsersByIDs gets multiple users by their IDs
func (h *UserHandler) GetUsersByIDs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	// Parse user IDs from query parameter (comma-separated)
	idsStr := r.URL.Query().Get("ids")
	if idsStr == "" {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "User IDs parameter 'ids' is required",
		})
		return
	}

	// Split and parse IDs
	idStrings := splitAndTrim(idsStr, ",")
	if len(idStrings) == 0 {
		handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
			Error: "At least one user ID is required",
		})
		return
	}

	userIDs := make([]uuid.UUID, 0, len(idStrings))
	for _, idStr := range idStrings {
		id, err := uuid.Parse(idStr)
		if err != nil {
			handler.RespondJSON(w, http.StatusBadRequest, core.ErrorResponse{
				Error: "Invalid user ID format: " + idStr,
			})
			return
		}
		userIDs = append(userIDs, id)
	}

	users, err := h.userService.GetUsersByIDs(ctx, userIDs)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	// Convert to response format
	userResponses := make([]core.UserResponse, len(users))
	for i, user := range users {
		userResponses[i] = core.ToUserResponse(user)
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"users": userResponses,
		"count": len(userResponses),
	})
}

// CountUsers counts users by role
func (h *UserHandler) CountUsers(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	role := r.URL.Query().Get("role")

	count, err := h.userService.CountUsers(ctx, role)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]interface{}{
		"count": count,
		"role":  role,
	})
}

// Helper function to split and trim strings
func splitAndTrim(s, sep string) []string {
	if s == "" {
		return nil
	}
	parts := make([]string, 0)
	for _, part := range splitString(s, sep) {
		trimmed := trimSpace(part)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func splitString(s, sep string) []string {
	result := make([]string, 0)
	current := ""
	for _, char := range s {
		if string(char) == sep {
			result = append(result, current)
			current = ""
		} else {
			current += string(char)
		}
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}

func trimSpace(s string) string {
	start := 0
	end := len(s)

	// Trim leading spaces
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}

	// Trim trailing spaces
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}

	return s[start:end]
}
