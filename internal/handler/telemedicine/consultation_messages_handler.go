package telemedicine

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/handler"
	cm_dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/telemedicine"
	sc_dto "github.com/nyashahama/healthcare-access-connector-backend/internal/handler/dto/telemedicine"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/middleware"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/validator"
	"github.com/rs/zerolog"
)

// ConsultationMessagesHandler handles all consultation message HTTP endpoints.
type ConsultationMessagesHandler struct {
	messagesService service.ConsultationMessagesService
	logger          *zerolog.Logger
	timeout         time.Duration
}

// NewConsultationMessagesHandler creates a new consultation messages handler.
func NewConsultationMessagesHandler(
	messagesService service.ConsultationMessagesService,
	logger *zerolog.Logger,
	timeout time.Duration,
) *ConsultationMessagesHandler {
	return &ConsultationMessagesHandler{
		messagesService: messagesService,
		logger:          logger,
		timeout:         timeout,
	}
}

// RegisterRoutes registers all consultation message routes onto the provided router.
// All routes are nested under /consultations/{consultationId}/messages.
func (h *ConsultationMessagesHandler) RegisterRoutes(router chi.Router) {
	router.Route("/consultations/{consultationId}/messages", func(r chi.Router) {
		// ── Thread read/write ───────────────────────────────────────────────────
		r.Post("/", h.SendMessage)
		r.Get("/", h.GetConsultationMessages)
		r.Get("/since", h.GetMessagesAfterCursor)
		r.Delete("/{messageId}", h.DeleteMessage)

		// ── Convenience projections ────────────────────────────────────────────
		r.Get("/last", h.GetLastMessage)
		r.Get("/attachments", h.GetConsultationAttachments)
		r.Get("/events", h.GetSystemEvents)

		// ── Read receipts / badge counts ───────────────────────────────────────
		r.Put("/{messageId}/read", h.MarkMessageRead)
		r.Put("/read/provider", h.MarkAllProviderMessagesRead)
		r.Put("/read/patient", h.MarkAllPatientMessagesRead)
		r.Get("/unread-count", h.CountUnreadMessages)
	})

	// System event injection — separate path, typically called by internal services.
	router.Post("/consultations/{consultationId}/events", h.InsertSystemEvent)
}

// ─── Write handlers ────────────────────────────────────────────────────────────

// SendMessage handles POST /consultations/{consultationId}/messages.
//
// The sender_user_id is always stamped from the JWT — the client should not
// supply it in the body. The sender_role must be provided explicitly.
func (h *ConsultationMessagesHandler) SendMessage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	// Resolve sender identity from JWT.
	claims, found := middleware.GetUserFromContext(ctx)
	if !found {
		handler.RespondJSON(w, http.StatusUnauthorized, sc_dto.ErrorResponse{Error: "User not authenticated"})
		return
	}

	var req cm_dto.SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	// Stamp verified sender identity — ignore any client-supplied sender_user_id.
	req.SenderUserID = claims.UserID

	v := validator.New()
	if req.SenderRole == "" {
		v.AddError("sender_role", "required")
	} else {
		validRoles := map[string]bool{"patient": true, "provider": true, "system": true}
		if !validRoles[string(req.SenderRole)] {
			v.AddError("sender_role", "must be one of: patient, provider, system")
		}
	}
	if req.MessageType == "" {
		v.AddError("message_type", "required")
	} else {
		switch req.MessageType {
		case "text", "system_event", "prescription":
			if req.Content == nil || *req.Content == "" {
				v.AddError("content", "required for this message type")
			}
		case "attachment":
			if req.AttachmentURL == nil || *req.AttachmentURL == "" {
				v.AddError("attachment_url", "required for attachment messages")
			}
			if req.AttachmentType == nil {
				v.AddError("attachment_type", "required for attachment messages")
			}
		default:
			v.AddError("message_type", "must be one of: text, attachment, system_event, prescription")
		}
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	msg := cm_dto.ToDomainMessage(consultationID, req)
	created, err := h.messagesService.SendMessage(ctx, msg)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, cm_dto.ToConsultationMessageResponse(created))
}

// DeleteMessage handles DELETE /consultations/{consultationId}/messages/{messageId}.
// Only the original sender may delete their own messages; system events cannot be deleted.
func (h *ConsultationMessagesHandler) DeleteMessage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	messageID, err := parseUUIDParam(r, "messageId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid message ID"})
		return
	}

	claims, found := middleware.GetUserFromContext(ctx)
	if !found {
		handler.RespondJSON(w, http.StatusUnauthorized, sc_dto.ErrorResponse{Error: "User not authenticated"})
		return
	}

	if err := h.messagesService.DeleteMessage(ctx, messageID, claims.UserID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Message deleted",
	})
}

// InsertSystemEvent handles POST /consultations/{consultationId}/events.
// Emits a system-generated event into the consultation's message thread.
// Typically called by internal services (consultation lifecycle transitions, etc.).
func (h *ConsultationMessagesHandler) InsertSystemEvent(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	var req cm_dto.InsertSystemEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid request body"})
		return
	}

	v := validator.New()
	if req.SystemUserID == uuid.Nil {
		v.AddError("system_user_id", "required")
	}
	v.ValidateRequired("label", req.Label)
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	created, err := h.messagesService.InsertSystemEvent(ctx, consultationID, req.SystemUserID, req.Label, req.Metadata)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusCreated, cm_dto.ToConsultationMessageResponse(created))
}

// ─── Read handlers ─────────────────────────────────────────────────────────────

// GetConsultationMessages handles GET /consultations/{consultationId}/messages.
// Returns the paginated message thread for the initial chat screen load.
// Supports ?limit=20&offset=0.
func (h *ConsultationMessagesHandler) GetConsultationMessages(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	limit := parseIntQuery(r, "limit", 20)
	offset := parseIntQuery(r, "offset", 0)

	msgs, err := h.messagesService.GetConsultationMessages(ctx, consultationID, limit, offset)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]cm_dto.ConsultationMessageResponse, len(msgs))
	for i, m := range msgs {
		items[i] = cm_dto.ToConsultationMessageResponse(m)
	}

	handler.RespondJSON(w, http.StatusOK, cm_dto.MessageThreadResponse{
		Messages: items,
		Count:    len(items),
		Limit:    limit,
		Offset:   offset,
	})
}

// GetMessagesAfterCursor handles GET /consultations/{consultationId}/messages/since.
// Returns all messages newer than the provided cursor timestamp for polling / WebSocket catch-up.
// Query param: cursor (RFC3339 timestamp, e.g. 2024-01-15T10:30:00Z).
func (h *ConsultationMessagesHandler) GetMessagesAfterCursor(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	cursorStr := r.URL.Query().Get("cursor")
	if cursorStr == "" {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "cursor query parameter is required (RFC3339 format)",
		})
		return
	}

	cursor, err := time.Parse(time.RFC3339, cursorStr)
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{
			Error: "Invalid cursor format. Use RFC3339 (e.g. 2024-01-15T10:30:00Z)",
		})
		return
	}

	msgs, err := h.messagesService.GetMessagesAfterCursor(ctx, consultationID, cursor)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]cm_dto.MessageAfterCursorResponse, len(msgs))
	for i, m := range msgs {
		items[i] = cm_dto.ToMessageAfterCursorResponse(m)
	}

	handler.RespondJSON(w, http.StatusOK, cm_dto.MessagesAfterCursorResponse{
		Messages: items,
		Count:    len(items),
	})
}

// GetLastMessage handles GET /consultations/{consultationId}/messages/last.
// Returns the minimal preview used in consultation list cards.
func (h *ConsultationMessagesHandler) GetLastMessage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	msg, err := h.messagesService.GetLastMessage(ctx, consultationID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, cm_dto.ToLastMessagePreviewResponse(msg))
}

// GetConsultationAttachments handles GET /consultations/{consultationId}/messages/attachments.
// Returns all files shared during the consultation for the attachment panel.
func (h *ConsultationMessagesHandler) GetConsultationAttachments(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	attachments, err := h.messagesService.GetConsultationAttachments(ctx, consultationID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]cm_dto.AttachmentEntryResponse, len(attachments))
	for i, a := range attachments {
		items[i] = cm_dto.ToAttachmentEntryResponse(a)
	}

	handler.RespondJSON(w, http.StatusOK, cm_dto.AttachmentsResponse{
		Attachments: items,
		Count:       len(items),
	})
}

// GetSystemEvents handles GET /consultations/{consultationId}/messages/events.
// Returns all system-generated events for the call log panel.
func (h *ConsultationMessagesHandler) GetSystemEvents(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	events, err := h.messagesService.GetSystemEvents(ctx, consultationID)
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	items := make([]cm_dto.SystemEventResponse, len(events))
	for i, e := range events {
		items[i] = cm_dto.ToSystemEventResponse(e)
	}

	handler.RespondJSON(w, http.StatusOK, cm_dto.SystemEventsResponse{
		Events: items,
		Count:  len(items),
	})
}

// ─── Read receipt handlers ─────────────────────────────────────────────────────

// MarkMessageRead handles PUT /consultations/{consultationId}/messages/{messageId}/read.
func (h *ConsultationMessagesHandler) MarkMessageRead(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	messageID, err := parseUUIDParam(r, "messageId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid message ID"})
		return
	}

	if err := h.messagesService.MarkMessageRead(ctx, messageID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "Message marked as read",
	})
}

// MarkAllProviderMessagesRead handles PUT /consultations/{consultationId}/messages/read/provider.
// Called by the patient when they open the chat screen to clear the provider-message badge.
func (h *ConsultationMessagesHandler) MarkAllProviderMessagesRead(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	if err := h.messagesService.MarkAllProviderMessagesRead(ctx, consultationID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "All provider messages marked as read",
	})
}

// MarkAllPatientMessagesRead handles PUT /consultations/{consultationId}/messages/read/patient.
// Called by the provider when they open the chat screen to clear the patient-message badge.
func (h *ConsultationMessagesHandler) MarkAllPatientMessagesRead(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	if err := h.messagesService.MarkAllPatientMessagesRead(ctx, consultationID); err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, map[string]string{
		"message": "All patient messages marked as read",
	})
}

// CountUnreadMessages handles GET /consultations/{consultationId}/messages/unread-count.
// Query param: sender_role (patient|provider) — determines whose messages to count.
func (h *ConsultationMessagesHandler) CountUnreadMessages(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	consultationID, err := parseUUIDParam(r, "consultationId")
	if err != nil {
		handler.RespondJSON(w, http.StatusBadRequest, sc_dto.ErrorResponse{Error: "Invalid consultation ID"})
		return
	}

	roleStr := r.URL.Query().Get("sender_role")

	v := validator.New()
	validRoles := map[string]bool{"patient": true, "provider": true}
	if roleStr == "" {
		v.AddError("sender_role", "required")
	} else if !validRoles[roleStr] {
		v.AddError("sender_role", "must be one of: patient, provider")
	}
	if !v.Valid() {
		handler.RespondValidationError(w, v.Errors())
		return
	}

	count, err := h.messagesService.CountUnreadMessages(ctx, consultationID, cm_dto.SenderRoleFromString(roleStr))
	if err != nil {
		handler.RespondError(w, h.logger, err)
		return
	}

	handler.RespondJSON(w, http.StatusOK, cm_dto.ToUnreadCountResponse(count))
}
