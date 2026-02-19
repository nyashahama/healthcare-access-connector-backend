package telemedicine

import (
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
)

// ─── Request DTOs ──────────────────────────────────────────────────────────────

// SendMessageRequest is the patient- or provider-facing payload for sending a
// new message into a consultation thread.
type SendMessageRequest struct {
	SenderUserID       uuid.UUID                    `json:"sender_user_id"`
	SenderRole         telemedicine.SenderRole      `json:"sender_role"`
	MessageType        telemedicine.MessageType     `json:"message_type"`
	Content            *string                      `json:"content,omitempty"`
	AttachmentURL      *string                      `json:"attachment_url,omitempty"`
	AttachmentType     *telemedicine.AttachmentType `json:"attachment_type,omitempty"`
	AttachmentFilename *string                      `json:"attachment_filename,omitempty"`
	Metadata           map[string]interface{}       `json:"metadata,omitempty"`
}

// InsertSystemEventRequest is used internally (or by admin endpoints) to emit
// a system-generated event into a consultation's message thread.
type InsertSystemEventRequest struct {
	SystemUserID uuid.UUID              `json:"system_user_id"`
	Label        string                 `json:"label"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// GetMessagesRequest carries pagination params for the initial thread load.
type GetMessagesRequest struct {
	Limit  int `json:"limit,omitempty"`
	Offset int `json:"offset,omitempty"`
}

// GetMessagesAfterCursorRequest carries the cursor timestamp for polling /
// WebSocket catch-up.
type GetMessagesAfterCursorRequest struct {
	Cursor time.Time `json:"cursor"` // ISO-8601 timestamp
}

// CountUnreadRequest carries the sender role used to scope the unread badge query.
type CountUnreadRequest struct {
	SenderRole telemedicine.SenderRole `json:"sender_role"`
}

// ─── Response DTOs ─────────────────────────────────────────────────────────────

// ConsultationMessageResponse is the full message response returned after
// SendMessage or GetMessageByID.
type ConsultationMessageResponse struct {
	ID                 uuid.UUID                    `json:"id"`
	ConsultationID     uuid.UUID                    `json:"consultation_id"`
	SenderUserID       uuid.UUID                    `json:"sender_user_id"`
	SenderRole         telemedicine.SenderRole      `json:"sender_role"`
	MessageType        telemedicine.MessageType     `json:"message_type"`
	Content            *string                      `json:"content,omitempty"`
	AttachmentURL      *string                      `json:"attachment_url,omitempty"`
	AttachmentType     *telemedicine.AttachmentType `json:"attachment_type,omitempty"`
	AttachmentFilename *string                      `json:"attachment_filename,omitempty"`
	IsRead             bool                         `json:"is_read"`
	ReadAt             *time.Time                   `json:"read_at,omitempty"`
	IsDeleted          bool                         `json:"is_deleted"`
	Metadata           map[string]interface{}       `json:"metadata,omitempty"`
	SentAt             time.Time                    `json:"sent_at"`
}

// MessageAfterCursorResponse is the lightweight projection returned by the
// polling / WebSocket catch-up endpoint.
type MessageAfterCursorResponse struct {
	ID                 uuid.UUID                    `json:"id"`
	SenderUserID       uuid.UUID                    `json:"sender_user_id"`
	SenderRole         telemedicine.SenderRole      `json:"sender_role"`
	MessageType        telemedicine.MessageType     `json:"message_type"`
	Content            *string                      `json:"content,omitempty"`
	AttachmentURL      *string                      `json:"attachment_url,omitempty"`
	AttachmentType     *telemedicine.AttachmentType `json:"attachment_type,omitempty"`
	AttachmentFilename *string                      `json:"attachment_filename,omitempty"`
	IsRead             bool                         `json:"is_read"`
	Metadata           map[string]interface{}       `json:"metadata,omitempty"`
	SentAt             time.Time                    `json:"sent_at"`
}

// LastMessagePreviewResponse is the minimal projection shown in consultation
// list cards.
type LastMessagePreviewResponse struct {
	ID             uuid.UUID                    `json:"id"`
	SenderRole     telemedicine.SenderRole      `json:"sender_role"`
	MessageType    telemedicine.MessageType     `json:"message_type"`
	Content        *string                      `json:"content,omitempty"`
	AttachmentType *telemedicine.AttachmentType `json:"attachment_type,omitempty"`
	SentAt         time.Time                    `json:"sent_at"`
}

// SystemEventResponse is the projection for the call log panel.
type SystemEventResponse struct {
	ID       uuid.UUID              `json:"id"`
	Content  *string                `json:"content,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	SentAt   time.Time              `json:"sent_at"`
}

// AttachmentEntryResponse is the projection for the attachment list panel.
type AttachmentEntryResponse struct {
	ID                 uuid.UUID                   `json:"id"`
	SenderUserID       uuid.UUID                   `json:"sender_user_id"`
	SenderRole         telemedicine.SenderRole     `json:"sender_role"`
	AttachmentURL      string                      `json:"attachment_url"`
	AttachmentType     telemedicine.AttachmentType `json:"attachment_type"`
	AttachmentFilename *string                     `json:"attachment_filename,omitempty"`
	SentAt             time.Time                   `json:"sent_at"`
}

// UnreadCountResponse is the badge-counter response.
type UnreadCountResponse struct {
	Count int64 `json:"count"`
}

// ─── List wrappers ─────────────────────────────────────────────────────────────

// MessageThreadResponse wraps the paginated message thread.
type MessageThreadResponse struct {
	Messages []ConsultationMessageResponse `json:"messages"`
	Count    int                           `json:"count"`
	Limit    int                           `json:"limit"`
	Offset   int                           `json:"offset"`
}

// MessagesAfterCursorResponse wraps the polling catch-up result.
type MessagesAfterCursorResponse struct {
	Messages []MessageAfterCursorResponse `json:"messages"`
	Count    int                          `json:"count"`
}

// SystemEventsResponse wraps the call log panel result.
type SystemEventsResponse struct {
	Events []SystemEventResponse `json:"events"`
	Count  int                   `json:"count"`
}

// AttachmentsResponse wraps the attachment panel result.
type AttachmentsResponse struct {
	Attachments []AttachmentEntryResponse `json:"attachments"`
	Count       int                       `json:"count"`
}

// ─── Conversion helpers ────────────────────────────────────────────────────────

// ToConsultationMessageResponse converts a full domain message to its response DTO.
func ToConsultationMessageResponse(m telemedicine.ConsultationMessage) ConsultationMessageResponse {
	return ConsultationMessageResponse{
		ID:                 m.ID,
		ConsultationID:     m.ConsultationID,
		SenderUserID:       m.SenderUserID,
		SenderRole:         m.SenderRole,
		MessageType:        m.MessageType,
		Content:            m.Content,
		AttachmentURL:      m.AttachmentURL,
		AttachmentType:     m.AttachmentType,
		AttachmentFilename: m.AttachmentFilename,
		IsRead:             m.IsRead,
		ReadAt:             m.ReadAt,
		IsDeleted:          m.IsDeleted,
		Metadata:           m.Metadata,
		SentAt:             m.SentAt,
	}
}

// ToMessageAfterCursorResponse converts a catch-up projection to its response DTO.
func ToMessageAfterCursorResponse(m telemedicine.MessageAfterCursor) MessageAfterCursorResponse {
	return MessageAfterCursorResponse{
		ID:                 m.ID,
		SenderUserID:       m.SenderUserID,
		SenderRole:         m.SenderRole,
		MessageType:        m.MessageType,
		Content:            m.Content,
		AttachmentURL:      m.AttachmentURL,
		AttachmentType:     m.AttachmentType,
		AttachmentFilename: m.AttachmentFilename,
		IsRead:             m.IsRead,
		Metadata:           m.Metadata,
		SentAt:             m.SentAt,
	}
}

// ToLastMessagePreviewResponse converts the card-preview projection.
func ToLastMessagePreviewResponse(m telemedicine.LastMessagePreview) LastMessagePreviewResponse {
	return LastMessagePreviewResponse{
		ID:             m.ID,
		SenderRole:     m.SenderRole,
		MessageType:    m.MessageType,
		Content:        m.Content,
		AttachmentType: m.AttachmentType,
		SentAt:         m.SentAt,
	}
}

// ToSystemEventResponse converts a system event projection.
func ToSystemEventResponse(e telemedicine.SystemEvent) SystemEventResponse {
	return SystemEventResponse{
		ID:       e.ID,
		Content:  e.Content,
		Metadata: e.Metadata,
		SentAt:   e.SentAt,
	}
}

// ToAttachmentEntryResponse converts an attachment entry projection.
func ToAttachmentEntryResponse(a telemedicine.AttachmentEntry) AttachmentEntryResponse {
	return AttachmentEntryResponse{
		ID:                 a.ID,
		SenderUserID:       a.SenderUserID,
		SenderRole:         a.SenderRole,
		AttachmentURL:      a.AttachmentURL,
		AttachmentType:     a.AttachmentType,
		AttachmentFilename: a.AttachmentFilename,
		SentAt:             a.SentAt,
	}
}

// ToUnreadCountResponse converts an UnreadCount domain model.
func ToUnreadCountResponse(u telemedicine.UnreadCount) UnreadCountResponse {
	return UnreadCountResponse{Count: u.Count}
}

// ToDomainMessage converts a SendMessageRequest to the domain ConsultationMessage.
func ToDomainMessage(consultationID uuid.UUID, req SendMessageRequest) telemedicine.ConsultationMessage {
	return telemedicine.ConsultationMessage{
		ConsultationID:     consultationID,
		SenderUserID:       req.SenderUserID,
		SenderRole:         req.SenderRole,
		MessageType:        req.MessageType,
		Content:            req.Content,
		AttachmentURL:      req.AttachmentURL,
		AttachmentType:     req.AttachmentType,
		AttachmentFilename: req.AttachmentFilename,
		Metadata:           req.Metadata,
	}
}

// SenderRoleFromString safely converts a query-param string to the domain SenderRole type.
func SenderRoleFromString(s string) telemedicine.SenderRole {
	return telemedicine.SenderRole(s)
}
