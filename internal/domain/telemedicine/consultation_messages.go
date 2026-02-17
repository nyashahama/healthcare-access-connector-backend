package telemedicine

import (
	"time"

	"github.com/google/uuid"
)

// SenderRole identifies who sent a message in a consultation chat.
type SenderRole string

const (
	SenderRolePatient  SenderRole = "patient"
	SenderRoleProvider SenderRole = "provider"
	SenderRoleSystem   SenderRole = "system"
)

// MessageType categorises the content of a consultation message.
type MessageType string

const (
	MessageTypeText        MessageType = "text"
	MessageTypeAttachment  MessageType = "attachment"
	MessageTypeSystemEvent MessageType = "system_event"
	MessageTypePrescription MessageType = "prescription"
)

// AttachmentType describes the kind of file shared in a consultation.
type AttachmentType string

const (
	AttachmentTypePhoto           AttachmentType = "photo"
	AttachmentTypeDocument        AttachmentType = "document"
	AttachmentTypeLabResult       AttachmentType = "lab_result"
	AttachmentTypePrescriptionPDF AttachmentType = "prescription_pdf"
)

// ConsultationMessage is the core domain model for a single message in a
// consultation chat thread. Soft-deleted messages retain their row but have
// content and attachment_url set to nil.
type ConsultationMessage struct {
	ID             uuid.UUID `json:"id"`
	ConsultationID uuid.UUID `json:"consultation_id"`
	SenderUserID   uuid.UUID `json:"sender_user_id"`
	SenderRole     SenderRole  `json:"sender_role"`
	MessageType    MessageType `json:"message_type"`

	// Content: populated for text / system_event / prescription messages
	Content *string `json:"content,omitempty"`

	// Attachment: populated for attachment-type messages
	AttachmentURL      *string         `json:"attachment_url,omitempty"`
	AttachmentType     *AttachmentType `json:"attachment_type,omitempty"`
	AttachmentFilename *string         `json:"attachment_filename,omitempty"`

	// Read state
	IsRead bool       `json:"is_read"`
	ReadAt *time.Time `json:"read_at,omitempty"`

	// Soft delete — row kept for audit; content nulled server-side
	IsDeleted bool `json:"is_deleted"`

	// Extensible metadata (video call SID, system event type, etc.)
	Metadata map[string]interface{} `json:"metadata,omitempty"`

	SentAt time.Time `json:"sent_at"`
}

// MessageAfterCursor is the projection returned by the polling / WebSocket
// catch-up query. It omits is_deleted (always false by query filter) and
// read_at fields that aren't needed for catch-up.
type MessageAfterCursor struct {
	ID                 uuid.UUID       `json:"id"`
	SenderUserID       uuid.UUID       `json:"sender_user_id"`
	SenderRole         SenderRole      `json:"sender_role"`
	MessageType        MessageType     `json:"message_type"`
	Content            *string         `json:"content,omitempty"`
	AttachmentURL      *string         `json:"attachment_url,omitempty"`
	AttachmentType     *AttachmentType `json:"attachment_type,omitempty"`
	AttachmentFilename *string         `json:"attachment_filename,omitempty"`
	IsRead             bool            `json:"is_read"`
	Metadata           map[string]interface{} `json:"metadata,omitempty"`
	SentAt             time.Time       `json:"sent_at"`
}

// LastMessagePreview is the minimal projection used in consultation list cards
// to show a preview of the most recent message.
type LastMessagePreview struct {
	ID             uuid.UUID       `json:"id"`
	SenderRole     SenderRole      `json:"sender_role"`
	MessageType    MessageType     `json:"message_type"`
	Content        *string         `json:"content,omitempty"`
	AttachmentType *AttachmentType `json:"attachment_type,omitempty"`
	SentAt         time.Time       `json:"sent_at"`
}

// SystemEvent is the projection for system-generated events in a consultation
// (e.g. "Chat started", "Video call initiated"). Used by the call log panel.
type SystemEvent struct {
	ID       uuid.UUID              `json:"id"`
	Content  *string                `json:"content,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
	SentAt   time.Time              `json:"sent_at"`
}

// AttachmentEntry is the projection for the attachment list panel, showing all
// files shared during a consultation.
type AttachmentEntry struct {
	ID                 uuid.UUID      `json:"id"`
	SenderUserID       uuid.UUID      `json:"sender_user_id"`
	SenderRole         SenderRole     `json:"sender_role"`
	AttachmentURL      string         `json:"attachment_url"`
	AttachmentType     AttachmentType `json:"attachment_type"`
	AttachmentFilename *string        `json:"attachment_filename,omitempty"`
	SentAt             time.Time      `json:"sent_at"`
}

// UnreadCount holds the result of the badge-counter query.
type UnreadCount struct {
	Count int64 `json:"count"`
}