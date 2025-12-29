package sms

import (
	"time"

	"github.com/google/uuid"
)

// SMSConversation represents an SMS conversation state
type SMSConversation struct {
	ID                  uuid.UUID      `json:"id"`
	UserID              *uuid.UUID     `json:"user_id,omitempty"`
	PhoneNumber         string         `json:"phone_number"`
	CurrentMenu         *string        `json:"current_menu,omitempty"` // main, clinic_search, nutrition, callback
	ConversationState   map[string]any `json:"conversation_state,omitempty"`
	LastMessageSent     *string        `json:"last_message_sent,omitempty"`
	LastMessageReceived *string        `json:"last_message_received,omitempty"`
	LastInteractionAt   *time.Time     `json:"last_interaction_at,omitempty"`
	LastLocation        map[string]any `json:"last_location,omitempty"`
	LastSearchQuery     *string        `json:"last_search_query,omitempty"`
	CallbackScheduled   *time.Time     `json:"callback_scheduled,omitempty"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
}