package sms

import (
	"time"

	"github.com/google/uuid"
)

// SMSMessage represents an SMS message log
type SMSMessage struct {
	ID              uuid.UUID  `json:"id"`
	ConversationID  uuid.UUID  `json:"conversation_id"`
	Direction       string     `json:"direction"` // inbound, outbound
	MessageBody     string     `json:"message_body"`
	TwilioMessageID *string    `json:"twilio_message_id,omitempty"`
	TwilioStatus    *string    `json:"twilio_status,omitempty"`
	SentAt          *time.Time `json:"sent_at,omitempty"`
	DeliveredAt     *time.Time `json:"delivered_at,omitempty"`
	Segments        int        `json:"segments"`
	Cost            *float64   `json:"cost,omitempty"`
	CostCurrency    string     `json:"cost_currency"`
	CreatedAt       time.Time  `json:"created_at"`
}