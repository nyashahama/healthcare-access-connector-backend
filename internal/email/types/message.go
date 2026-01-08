// Package types defines core email types
package types

// Message represents an email message
type Message struct {
	To          []string
	CC          []string
	BCC         []string
	Subject     string
	Body        string
	HTMLBody    string
	ReplyTo     string
	Attachments []Attachment
	Template    EmailTemplate
	Data        map[string]interface{}
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// EmailTemplate represents template types
type EmailTemplate string

const (
	TemplateWelcome         EmailTemplate = "welcome"
	TemplatePasswordReset   EmailTemplate = "password_reset"
	TemplateVerification    EmailTemplate = "verification"
	TemplatePasswordChanged EmailTemplate = "password_changed"
	TemplateLoginAlert      EmailTemplate = "login_alert"
	TemplateOTP             EmailTemplate = "otp"
)