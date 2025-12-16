// Package email provides email sending capabilities
package email

import (
	"context"
	"fmt"
)

// Service defines email operations
type Service interface {
	SendWelcomeEmail(ctx context.Context, to, username string) error
	SendPasswordResetEmail(ctx context.Context, to, resetToken string) error
	SendVerificationEmail(ctx context.Context, to, verificationToken string) error
	SendPasswordChangedEmail(ctx context.Context, to, username string) error
	SendLoginAlertEmail(ctx context.Context, to, username, ipAddress, location string) error
	SendEmail(ctx context.Context, msg *Message) error
	IsAvailable() bool
}

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
}

// Attachment represents an email attachment
type Attachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

// Template types
type EmailTemplate string

const (
	TemplateWelcome         EmailTemplate = "welcome"
	TemplatePasswordReset   EmailTemplate = "password_reset"
	TemplateVerification    EmailTemplate = "verification"
	TemplatePasswordChanged EmailTemplate = "password_changed"
	TemplateLoginAlert      EmailTemplate = "login_alert"
)

// Config holds email service configuration
type Config struct {
	Provider    string // "ses" or "smtp"
	FromAddress string
	FromName    string

	// AWS SES config
	AWSRegion          string
	AWSAccessKeyID     string
	AWSSecretAccessKey string

	// SMTP config (fallback for local dev)
	SMTPHost     string
	SMTPPort     int
	SMTPUsername string
	SMTPPassword string
	SMTPUseTLS   bool
}

// Validate validates email configuration
func (c *Config) Validate() error {
	if c.FromAddress == "" {
		return fmt.Errorf("from address is required")
	}

	if c.Provider == "" {
		c.Provider = "ses" // Default to SES
	}

	switch c.Provider {
	case "ses":
		if c.AWSRegion == "" {
			return fmt.Errorf("AWS region is required for SES")
		}
	case "smtp":
		if c.SMTPHost == "" {
			return fmt.Errorf("SMTP host is required")
		}
		if c.SMTPPort == 0 {
			c.SMTPPort = 587
		}
	default:
		return fmt.Errorf("invalid email provider: %s (must be 'ses' or 'smtp')", c.Provider)
	}

	return nil
}
