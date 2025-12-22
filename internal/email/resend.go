// Package email implements Resend email service
package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

type resendService struct {
	apiKey    string
	config    *Config
	logger    *zerolog.Logger
	templates *TemplateManager
	client    *http.Client
	available bool
}

// ResendEmailRequest represents the Resend API request payload
type ResendEmailRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html,omitempty"`
	Text    string   `json:"text,omitempty"`
	ReplyTo string   `json:"reply_to,omitempty"`
	CC      []string `json:"cc,omitempty"`
	BCC     []string `json:"bcc,omitempty"`
}

// ResendEmailResponse represents the Resend API response
type ResendEmailResponse struct {
	ID    string `json:"id"`
	Error struct {
		Message string `json:"message"`
		Name    string `json:"name"`
	} `json:"error,omitempty"`
}

// NewResendService creates a new Resend email service
func NewResendService(cfg *Config, logger *zerolog.Logger) (Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid email config: %w", err)
	}

	if cfg.ResendAPIKey == "" {
		return nil, fmt.Errorf("Resend API key is required")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	service := &resendService{
		apiKey:    cfg.ResendAPIKey,
		config:    cfg,
		logger:    logger,
		templates: NewTemplateManager(cfg),
		client:    client,
		available: true,
	}

	// Test the API key by making a simple request
	if err := service.testConnection(context.Background()); err != nil {
		logger.Warn().Err(err).Msg("Resend API key validation failed, email service degraded")
		service.available = false
	} else {
		logger.Info().
			Str("provider", "resend").
			Msg("Resend email service initialized successfully")
	}

	return service, nil
}

func (s *resendService) IsAvailable() bool {
	return s.available
}

func (s *resendService) testConnection(ctx context.Context) error {
	// Make a test request to verify API key
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.resend.com/emails", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return fmt.Errorf("invalid API key")
	}

	return nil
}

func (s *resendService) SendEmail(ctx context.Context, msg *Message) error {
	if !s.available {
		s.logger.Warn().Msg("Resend service unavailable, skipping email")
		return fmt.Errorf("email service unavailable")
	}

	if len(msg.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	// Build Resend request
	resendReq := ResendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromAddress),
		To:      msg.To,
		Subject: msg.Subject,
	}

	// Prefer HTML body if available
	if msg.HTMLBody != "" {
		resendReq.HTML = msg.HTMLBody
	}

	// Always include text fallback
	if msg.Body != "" {
		resendReq.Text = msg.Body
	}

	if msg.ReplyTo != "" {
		resendReq.ReplyTo = msg.ReplyTo
	}

	if len(msg.CC) > 0 {
		resendReq.CC = msg.CC
	}

	if len(msg.BCC) > 0 {
		resendReq.BCC = msg.BCC
	}

	// Marshal request to JSON
	jsonData, err := json.Marshal(resendReq)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.resend.com/emails", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+s.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := s.client.Do(req)
	if err != nil {
		s.logger.Error().
			Err(err).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Msg("Failed to send email via Resend")
		return fmt.Errorf("failed to send email: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var resendResp ResendEmailResponse
	if err := json.Unmarshal(body, &resendResp); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for errors
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		s.logger.Error().
			Int("status_code", resp.StatusCode).
			Str("error", resendResp.Error.Message).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Msg("Resend API returned error")
		return fmt.Errorf("resend API error: %s (status: %d)", resendResp.Error.Message, resp.StatusCode)
	}

	s.logger.Info().
		Str("message_id", resendResp.ID).
		Strs("recipients", msg.To).
		Str("subject", msg.Subject).
		Msg("Email sent successfully via Resend")

	return nil
}

func (s *resendService) SendWelcomeEmail(ctx context.Context, to, username string) error {
	subject, body, htmlBody := s.templates.RenderWelcome(username)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *resendService) SendPasswordResetEmail(ctx context.Context, to, resetToken string) error {
	subject, body, htmlBody := s.templates.RenderPasswordReset(resetToken)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *resendService) SendVerificationEmail(ctx context.Context, to, verificationToken string) error {
	subject, body, htmlBody := s.templates.RenderVerification(verificationToken)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *resendService) SendPasswordChangedEmail(ctx context.Context, to, username string) error {
	subject, body, htmlBody := s.templates.RenderPasswordChanged(username)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *resendService) SendLoginAlertEmail(ctx context.Context, to, username, ipAddress, location string) error {
	subject, body, htmlBody := s.templates.RenderLoginAlert(username, ipAddress, location)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}
