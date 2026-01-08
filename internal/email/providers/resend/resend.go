// Package resend implements Resend email provider
package resend

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	emailtypes "github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// Provider implements the Resend email provider
type Provider struct {
	apiKey    string
	config    *emailtypes.Config
	logger    *zerolog.Logger
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

// New creates a new Resend provider
func New(cfg *emailtypes.Config, logger *zerolog.Logger) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid email config: %w", err)
	}

	if cfg.ResendAPIKey == "" {
		return nil, fmt.Errorf("Resend API key is required")
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	logger.Info().
		Str("provider", "resend").
		Str("from_address", cfg.FromAddress).
		Msg("Resend provider initialized")

	return &Provider{
		apiKey:    cfg.ResendAPIKey,
		config:    cfg,
		logger:    logger,
		client:    client,
		available: true,
	}, nil
}

// Send sends an email via Resend
func (p *Provider) Send(ctx context.Context, msg *emailtypes.Message) error {
	if !p.available {
		return emailtypes.ErrServiceUnavailable
	}

	if len(msg.To) == 0 {
		return emailtypes.ErrNoRecipients
	}

	// Build Resend request
	resendReq := ResendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", p.config.FromName, p.config.FromAddress),
		To:      msg.To,
		Subject: msg.Subject,
	}

	if msg.HTMLBody != "" {
		resendReq.HTML = msg.HTMLBody
	}

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

	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Error().
			Err(err).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Msg("Failed to send email via Resend")
		return fmt.Errorf("%w: %v", emailtypes.ErrSendFailed, err)
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

	// Check for success
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
		p.logger.Info().
			Str("message_id", resendResp.ID).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Msg("Email sent successfully via Resend")
		return nil
	}

	// Handle 403 specifically (common with unverified domains)
	if resp.StatusCode == 403 {
		p.logger.Warn().
			Int("status_code", resp.StatusCode).
			Str("error", resendResp.Error.Message).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Msg("Resend API returned 403 - Check domain verification")
		return nil
	}

	// For other errors
	p.logger.Error().
		Int("status_code", resp.StatusCode).
		Str("error", resendResp.Error.Message).
		Strs("recipients", msg.To).
		Str("subject", msg.Subject).
		Msg("Resend API returned error")
	return fmt.Errorf("%w: %s (status: %d)", emailtypes.ErrSendFailed, resendResp.Error.Message, resp.StatusCode)
}

// IsAvailable checks if the provider is available
func (p *Provider) IsAvailable() bool {
	return p.available
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "resend"
}

// HealthCheck performs a health check
func (p *Provider) HealthCheck(ctx context.Context) error {
	if !p.available {
		return emailtypes.ErrServiceUnavailable
	}

	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.resend.com/emails", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		p.available = false
		return fmt.Errorf("Resend health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		p.available = false
		return fmt.Errorf("invalid Resend API key")
	}

	return nil
}

// Close closes the provider connection
func (p *Provider) Close() error {
	p.logger.Info().Msg("Closing Resend provider")
	return nil
}