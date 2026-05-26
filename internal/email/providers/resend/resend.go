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
	Tags    []Tag    `json:"tags,omitempty"`
}

// Tag represents an email tag for tracking
type Tag struct {
	Name  string `json:"name"`
	Value string `json:"value"`
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
		return nil, fmt.Errorf("resend API key is required")
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        cfg.ConnectionPoolSize,
			MaxIdleConnsPerHost: cfg.ConnectionPoolSize,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	logger.Info().
		Str("provider", "resend").
		Str("from_address", cfg.FromAddress).
		Str("noreply_address", cfg.NoReplyAddress).
		Str("support_address", cfg.SupportAddress).
		Str("health_address", cfg.HealthAddress).
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

	// Determine from address and name based on template type
	fromAddress := p.config.GetFromAddress(msg.Template)
	fromName := p.config.GetFromName(msg.Template)

	// Build Resend request
	resendReq := ResendEmailRequest{
		From:    fmt.Sprintf("%s <%s>", fromName, fromAddress),
		To:      msg.To,
		Subject: msg.Subject,
	}

	if msg.HTMLBody != "" {
		resendReq.HTML = msg.HTMLBody
	}

	if msg.Body != "" {
		resendReq.Text = msg.Body
	}

	// Set reply-to based on template type
	replyTo := p.config.GetReplyTo(msg.Template)
	if msg.ReplyTo != "" {
		replyTo = msg.ReplyTo
	}
	if replyTo != "" && replyTo != fromAddress {
		resendReq.ReplyTo = replyTo
	}

	if len(msg.CC) > 0 {
		resendReq.CC = msg.CC
	}

	if len(msg.BCC) > 0 {
		resendReq.BCC = msg.BCC
	}

	// Add tags for tracking
	resendReq.Tags = []Tag{
		{Name: "template", Value: string(msg.Template)},
		{Name: "environment", Value: p.getEnvironment()},
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
	req.Header.Set("User-Agent", "Healthcare-Access-Connector/1.0")

	// Send request
	resp, err := p.client.Do(req)
	if err != nil {
		p.logger.Error().
			Err(err).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Str("from", fromAddress).
			Str("template", string(msg.Template)).
			Msg("Failed to send email via Resend")
		return fmt.Errorf("%w: %v", emailtypes.ErrSendFailed, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error().Err(err).Msg("Failed to close Resend response body")
		}
	}()

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
			Str("from", fromAddress).
			Str("template", string(msg.Template)).
			Msg("Email sent successfully via Resend")
		return nil
	}

	// Handle specific error codes
	switch resp.StatusCode {
	case 403:
		p.logger.Warn().
			Int("status_code", resp.StatusCode).
			Str("error", resendResp.Error.Message).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Str("from", fromAddress).
			Msg("Resend API returned 403 - Check domain verification and API key")
		return fmt.Errorf("%w: domain not verified or invalid API key", emailtypes.ErrSendFailed)

	case 401:
		p.logger.Error().
			Int("status_code", resp.StatusCode).
			Str("error", resendResp.Error.Message).
			Msg("Resend API authentication failed - Check API key")
		p.available = false
		return fmt.Errorf("%w: invalid API key", emailtypes.ErrSendFailed)

	case 429:
		p.logger.Warn().
			Int("status_code", resp.StatusCode).
			Str("error", resendResp.Error.Message).
			Msg("Resend API rate limit exceeded")
		return fmt.Errorf("%w: rate limit exceeded", emailtypes.ErrSendFailed)

	default:
		p.logger.Error().
			Int("status_code", resp.StatusCode).
			Str("error", resendResp.Error.Message).
			Str("error_name", resendResp.Error.Name).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Str("from", fromAddress).
			Msg("Resend API returned error")
		return fmt.Errorf("%w: %s (status: %d)", emailtypes.ErrSendFailed, resendResp.Error.Message, resp.StatusCode)
	}
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

	// Resend doesn't have a dedicated health check endpoint
	// We'll use the domains endpoint as a health check
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.resend.com/domains", nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+p.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		p.available = false
		return fmt.Errorf("resend health check failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Error().Err(err).Msg("Failed to close Resend health check response body")
		}
	}()

	if resp.StatusCode == 401 {
		p.available = false
		return fmt.Errorf("invalid Resend API key")
	}

	if resp.StatusCode != 200 {
		p.available = false
		return fmt.Errorf("resend health check failed with status: %d", resp.StatusCode)
	}

	return nil
}

// Close closes the provider connection
func (p *Provider) Close() error {
	p.logger.Info().Msg("Closing Resend provider")
	p.client.CloseIdleConnections()
	return nil
}

// getEnvironment returns the current environment
func (p *Provider) getEnvironment() string {
	// You can get this from config or environment variable
	return "production"
}
