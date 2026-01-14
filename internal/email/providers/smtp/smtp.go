// Package smtp implements SMTP email provider
package smtp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/rs/zerolog"

	emailtypes "github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// Provider implements the SMTP email provider
type Provider struct {
	config    *emailtypes.Config
	logger    *zerolog.Logger
	available bool
}

// New creates a new SMTP provider
func New(cfg *emailtypes.Config, logger *zerolog.Logger) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid email config: %w", err)
	}

	// Test SMTP connection
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)
	available := true

	if cfg.SMTPUseTLS {
		tlsConfig := &tls.Config{
			ServerName: cfg.SMTPHost,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			logger.Warn().Err(err).Msg("Failed to connect to SMTP server")
			available = false
		} else {
			conn.Close()
		}
	}

	logger.Info().
		Str("provider", "smtp").
		Str("host", cfg.SMTPHost).
		Int("port", cfg.SMTPPort).
		Bool("available", available).
		Msg("SMTP provider initialized")

	return &Provider{
		config:    cfg,
		logger:    logger,
		available: available,
	}, nil
}

// Send sends an email via SMTP
func (p *Provider) Send(ctx context.Context, msg *emailtypes.Message) error {
	if !p.available {
		return emailtypes.ErrServiceUnavailable
	}

	if len(msg.To) == 0 {
		return emailtypes.ErrNoRecipients
	}

	// Build email headers and body
	from := fmt.Sprintf("%s <%s>", p.config.FromName, p.config.FromAddress)
	headers := make(map[string]string)
	headers["From"] = from
	headers["To"] = strings.Join(msg.To, ", ")
	headers["Subject"] = msg.Subject
	headers["MIME-Version"] = "1.0"

	if len(msg.CC) > 0 {
		headers["Cc"] = strings.Join(msg.CC, ", ")
	}
	if msg.ReplyTo != "" {
		headers["Reply-To"] = msg.ReplyTo
	}

	// Build message body
	var body strings.Builder
	for k, v := range headers {
		body.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	if msg.HTMLBody != "" {
		body.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		body.WriteString(msg.HTMLBody)
	} else {
		body.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		body.WriteString(msg.Body)
	}

	// Send email
	addr := fmt.Sprintf("%s:%d", p.config.SMTPHost, p.config.SMTPPort)

	var auth smtp.Auth
	if p.config.SMTPUsername != "" {
		auth = smtp.PlainAuth("", p.config.SMTPUsername, p.config.SMTPPassword, p.config.SMTPHost)
	}

	recipients := append(msg.To, msg.CC...)
	recipients = append(recipients, msg.BCC...)

	err := smtp.SendMail(addr, auth, p.config.FromAddress, recipients, []byte(body.String()))
	if err != nil {
		p.logger.Error().
			Err(err).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Msg("Failed to send email via SMTP")
		return fmt.Errorf("%w: %v", emailtypes.ErrSendFailed, err)
	}

	p.logger.Info().
		Strs("recipients", msg.To).
		Str("subject", msg.Subject).
		Msg("Email sent successfully via SMTP")

	return nil
}

// IsAvailable checks if the provider is available
func (p *Provider) IsAvailable() bool {
	return p.available
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "smtp"
}

// HealthCheck performs a health check
func (p *Provider) HealthCheck(ctx context.Context) error {
	if !p.available {
		return emailtypes.ErrServiceUnavailable
	}

	addr := fmt.Sprintf("%s:%d", p.config.SMTPHost, p.config.SMTPPort)

	if p.config.SMTPUseTLS {
		tlsConfig := &tls.Config{
			ServerName: p.config.SMTPHost,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			p.available = false
			return fmt.Errorf("SMTP health check failed: %w", err)
		}
		conn.Close()
	}

	return nil
}

// Close closes the provider connection
func (p *Provider) Close() error {
	p.logger.Info().Msg("Closing SMTP provider")
	return nil
}
