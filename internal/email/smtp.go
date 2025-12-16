// Package email implements SMTP email service
package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/rs/zerolog"
)

type smtpService struct {
	config    *Config
	logger    *zerolog.Logger
	templates *TemplateManager
	available bool
}

// NewSMTPService creates a new SMTP email service (for local development)
func NewSMTPService(cfg *Config, logger *zerolog.Logger) (Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid email config: %w", err)
	}

	// Test SMTP connection
	addr := fmt.Sprintf("%s:%d", cfg.SMTPHost, cfg.SMTPPort)

	var auth smtp.Auth
	fmt.Printf("auth", auth)
	if cfg.SMTPUsername != "" {
		auth = smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, cfg.SMTPHost)
	}

	// Try to connect
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
		Msg("SMTP email service initialized")

	return &smtpService{
		config:    cfg,
		logger:    logger,
		templates: NewTemplateManager(cfg),
		available: available,
	}, nil
}

func (s *smtpService) IsAvailable() bool {
	return s.available
}

func (s *smtpService) SendEmail(ctx context.Context, msg *Message) error {
	if !s.available {
		s.logger.Warn().Msg("SMTP service unavailable, skipping email")
		return fmt.Errorf("email service unavailable")
	}

	if len(msg.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	// Build email headers and body
	from := fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromAddress)
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
	addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)

	var auth smtp.Auth
	if s.config.SMTPUsername != "" {
		auth = smtp.PlainAuth("", s.config.SMTPUsername, s.config.SMTPPassword, s.config.SMTPHost)
	}

	recipients := append(msg.To, msg.CC...)
	recipients = append(recipients, msg.BCC...)

	err := smtp.SendMail(addr, auth, s.config.FromAddress, recipients, []byte(body.String()))
	if err != nil {
		s.logger.Error().
			Err(err).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Msg("Failed to send email via SMTP")
		return fmt.Errorf("failed to send email: %w", err)
	}

	s.logger.Info().
		Strs("recipients", msg.To).
		Str("subject", msg.Subject).
		Msg("Email sent successfully via SMTP")

	return nil
}

func (s *smtpService) SendWelcomeEmail(ctx context.Context, to, username string) error {
	subject, body, htmlBody := s.templates.RenderWelcome(username)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *smtpService) SendPasswordResetEmail(ctx context.Context, to, resetToken string) error {
	subject, body, htmlBody := s.templates.RenderPasswordReset(resetToken)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *smtpService) SendVerificationEmail(ctx context.Context, to, verificationToken string) error {
	subject, body, htmlBody := s.templates.RenderVerification(verificationToken)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *smtpService) SendPasswordChangedEmail(ctx context.Context, to, username string) error {
	subject, body, htmlBody := s.templates.RenderPasswordChanged(username)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *smtpService) SendLoginAlertEmail(ctx context.Context, to, username, ipAddress, location string) error {
	subject, body, htmlBody := s.templates.RenderLoginAlert(username, ipAddress, location)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}
