// Package email implements AWS SES email service
package email

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/rs/zerolog"
)

type sesService struct {
	client    *ses.Client
	config    *Config
	logger    *zerolog.Logger
	templates *TemplateManager
	available bool
}

// NewSESService creates a new AWS SES email service
func NewSESService(cfg *Config, logger *zerolog.Logger) (Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid email config: %w", err)
	}

	// Load AWS configuration
	var awsCfg aws.Config
	var err error

	if cfg.AWSAccessKeyID != "" && cfg.AWSSecretAccessKey != "" {
		// Use provided credentials
		awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
			awsconfig.WithRegion(cfg.AWSRegion),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.AWSAccessKeyID,
				cfg.AWSSecretAccessKey,
				"",
			)),
		)
	} else {
		// Use IAM role or environment credentials
		awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
			awsconfig.WithRegion(cfg.AWSRegion),
		)
	}

	if err != nil {
		logger.Warn().Err(err).Msg("Failed to load AWS config, email service unavailable")
		return &sesService{
			config:    cfg,
			logger:    logger,
			templates: NewTemplateManager(cfg),
			available: false,
		}, nil
	}

	client := ses.NewFromConfig(awsCfg)

	// Test connection
	_, err = client.GetSendQuota(context.Background(), &ses.GetSendQuotaInput{})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to verify SES connection, email service degraded")
		return &sesService{
			client:    client,
			config:    cfg,
			logger:    logger,
			templates: NewTemplateManager(cfg),
			available: false,
		}, nil
	}

	logger.Info().
		Str("provider", "ses").
		Str("region", cfg.AWSRegion).
		Msg("Email service initialized successfully")

	return &sesService{
		client:    client,
		config:    cfg,
		logger:    logger,
		templates: NewTemplateManager(cfg),
		available: true,
	}, nil
}

func (s *sesService) IsAvailable() bool {
	return s.available
}

func (s *sesService) SendEmail(ctx context.Context, msg *Message) error {
	if !s.available {
		s.logger.Warn().Msg("Email service unavailable, skipping email")
		return fmt.Errorf("email service unavailable")
	}

	if len(msg.To) == 0 {
		return fmt.Errorf("no recipients specified")
	}

	// Build destination
	destination := &types.Destination{
		ToAddresses: msg.To,
	}
	if len(msg.CC) > 0 {
		destination.CcAddresses = msg.CC
	}
	if len(msg.BCC) > 0 {
		destination.BccAddresses = msg.BCC
	}

	// Build message body
	body := &types.Body{}
	if msg.HTMLBody != "" {
		body.Html = &types.Content{
			Charset: aws.String("UTF-8"),
			Data:    aws.String(msg.HTMLBody),
		}
	}
	if msg.Body != "" {
		body.Text = &types.Content{
			Charset: aws.String("UTF-8"),
			Data:    aws.String(msg.Body),
		}
	}

	// Build message
	input := &ses.SendEmailInput{
		Source:      aws.String(fmt.Sprintf("%s <%s>", s.config.FromName, s.config.FromAddress)),
		Destination: destination,
		Message: &types.Message{
			Subject: &types.Content{
				Charset: aws.String("UTF-8"),
				Data:    aws.String(msg.Subject),
			},
			Body: body,
		},
	}

	if msg.ReplyTo != "" {
		input.ReplyToAddresses = []string{msg.ReplyTo}
	}

	// Send email
	result, err := s.client.SendEmail(ctx, input)
	if err != nil {
		s.logger.Error().
			Err(err).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Msg("Failed to send email")
		return fmt.Errorf("failed to send email: %w", err)
	}

	s.logger.Info().
		Str("message_id", *result.MessageId).
		Strs("recipients", msg.To).
		Str("subject", msg.Subject).
		Msg("Email sent successfully")

	return nil
}

func (s *sesService) SendWelcomeEmail(ctx context.Context, to, username string) error {
	subject, body, htmlBody := s.templates.RenderWelcome(username)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *sesService) SendPasswordResetEmail(ctx context.Context, to, resetToken string) error {
	subject, body, htmlBody := s.templates.RenderPasswordReset(resetToken)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *sesService) SendVerificationEmail(ctx context.Context, to, verificationToken string) error {
	subject, body, htmlBody := s.templates.RenderVerification(verificationToken)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *sesService) SendPasswordChangedEmail(ctx context.Context, to, username string) error {
	subject, body, htmlBody := s.templates.RenderPasswordChanged(username)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}

func (s *sesService) SendLoginAlertEmail(ctx context.Context, to, username, ipAddress, location string) error {
	subject, body, htmlBody := s.templates.RenderLoginAlert(username, ipAddress, location)

	return s.SendEmail(ctx, &Message{
		To:       []string{to},
		Subject:  subject,
		Body:     body,
		HTMLBody: htmlBody,
	})
}
