// Package ses implements AWS SES email provider
package ses

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ses"
	"github.com/aws/aws-sdk-go-v2/service/ses/types"
	"github.com/rs/zerolog"

	emailtypes "github.com/nyashahama/healthcare-access-connector-backend/internal/email/types"
)

// Provider implements the SES email provider
type Provider struct {
	client    *ses.Client
	config    *emailtypes.Config
	logger    *zerolog.Logger
	available bool
}

// New creates a new SES provider
func New(cfg *emailtypes.Config, logger *zerolog.Logger) (*Provider, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid email config: %w", err)
	}

	// Load AWS configuration
	var awsCfg aws.Config
	var err error

	if cfg.AWSAccessKeyID != "" && cfg.AWSSecretAccessKey != "" {
		awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
			awsconfig.WithRegion(cfg.AWSRegion),
			awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
				cfg.AWSAccessKeyID,
				cfg.AWSSecretAccessKey,
				"",
			)),
		)
	} else {
		awsCfg, err = awsconfig.LoadDefaultConfig(context.Background(),
			awsconfig.WithRegion(cfg.AWSRegion),
		)
	}

	if err != nil {
		logger.Warn().Err(err).Msg("Failed to load AWS config")
		return &Provider{
			config:    cfg,
			logger:    logger,
			available: false,
		}, nil
	}

	client := ses.NewFromConfig(awsCfg)

	// Test connection
	_, err = client.GetSendQuota(context.Background(), &ses.GetSendQuotaInput{})
	if err != nil {
		logger.Warn().Err(err).Msg("Failed to verify SES connection")
		return &Provider{
			client:    client,
			config:    cfg,
			logger:    logger,
			available: false,
		}, nil
	}

	logger.Info().
		Str("provider", "ses").
		Str("region", cfg.AWSRegion).
		Msg("SES provider initialized successfully")

	return &Provider{
		client:    client,
		config:    cfg,
		logger:    logger,
		available: true,
	}, nil
}

// Send sends an email via SES
func (p *Provider) Send(ctx context.Context, msg *emailtypes.Message) error {
	if !p.available {
		return emailtypes.ErrServiceUnavailable
	}

	if len(msg.To) == 0 {
		return emailtypes.ErrNoRecipients
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
		Source:      aws.String(fmt.Sprintf("%s <%s>", p.config.FromName, p.config.FromAddress)),
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
	result, err := p.client.SendEmail(ctx, input)
	if err != nil {
		p.logger.Error().
			Err(err).
			Strs("recipients", msg.To).
			Str("subject", msg.Subject).
			Msg("Failed to send email via SES")
		return fmt.Errorf("%w: %v", emailtypes.ErrSendFailed, err)
	}

	p.logger.Info().
		Str("message_id", *result.MessageId).
		Strs("recipients", msg.To).
		Str("subject", msg.Subject).
		Msg("Email sent successfully via SES")

	return nil
}

// IsAvailable checks if the provider is available
func (p *Provider) IsAvailable() bool {
	return p.available
}

// Name returns the provider name
func (p *Provider) Name() string {
	return "ses"
}

// HealthCheck performs a health check
func (p *Provider) HealthCheck(ctx context.Context) error {
	if !p.available {
		return emailtypes.ErrServiceUnavailable
	}

	_, err := p.client.GetSendQuota(ctx, &ses.GetSendQuotaInput{})
	if err != nil {
		p.available = false
		return fmt.Errorf("SES health check failed: %w", err)
	}

	return nil
}

// Close closes the provider connection
func (p *Provider) Close() error {
	p.logger.Info().Msg("Closing SES provider")
	return nil
}
