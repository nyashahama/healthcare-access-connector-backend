package core

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	domaincore "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	domainsms "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/sms"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/service"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type otpAuditSMSSender struct {
	available bool
	delivery  *otpSMSDelivery
	err       error
}

func (m *otpAuditSMSSender) IsAvailable() bool { return m.available }
func (m *otpAuditSMSSender) SendOTP(ctx context.Context, phoneNumber, otp string) (*otpSMSDelivery, error) {
	return m.delivery, m.err
}

type otpAuditSMSService struct {
	getConversationByPhoneFunc func(ctx context.Context, phone string) (domainsms.SMSConversation, error)
	createConversationFunc     func(ctx context.Context, conv domainsms.SMSConversation) (domainsms.SMSConversation, error)
	logMessageFunc             func(ctx context.Context, msg domainsms.SMSMessage) (domainsms.SMSMessage, error)
}

func (m *otpAuditSMSService) CreateConversation(ctx context.Context, conv domainsms.SMSConversation) (domainsms.SMSConversation, error) {
	return m.createConversationFunc(ctx, conv)
}
func (m *otpAuditSMSService) GetConversation(ctx context.Context, id uuid.UUID) (domainsms.SMSConversation, error) {
	return domainsms.SMSConversation{}, nil
}
func (m *otpAuditSMSService) GetConversationByPhone(ctx context.Context, phone string) (domainsms.SMSConversation, error) {
	return m.getConversationByPhoneFunc(ctx, phone)
}
func (m *otpAuditSMSService) GetConversationByUserID(ctx context.Context, userID uuid.UUID) (domainsms.SMSConversation, error) {
	return domainsms.SMSConversation{}, nil
}
func (m *otpAuditSMSService) UpdateConversation(ctx context.Context, conv domainsms.SMSConversation) error {
	return nil
}
func (m *otpAuditSMSService) CloseConversation(ctx context.Context, id uuid.UUID, reason string) error {
	return nil
}
func (m *otpAuditSMSService) GetActiveConversations(ctx context.Context) ([]domainsms.SMSConversation, error) {
	return nil, nil
}
func (m *otpAuditSMSService) LogMessage(ctx context.Context, msg domainsms.SMSMessage) (domainsms.SMSMessage, error) {
	return m.logMessageFunc(ctx, msg)
}
func (m *otpAuditSMSService) GetMessage(ctx context.Context, id uuid.UUID) (domainsms.SMSMessage, error) {
	return domainsms.SMSMessage{}, nil
}
func (m *otpAuditSMSService) GetConversationMessages(ctx context.Context, conversationID uuid.UUID, limit, offset int) ([]domainsms.SMSMessage, error) {
	return nil, nil
}
func (m *otpAuditSMSService) GetFailedMessages(ctx context.Context, startDate, endDate time.Time) ([]domainsms.SMSMessage, error) {
	return nil, nil
}
func (m *otpAuditSMSService) ArchiveOldMessages(ctx context.Context, olderThan time.Duration) error {
	return nil
}
func (m *otpAuditSMSService) ExportConversation(ctx context.Context, conversationID uuid.UUID) ([]byte, error) {
	return nil, nil
}

var _ service.SMSService = (*otpAuditSMSService)(nil)

func TestGenerateOTPLogsOutboundSMSMessage(t *testing.T) {
	logger := zerolog.New(io.Discard)
	user := domaincore.User{
		ID:              uuid.New(),
		Phone:           otpStringPtr("+27712223333"),
		SMSConsentGiven: true,
	}

	authRepo := &otpTestAuthRepository{
		getUserByPhoneWithHashFunc: func(ctx context.Context, phone string) (domaincore.User, string, error) {
			return user, "hash", nil
		},
	}
	otpRepo := &otpTestOTPRepository{
		getOTPAttemptCountFunc: func(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) { return 0, nil },
		deleteUserOTPsFunc:     func(ctx context.Context, userID uuid.UUID, otpType string) error { return nil },
		saveOTPFunc:            func(ctx context.Context, otp domaincore.OTPVerification) error { return nil },
	}

	conversationID := uuid.New()
	var logged domainsms.SMSMessage
	smsSvc := &otpAuditSMSService{
		getConversationByPhoneFunc: func(ctx context.Context, phone string) (domainsms.SMSConversation, error) {
			return domainsms.SMSConversation{}, domain.ErrNotFound
		},
		createConversationFunc: func(ctx context.Context, conv domainsms.SMSConversation) (domainsms.SMSConversation, error) {
			assert.Equal(t, *user.Phone, conv.PhoneNumber)
			return domainsms.SMSConversation{ID: conversationID, PhoneNumber: conv.PhoneNumber}, nil
		},
		logMessageFunc: func(ctx context.Context, msg domainsms.SMSMessage) (domainsms.SMSMessage, error) {
			logged = msg
			return msg, nil
		},
	}

	messageID := "SM123"
	status := "queued"
	sentAt := time.Now().UTC()
	sender := &otpAuditSMSSender{
		available: true,
		delivery: &otpSMSDelivery{
			MessageBody:     "Your Healthcare Access Connector verification code is 123456. It expires in 10 minutes.",
			TwilioMessageID: &messageID,
			TwilioStatus:    &status,
			SentAt:          &sentAt,
			Segments:        1,
		},
	}

	svc := newOTPService(authRepo, otpRepo, nil, smsSvc, &logger, true, 4, sender)

	channel, err := svc.GenerateOTP(context.Background(), *user.Phone)
	require.NoError(t, err)
	assert.Equal(t, "sms", channel)
	assert.Equal(t, conversationID, logged.ConversationID)
	assert.Equal(t, "outbound", logged.Direction)
	assert.Equal(t, messageID, *logged.TwilioMessageID)
	assert.Equal(t, status, *logged.TwilioStatus)
	assert.Contains(t, logged.MessageBody, "******")
	assert.NotContains(t, logged.MessageBody, "123456")
}

func TestGenerateOTPDoesNotFailWhenSMSAuditLoggingFails(t *testing.T) {
	logger := zerolog.New(io.Discard)
	user := domaincore.User{
		ID:              uuid.New(),
		Phone:           otpStringPtr("+27714445555"),
		SMSConsentGiven: true,
	}

	authRepo := &otpTestAuthRepository{
		getUserByPhoneWithHashFunc: func(ctx context.Context, phone string) (domaincore.User, string, error) {
			return user, "hash", nil
		},
	}
	otpRepo := &otpTestOTPRepository{
		getOTPAttemptCountFunc: func(ctx context.Context, userID uuid.UUID, otpType string) (int64, error) { return 0, nil },
		deleteUserOTPsFunc:     func(ctx context.Context, userID uuid.UUID, otpType string) error { return nil },
		saveOTPFunc:            func(ctx context.Context, otp domaincore.OTPVerification) error { return nil },
	}

	smsSvc := &otpAuditSMSService{
		getConversationByPhoneFunc: func(ctx context.Context, phone string) (domainsms.SMSConversation, error) {
			return domainsms.SMSConversation{}, errors.New("db unavailable")
		},
		createConversationFunc: func(ctx context.Context, conv domainsms.SMSConversation) (domainsms.SMSConversation, error) {
			return domainsms.SMSConversation{}, nil
		},
		logMessageFunc: func(ctx context.Context, msg domainsms.SMSMessage) (domainsms.SMSMessage, error) {
			return domainsms.SMSMessage{}, nil
		},
	}

	sender := &otpAuditSMSSender{
		available: true,
		delivery: &otpSMSDelivery{
			MessageBody: "Your Healthcare Access Connector verification code is 654321. It expires in 10 minutes.",
			Segments:    1,
		},
	}

	svc := newOTPService(authRepo, otpRepo, nil, smsSvc, &logger, true, 4, sender)

	channel, err := svc.GenerateOTP(context.Background(), *user.Phone)
	require.NoError(t, err)
	assert.Equal(t, "sms", channel)
}
