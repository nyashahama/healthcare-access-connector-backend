package sms

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	domainsms "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/sms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSMSRepository struct {
	createConversationFunc      func(ctx context.Context, conv domainsms.SMSConversation) (domainsms.SMSConversation, error)
	getConversationFunc         func(ctx context.Context, id uuid.UUID) (domainsms.SMSConversation, error)
	getConversationByPhoneFunc  func(ctx context.Context, phone string) (domainsms.SMSConversation, error)
	getConversationByUserIDFunc func(ctx context.Context, userID uuid.UUID) (domainsms.SMSConversation, error)
	updateConversationFunc      func(ctx context.Context, conv domainsms.SMSConversation) error
	closeConversationFunc       func(ctx context.Context, id uuid.UUID, reason string) error
	getActiveConversationsFunc  func(ctx context.Context) ([]domainsms.SMSConversation, error)
	logMessageFunc              func(ctx context.Context, msg domainsms.SMSMessage) (domainsms.SMSMessage, error)
	getMessageFunc              func(ctx context.Context, id uuid.UUID) (domainsms.SMSMessage, error)
	getConversationMessagesFunc func(ctx context.Context, conversationID uuid.UUID, limit, offset int) ([]domainsms.SMSMessage, error)
	getFailedMessagesFunc       func(ctx context.Context, startDate, endDate time.Time) ([]domainsms.SMSMessage, error)
	archiveOldMessagesFunc      func(ctx context.Context, olderThan time.Duration) error
	exportConversationFunc      func(ctx context.Context, conversationID uuid.UUID) ([]byte, error)
}

func (m *mockSMSRepository) CreateConversation(ctx context.Context, conv domainsms.SMSConversation) (domainsms.SMSConversation, error) {
	return m.createConversationFunc(ctx, conv)
}

func (m *mockSMSRepository) GetConversation(ctx context.Context, id uuid.UUID) (domainsms.SMSConversation, error) {
	return m.getConversationFunc(ctx, id)
}

func (m *mockSMSRepository) GetConversationByPhone(ctx context.Context, phone string) (domainsms.SMSConversation, error) {
	return m.getConversationByPhoneFunc(ctx, phone)
}

func (m *mockSMSRepository) GetConversationByUserID(ctx context.Context, userID uuid.UUID) (domainsms.SMSConversation, error) {
	return m.getConversationByUserIDFunc(ctx, userID)
}

func (m *mockSMSRepository) UpdateConversation(ctx context.Context, conv domainsms.SMSConversation) error {
	return m.updateConversationFunc(ctx, conv)
}

func (m *mockSMSRepository) CloseConversation(ctx context.Context, id uuid.UUID, reason string) error {
	return m.closeConversationFunc(ctx, id, reason)
}

func (m *mockSMSRepository) GetActiveConversations(ctx context.Context) ([]domainsms.SMSConversation, error) {
	return m.getActiveConversationsFunc(ctx)
}

func (m *mockSMSRepository) LogMessage(ctx context.Context, msg domainsms.SMSMessage) (domainsms.SMSMessage, error) {
	return m.logMessageFunc(ctx, msg)
}

func (m *mockSMSRepository) GetMessage(ctx context.Context, id uuid.UUID) (domainsms.SMSMessage, error) {
	return m.getMessageFunc(ctx, id)
}

func (m *mockSMSRepository) GetConversationMessages(ctx context.Context, conversationID uuid.UUID, limit, offset int) ([]domainsms.SMSMessage, error) {
	return m.getConversationMessagesFunc(ctx, conversationID, limit, offset)
}

func (m *mockSMSRepository) GetFailedMessages(ctx context.Context, startDate, endDate time.Time) ([]domainsms.SMSMessage, error) {
	return m.getFailedMessagesFunc(ctx, startDate, endDate)
}

func (m *mockSMSRepository) ArchiveOldMessages(ctx context.Context, olderThan time.Duration) error {
	return m.archiveOldMessagesFunc(ctx, olderThan)
}

func (m *mockSMSRepository) ExportConversation(ctx context.Context, conversationID uuid.UUID) ([]byte, error) {
	return m.exportConversationFunc(ctx, conversationID)
}

func TestSMSServiceRequiresRepository(t *testing.T) {
	svc := NewSMSService(nil)

	_, err := svc.CreateConversation(context.Background(), domainsms.SMSConversation{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SMS service repository is not configured")
}

func TestSMSServiceDelegatesConversationOperations(t *testing.T) {
	conversationID := uuid.New()
	userID := uuid.New()
	conv := domainsms.SMSConversation{
		ID:          conversationID,
		UserID:      &userID,
		PhoneNumber: "+27710000000",
	}

	repo := &mockSMSRepository{
		createConversationFunc: func(ctx context.Context, got domainsms.SMSConversation) (domainsms.SMSConversation, error) {
			assert.Equal(t, conv.PhoneNumber, got.PhoneNumber)
			return conv, nil
		},
		getConversationFunc: func(ctx context.Context, got uuid.UUID) (domainsms.SMSConversation, error) {
			assert.Equal(t, conversationID, got)
			return conv, nil
		},
		getConversationByPhoneFunc: func(ctx context.Context, phone string) (domainsms.SMSConversation, error) {
			assert.Equal(t, conv.PhoneNumber, phone)
			return conv, nil
		},
		getConversationByUserIDFunc: func(ctx context.Context, got uuid.UUID) (domainsms.SMSConversation, error) {
			assert.Equal(t, userID, got)
			return conv, nil
		},
		updateConversationFunc: func(ctx context.Context, got domainsms.SMSConversation) error {
			assert.Equal(t, conversationID, got.ID)
			return nil
		},
		closeConversationFunc: func(ctx context.Context, got uuid.UUID, reason string) error {
			assert.Equal(t, conversationID, got)
			assert.Equal(t, "resolved", reason)
			return nil
		},
		getActiveConversationsFunc: func(ctx context.Context) ([]domainsms.SMSConversation, error) {
			return []domainsms.SMSConversation{conv}, nil
		},
	}

	svc := NewSMSService(repo)

	created, err := svc.CreateConversation(context.Background(), conv)
	require.NoError(t, err)
	assert.Equal(t, conv, created)

	gotByID, err := svc.GetConversation(context.Background(), conversationID)
	require.NoError(t, err)
	assert.Equal(t, conv, gotByID)

	gotByPhone, err := svc.GetConversationByPhone(context.Background(), conv.PhoneNumber)
	require.NoError(t, err)
	assert.Equal(t, conv, gotByPhone)

	gotByUser, err := svc.GetConversationByUserID(context.Background(), userID)
	require.NoError(t, err)
	assert.Equal(t, conv, gotByUser)

	require.NoError(t, svc.UpdateConversation(context.Background(), conv))
	require.NoError(t, svc.CloseConversation(context.Background(), conversationID, "resolved"))

	active, err := svc.GetActiveConversations(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []domainsms.SMSConversation{conv}, active)
}

func TestSMSServiceDelegatesMessageOperations(t *testing.T) {
	conversationID := uuid.New()
	messageID := uuid.New()
	startDate := time.Now().Add(-24 * time.Hour).UTC()
	endDate := time.Now().UTC()
	message := domainsms.SMSMessage{
		ID:             messageID,
		ConversationID: conversationID,
		Direction:      "outbound",
		MessageBody:    "Your OTP is 123456",
	}

	repoErr := errors.New("archive failed")
	repo := &mockSMSRepository{
		logMessageFunc: func(ctx context.Context, got domainsms.SMSMessage) (domainsms.SMSMessage, error) {
			assert.Equal(t, message.MessageBody, got.MessageBody)
			return message, nil
		},
		getMessageFunc: func(ctx context.Context, got uuid.UUID) (domainsms.SMSMessage, error) {
			assert.Equal(t, messageID, got)
			return message, nil
		},
		getConversationMessagesFunc: func(ctx context.Context, got uuid.UUID, limit, offset int) ([]domainsms.SMSMessage, error) {
			assert.Equal(t, conversationID, got)
			assert.Equal(t, 25, limit)
			assert.Equal(t, 5, offset)
			return []domainsms.SMSMessage{message}, nil
		},
		getFailedMessagesFunc: func(ctx context.Context, gotStart, gotEnd time.Time) ([]domainsms.SMSMessage, error) {
			assert.Equal(t, startDate, gotStart)
			assert.Equal(t, endDate, gotEnd)
			return []domainsms.SMSMessage{message}, nil
		},
		archiveOldMessagesFunc: func(ctx context.Context, olderThan time.Duration) error {
			assert.Equal(t, 30*24*time.Hour, olderThan)
			return repoErr
		},
		exportConversationFunc: func(ctx context.Context, got uuid.UUID) ([]byte, error) {
			assert.Equal(t, conversationID, got)
			return []byte(`{"conversation":"exported"}`), nil
		},
	}

	svc := NewSMSService(repo)

	logged, err := svc.LogMessage(context.Background(), message)
	require.NoError(t, err)
	assert.Equal(t, message, logged)

	gotMessage, err := svc.GetMessage(context.Background(), messageID)
	require.NoError(t, err)
	assert.Equal(t, message, gotMessage)

	gotMessages, err := svc.GetConversationMessages(context.Background(), conversationID, 25, 5)
	require.NoError(t, err)
	assert.Equal(t, []domainsms.SMSMessage{message}, gotMessages)

	failedMessages, err := svc.GetFailedMessages(context.Background(), startDate, endDate)
	require.NoError(t, err)
	assert.Equal(t, []domainsms.SMSMessage{message}, failedMessages)

	err = svc.ArchiveOldMessages(context.Background(), 30*24*time.Hour)
	require.ErrorIs(t, err, repoErr)

	exported, err := svc.ExportConversation(context.Background(), conversationID)
	require.NoError(t, err)
	assert.Equal(t, []byte(`{"conversation":"exported"}`), exported)
}
