package telemedicine

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func buildMessageRow(id, consultationID, senderUserID string, senderRole, messageType string, isRead bool) sqlc.ConsultationMessage {
	now := nowTime()
	return sqlc.ConsultationMessage{
		ID:             uuidPgtypeFromString(id),
		ConsultationID: uuidPgtypeFromString(consultationID),
		SenderUserID:   uuidPgtypeFromString(senderUserID),
		SenderRole:     senderRole,
		MessageType:    messageType,
		Content:        pgtype.Text{String: "Test message content", Valid: true},
		AttachmentUrl:  pgtype.Text{Valid: false},
		AttachmentType: pgtype.Text{Valid: false},
		AttachmentFilename: pgtype.Text{Valid: false},
		IsRead:        isRead,
		ReadAt:        pgtype.Timestamp{Valid: false},
		IsDeleted:     false,
		Metadata:      []byte{},
		SentAt:        pgtype.Timestamp{Time: now, Valid: true},
	}
}

func buildMessage(id string, senderRole telemedicine.SenderRole, messageType telemedicine.MessageType) telemedicine.ConsultationMessage {
	now := nowTime()
	return telemedicine.ConsultationMessage{
		ID:             uuid.MustParse(id),
		ConsultationID: uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
		SenderUserID:   uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
		SenderRole:     senderRole,
		MessageType:    messageType,
		Content:        stringPtr("Test message content"),
		IsRead:         false,
		SentAt:         now,
	}
}

func TestConsultationMessagesRepository_InsertMessage(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		message       telemedicine.ConsultationMessage
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.ConsultationMessage
		expectedError error
	}{
		{
			name:    "success",
			message: buildMessage("123e4567-e89b-12d3-a456-426614174000", telemedicine.SenderRolePatient, telemedicine.MessageTypeText),
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildMessageRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174002",
					"patient", "text", false,
				)
				m.On("InsertMessage", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildMessage("123e4567-e89b-12d3-a456-426614174000", telemedicine.SenderRolePatient, telemedicine.MessageTypeText),
			expectedError: nil,
		},
		{
			name: "database error",
			message: telemedicine.ConsultationMessage{
				ID:             uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				ConsultationID: uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
				SenderUserID:   uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
				SenderRole:     telemedicine.SenderRolePatient,
				MessageType:    telemedicine.MessageTypeText,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("InsertMessage", ctx, mock.Anything).Return(sqlc.ConsultationMessage{}, assert.AnError)
			},
			expected:      telemedicine.ConsultationMessage{},
			expectedError: assert.AnError,
		},
		{
			name: "foreign key violation",
			message: telemedicine.ConsultationMessage{
				ID:             uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
				ConsultationID: uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
				SenderUserID:   uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
				SenderRole:     telemedicine.SenderRolePatient,
				MessageType:    telemedicine.MessageTypeText,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("InsertMessage", ctx, mock.Anything).Return(sqlc.ConsultationMessage{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.ConsultationMessage{},
			expectedError: domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationMessagesRepositoryWithQuerier(mockQuerier)

			got, err := repo.InsertMessage(ctx, tt.message)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "insert message")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.ConsultationID, got.ConsultationID)
				assert.Equal(t, tt.expected.SenderUserID, got.SenderUserID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationMessagesRepository_GetConsultationMessages(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174001")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		limit         int
		offset        int
		mockSetup     func(*mocks.MockQuerier)
		expected      []telemedicine.ConsultationMessage
		expectedError error
	}{
		{
			name:           "found",
			consultationID: consultationID,
			limit:          10,
			offset:         0,
			mockSetup: func(m *mocks.MockQuerier) {
				rows := []sqlc.GetConsultationMessagesRow{
					{
						ID:             uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
						ConsultationID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001"),
						SenderUserID:   uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174002"),
						SenderRole:     "patient",
						MessageType:    "text",
						Content:        pgtype.Text{String: "Hello", Valid: true},
						AttachmentUrl:  pgtype.Text{Valid: false},
						AttachmentType: pgtype.Text{Valid: false},
						AttachmentFilename: pgtype.Text{Valid: false},
						IsRead:         false,
						ReadAt:         pgtype.Timestamp{Valid: false},
						Metadata:       []byte{},
						SentAt:         pgtype.Timestamp{Time: nowTime(), Valid: true},
					},
				}
				m.On("GetConsultationMessages", ctx, mock.Anything).Return(rows, nil)
			},
			expected: []telemedicine.ConsultationMessage{
				{
					ID:             uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
					ConsultationID: uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
					SenderUserID:   uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
					SenderRole:     telemedicine.SenderRolePatient,
					MessageType:    telemedicine.MessageTypeText,
					Content:        stringPtr("Hello"),
					IsRead:         false,
				},
			},
			expectedError: nil,
		},
		{
			name:           "empty",
			consultationID: consultationID,
			limit:          10,
			offset:         0,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetConsultationMessages", ctx, mock.Anything).Return([]sqlc.GetConsultationMessagesRow{}, nil)
			},
			expected:      []telemedicine.ConsultationMessage{},
			expectedError: nil,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			limit:          10,
			offset:         0,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetConsultationMessages", ctx, mock.Anything).Return(nil, assert.AnError)
			},
			expected:      nil,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationMessagesRepositoryWithQuerier(mockQuerier)

			got, err := repo.GetConsultationMessages(ctx, tt.consultationID, tt.limit, tt.offset)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get consultation messages")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(tt.expected), len(got))
				if len(got) > 0 {
					assert.Equal(t, tt.expected[0].ID, got[0].ID)
					assert.Equal(t, tt.expected[0].Content, got[0].Content)
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationMessagesRepository_MarkMessageRead(t *testing.T) {
	ctx := context.Background()
	messageID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		messageID     uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name:      "success",
			messageID: messageID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("MarkMessageRead", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "not found",
			messageID: messageID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("MarkMessageRead", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(pgx.ErrNoRows)
			},
			expectedError: domain.ErrNotFound,
		},
		{
			name:      "database error",
			messageID: messageID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("MarkMessageRead", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationMessagesRepositoryWithQuerier(mockQuerier)

			err := repo.MarkMessageRead(ctx, tt.messageID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "mark message read")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationMessagesRepository_CountUnreadMessages(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174001")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		senderRole    telemedicine.SenderRole
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.UnreadCount
		expectedError error
	}{
		{
			name:           "success with count",
			consultationID: consultationID,
			senderRole:    telemedicine.SenderRoleProvider,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CountUnreadMessages", ctx, mock.Anything).Return(int64(5), nil)
			},
			expected:      telemedicine.UnreadCount{Count: 5},
			expectedError: nil,
		},
		{
			name:           "zero unread",
			consultationID: consultationID,
			senderRole:    telemedicine.SenderRoleProvider,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CountUnreadMessages", ctx, mock.Anything).Return(int64(0), nil)
			},
			expected:      telemedicine.UnreadCount{Count: 0},
			expectedError: nil,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			senderRole:    telemedicine.SenderRoleProvider,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CountUnreadMessages", ctx, mock.Anything).Return(int64(0), assert.AnError)
			},
			expected:      telemedicine.UnreadCount{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationMessagesRepositoryWithQuerier(mockQuerier)

			got, err := repo.CountUnreadMessages(ctx, tt.consultationID, tt.senderRole)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "count unread messages")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.Count, got.Count)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}