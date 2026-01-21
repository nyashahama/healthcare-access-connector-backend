package core

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Helper function to assert equality between two core.UserSession structs
func assertUserSessionEqual(t *testing.T, expected, got core.UserSession, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected.ID, got.ID, msgAndArgs...)
	assert.Equal(t, expected.UserID, got.UserID, msgAndArgs...)
	assert.Equal(t, expected.SessionToken, got.SessionToken, msgAndArgs...)
	assert.Equal(t, expected.DeviceType, got.DeviceType, msgAndArgs...)
	assert.Equal(t, expected.DeviceID, got.DeviceID, msgAndArgs...)
	assert.Equal(t, expected.IPAddress, got.IPAddress, msgAndArgs...)
	assert.Equal(t, expected.UserAgent, got.UserAgent, msgAndArgs...)
	assert.True(t, expected.ExpiresAt.Equal(got.ExpiresAt), msgAndArgs...)
	assert.True(t, expected.CreatedAt.Equal(got.CreatedAt), msgAndArgs...)
}

func TestSessionRepository_CreateSession(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	expires := now.Add(time.Hour * 24)
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	sessionID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr, _ := netip.ParseAddr(ipStr)
	fmt.Println(ipAddr)

	tests := []struct {
		name          string
		session       core.UserSession
		mockSetup     func(*mocks.Querier)
		expectedSess  core.UserSession
		expectedError error
	}{
		{
			name: "successful create session with all fields",
			session: core.UserSession{
				UserID:       userID,
				SessionToken: "token123",
				DeviceType:   stringPtr("mobile"),
				DeviceID:     stringPtr("device123"),
				IPAddress:    &ipStr,
				UserAgent:    stringPtr("Mozilla/5.0"),
				ExpiresAt:    expires,
			},
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.CreateSessionRow{
					ID:           uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:       uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					SessionToken: "token123",
					CreatedAt:    pgtype.Timestamp{Time: now, Valid: true},
					ExpiresAt:    pgtype.Timestamp{Time: expires, Valid: true},
				}
				m.On("CreateSession", ctx, mock.MatchedBy(func(p sqlc.CreateSessionParams) bool {
					return p.UserID.Bytes == userID &&
						p.SessionToken == "token123" &&
						p.DeviceType.String == "mobile" &&
						p.DeviceID.String == "device123" &&
						p.IpAddress.String() == ipStr &&
						p.UserAgent.String == "Mozilla/5.0" &&
						p.ExpiresAt.Time.Equal(expires)
				})).Return(expectedRow, nil)
			},
			expectedSess: core.UserSession{
				ID:           sessionID,
				UserID:       userID,
				SessionToken: "token123",
				CreatedAt:    now,
				ExpiresAt:    expires,
			},
			expectedError: nil,
		},
		{
			name: "successful create session with minimal fields",
			session: core.UserSession{
				UserID:       userID,
				SessionToken: "token456",
				ExpiresAt:    expires,
			},
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.CreateSessionRow{
					ID:           uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:       uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					SessionToken: "token456",
					CreatedAt:    pgtype.Timestamp{Time: now, Valid: true},
					ExpiresAt:    pgtype.Timestamp{Time: expires, Valid: true},
				}
				m.On("CreateSession", ctx, mock.MatchedBy(func(p sqlc.CreateSessionParams) bool {
					return p.UserID.Bytes == userID &&
						p.SessionToken == "token456" &&
						!p.DeviceType.Valid &&
						!p.DeviceID.Valid &&
						p.IpAddress == nil &&
						!p.UserAgent.Valid &&
						p.ExpiresAt.Time.Equal(expires)
				})).Return(expectedRow, nil)
			},
			expectedSess: core.UserSession{
				ID:           sessionID,
				UserID:       userID,
				SessionToken: "token456",
				CreatedAt:    now,
				ExpiresAt:    expires,
			},
			expectedError: nil,
		},
		{
			name: "database error",
			session: core.UserSession{
				UserID:       userID,
				SessionToken: "token123",
				ExpiresAt:    expires,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("CreateSession", ctx, mock.Anything).Return(sqlc.CreateSessionRow{}, assert.AnError)
			},
			expectedSess:  core.UserSession{},
			expectedError: fmt.Errorf("create session failed: %w", assert.AnError),
		},
		{
			name: "foreign key violation",
			session: core.UserSession{
				UserID:       userID,
				SessionToken: "token123",
				ExpiresAt:    expires,
			},
			mockSetup: func(m *mocks.Querier) {
				pgErr := &pgconn.PgError{Code: "23503"}
				m.On("CreateSession", ctx, mock.Anything).Return(sqlc.CreateSessionRow{}, pgErr)
			},
			expectedSess:  core.UserSession{},
			expectedError: fmt.Errorf("foreign key violation: %w", &pgconn.PgError{Code: "23503"}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &sessionRepository{querier: mockQuerier}

			gotSess, err := repo.CreateSession(ctx, tt.session)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assertUserSessionEqual(t, tt.expectedSess, gotSess)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestSessionRepository_GetSession(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	expires := now.Add(time.Hour * 24)
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	sessionID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)

	tests := []struct {
		name          string
		sessionToken  string
		mockSetup     func(*mocks.Querier)
		expectedSess  core.UserSession
		expectedError error
	}{
		{
			name:         "successful get session",
			sessionToken: "token123",
			mockSetup: func(m *mocks.Querier) {
				expectedRow := sqlc.GetSessionRow{
					ID:           uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:       uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					SessionToken: "token123",
					DeviceType:   pgtype.Text{String: "mobile", Valid: true},
					IpAddress:    &ipAddr,
					UserAgent:    pgtype.Text{String: "Mozilla/5.0", Valid: true},
					ExpiresAt:    pgtype.Timestamp{Time: expires, Valid: true},
					CreatedAt:    pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetSession", ctx, "token123").Return(expectedRow, nil)
			},
			expectedSess: core.UserSession{
				ID:           sessionID,
				UserID:       userID,
				SessionToken: "token123",
				DeviceType:   stringPtr("mobile"),
				DeviceID:     nil, // Not selected in query
				IPAddress:    &ipStr,
				UserAgent:    stringPtr("Mozilla/5.0"),
				ExpiresAt:    expires,
				CreatedAt:    now,
			},
			expectedError: nil,
		},
		{
			name:         "session not found",
			sessionToken: "invalidtoken",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetSession", ctx, "invalidtoken").Return(sqlc.GetSessionRow{}, pgx.ErrNoRows)
			},
			expectedSess:  core.UserSession{},
			expectedError: domain.ErrSessionNotFound,
		},
		{
			name:         "database error",
			sessionToken: "token123",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetSession", ctx, "token123").Return(sqlc.GetSessionRow{}, assert.AnError)
			},
			expectedSess:  core.UserSession{},
			expectedError: fmt.Errorf("get session failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &sessionRepository{querier: mockQuerier}

			gotSess, err := repo.GetSession(ctx, tt.sessionToken)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Equal(t, tt.expectedError, err)
			} else {
				require.NoError(t, err)
				assertUserSessionEqual(t, tt.expectedSess, gotSess)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}
