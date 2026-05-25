package core

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type mockSessionRepositoryForService struct {
	createSessionFunc func(ctx context.Context, session core.UserSession) (core.UserSession, error)
	getSessionFunc    func(ctx context.Context, sessionToken string) (core.UserSession, error)
	deleteSessionFunc func(ctx context.Context, sessionToken string) error
}

func (m *mockSessionRepositoryForService) CreateSession(ctx context.Context, session core.UserSession) (core.UserSession, error) {
	return m.createSessionFunc(ctx, session)
}

func (m *mockSessionRepositoryForService) GetSession(ctx context.Context, sessionToken string) (core.UserSession, error) {
	if m.getSessionFunc != nil {
		return m.getSessionFunc(ctx, sessionToken)
	}
	return core.UserSession{}, nil
}

func (m *mockSessionRepositoryForService) DeleteSession(ctx context.Context, sessionToken string) error {
	if m.deleteSessionFunc != nil {
		return m.deleteSessionFunc(ctx, sessionToken)
	}
	return nil
}

func (m *mockSessionRepositoryForService) DeleteUserSessions(ctx context.Context, userID uuid.UUID) error {
	return nil
}

func (m *mockSessionRepositoryForService) DeleteExpiredSessions(ctx context.Context) error {
	return nil
}

func (m *mockSessionRepositoryForService) UpdateSessionToken(ctx context.Context, id uuid.UUID, sessionToken string, expiresAt time.Time) error {
	return nil
}

func (m *mockSessionRepositoryForService) GetUserSessions(ctx context.Context, userID uuid.UUID) ([]core.UserSession, error) {
	return nil, nil
}

func (m *mockSessionRepositoryForService) RevokeAllExceptCurrent(ctx context.Context, userID, currentSessionID uuid.UUID) error {
	return nil
}

func (m *mockSessionRepositoryForService) InvalidateSessionByDevice(ctx context.Context, userID uuid.UUID, deviceID string) error {
	return nil
}

var _ repository.SessionRepository = (*mockSessionRepositoryForService)(nil)

func TestSessionServiceCreateSessionWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	repo := &mockSessionRepositoryForService{
		createSessionFunc: func(ctx context.Context, session core.UserSession) (core.UserSession, error) {
			return session, nil
		},
	}

	svc := NewSessionService(repo, nil, nil, &logger)

	session, err := svc.CreateSession(context.Background(), uuid.New(), "token-123", time.Now().Add(time.Hour), "127.0.0.1", "agent", "web")
	require.NoError(t, err)
	require.Equal(t, "token-123", session.SessionToken)
}

func TestSessionServiceRevokeSessionWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	repo := &mockSessionRepositoryForService{
		getSessionFunc: func(ctx context.Context, sessionToken string) (core.UserSession, error) {
			return core.UserSession{ID: uuid.New(), UserID: userID, SessionToken: sessionToken, ExpiresAt: time.Now().Add(time.Hour)}, nil
		},
		deleteSessionFunc: func(ctx context.Context, sessionToken string) error {
			return nil
		},
	}

	svc := NewSessionService(repo, nil, nil, &logger)

	err := svc.RevokeSession(context.Background(), "token-123", userID)
	require.NoError(t, err)
}

func TestSessionServiceGetSessionWithShortTokenDoesNotPanic(t *testing.T) {
	logger := zerolog.New(io.Discard)
	repo := &mockSessionRepositoryForService{
		getSessionFunc: func(ctx context.Context, sessionToken string) (core.UserSession, error) {
			return core.UserSession{}, domain.ErrSessionNotFound
		},
	}

	svc := NewSessionService(repo, nil, nil, &logger)

	_, err := svc.GetSession(context.Background(), "short")
	require.Error(t, err)
}
