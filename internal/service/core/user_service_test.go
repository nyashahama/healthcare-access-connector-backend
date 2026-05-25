package core

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	domaincore "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type mockUserRepositoryForUserService struct {
	getUserByIDFunc    func(ctx context.Context, id uuid.UUID) (domaincore.User, error)
	updateUserEmailFunc func(ctx context.Context, id uuid.UUID, email string) error
}

func (m *mockUserRepositoryForUserService) GetUserByID(ctx context.Context, id uuid.UUID) (domaincore.User, error) {
	return m.getUserByIDFunc(ctx, id)
}

func (m *mockUserRepositoryForUserService) UpdateUser(ctx context.Context, user domaincore.User) error {
	return nil
}

func (m *mockUserRepositoryForUserService) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepositoryForUserService) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepositoryForUserService) ListUsers(ctx context.Context, role string, limit, offset int) ([]domaincore.User, error) {
	return nil, nil
}

func (m *mockUserRepositoryForUserService) SearchUsers(ctx context.Context, query string, role string, status string) ([]domaincore.User, error) {
	return nil, nil
}

func (m *mockUserRepositoryForUserService) CountUsers(ctx context.Context, role string) (int64, error) {
	return 0, nil
}

func (m *mockUserRepositoryForUserService) GetUserProfile(ctx context.Context, userID uuid.UUID) (domaincore.User, patients.PatientProfile, error) {
	return domaincore.User{}, patients.PatientProfile{}, nil
}

func (m *mockUserRepositoryForUserService) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	if m.updateUserEmailFunc != nil {
		return m.updateUserEmailFunc(ctx, id, email)
	}
	return nil
}

func (m *mockUserRepositoryForUserService) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	return nil
}

func (m *mockUserRepositoryForUserService) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	return nil
}

func (m *mockUserRepositoryForUserService) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepositoryForUserService) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	return nil
}

func (m *mockUserRepositoryForUserService) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	return nil
}

func (m *mockUserRepositoryForUserService) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepositoryForUserService) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]domaincore.User, error) {
	return nil, nil
}

var _ repository.UserRepository = (*mockUserRepositoryForUserService)(nil)

func TestUserServiceGetUserByIDWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	expected := domaincore.User{
		ID:   userID,
		Role: "patient",
	}

	svc := &userService{
		userRepo: &mockUserRepositoryForUserService{
			getUserByIDFunc: func(ctx context.Context, got uuid.UUID) (domaincore.User, error) {
				require.Equal(t, userID, got)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetUserByID(context.Background(), userID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
}

func TestUserServiceGetUserProfileWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	expected := domaincore.User{
		ID:   userID,
		Role: "system_admin",
	}

	svc := &userService{
		userRepo: &mockUserRepositoryForUserService{
			getUserByIDFunc: func(ctx context.Context, got uuid.UUID) (domaincore.User, error) {
				require.Equal(t, userID, got)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	user, profile, err := svc.GetUserProfile(context.Background(), userID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, user.ID)
	require.Equal(t, patients.PatientProfile{}, profile)
}

func TestUserServiceUpdateUserEmailWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	email := "user@example.com"

	svc := &userService{
		userRepo: &mockUserRepositoryForUserService{
			updateUserEmailFunc: func(ctx context.Context, got uuid.UUID, gotEmail string) error {
				require.Equal(t, userID, got)
				require.Equal(t, email, gotEmail)
				return nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	err := svc.UpdateUserEmail(context.Background(), userID, email)
	require.NoError(t, err)
}
