package core

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// userQuerier interface defines only the methods needed by userRepository
type userQuerier interface {
	GetUserByID(ctx context.Context, id pgtype.UUID) (sqlc.GetUserByIDRow, error)
	UpdateUser(ctx context.Context, params sqlc.UpdateUserParams) error
	UpdateUserStatus(ctx context.Context, params sqlc.UpdateUserStatusParams) error
	DeleteUser(ctx context.Context, id pgtype.UUID) error
	ListUsersByRole(ctx context.Context, params sqlc.ListUsersByRoleParams) ([]sqlc.ListUsersByRoleRow, error)
	SearchUsers(ctx context.Context, params sqlc.SearchUsersParams) ([]sqlc.SearchUsersRow, error)
	CountUsersByRole(ctx context.Context, role string) (int64, error)
	UpdateUserEmail(ctx context.Context, params sqlc.UpdateUserEmailParams) error
	UpdateUserPhone(ctx context.Context, params sqlc.UpdateUserPhoneParams) error
	UpdateUserRole(ctx context.Context, params sqlc.UpdateUserRoleParams) error
	UpdateUserProfileCompletion(ctx context.Context, params sqlc.UpdateUserProfileCompletionParams) error
	UpdateUserConsents(ctx context.Context, params sqlc.UpdateUserConsentsParams) error
	BulkUpdateUserStatus(ctx context.Context, params sqlc.BulkUpdateUserStatusParams) error
	GetUsersByIDs(ctx context.Context, ids []pgtype.UUID) ([]sqlc.GetUsersByIDsRow, error)
}

// MockUserQuerier is a mock implementation of userQuerier
type MockUserQuerier struct {
	mock.Mock
}

func (m *MockUserQuerier) GetUserByID(ctx context.Context, id pgtype.UUID) (sqlc.GetUserByIDRow, error) {
	args := m.Called(ctx, id)
	return args.Get(0).(sqlc.GetUserByIDRow), args.Error(1)
}

func (m *MockUserQuerier) UpdateUser(ctx context.Context, params sqlc.UpdateUserParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockUserQuerier) UpdateUserStatus(ctx context.Context, params sqlc.UpdateUserStatusParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockUserQuerier) DeleteUser(ctx context.Context, id pgtype.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockUserQuerier) ListUsersByRole(ctx context.Context, params sqlc.ListUsersByRoleParams) ([]sqlc.ListUsersByRoleRow, error) {
	args := m.Called(ctx, params)
	return args.Get(0).([]sqlc.ListUsersByRoleRow), args.Error(1)
}

func (m *MockUserQuerier) SearchUsers(ctx context.Context, params sqlc.SearchUsersParams) ([]sqlc.SearchUsersRow, error) {
	args := m.Called(ctx, params)
	return args.Get(0).([]sqlc.SearchUsersRow), args.Error(1)
}

func (m *MockUserQuerier) CountUsersByRole(ctx context.Context, role string) (int64, error) {
	args := m.Called(ctx, role)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockUserQuerier) UpdateUserEmail(ctx context.Context, params sqlc.UpdateUserEmailParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockUserQuerier) UpdateUserPhone(ctx context.Context, params sqlc.UpdateUserPhoneParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockUserQuerier) UpdateUserRole(ctx context.Context, params sqlc.UpdateUserRoleParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockUserQuerier) UpdateUserProfileCompletion(ctx context.Context, params sqlc.UpdateUserProfileCompletionParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockUserQuerier) UpdateUserConsents(ctx context.Context, params sqlc.UpdateUserConsentsParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockUserQuerier) BulkUpdateUserStatus(ctx context.Context, params sqlc.BulkUpdateUserStatusParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockUserQuerier) GetUsersByIDs(ctx context.Context, ids []pgtype.UUID) ([]sqlc.GetUsersByIDsRow, error) {
	args := m.Called(ctx, ids)
	return args.Get(0).([]sqlc.GetUsersByIDsRow), args.Error(1)
}

// testUserRepository wraps userRepository but uses userQuerier interface
type testUserRepository struct {
	querier userQuerier
}

func (r *testUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error) {
	u, err := r.querier.GetUserByID(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		if err == domain.ErrUserNotFound {
			return core.User{}, domain.ErrUserNotFound
		}
		return core.User{}, testHandleError(err, "get user by id")
	}
	return testMapToUserFromGetByID(u), nil
}

func (r *testUserRepository) UpdateUser(ctx context.Context, user core.User) error {
	var email string
	if user.Email != nil {
		email = *user.Email
	}

	var phone pgtype.Text
	if user.Phone != nil {
		phone = pgtype.Text{String: *user.Phone, Valid: true}
	}

	err := r.querier.UpdateUser(ctx, sqlc.UpdateUserParams{
		ID:                          uuidToPgtypeUUID(user.ID),
		Email:                       email,
		Phone:                       phone,
		Role:                        user.Role,
		Status:                      pgtype.Text{String: user.Status, Valid: true},
		IsSmsOnly:                   pgtype.Bool{Bool: user.IsSMSOnly, Valid: true},
		SmsConsentGiven:             pgtype.Bool{Bool: user.SMSConsentGiven, Valid: true},
		PopiaConsentGiven:           pgtype.Bool{Bool: user.POPIAConsentGiven, Valid: true},
		ConsentDate:                 timePtrToPgtypeTimestamp(user.ConsentDate),
		ProfileCompletionPercentage: pgtype.Int4{Int32: int32(user.ProfileCompletionPct), Valid: true},
	})
	if err != nil {
		return testHandleError(err, "update user")
	}
	return nil
}

func (r *testUserRepository) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	err := r.querier.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtype.Text{String: "inactive", Valid: true},
	})
	if err != nil {
		return testHandleError(err, "deactivate user")
	}
	return nil
}

func (r *testUserRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	err := r.querier.DeleteUser(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		return testHandleError(err, "delete user")
	}
	return nil
}

func (r *testUserRepository) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	users, err := r.querier.ListUsersByRole(ctx, sqlc.ListUsersByRoleParams{
		Role:   role,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		return nil, testHandleError(err, "list users")
	}

	result := make([]core.User, len(users))
	for i, u := range users {
		result[i] = testMapToUserFromList(u)
	}
	return result, nil
}

func (r *testUserRepository) SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error) {
	users, err := r.querier.SearchUsers(ctx, sqlc.SearchUsersParams{
		Column1: query,
		Column2: role,
		Column3: status,
	})
	if err != nil {
		return nil, testHandleError(err, "search users")
	}

	result := make([]core.User, len(users))
	for i, u := range users {
		result[i] = testMapToUserFromSearch(u)
	}
	return result, nil
}

func (r *testUserRepository) CountUsers(ctx context.Context, role string) (int64, error) {
	count, err := r.querier.CountUsersByRole(ctx, role)
	if err != nil {
		return 0, testHandleError(err, "count users")
	}
	return count, nil
}

func (r *testUserRepository) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	err := r.querier.UpdateUserEmail(ctx, sqlc.UpdateUserEmailParams{
		ID:    uuidToPgtypeUUID(id),
		Email: email,
	})
	if err != nil {
		return testHandleError(err, "update user email")
	}
	return nil
}

func (r *testUserRepository) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	err := r.querier.UpdateUserPhone(ctx, sqlc.UpdateUserPhoneParams{
		ID:    uuidToPgtypeUUID(id),
		Phone: pgtype.Text{String: phone, Valid: true},
	})
	if err != nil {
		return testHandleError(err, "update user phone")
	}
	return nil
}

func (r *testUserRepository) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	err := r.querier.UpdateUserRole(ctx, sqlc.UpdateUserRoleParams{
		ID:   uuidToPgtypeUUID(id),
		Role: role,
	})
	if err != nil {
		return testHandleError(err, "update user role")
	}
	return nil
}

func (r *testUserRepository) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	err := r.querier.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtype.Text{String: status, Valid: true},
	})
	if err != nil {
		return testHandleError(err, "update user status")
	}
	return nil
}

func (r *testUserRepository) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	err := r.querier.UpdateUserProfileCompletion(ctx, sqlc.UpdateUserProfileCompletionParams{
		ID:                          uuidToPgtypeUUID(id),
		ProfileCompletionPercentage: pgtype.Int4{Int32: int32(percentage), Valid: true},
	})
	if err != nil {
		return testHandleError(err, "update user profile completion")
	}
	return nil
}

func (r *testUserRepository) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	err := r.querier.UpdateUserConsents(ctx, sqlc.UpdateUserConsentsParams{
		ID:                uuidToPgtypeUUID(id),
		SmsConsentGiven:   pgtype.Bool{Bool: smsConsent, Valid: true},
		PopiaConsentGiven: pgtype.Bool{Bool: popiaConsent, Valid: true},
		ConsentDate:       pgtype.Timestamp{Time: consentDate, Valid: true},
	})
	if err != nil {
		return testHandleError(err, "update user consents")
	}
	return nil
}

func (r *testUserRepository) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	pgIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgIDs[i] = uuidToPgtypeUUID(id)
	}

	err := r.querier.BulkUpdateUserStatus(ctx, sqlc.BulkUpdateUserStatusParams{
		Column1: pgIDs,
		Status:  pgtype.Text{String: status, Valid: true},
	})
	if err != nil {
		return testHandleError(err, "bulk update status")
	}
	return nil
}

func (r *testUserRepository) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error) {
	pgIDs := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		pgIDs[i] = uuidToPgtypeUUID(id)
	}

	users, err := r.querier.GetUsersByIDs(ctx, pgIDs)
	if err != nil {
		return nil, testHandleError(err, "get users by ids")
	}

	result := make([]core.User, len(users))
	for i, u := range users {
		result[i] = testMapToUserFromGetByIDs(u)
	}
	return result, nil
}

// Test mapping functions
func testMapToUserFromGetByID(u sqlc.GetUserByIDRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func testMapToUserFromList(u sqlc.ListUsersByRoleRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
	}
}

func testMapToUserFromSearch(u sqlc.SearchUsersRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
	}
}

func testMapToUserFromGetByIDs(u sqlc.GetUsersByIDsRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

// Helper functions
func newTestUserRepository(mockQuerier *MockUserQuerier) *testUserRepository {
	return &testUserRepository{querier: mockQuerier}
}

// Test GetUserByID
func TestUserRepository_GetUserByID(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	now := time.Now()

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		expectedRow := sqlc.GetUserByIDRow{
			ID:                          makePgtypeUUID(userID),
			Email:                       "test@example.com",
			Phone:                       makePgtypeText("+1234567890"),
			Role:                        "patient",
			Status:                      makePgtypeText("active"),
			IsVerified:                  makePgtypeBool(true),
			LastLogin:                   makePgtypeTimestamp(now),
			LoginCount:                  makePgtypeInt4(5),
			IsSmsOnly:                   makePgtypeBool(false),
			ProfileCompletionPercentage: makePgtypeInt4(80),
			CreatedAt:                   makePgtypeTimestamp(now),
			UpdatedAt:                   makePgtypeTimestamp(now),
		}

		mockQuerier.On("GetUserByID", ctx, makePgtypeUUID(userID)).Return(expectedRow, nil)

		user, err := repo.GetUserByID(ctx, userID)

		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, "test@example.com", *user.Email)
		assert.Equal(t, "+1234567890", *user.Phone)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("GetUserByID", ctx, makePgtypeUUID(userID)).
			Return(sqlc.GetUserByIDRow{}, domain.ErrUserNotFound)

		_, err := repo.GetUserByID(ctx, userID)

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateUser
func TestUserRepository_UpdateUser(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	now := time.Now()
	user := core.User{
		ID:                   userID,
		Email:                stringPtr("updated@example.com"),
		Phone:                stringPtr("+9876543210"),
		Role:                 "doctor",
		Status:               "active",
		IsSMSOnly:            true,
		SMSConsentGiven:      true,
		POPIAConsentGiven:    true,
		ConsentDate:          &now,
		ProfileCompletionPct: 90,
	}

	t.Run("successful update", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("UpdateUser", ctx, mock.MatchedBy(func(params sqlc.UpdateUserParams) bool {
			return params.ID.Bytes == userID &&
				params.Email == "updated@example.com" &&
				params.Phone.String == "+9876543210" &&
				params.Role == "doctor"
		})).Return(nil)

		err := repo.UpdateUser(ctx, user)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test DeactivateUser
func TestUserRepository_DeactivateUser(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	t.Run("successful deactivation", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("UpdateUserStatus", ctx, mock.MatchedBy(func(params sqlc.UpdateUserStatusParams) bool {
			return params.ID.Bytes == userID &&
				params.Status.String == "inactive"
		})).Return(nil)

		err := repo.DeactivateUser(ctx, userID)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test DeleteUser
func TestUserRepository_DeleteUser(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	t.Run("successful deletion", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("DeleteUser", ctx, makePgtypeUUID(userID)).Return(nil)

		err := repo.DeleteUser(ctx, userID)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test ListUsers
func TestUserRepository_ListUsers(t *testing.T) {
	ctx := context.Background()
	role := "patient"
	limit := 10
	offset := 0
	now := time.Now()

	t.Run("successful list", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		expectedRows := []sqlc.ListUsersByRoleRow{
			{
				ID:                          makePgtypeUUID(uuid.New()),
				Email:                       "user1@example.com",
				Phone:                       makePgtypeText("+1"),
				Role:                        "patient",
				Status:                      makePgtypeText("active"),
				IsVerified:                  makePgtypeBool(true),
				LastLogin:                   makePgtypeTimestamp(now),
				ProfileCompletionPercentage: makePgtypeInt4(100),
				CreatedAt:                   makePgtypeTimestamp(now),
			},
		}

		mockQuerier.On("ListUsersByRole", ctx, sqlc.ListUsersByRoleParams{
			Role:   role,
			Limit:  int32(limit),
			Offset: int32(offset),
		}).Return(expectedRows, nil)

		users, err := repo.ListUsers(ctx, role, limit, offset)

		require.NoError(t, err)
		assert.Len(t, users, 1)
		mockQuerier.AssertExpectations(t)
	})
}

// Test SearchUsers
func TestUserRepository_SearchUsers(t *testing.T) {
	ctx := context.Background()
	query := "test"
	role := "patient"
	status := "active"
	now := time.Now()

	t.Run("successful search", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		expectedRows := []sqlc.SearchUsersRow{
			{
				ID:                          makePgtypeUUID(uuid.New()),
				Email:                       "user1@example.com",
				Phone:                       makePgtypeText("+1"),
				Role:                        "patient",
				Status:                      makePgtypeText("active"),
				IsVerified:                  makePgtypeBool(true),
				LastLogin:                   makePgtypeTimestamp(now),
				ProfileCompletionPercentage: makePgtypeInt4(100),
				CreatedAt:                   makePgtypeTimestamp(now),
			},
		}

		mockQuerier.On("SearchUsers", ctx, sqlc.SearchUsersParams{
			Column1: query,
			Column2: role,
			Column3: status,
		}).Return(expectedRows, nil)

		users, err := repo.SearchUsers(ctx, query, role, status)

		require.NoError(t, err)
		assert.Len(t, users, 1)
		mockQuerier.AssertExpectations(t)
	})
}

// Test CountUsers
func TestUserRepository_CountUsers(t *testing.T) {
	ctx := context.Background()
	role := "patient"

	t.Run("successful count", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("CountUsersByRole", ctx, role).Return(int64(5), nil)

		count, err := repo.CountUsers(ctx, role)

		require.NoError(t, err)
		assert.Equal(t, int64(5), count)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateUserEmail
func TestUserRepository_UpdateUserEmail(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	email := "newemail@example.com"

	t.Run("successful update", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("UpdateUserEmail", ctx, sqlc.UpdateUserEmailParams{
			ID:    makePgtypeUUID(userID),
			Email: email,
		}).Return(nil)

		err := repo.UpdateUserEmail(ctx, userID, email)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateUserPhone
func TestUserRepository_UpdateUserPhone(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	phone := "+9876543210"

	t.Run("successful update", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("UpdateUserPhone", ctx, sqlc.UpdateUserPhoneParams{
			ID:    makePgtypeUUID(userID),
			Phone: makePgtypeText(phone),
		}).Return(nil)

		err := repo.UpdateUserPhone(ctx, userID, phone)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateUserRole
func TestUserRepository_UpdateUserRole(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	role := "admin"

	t.Run("successful update", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("UpdateUserRole", ctx, sqlc.UpdateUserRoleParams{
			ID:   makePgtypeUUID(userID),
			Role: role,
		}).Return(nil)

		err := repo.UpdateUserRole(ctx, userID, role)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateUserStatus
func TestUserRepository_UpdateUserStatus(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	status := "suspended"

	t.Run("successful update", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("UpdateUserStatus", ctx, sqlc.UpdateUserStatusParams{
			ID:     makePgtypeUUID(userID),
			Status: makePgtypeText(status),
		}).Return(nil)

		err := repo.UpdateUserStatus(ctx, userID, status)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateUserProfileCompletion
func TestUserRepository_UpdateUserProfileCompletion(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	percentage := 95

	t.Run("successful update", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("UpdateUserProfileCompletion", ctx, sqlc.UpdateUserProfileCompletionParams{
			ID:                          makePgtypeUUID(userID),
			ProfileCompletionPercentage: makePgtypeInt4(95),
		}).Return(nil)

		err := repo.UpdateUserProfileCompletion(ctx, userID, percentage)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateUserConsents
func TestUserRepository_UpdateUserConsents(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	smsConsent := true
	popiaConsent := true
	consentDate := time.Now()

	t.Run("successful update", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		mockQuerier.On("UpdateUserConsents", ctx, mock.MatchedBy(func(params sqlc.UpdateUserConsentsParams) bool {
			return params.ID.Bytes == userID &&
				params.SmsConsentGiven.Bool == smsConsent &&
				params.PopiaConsentGiven.Bool == popiaConsent
		})).Return(nil)

		err := repo.UpdateUserConsents(ctx, userID, smsConsent, popiaConsent, consentDate)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test BulkUpdateStatus
func TestUserRepository_BulkUpdateStatus(t *testing.T) {
	ctx := context.Background()
	userIDs := []uuid.UUID{uuid.New(), uuid.New()}
	status := "suspended"

	t.Run("successful bulk update", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		pgIDs := []pgtype.UUID{makePgtypeUUID(userIDs[0]), makePgtypeUUID(userIDs[1])}

		mockQuerier.On("BulkUpdateUserStatus", ctx, sqlc.BulkUpdateUserStatusParams{
			Column1: pgIDs,
			Status:  makePgtypeText(status),
		}).Return(nil)

		err := repo.BulkUpdateStatus(ctx, userIDs, status)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetUsersByIDs
func TestUserRepository_GetUsersByIDs(t *testing.T) {
	ctx := context.Background()
	userIDs := []uuid.UUID{uuid.New(), uuid.New()}
	now := time.Now()

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockUserQuerier)
		repo := newTestUserRepository(mockQuerier)

		pgIDs := []pgtype.UUID{makePgtypeUUID(userIDs[0]), makePgtypeUUID(userIDs[1])}

		expectedRows := []sqlc.GetUsersByIDsRow{
			{
				ID:                          makePgtypeUUID(userIDs[0]),
				Email:                       "user1@example.com",
				Phone:                       makePgtypeText("+1"),
				Role:                        "patient",
				Status:                      makePgtypeText("active"),
				IsVerified:                  makePgtypeBool(true),
				LastLogin:                   makePgtypeTimestamp(now),
				LoginCount:                  makePgtypeInt4(5),
				IsSmsOnly:                   makePgtypeBool(false),
				ProfileCompletionPercentage: makePgtypeInt4(100),
				CreatedAt:                   makePgtypeTimestamp(now),
				UpdatedAt:                   makePgtypeTimestamp(now),
			},
			{
				ID:                          makePgtypeUUID(userIDs[1]),
				Email:                       "user2@example.com",
				Phone:                       makePgtypeText("+2"),
				Role:                        "doctor",
				Status:                      makePgtypeText("active"),
				IsVerified:                  makePgtypeBool(true),
				LastLogin:                   makePgtypeTimestamp(now),
				LoginCount:                  makePgtypeInt4(3),
				IsSmsOnly:                   makePgtypeBool(true),
				ProfileCompletionPercentage: makePgtypeInt4(90),
				CreatedAt:                   makePgtypeTimestamp(now),
				UpdatedAt:                   makePgtypeTimestamp(now),
			},
		}

		mockQuerier.On("GetUsersByIDs", ctx, pgIDs).Return(expectedRows, nil)

		users, err := repo.GetUsersByIDs(ctx, userIDs)

		require.NoError(t, err)
		assert.Len(t, users, 2)
		assert.Equal(t, userIDs[0], users[0].ID)
		assert.Equal(t, userIDs[1], users[1].ID)
		mockQuerier.AssertExpectations(t)
	})
}
