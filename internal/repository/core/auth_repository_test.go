package core

import (
	"context"
	"errors"
	"fmt"
	"strings"
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

// authQuerier interface defines only the methods needed by authRepository
type authQuerier interface {
	CreateUser(ctx context.Context, params sqlc.CreateUserParams) (sqlc.CreateUserRow, error)
	GetUserByEmail(ctx context.Context, email string) (sqlc.GetUserByEmailRow, error)
	GetUserByPhone(ctx context.Context, phone pgtype.Text) (sqlc.GetUserByPhoneRow, error)
	GetUserByPhoneWithHash(ctx context.Context, phone pgtype.Text) (sqlc.GetUserByPhoneWithHashRow, error)
	GetUserByVerificationToken(ctx context.Context, token pgtype.Text) (sqlc.GetUserByVerificationTokenRow, error)
	GetUserByPasswordResetToken(ctx context.Context, token pgtype.Text) (sqlc.GetUserByPasswordResetTokenRow, error)
	VerifyUser(ctx context.Context, id pgtype.UUID) error
	SetVerificationToken(ctx context.Context, params sqlc.SetVerificationTokenParams) error
	SetPasswordResetToken(ctx context.Context, params sqlc.SetPasswordResetTokenParams) error
	UpdateUserPassword(ctx context.Context, params sqlc.UpdateUserPasswordParams) error
	UpdateUserStatus(ctx context.Context, params sqlc.UpdateUserStatusParams) error
	UpdateUserLastLogin(ctx context.Context, id pgtype.UUID) error
}

// MockAuthQuerier is a mock implementation of authQuerier
type MockAuthQuerier struct {
	mock.Mock
}

func (m *MockAuthQuerier) CreateUser(ctx context.Context, params sqlc.CreateUserParams) (sqlc.CreateUserRow, error) {
	args := m.Called(ctx, params)
	return args.Get(0).(sqlc.CreateUserRow), args.Error(1)
}

func (m *MockAuthQuerier) GetUserByEmail(ctx context.Context, email string) (sqlc.GetUserByEmailRow, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(sqlc.GetUserByEmailRow), args.Error(1)
}

func (m *MockAuthQuerier) GetUserByPhone(ctx context.Context, phone pgtype.Text) (sqlc.GetUserByPhoneRow, error) {
	args := m.Called(ctx, phone)
	return args.Get(0).(sqlc.GetUserByPhoneRow), args.Error(1)
}

func (m *MockAuthQuerier) GetUserByPhoneWithHash(ctx context.Context, phone pgtype.Text) (sqlc.GetUserByPhoneWithHashRow, error) {
	args := m.Called(ctx, phone)
	return args.Get(0).(sqlc.GetUserByPhoneWithHashRow), args.Error(1)
}

func (m *MockAuthQuerier) GetUserByVerificationToken(ctx context.Context, token pgtype.Text) (sqlc.GetUserByVerificationTokenRow, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(sqlc.GetUserByVerificationTokenRow), args.Error(1)
}

func (m *MockAuthQuerier) GetUserByPasswordResetToken(ctx context.Context, token pgtype.Text) (sqlc.GetUserByPasswordResetTokenRow, error) {
	args := m.Called(ctx, token)
	return args.Get(0).(sqlc.GetUserByPasswordResetTokenRow), args.Error(1)
}

func (m *MockAuthQuerier) VerifyUser(ctx context.Context, id pgtype.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

func (m *MockAuthQuerier) SetVerificationToken(ctx context.Context, params sqlc.SetVerificationTokenParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockAuthQuerier) SetPasswordResetToken(ctx context.Context, params sqlc.SetPasswordResetTokenParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockAuthQuerier) UpdateUserPassword(ctx context.Context, params sqlc.UpdateUserPasswordParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockAuthQuerier) UpdateUserStatus(ctx context.Context, params sqlc.UpdateUserStatusParams) error {
	args := m.Called(ctx, params)
	return args.Error(0)
}

func (m *MockAuthQuerier) UpdateUserLastLogin(ctx context.Context, id pgtype.UUID) error {
	args := m.Called(ctx, id)
	return args.Error(0)
}

// testAuthRepository wraps authRepository but uses authQuerier interface
type testAuthRepository struct {
	querier authQuerier
}

func (r *testAuthRepository) CreateUser(ctx context.Context, user core.User, passwordHash string) (core.User, error) {
	var email string
	if user.Email != nil {
		email = *user.Email
	}

	var phone pgtype.Text
	if user.Phone != nil {
		phone = pgtype.Text{String: *user.Phone, Valid: true}
	}

	created, err := r.querier.CreateUser(ctx, sqlc.CreateUserParams{
		Email:             email,
		Phone:             phone,
		PasswordHash:      pgtype.Text{String: passwordHash, Valid: true},
		Role:              user.Role,
		Status:            pgtype.Text{String: user.Status, Valid: true},
		IsSmsOnly:         pgtype.Bool{Bool: user.IsSMSOnly, Valid: true},
		SmsConsentGiven:   pgtype.Bool{Bool: user.SMSConsentGiven, Valid: true},
		PopiaConsentGiven: pgtype.Bool{Bool: user.POPIAConsentGiven, Valid: true},
		ConsentDate:       timePtrToPgtypeTimestamp(user.ConsentDate),
	})
	if err != nil {
		return core.User{}, testHandleError(err, "create user")
	}

	return testMapToUserFromCreate(created), nil
}

func (r *testAuthRepository) GetUserByEmail(ctx context.Context, email string) (core.User, string, error) {
	u, err := r.querier.GetUserByEmail(ctx, email)
	if err != nil {
		if err == domain.ErrUserNotFound {
			return core.User{}, "", domain.ErrUserNotFound
		}
		return core.User{}, "", testHandleError(err, "get user by email")
	}

	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return testMapToUserFromGetByEmail(u), passwordHash, nil
}

func (r *testAuthRepository) GetUserByPhone(ctx context.Context, phone string) (core.User, error) {
	u, err := r.querier.GetUserByPhone(ctx, pgtype.Text{String: phone, Valid: true})
	if err != nil {
		if err == domain.ErrUserNotFound {
			return core.User{}, domain.ErrUserNotFound
		}
		return core.User{}, testHandleError(err, "get user by phone")
	}

	return testMapToUserFromGetByPhone(u), nil
}

func (r *testAuthRepository) GetUserByPhoneWithHash(ctx context.Context, phone string) (core.User, string, error) {
	u, err := r.querier.GetUserByPhoneWithHash(ctx, pgtype.Text{String: phone, Valid: true})
	if err != nil {
		if err == domain.ErrUserNotFound {
			return core.User{}, "", domain.ErrUserNotFound
		}
		return core.User{}, "", testHandleError(err, "get user by phone with hash")
	}

	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return testMapToUserFromGetByPhoneWithHash(u), passwordHash, nil
}

func (r *testAuthRepository) GetUserByVerificationToken(ctx context.Context, token string) (core.User, string, error) {
	u, err := r.querier.GetUserByVerificationToken(ctx, pgtype.Text{String: token, Valid: true})
	if err != nil {
		if err == domain.ErrUserNotFound {
			return core.User{}, "", domain.ErrUserNotFound
		}
		return core.User{}, "", testHandleError(err, "get user by verification token")
	}

	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return testMapToUserFromGetByVerificationToken(u), passwordHash, nil
}

func (r *testAuthRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (core.User, string, error) {
	u, err := r.querier.GetUserByPasswordResetToken(ctx, pgtype.Text{String: token, Valid: true})
	if err != nil {
		if err == domain.ErrUserNotFound {
			return core.User{}, "", domain.ErrUserNotFound
		}
		return core.User{}, "", testHandleError(err, "get user by password reset token")
	}

	passwordHash := ""
	if u.PasswordHash.Valid {
		passwordHash = u.PasswordHash.String
	}

	return testMapToUserFromGetByPasswordResetToken(u), passwordHash, nil
}

func (r *testAuthRepository) VerifyUser(ctx context.Context, id uuid.UUID) error {
	err := r.querier.VerifyUser(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		return testHandleError(err, "verify user")
	}
	return nil
}

func (r *testAuthRepository) SetVerificationToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	err := r.querier.SetVerificationToken(ctx, sqlc.SetVerificationTokenParams{
		ID:                  uuidToPgtypeUUID(id),
		VerificationToken:   pgtype.Text{String: token, Valid: true},
		VerificationExpires: pgtype.Timestamp{Time: expires, Valid: true},
	})
	if err != nil {
		return testHandleError(err, "set verification token")
	}
	return nil
}

func (r *testAuthRepository) SetPasswordResetToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	err := r.querier.SetPasswordResetToken(ctx, sqlc.SetPasswordResetTokenParams{
		ID:                   uuidToPgtypeUUID(id),
		ResetPasswordToken:   pgtype.Text{String: token, Valid: true},
		ResetPasswordExpires: pgtype.Timestamp{Time: expires, Valid: true},
	})
	if err != nil {
		return testHandleError(err, "set password reset token")
	}
	return nil
}

func (r *testAuthRepository) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	err := r.querier.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		ID:           uuidToPgtypeUUID(id),
		PasswordHash: pgtype.Text{String: passwordHash, Valid: true},
	})
	if err != nil {
		return testHandleError(err, "update user password")
	}
	return nil
}

func (r *testAuthRepository) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	err := r.querier.UpdateUserStatus(ctx, sqlc.UpdateUserStatusParams{
		ID:     uuidToPgtypeUUID(id),
		Status: pgtype.Text{String: status, Valid: true},
	})
	if err != nil {
		return testHandleError(err, "update user status")
	}
	return nil
}

func (r *testAuthRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	err := r.querier.UpdateUserLastLogin(ctx, uuidToPgtypeUUID(id))
	if err != nil {
		return testHandleError(err, "update last login")
	}
	return nil
}

// Test helper functions - mirrors the production code
func testHandleError(err error, operation string) error {
	var pgErr *mockPgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code() {
		case "23505": // unique_violation
			if strings.Contains(pgErr.ConstraintName(), "email") {
				return domain.ErrDuplicateEmail
			}
			if strings.Contains(pgErr.ConstraintName(), "phone") {
				return domain.ErrDuplicatePhone
			}
			return fmt.Errorf("duplicate constraint violation: %w", err)
		case "23503": // foreign_key_violation
			return fmt.Errorf("foreign key violation: %w", err)
		case "23514": // check_violation
			return fmt.Errorf("check constraint violation: %w", err)
		}
	}
	return fmt.Errorf("%s failed: %w", operation, err)
}

func testMapToUserFromCreate(u sqlc.CreateUserRow) core.User {
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
		SMSConsentGiven:      false,
		POPIAConsentGiven:    false,
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func testMapToUserFromGetByVerificationToken(u sqlc.GetUserByVerificationTokenRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		VerificationToken:    pgtypeTextToStringPtr(u.VerificationToken),
		VerificationExpires:  pgtypeTimestampToTimePtr(u.VerificationExpires),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func testMapToUserFromGetByPasswordResetToken(u sqlc.GetUserByPasswordResetTokenRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		ResetPasswordToken:   pgtypeTextToStringPtr(u.ResetPasswordToken),
		ResetPasswordExpires: pgtypeTimestampToTimePtr(u.ResetPasswordExpires),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func testMapToUserFromGetByEmail(u sqlc.GetUserByEmailRow) core.User {
	return core.User{
		ID:                   pgtypeUUIDToUUID(u.ID),
		Email:                stringToStringPtr(u.Email),
		Phone:                pgtypeTextToStringPtr(u.Phone),
		Role:                 u.Role,
		Status:               pgtypeTextToString(u.Status),
		IsVerified:           pgtypeBoolToBool(u.IsVerified),
		VerificationToken:    pgtypeTextToStringPtr(u.VerificationToken),
		VerificationExpires:  pgtypeTimestampToTimePtr(u.VerificationExpires),
		LastLogin:            pgtypeTimestampToTimePtr(u.LastLogin),
		LoginCount:           int(u.LoginCount.Int32),
		IsSMSOnly:            pgtypeBoolToBool(u.IsSmsOnly),
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func testMapToUserFromGetByPhone(u sqlc.GetUserByPhoneRow) core.User {
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
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

func testMapToUserFromGetByPhoneWithHash(u sqlc.GetUserByPhoneWithHashRow) core.User {
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
		SMSConsentGiven:      pgtypeBoolToBool(u.SmsConsentGiven),
		POPIAConsentGiven:    pgtypeBoolToBool(u.PopiaConsentGiven),
		ProfileCompletionPct: int(u.ProfileCompletionPercentage.Int32),
		CreatedAt:            u.CreatedAt.Time,
		UpdatedAt:            u.UpdatedAt.Time,
	}
}

// Test Helper Functions
func stringPtr(s string) *string {
	return &s
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func makePgtypeUUID(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func makePgtypeText(s string) pgtype.Text {
	return pgtype.Text{String: s, Valid: true}
}

func makePgtypeBool(b bool) pgtype.Bool {
	return pgtype.Bool{Bool: b, Valid: true}
}

func makePgtypeTimestamp(t time.Time) pgtype.Timestamp {
	return pgtype.Timestamp{Time: t, Valid: true}
}

func makePgtypeInt4(i int32) pgtype.Int4 {
	return pgtype.Int4{Int32: i, Valid: true}
}

// newTestAuthRepository creates a repository with a mock querier
func newTestAuthRepository(mockQuerier *MockAuthQuerier) *testAuthRepository {
	return &testAuthRepository{
		querier: mockQuerier,
	}
}

// Test CreateUser
func TestAuthRepository_CreateUser(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.New()
	email := "test@example.com"
	passwordHash := "$2a$10$hashedpassword"

	t.Run("successful user creation with email", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		user := core.User{
			Email:             stringPtr(email),
			Role:              "patient",
			Status:            "active",
			IsSMSOnly:         false,
			SMSConsentGiven:   true,
			POPIAConsentGiven: true,
			ConsentDate:       &now,
		}

		expectedRow := sqlc.CreateUserRow{
			ID:                          makePgtypeUUID(userID),
			Email:                       email,
			Phone:                       pgtype.Text{},
			Role:                        "patient",
			Status:                      makePgtypeText("active"),
			IsVerified:                  makePgtypeBool(false),
			LastLogin:                   pgtype.Timestamp{},
			LoginCount:                  makePgtypeInt4(0),
			IsSmsOnly:                   makePgtypeBool(false),
			ProfileCompletionPercentage: makePgtypeInt4(0),
			CreatedAt:                   makePgtypeTimestamp(now),
			UpdatedAt:                   makePgtypeTimestamp(now),
		}

		mockQuerier.On("CreateUser", ctx, mock.MatchedBy(func(params sqlc.CreateUserParams) bool {
			return params.Email == email &&
				params.Role == "patient" &&
				params.PasswordHash.String == passwordHash
		})).Return(expectedRow, nil)

		created, err := repo.CreateUser(ctx, user, passwordHash)

		require.NoError(t, err)
		assert.Equal(t, userID, created.ID)
		assert.Equal(t, stringPtr(email), created.Email)
		assert.Equal(t, "patient", created.Role)
		assert.Equal(t, "active", created.Status)
		mockQuerier.AssertExpectations(t)
	})
}

// Test VerifyUser
func TestAuthRepository_VerifyUser(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	t.Run("successful verification", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("VerifyUser", ctx, makePgtypeUUID(userID)).Return(nil)

		err := repo.VerifyUser(ctx, userID)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("verification error", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("VerifyUser", ctx, makePgtypeUUID(userID)).
			Return(assert.AnError)

		err := repo.VerifyUser(ctx, userID)

		require.Error(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test SetVerificationToken
func TestAuthRepository_SetVerificationToken(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	token := "new-verification-token"
	expires := time.Now().Add(24 * time.Hour)

	t.Run("successful token set", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("SetVerificationToken", ctx, mock.MatchedBy(func(params sqlc.SetVerificationTokenParams) bool {
			return params.ID.Bytes == userID &&
				params.VerificationToken.String == token &&
				params.VerificationExpires.Valid
		})).Return(nil)

		err := repo.SetVerificationToken(ctx, userID, token, expires)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test SetPasswordResetToken
func TestAuthRepository_SetPasswordResetToken(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	token := "reset-password-token"
	expires := time.Now().Add(1 * time.Hour)

	t.Run("successful token set", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("SetPasswordResetToken", ctx, mock.MatchedBy(func(params sqlc.SetPasswordResetTokenParams) bool {
			return params.ID.Bytes == userID &&
				params.ResetPasswordToken.String == token &&
				params.ResetPasswordExpires.Valid
		})).Return(nil)

		err := repo.SetPasswordResetToken(ctx, userID, token, expires)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateUserPassword
func TestAuthRepository_UpdateUserPassword(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()
	newPasswordHash := "$2a$10$newhashedpassword"

	t.Run("successful password update", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("UpdateUserPassword", ctx, mock.MatchedBy(func(params sqlc.UpdateUserPasswordParams) bool {
			return params.ID.Bytes == userID &&
				params.PasswordHash.String == newPasswordHash
		})).Return(nil)

		err := repo.UpdateUserPassword(ctx, userID, newPasswordHash)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateUserStatus
func TestAuthRepository_UpdateUserStatus(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	t.Run("successful status update", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("UpdateUserStatus", ctx, mock.MatchedBy(func(params sqlc.UpdateUserStatusParams) bool {
			return params.ID.Bytes == userID &&
				params.Status.String == "suspended"
		})).Return(nil)

		err := repo.UpdateUserStatus(ctx, userID, "suspended")

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test UpdateLastLogin
func TestAuthRepository_UpdateLastLogin(t *testing.T) {
	ctx := context.Background()
	userID := uuid.New()

	t.Run("successful last login update", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("UpdateUserLastLogin", ctx, makePgtypeUUID(userID)).Return(nil)

		err := repo.UpdateLastLogin(ctx, userID)

		require.NoError(t, err)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetUserByEmail
func TestAuthRepository_GetUserByEmail(t *testing.T) {
	ctx := context.Background()
	email := "test@example.com"
	userID := uuid.New()
	passwordHash := "$2a$10$hashedpassword"
	now := time.Now()

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		expectedRow := sqlc.GetUserByEmailRow{
			ID:                          makePgtypeUUID(userID),
			Email:                       email,
			Phone:                       pgtype.Text{},
			PasswordHash:                makePgtypeText(passwordHash),
			Role:                        "patient",
			Status:                      makePgtypeText("active"),
			IsVerified:                  makePgtypeBool(true),
			VerificationToken:           pgtype.Text{},
			VerificationExpires:         pgtype.Timestamp{},
			LastLogin:                   makePgtypeTimestamp(now),
			LoginCount:                  makePgtypeInt4(5),
			IsSmsOnly:                   makePgtypeBool(false),
			SmsConsentGiven:             makePgtypeBool(true),
			PopiaConsentGiven:           makePgtypeBool(true),
			ProfileCompletionPercentage: makePgtypeInt4(80),
			CreatedAt:                   makePgtypeTimestamp(now),
			UpdatedAt:                   makePgtypeTimestamp(now),
		}

		mockQuerier.On("GetUserByEmail", ctx, email).Return(expectedRow, nil)

		user, hash, err := repo.GetUserByEmail(ctx, email)

		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, stringPtr(email), user.Email)
		assert.Equal(t, passwordHash, hash)
		assert.Equal(t, "patient", user.Role)
		assert.Equal(t, "active", user.Status)
		assert.True(t, user.IsVerified)
		assert.Equal(t, 5, user.LoginCount)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("GetUserByEmail", ctx, email).
			Return(sqlc.GetUserByEmailRow{}, domain.ErrUserNotFound)

		_, _, err := repo.GetUserByEmail(ctx, email)

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetUserByPhone
func TestAuthRepository_GetUserByPhone(t *testing.T) {
	ctx := context.Background()
	phone := "+27123456789"
	userID := uuid.New()
	now := time.Now()

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		expectedRow := sqlc.GetUserByPhoneRow{
			ID:                          makePgtypeUUID(userID),
			Email:                       "",
			Phone:                       makePgtypeText(phone),
			Role:                        "patient",
			Status:                      makePgtypeText("active"),
			IsVerified:                  makePgtypeBool(true),
			LastLogin:                   makePgtypeTimestamp(now),
			LoginCount:                  makePgtypeInt4(3),
			IsSmsOnly:                   makePgtypeBool(true),
			SmsConsentGiven:             makePgtypeBool(true),
			PopiaConsentGiven:           makePgtypeBool(true),
			ProfileCompletionPercentage: makePgtypeInt4(60),
			CreatedAt:                   makePgtypeTimestamp(now),
			UpdatedAt:                   makePgtypeTimestamp(now),
		}

		mockQuerier.On("GetUserByPhone", ctx, makePgtypeText(phone)).Return(expectedRow, nil)

		user, err := repo.GetUserByPhone(ctx, phone)

		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, stringPtr(phone), user.Phone)
		assert.True(t, user.IsSMSOnly)
		assert.True(t, user.SMSConsentGiven)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("user not found", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("GetUserByPhone", ctx, makePgtypeText(phone)).
			Return(sqlc.GetUserByPhoneRow{}, domain.ErrUserNotFound)

		_, err := repo.GetUserByPhone(ctx, phone)

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetUserByPhoneWithHash
func TestAuthRepository_GetUserByPhoneWithHash(t *testing.T) {
	ctx := context.Background()
	phone := "+27123456789"
	userID := uuid.New()
	passwordHash := "$2a$10$hashedpassword"
	now := time.Now()

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		expectedRow := sqlc.GetUserByPhoneWithHashRow{
			ID:                          makePgtypeUUID(userID),
			Email:                       "",
			Phone:                       makePgtypeText(phone),
			PasswordHash:                makePgtypeText(passwordHash),
			Role:                        "patient",
			Status:                      makePgtypeText("active"),
			IsVerified:                  makePgtypeBool(true),
			LastLogin:                   makePgtypeTimestamp(now),
			LoginCount:                  makePgtypeInt4(2),
			IsSmsOnly:                   makePgtypeBool(true),
			SmsConsentGiven:             makePgtypeBool(true),
			PopiaConsentGiven:           makePgtypeBool(true),
			ProfileCompletionPercentage: makePgtypeInt4(50),
			CreatedAt:                   makePgtypeTimestamp(now),
			UpdatedAt:                   makePgtypeTimestamp(now),
		}

		mockQuerier.On("GetUserByPhoneWithHash", ctx, makePgtypeText(phone)).Return(expectedRow, nil)

		user, hash, err := repo.GetUserByPhoneWithHash(ctx, phone)

		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, stringPtr(phone), user.Phone)
		assert.Equal(t, passwordHash, hash)
		assert.True(t, user.IsSMSOnly)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetUserByVerificationToken
func TestAuthRepository_GetUserByVerificationToken(t *testing.T) {
	ctx := context.Background()
	token := "verification-token-123"
	userID := uuid.New()
	email := "test@example.com"
	passwordHash := "$2a$10$hashedpassword"
	now := time.Now()
	expires := now.Add(24 * time.Hour)

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		expectedRow := sqlc.GetUserByVerificationTokenRow{
			ID:                          makePgtypeUUID(userID),
			Email:                       email,
			Phone:                       pgtype.Text{},
			PasswordHash:                makePgtypeText(passwordHash),
			Role:                        "patient",
			Status:                      makePgtypeText("pending"),
			IsVerified:                  makePgtypeBool(false),
			VerificationToken:           makePgtypeText(token),
			VerificationExpires:         makePgtypeTimestamp(expires),
			LastLogin:                   pgtype.Timestamp{},
			LoginCount:                  makePgtypeInt4(0),
			IsSmsOnly:                   makePgtypeBool(false),
			SmsConsentGiven:             makePgtypeBool(true),
			PopiaConsentGiven:           makePgtypeBool(true),
			ProfileCompletionPercentage: makePgtypeInt4(20),
			CreatedAt:                   makePgtypeTimestamp(now),
			UpdatedAt:                   makePgtypeTimestamp(now),
		}

		mockQuerier.On("GetUserByVerificationToken", ctx, makePgtypeText(token)).Return(expectedRow, nil)

		user, hash, err := repo.GetUserByVerificationToken(ctx, token)

		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, passwordHash, hash)
		assert.False(t, user.IsVerified)
		assert.NotNil(t, user.VerificationToken)
		assert.Equal(t, token, *user.VerificationToken)
		assert.NotNil(t, user.VerificationExpires)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("token not found", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("GetUserByVerificationToken", ctx, makePgtypeText(token)).
			Return(sqlc.GetUserByVerificationTokenRow{}, domain.ErrUserNotFound)

		_, _, err := repo.GetUserByVerificationToken(ctx, token)

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
		mockQuerier.AssertExpectations(t)
	})
}

// Test GetUserByPasswordResetToken
func TestAuthRepository_GetUserByPasswordResetToken(t *testing.T) {
	ctx := context.Background()
	token := "reset-token-456"
	userID := uuid.New()
	email := "test@example.com"
	passwordHash := "$2a$10$hashedpassword"
	now := time.Now()
	expires := now.Add(1 * time.Hour)

	t.Run("successful retrieval", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		expectedRow := sqlc.GetUserByPasswordResetTokenRow{
			ID:                          makePgtypeUUID(userID),
			Email:                       email,
			Phone:                       pgtype.Text{},
			PasswordHash:                makePgtypeText(passwordHash),
			Role:                        "patient",
			Status:                      makePgtypeText("active"),
			IsVerified:                  makePgtypeBool(true),
			ResetPasswordToken:          makePgtypeText(token),
			ResetPasswordExpires:        makePgtypeTimestamp(expires),
			LastLogin:                   makePgtypeTimestamp(now),
			LoginCount:                  makePgtypeInt4(10),
			IsSmsOnly:                   makePgtypeBool(false),
			SmsConsentGiven:             makePgtypeBool(true),
			PopiaConsentGiven:           makePgtypeBool(true),
			ProfileCompletionPercentage: makePgtypeInt4(100),
			CreatedAt:                   makePgtypeTimestamp(now),
			UpdatedAt:                   makePgtypeTimestamp(now),
		}

		mockQuerier.On("GetUserByPasswordResetToken", ctx, makePgtypeText(token)).Return(expectedRow, nil)

		user, hash, err := repo.GetUserByPasswordResetToken(ctx, token)

		require.NoError(t, err)
		assert.Equal(t, userID, user.ID)
		assert.Equal(t, passwordHash, hash)
		assert.NotNil(t, user.ResetPasswordToken)
		assert.Equal(t, token, *user.ResetPasswordToken)
		assert.NotNil(t, user.ResetPasswordExpires)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("token not found", func(t *testing.T) {
		mockQuerier := new(MockAuthQuerier)
		repo := newTestAuthRepository(mockQuerier)

		mockQuerier.On("GetUserByPasswordResetToken", ctx, makePgtypeText(token)).
			Return(sqlc.GetUserByPasswordResetTokenRow{}, domain.ErrUserNotFound)

		_, _, err := repo.GetUserByPasswordResetToken(ctx, token)

		require.Error(t, err)
		assert.ErrorIs(t, err, domain.ErrUserNotFound)
		mockQuerier.AssertExpectations(t)
	})
}

// Mock PgError for testing constraint violations
type mockPgError struct {
	code       string
	constraint string
}

func (e *mockPgError) Error() string {
	return "mock pg error"
}

func (e *mockPgError) SQLState() string {
	return e.code
}

// Implement additional methods to satisfy pgconn.PgError interface
func (e *mockPgError) Severity() string        { return "" }
func (e *mockPgError) Code() string            { return e.code }
func (e *mockPgError) Message() string         { return "mock error" }
func (e *mockPgError) Detail() string          { return "" }
func (e *mockPgError) Hint() string            { return "" }
func (e *mockPgError) Position() int32         { return 0 }
func (e *mockPgError) InternalPosition() int32 { return 0 }
func (e *mockPgError) InternalQuery() string   { return "" }
func (e *mockPgError) Where() string           { return "" }
func (e *mockPgError) SchemaName() string      { return "" }
func (e *mockPgError) TableName() string       { return "" }
func (e *mockPgError) ColumnName() string      { return "" }
func (e *mockPgError) DataTypeName() string    { return "" }
func (e *mockPgError) ConstraintName() string  { return e.constraint }
func (e *mockPgError) File() string            { return "" }
func (e *mockPgError) Line() int32             { return 0 }
func (e *mockPgError) Routine() string         { return "" }

// Helper to create mock PgError
func newMockPgError(code, constraint string) error {
	return &mockPgError{code: code, constraint: constraint}
}
