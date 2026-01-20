package core

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/stretchr/testify/assert"
)

// Helper function to assert equality between two core.User structs
func assertUserEqual(t *testing.T, expected, got core.User, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected.ID, got.ID, msgAndArgs...)
	if expected.Email == nil {
		assert.Nil(t, got.Email, msgAndArgs...)
	} else {
		assert.NotNil(t, got.Email, msgAndArgs...)
		assert.Equal(t, *expected.Email, *got.Email, msgAndArgs...)
	}
	if expected.Phone == nil {
		assert.Nil(t, got.Phone, msgAndArgs...)
	} else {
		assert.NotNil(t, got.Phone, msgAndArgs...)
		assert.Equal(t, *expected.Phone, *got.Phone, msgAndArgs...)
	}
	assert.Equal(t, expected.Role, got.Role, msgAndArgs...)
	assert.Equal(t, expected.Status, got.Status, msgAndArgs...)
	assert.Equal(t, expected.IsVerified, got.IsVerified, msgAndArgs...)
	if expected.VerificationToken == nil {
		assert.Nil(t, got.VerificationToken, msgAndArgs...)
	} else {
		assert.NotNil(t, got.VerificationToken, msgAndArgs...)
		assert.Equal(t, *expected.VerificationToken, *got.VerificationToken, msgAndArgs...)
	}
	if expected.VerificationExpires == nil {
		assert.Nil(t, got.VerificationExpires, msgAndArgs...)
	} else {
		assert.NotNil(t, got.VerificationExpires, msgAndArgs...)
		assert.True(t, expected.VerificationExpires.Equal(*got.VerificationExpires), msgAndArgs...)
	}
	if expected.ResetPasswordToken == nil {
		assert.Nil(t, got.ResetPasswordToken, msgAndArgs...)
	} else {
		assert.NotNil(t, got.ResetPasswordToken, msgAndArgs...)
		assert.Equal(t, *expected.ResetPasswordToken, *got.ResetPasswordToken, msgAndArgs...)
	}
	if expected.ResetPasswordExpires == nil {
		assert.Nil(t, got.ResetPasswordExpires, msgAndArgs...)
	} else {
		assert.NotNil(t, got.ResetPasswordExpires, msgAndArgs...)
		assert.True(t, expected.ResetPasswordExpires.Equal(*got.ResetPasswordExpires), msgAndArgs...)
	}
	if expected.LastLogin == nil {
		assert.Nil(t, got.LastLogin, msgAndArgs...)
	} else {
		assert.NotNil(t, got.LastLogin, msgAndArgs...)
		assert.True(t, expected.LastLogin.Equal(*got.LastLogin), msgAndArgs...)
	}
	assert.Equal(t, expected.LoginCount, got.LoginCount, msgAndArgs...)
	assert.Equal(t, expected.IsSMSOnly, got.IsSMSOnly, msgAndArgs...)
	assert.Equal(t, expected.SMSConsentGiven, got.SMSConsentGiven, msgAndArgs...)
	assert.Equal(t, expected.POPIAConsentGiven, got.POPIAConsentGiven, msgAndArgs...)
	assert.Equal(t, expected.ProfileCompletionPct, got.ProfileCompletionPct, msgAndArgs...)
	assert.True(t, expected.CreatedAt.Equal(got.CreatedAt), msgAndArgs...)
	assert.True(t, expected.UpdatedAt.Equal(got.UpdatedAt), msgAndArgs...)
}

// Helper function to assert equality between two core.OTPVerification structs
func assertOTPVerificationEqual(t *testing.T, expected, got core.OTPVerification, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected.ID, got.ID, msgAndArgs...)
	assert.Equal(t, expected.UserID, got.UserID, msgAndArgs...)
	assert.Equal(t, expected.OTP, got.OTP, msgAndArgs...)
	assert.Equal(t, expected.Type, got.Type, msgAndArgs...)
	assert.Equal(t, expected.Channel, got.Channel, msgAndArgs...)
	assert.True(t, expected.ExpiresAt.Equal(got.ExpiresAt), msgAndArgs...)
	if expected.UsedAt == nil {
		assert.Nil(t, got.UsedAt, msgAndArgs...)
	} else {
		assert.NotNil(t, got.UsedAt, msgAndArgs...)
		assert.True(t, expected.UsedAt.Equal(*got.UsedAt), msgAndArgs...)
	}
	assert.True(t, expected.CreatedAt.Equal(got.CreatedAt), msgAndArgs...)
}

// Helper to create a pgtype.UUID from a string
func uuidPgtypeFromString(s string) pgtype.UUID {
	return pgtype.UUID{Bytes: uuid.MustParse(s), Valid: true}
}

// Helper to create a standard now time for consistency
func nowTime() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

// Helper function to create string pointer
func stringPtr(s string) *string {
	return &s
}
