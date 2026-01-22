package core

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Helper function to assert equality between two core.PrivacyConsent structs
func assertPrivacyConsentEqual(t *testing.T, expected, got core.PrivacyConsent, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected.ID, got.ID, msgAndArgs...)
	assert.Equal(t, expected.UserID, got.UserID, msgAndArgs...)
	assert.Equal(t, expected.HealthDataConsent, got.HealthDataConsent, msgAndArgs...)

	if expected.HealthDataConsentDate == nil {
		assert.Nil(t, got.HealthDataConsentDate, msgAndArgs...)
	} else {
		assert.NotNil(t, got.HealthDataConsentDate, msgAndArgs...)
		assert.WithinDuration(t, *expected.HealthDataConsentDate, *got.HealthDataConsentDate, time.Second, msgAndArgs...)
	}

	assert.Equal(t, expected.HealthDataConsentVersion, got.HealthDataConsentVersion, msgAndArgs...)
	assert.Equal(t, expected.ResearchConsent, got.ResearchConsent, msgAndArgs...)

	if expected.ResearchConsentDate == nil {
		assert.Nil(t, got.ResearchConsentDate, msgAndArgs...)
	} else {
		assert.NotNil(t, got.ResearchConsentDate, msgAndArgs...)
		assert.WithinDuration(t, *expected.ResearchConsentDate, *got.ResearchConsentDate, time.Second, msgAndArgs...)
	}

	assert.Equal(t, expected.EmergencyAccessConsent, got.EmergencyAccessConsent, msgAndArgs...)

	if expected.EmergencyAccessConsentDate == nil {
		assert.Nil(t, got.EmergencyAccessConsentDate, msgAndArgs...)
	} else {
		assert.NotNil(t, got.EmergencyAccessConsentDate, msgAndArgs...)
		assert.WithinDuration(t, *expected.EmergencyAccessConsentDate, *got.EmergencyAccessConsentDate, time.Second, msgAndArgs...)
	}

	assert.Equal(t, expected.SMSCommunicationConsent, got.SMSCommunicationConsent, msgAndArgs...)
	assert.Equal(t, expected.EmailCommunicationConsent, got.EmailCommunicationConsent, msgAndArgs...)
	assert.Equal(t, expected.DataSharingConsent, got.DataSharingConsent, msgAndArgs...)
	assert.Equal(t, expected.SpecialCategoriesConsent, got.SpecialCategoriesConsent, msgAndArgs...)
	assert.Equal(t, expected.ConsentWithdrawn, got.ConsentWithdrawn, msgAndArgs...)

	if expected.ConsentWithdrawnDate == nil {
		assert.Nil(t, got.ConsentWithdrawnDate, msgAndArgs...)
	} else {
		assert.NotNil(t, got.ConsentWithdrawnDate, msgAndArgs...)
		assert.WithinDuration(t, *expected.ConsentWithdrawnDate, *got.ConsentWithdrawnDate, time.Second, msgAndArgs...)
	}

	assert.Equal(t, expected.WithdrawalReason, got.WithdrawalReason, msgAndArgs...)
	assert.Equal(t, expected.IPAddress, got.IPAddress, msgAndArgs...)
	assert.Equal(t, expected.UserAgent, got.UserAgent, msgAndArgs...)
	assert.WithinDuration(t, expected.CreatedAt, got.CreatedAt, time.Second, msgAndArgs...)
	assert.WithinDuration(t, expected.UpdatedAt, got.UpdatedAt, time.Second, msgAndArgs...)
}

func TestConsentRepository_CreatePrivacyConsent(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	fmt.Print(ipAddr)

	tests := []struct {
		name           string
		consent        core.PrivacyConsent
		mockSetup      func(*mocks.Querier)
		expectedResult core.PrivacyConsent
		expectedError  error
	}{
		{
			name: "successful create privacy consent with all fields",
			consent: core.PrivacyConsent{
				UserID:                    userID,
				HealthDataConsent:         true,
				HealthDataConsentDate:     &now,
				HealthDataConsentVersion:  stringPtr("v1.0"),
				EmergencyAccessConsent:    true,
				SMSCommunicationConsent:   true,
				EmailCommunicationConsent: true,
				IPAddress:                 &ipStr,
				UserAgent:                 stringPtr("Mozilla/5.0"),
			},
			mockSetup: func(m *mocks.Querier) {
				createdRow := sqlc.CreatePrivacyConsentRow{
					ID:                uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:            pgtype.UUID{Bytes: userID, Valid: true},
					HealthDataConsent: pgtype.Bool{Bool: true, Valid: true},
					CreatedAt:         pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreatePrivacyConsent", ctx, mock.MatchedBy(func(p sqlc.CreatePrivacyConsentParams) bool {
					return p.UserID.Bytes == userID &&
						p.HealthDataConsent.Bool == true &&
						p.HealthDataConsentDate.Time.Equal(now) &&
						p.HealthDataConsentVersion.String == "v1.0" &&
						p.EmergencyAccessConsent.Bool == true &&
						p.SmsCommunicationConsent.Bool == true &&
						p.EmailCommunicationConsent.Bool == true &&
						p.IpAddress.String() == ipStr &&
						p.UserAgent.String == "Mozilla/5.0"
				})).Return(createdRow, nil)
			},
			expectedResult: core.PrivacyConsent{
				ID:                uuid.MustParse("223e4567-e89b-12d3-a456-426614174000"),
				UserID:            userID,
				HealthDataConsent: true,
				CreatedAt:         now,
			},
			expectedError: nil,
		},
		{
			name: "successful create privacy consent with minimal fields",
			consent: core.PrivacyConsent{
				UserID:            userID,
				HealthDataConsent: false,
			},
			mockSetup: func(m *mocks.Querier) {
				createdRow := sqlc.CreatePrivacyConsentRow{
					ID:                uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					UserID:            pgtype.UUID{Bytes: userID, Valid: true},
					HealthDataConsent: pgtype.Bool{Bool: false, Valid: true},
					CreatedAt:         pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("CreatePrivacyConsent", ctx, mock.MatchedBy(func(p sqlc.CreatePrivacyConsentParams) bool {
					return p.UserID.Bytes == userID &&
						p.HealthDataConsent.Bool == false &&
						!p.HealthDataConsentDate.Valid &&
						!p.HealthDataConsentVersion.Valid &&
						p.EmergencyAccessConsent.Bool == false &&
						p.SmsCommunicationConsent.Bool == false &&
						p.EmailCommunicationConsent.Bool == false &&
						p.IpAddress == nil &&
						!p.UserAgent.Valid
				})).Return(createdRow, nil)
			},
			expectedResult: core.PrivacyConsent{
				ID:                uuid.MustParse("223e4567-e89b-12d3-a456-426614174000"),
				UserID:            userID,
				HealthDataConsent: false,
				CreatedAt:         now,
			},
			expectedError: nil,
		},
		{
			name: "database error",
			consent: core.PrivacyConsent{
				UserID:            userID,
				HealthDataConsent: true,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("CreatePrivacyConsent", ctx, mock.Anything).Return(sqlc.CreatePrivacyConsentRow{}, assert.AnError)
			},
			expectedResult: core.PrivacyConsent{},
			expectedError:  fmt.Errorf("create privacy consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			result, err := repo.CreatePrivacyConsent(ctx, tt.consent)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assertPrivacyConsentEqual(t, tt.expectedResult, result)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_GetPrivacyConsent(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	consentID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	dataSharingConsent := map[string]interface{}{"provider": "hospital", "share": true}
	specialCategoriesConsent := map[string]interface{}{"genetic": true, "biometric": false}
	dataSharingBytes := []byte(`{"provider":"hospital","share":true}`)
	specialCategoriesBytes := []byte(`{"genetic":true,"biometric":false}`)

	tests := []struct {
		name           string
		userID         uuid.UUID
		mockSetup      func(*mocks.Querier)
		expectedResult core.PrivacyConsent
		expectedError  error
	}{
		{
			name:   "successful get privacy consent",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				consentRow := sqlc.PrivacyConsent{
					ID:                         pgtype.UUID{Bytes: consentID, Valid: true},
					UserID:                     pgtype.UUID{Bytes: userID, Valid: true},
					HealthDataConsent:          pgtype.Bool{Bool: true, Valid: true},
					HealthDataConsentDate:      pgtype.Timestamp{Time: now.Add(-30 * 24 * time.Hour), Valid: true},
					HealthDataConsentVersion:   pgtype.Text{String: "v1.0", Valid: true},
					ResearchConsent:            pgtype.Bool{Bool: false, Valid: true},
					ResearchConsentDate:        pgtype.Timestamp{Time: now.Add(-15 * 24 * time.Hour), Valid: true},
					EmergencyAccessConsent:     pgtype.Bool{Bool: true, Valid: true},
					EmergencyAccessConsentDate: pgtype.Timestamp{Time: now.Add(-10 * 24 * time.Hour), Valid: true},
					SmsCommunicationConsent:    pgtype.Bool{Bool: true, Valid: true},
					EmailCommunicationConsent:  pgtype.Bool{Bool: false, Valid: true},
					DataSharingConsent:         dataSharingBytes,
					SpecialCategoriesConsent:   specialCategoriesBytes,
					ConsentWithdrawn:           pgtype.Bool{Bool: false, Valid: true},
					IpAddress:                  &ipAddr,
					UserAgent:                  pgtype.Text{String: "Mozilla/5.0", Valid: true},
					CreatedAt:                  pgtype.Timestamp{Time: now.Add(-60 * 24 * time.Hour), Valid: true},
					UpdatedAt:                  pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("GetPrivacyConsent", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(consentRow, nil)
			},
			expectedResult: core.PrivacyConsent{
				ID:                         consentID,
				UserID:                     userID,
				HealthDataConsent:          true,
				HealthDataConsentDate:      timePtr(now.Add(-30 * 24 * time.Hour)),
				HealthDataConsentVersion:   stringPtr("v1.0"),
				ResearchConsent:            false,
				ResearchConsentDate:        timePtr(now.Add(-15 * 24 * time.Hour)),
				EmergencyAccessConsent:     true,
				EmergencyAccessConsentDate: timePtr(now.Add(-10 * 24 * time.Hour)),
				SMSCommunicationConsent:    true,
				EmailCommunicationConsent:  false,
				DataSharingConsent:         dataSharingConsent,
				SpecialCategoriesConsent:   specialCategoriesConsent,
				ConsentWithdrawn:           false,
				IPAddress:                  &ipStr,
				UserAgent:                  stringPtr("Mozilla/5.0"),
				CreatedAt:                  now.Add(-60 * 24 * time.Hour),
				UpdatedAt:                  now,
			},
			expectedError: nil,
		},
		{
			name:   "consent not found",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetPrivacyConsent", ctx, mock.Anything).Return(sqlc.PrivacyConsent{}, pgx.ErrNoRows)
			},
			expectedResult: core.PrivacyConsent{},
			expectedError:  domain.ErrNotFound,
		},
		{
			name:   "database error",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetPrivacyConsent", ctx, mock.Anything).Return(sqlc.PrivacyConsent{}, assert.AnError)
			},
			expectedResult: core.PrivacyConsent{},
			expectedError:  fmt.Errorf("get privacy consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			result, err := repo.GetPrivacyConsent(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if errors.Is(tt.expectedError, domain.ErrNotFound) {
					assert.ErrorIs(t, err, domain.ErrNotFound)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
			} else {
				require.NoError(t, err)
				assertPrivacyConsentEqual(t, tt.expectedResult, result)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_UpdatePrivacyConsent(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	dataSharingConsent := map[string]interface{}{"provider": "hospital", "share": true}

	tests := []struct {
		name          string
		consent       core.PrivacyConsent
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful update privacy consent",
			consent: core.PrivacyConsent{
				UserID:                    userID,
				HealthDataConsent:         true,
				ResearchConsent:           false,
				SMSCommunicationConsent:   true,
				EmailCommunicationConsent: false,
				DataSharingConsent:        dataSharingConsent,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdatePrivacyConsent", ctx, mock.MatchedBy(func(p sqlc.UpdatePrivacyConsentParams) bool {
					return p.UserID.Bytes == userID &&
						p.HealthDataConsent.Bool == true &&
						p.ResearchConsent.Bool == false &&
						p.SmsCommunicationConsent.Bool == true &&
						p.EmailCommunicationConsent.Bool == false &&
						string(p.DataSharingConsent) == `{"provider":"hospital","share":true}`
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "error converting data sharing consent to JSON",
			consent: core.PrivacyConsent{
				UserID:             userID,
				DataSharingConsent: map[string]interface{}{"invalid": make(chan int)}, // Unmarshallable
			},
			mockSetup:     func(m *mocks.Querier) {},
			expectedError: errors.New("convert data sharing consent"),
		},
		{
			name: "database error",
			consent: core.PrivacyConsent{
				UserID: userID,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdatePrivacyConsent", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update privacy consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			err := repo.UpdatePrivacyConsent(ctx, tt.consent)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_WithdrawConsent(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		reason        string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:   "successful withdraw consent with reason",
			userID: userID,
			reason: "Moving to another provider",
			mockSetup: func(m *mocks.Querier) {
				m.On("WithdrawConsent", ctx, sqlc.WithdrawConsentParams{
					UserID:           uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					WithdrawalReason: pgtype.Text{String: "Moving to another provider", Valid: true},
				}).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "successful withdraw consent without reason",
			userID: userID,
			reason: "",
			mockSetup: func(m *mocks.Querier) {
				m.On("WithdrawConsent", ctx, mock.MatchedBy(func(p sqlc.WithdrawConsentParams) bool {
					return p.UserID.Bytes == userID && !p.WithdrawalReason.Valid
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			userID: userID,
			reason: "test",
			mockSetup: func(m *mocks.Querier) {
				m.On("WithdrawConsent", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("withdraw consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			err := repo.WithdrawConsent(ctx, tt.userID, tt.reason)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_UpdateHealthDataConsent(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		consent       bool
		version       string
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful update health data consent (grant)",
			userID:  userID,
			consent: true,
			version: "v2.0",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateHealthDataConsent", ctx, mock.MatchedBy(func(p sqlc.UpdateHealthDataConsentParams) bool {
					return p.UserID.Bytes == userID &&
						p.HealthDataConsent.Bool == true &&
						p.HealthDataConsentVersion.String == "v2.0"
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "successful update health data consent (withdraw)",
			userID:  userID,
			consent: false,
			version: "v2.0",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateHealthDataConsent", ctx, mock.MatchedBy(func(p sqlc.UpdateHealthDataConsentParams) bool {
					return p.UserID.Bytes == userID &&
						p.HealthDataConsent.Bool == false &&
						p.HealthDataConsentVersion.String == "v2.0"
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "database error",
			userID:  userID,
			consent: true,
			version: "v1.0",
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateHealthDataConsent", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update health data consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			err := repo.UpdateHealthDataConsent(ctx, tt.userID, tt.consent, tt.version)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_UpdateResearchConsent(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		consent       bool
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful update research consent (grant)",
			userID:  userID,
			consent: true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateResearchConsent", ctx, mock.MatchedBy(func(p sqlc.UpdateResearchConsentParams) bool {
					return p.UserID.Bytes == userID && p.ResearchConsent.Bool == true
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "successful update research consent (withdraw)",
			userID:  userID,
			consent: false,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateResearchConsent", ctx, mock.MatchedBy(func(p sqlc.UpdateResearchConsentParams) bool {
					return p.UserID.Bytes == userID && p.ResearchConsent.Bool == false
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "database error",
			userID:  userID,
			consent: true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateResearchConsent", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update research consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			err := repo.UpdateResearchConsent(ctx, tt.userID, tt.consent)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_UpdateEmergencyAccessConsent(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		consent       bool
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:    "successful update emergency access consent (grant)",
			userID:  userID,
			consent: true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateEmergencyAccessConsent", ctx, mock.MatchedBy(func(p sqlc.UpdateEmergencyAccessConsentParams) bool {
					return p.UserID.Bytes == userID && p.EmergencyAccessConsent.Bool == true
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "successful update emergency access consent (withdraw)",
			userID:  userID,
			consent: false,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateEmergencyAccessConsent", ctx, mock.MatchedBy(func(p sqlc.UpdateEmergencyAccessConsentParams) bool {
					return p.UserID.Bytes == userID && p.EmergencyAccessConsent.Bool == false
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "database error",
			userID:  userID,
			consent: true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateEmergencyAccessConsent", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update emergency access consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			err := repo.UpdateEmergencyAccessConsent(ctx, tt.userID, tt.consent)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_UpdateCommunicationConsents(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		userID        uuid.UUID
		sms           bool
		email         bool
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:   "successful update communication consents (both true)",
			userID: userID,
			sms:    true,
			email:  true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateCommunicationConsents", ctx, mock.MatchedBy(func(p sqlc.UpdateCommunicationConsentsParams) bool {
					return p.UserID.Bytes == userID &&
						p.SmsCommunicationConsent.Bool == true &&
						p.EmailCommunicationConsent.Bool == true
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "successful update communication consents (sms true, email false)",
			userID: userID,
			sms:    true,
			email:  false,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateCommunicationConsents", ctx, mock.MatchedBy(func(p sqlc.UpdateCommunicationConsentsParams) bool {
					return p.UserID.Bytes == userID &&
						p.SmsCommunicationConsent.Bool == true &&
						p.EmailCommunicationConsent.Bool == false
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "successful update communication consents (both false)",
			userID: userID,
			sms:    false,
			email:  false,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateCommunicationConsents", ctx, mock.MatchedBy(func(p sqlc.UpdateCommunicationConsentsParams) bool {
					return p.UserID.Bytes == userID &&
						p.SmsCommunicationConsent.Bool == false &&
						p.EmailCommunicationConsent.Bool == false
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			userID: userID,
			sms:    true,
			email:  true,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateCommunicationConsents", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update communication consents failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			err := repo.UpdateCommunicationConsents(ctx, tt.userID, tt.sms, tt.email)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_UpdateDataSharingConsent(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	sharingPrefs := map[string]interface{}{"provider": "research_institute", "share": true, "anonymized": true}

	tests := []struct {
		name          string
		userID        uuid.UUID
		sharingPrefs  map[string]interface{}
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:         "successful update data sharing consent",
			userID:       userID,
			sharingPrefs: sharingPrefs,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateDataSharingConsent", ctx, mock.MatchedBy(func(p sqlc.UpdateDataSharingConsentParams) bool {
					return p.UserID.Bytes == userID &&
						string(p.DataSharingConsent) == `{"anonymized":true,"provider":"research_institute","share":true}`
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:          "error converting sharing preferences to JSON",
			userID:        userID,
			sharingPrefs:  map[string]interface{}{"invalid": make(chan int)},
			mockSetup:     func(m *mocks.Querier) {},
			expectedError: errors.New("convert data sharing preferences"),
		},
		{
			name:         "database error",
			userID:       userID,
			sharingPrefs: sharingPrefs,
			mockSetup: func(m *mocks.Querier) {
				m.On("UpdateDataSharingConsent", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update data sharing consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			err := repo.UpdateDataSharingConsent(ctx, tt.userID, tt.sharingPrefs)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_GetConsentHistory(t *testing.T) {
	ctx := context.Background()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	consentID1 := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	consentID2 := uuid.MustParse("323e4567-e89b-12d3-a456-426614174000")
	now := time.Now()

	tests := []struct {
		name           string
		userID         uuid.UUID
		mockSetup      func(*mocks.Querier)
		expectedResult []core.PrivacyConsent
		expectedError  error
	}{
		{
			name:   "successful get consent history",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				consentRows := []sqlc.PrivacyConsent{
					{
						ID:                pgtype.UUID{Bytes: consentID1, Valid: true},
						UserID:            pgtype.UUID{Bytes: userID, Valid: true},
						HealthDataConsent: pgtype.Bool{Bool: true, Valid: true},
						CreatedAt:         pgtype.Timestamp{Time: now.Add(-30 * 24 * time.Hour), Valid: true},
						UpdatedAt:         pgtype.Timestamp{Time: now.Add(-20 * 24 * time.Hour), Valid: true},
					},
					{
						ID:                pgtype.UUID{Bytes: consentID2, Valid: true},
						UserID:            pgtype.UUID{Bytes: userID, Valid: true},
						HealthDataConsent: pgtype.Bool{Bool: false, Valid: true},
						ConsentWithdrawn:  pgtype.Bool{Bool: true, Valid: true},
						CreatedAt:         pgtype.Timestamp{Time: now.Add(-10 * 24 * time.Hour), Valid: true},
						UpdatedAt:         pgtype.Timestamp{Time: now.Add(-5 * 24 * time.Hour), Valid: true},
					},
				}
				m.On("GetConsentHistory", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(consentRows, nil)
			},
			expectedResult: []core.PrivacyConsent{
				{
					ID:                consentID1,
					UserID:            userID,
					HealthDataConsent: true,
					ConsentWithdrawn:  false,
					CreatedAt:         now.Add(-30 * 24 * time.Hour),
					UpdatedAt:         now.Add(-20 * 24 * time.Hour),
				},
				{
					ID:                consentID2,
					UserID:            userID,
					HealthDataConsent: false,
					ConsentWithdrawn:  true,
					CreatedAt:         now.Add(-10 * 24 * time.Hour),
					UpdatedAt:         now.Add(-5 * 24 * time.Hour),
				},
			},
			expectedError: nil,
		},
		{
			name:   "no consent history found",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetConsentHistory", ctx, mock.Anything).Return([]sqlc.PrivacyConsent{}, nil)
			},
			expectedResult: []core.PrivacyConsent{},
			expectedError:  nil,
		},
		{
			name:   "database error",
			userID: userID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetConsentHistory", ctx, mock.Anything).Return([]sqlc.PrivacyConsent{}, assert.AnError)
			},
			expectedResult: nil,
			expectedError:  fmt.Errorf("get consent history failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			result, err := repo.GetConsentHistory(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedResult), len(result))
				for i, expected := range tt.expectedResult {
					assertPrivacyConsentEqual(t, expected, result[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_GetActiveConsentsByType(t *testing.T) {
	ctx := context.Background()
	userID1 := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	userID2 := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	consentID1 := uuid.MustParse("323e4567-e89b-12d3-a456-426614174000")
	consentID2 := uuid.MustParse("423e4567-e89b-12d3-a456-426614174000")
	now := time.Now()

	tests := []struct {
		name           string
		consentType    string
		mockSetup      func(*mocks.Querier)
		expectedResult []core.PrivacyConsent
		expectedError  error
	}{
		{
			name:        "successful get active health data consents",
			consentType: "health_data",
			mockSetup: func(m *mocks.Querier) {
				consentRows := []sqlc.PrivacyConsent{
					{
						ID:                pgtype.UUID{Bytes: consentID1, Valid: true},
						UserID:            pgtype.UUID{Bytes: userID1, Valid: true},
						HealthDataConsent: pgtype.Bool{Bool: true, Valid: true},
						CreatedAt:         pgtype.Timestamp{Time: now.Add(-30 * 24 * time.Hour), Valid: true},
					},
					{
						ID:                pgtype.UUID{Bytes: consentID2, Valid: true},
						UserID:            pgtype.UUID{Bytes: userID2, Valid: true},
						HealthDataConsent: pgtype.Bool{Bool: true, Valid: true},
						CreatedAt:         pgtype.Timestamp{Time: now.Add(-15 * 24 * time.Hour), Valid: true},
					},
				}
				m.On("GetActiveHealthDataConsents", ctx).Return(consentRows, nil)
			},
			expectedResult: []core.PrivacyConsent{
				{
					ID:                consentID1,
					UserID:            userID1,
					HealthDataConsent: true,
					CreatedAt:         now.Add(-30 * 24 * time.Hour),
				},
				{
					ID:                consentID2,
					UserID:            userID2,
					HealthDataConsent: true,
					CreatedAt:         now.Add(-15 * 24 * time.Hour),
				},
			},
			expectedError: nil,
		},
		{
			name:        "successful get active research consents",
			consentType: "research",
			mockSetup: func(m *mocks.Querier) {
				consentRows := []sqlc.PrivacyConsent{
					{
						ID:              pgtype.UUID{Bytes: consentID1, Valid: true},
						UserID:          pgtype.UUID{Bytes: userID1, Valid: true},
						ResearchConsent: pgtype.Bool{Bool: true, Valid: true},
						CreatedAt:       pgtype.Timestamp{Time: now.Add(-20 * 24 * time.Hour), Valid: true},
					},
				}
				m.On("GetActiveResearchConsents", ctx).Return(consentRows, nil)
			},
			expectedResult: []core.PrivacyConsent{
				{
					ID:              consentID1,
					UserID:          userID1,
					ResearchConsent: true,
					CreatedAt:       now.Add(-20 * 24 * time.Hour),
				},
			},
			expectedError: nil,
		},
		{
			name:        "successful get active emergency access consents",
			consentType: "emergency_access",
			mockSetup: func(m *mocks.Querier) {
				consentRows := []sqlc.PrivacyConsent{
					{
						ID:                     pgtype.UUID{Bytes: consentID1, Valid: true},
						UserID:                 pgtype.UUID{Bytes: userID1, Valid: true},
						EmergencyAccessConsent: pgtype.Bool{Bool: true, Valid: true},
						CreatedAt:              pgtype.Timestamp{Time: now.Add(-10 * 24 * time.Hour), Valid: true},
					},
				}
				m.On("GetActiveEmergencyAccessConsents", ctx).Return(consentRows, nil)
			},
			expectedResult: []core.PrivacyConsent{
				{
					ID:                     consentID1,
					UserID:                 userID1,
					EmergencyAccessConsent: true,
					CreatedAt:              now.Add(-10 * 24 * time.Hour),
				},
			},
			expectedError: nil,
		},
		{
			name:        "invalid consent type",
			consentType: "invalid_type",
			mockSetup: func(m *mocks.Querier) {
				// No mock setup needed since we return early
			},
			expectedResult: nil,
			expectedError:  errors.New("invalid consent type"),
		},
		{
			name:        "database error for health data consents",
			consentType: "health_data",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetActiveHealthDataConsents", ctx).Return([]sqlc.PrivacyConsent{}, assert.AnError)
			},
			expectedResult: nil,
			expectedError:  fmt.Errorf("get active consents by type failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			result, err := repo.GetActiveConsentsByType(ctx, tt.consentType)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedResult), len(result))
				for i, expected := range tt.expectedResult {
					assertPrivacyConsentEqual(t, expected, result[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_GetExpiredConsents(t *testing.T) {
	ctx := context.Background()
	userID1 := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	userID2 := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	consentID1 := uuid.MustParse("323e4567-e89b-12d3-a456-426614174000")
	consentID2 := uuid.MustParse("423e4567-e89b-12d3-a456-426614174000")
	now := time.Now()

	tests := []struct {
		name           string
		mockSetup      func(*mocks.Querier)
		expectedResult []core.PrivacyConsent
		expectedError  error
	}{
		{
			name: "successful get expired consents",
			mockSetup: func(m *mocks.Querier) {
				consentRows := []sqlc.PrivacyConsent{
					{
						ID:                     pgtype.UUID{Bytes: consentID1, Valid: true},
						UserID:                 pgtype.UUID{Bytes: userID1, Valid: true},
						HealthDataConsent:      pgtype.Bool{Bool: false, Valid: true},
						HealthDataConsentDate:  pgtype.Timestamp{Time: now.Add(-400 * 24 * time.Hour), Valid: true}, // Expired
						EmergencyAccessConsent: pgtype.Bool{Bool: false, Valid: true},
						CreatedAt:              pgtype.Timestamp{Time: now.Add(-500 * 24 * time.Hour), Valid: true},
					},
					{
						ID:                     pgtype.UUID{Bytes: consentID2, Valid: true},
						UserID:                 pgtype.UUID{Bytes: userID2, Valid: true},
						HealthDataConsent:      pgtype.Bool{Bool: true, Valid: true},
						HealthDataConsentDate:  pgtype.Timestamp{Time: now.Add(-400 * 24 * time.Hour), Valid: true}, // Expired but still consented
						EmergencyAccessConsent: pgtype.Bool{Bool: false, Valid: true},
						CreatedAt:              pgtype.Timestamp{Time: now.Add(-450 * 24 * time.Hour), Valid: true},
					},
				}
				m.On("GetExpiredConsents", ctx).Return(consentRows, nil)
			},
			expectedResult: []core.PrivacyConsent{
				{
					ID:                     consentID1,
					UserID:                 userID1,
					HealthDataConsent:      false,
					HealthDataConsentDate:  timePtr(now.Add(-400 * 24 * time.Hour)),
					EmergencyAccessConsent: false,
					CreatedAt:              now.Add(-500 * 24 * time.Hour),
				},
				{
					ID:                     consentID2,
					UserID:                 userID2,
					HealthDataConsent:      true,
					HealthDataConsentDate:  timePtr(now.Add(-400 * 24 * time.Hour)),
					EmergencyAccessConsent: false,
					CreatedAt:              now.Add(-450 * 24 * time.Hour),
				},
			},
			expectedError: nil,
		},
		{
			name: "no expired consents found",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetExpiredConsents", ctx).Return([]sqlc.PrivacyConsent{}, nil)
			},
			expectedResult: []core.PrivacyConsent{},
			expectedError:  nil,
		},
		{
			name: "database error",
			mockSetup: func(m *mocks.Querier) {
				m.On("GetExpiredConsents", ctx).Return([]sqlc.PrivacyConsent{}, assert.AnError)
			},
			expectedResult: nil,
			expectedError:  fmt.Errorf("get expired consents failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			result, err := repo.GetExpiredConsents(ctx)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedResult), len(result))
				for i, expected := range tt.expectedResult {
					assertPrivacyConsentEqual(t, expected, result[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsentRepository_GetWithdrawnConsents(t *testing.T) {
	ctx := context.Background()
	userID1 := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	userID2 := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	consentID1 := uuid.MustParse("323e4567-e89b-12d3-a456-426614174000")
	consentID2 := uuid.MustParse("423e4567-e89b-12d3-a456-426614174000")
	now := time.Now()
	startDate := now.Add(-30 * 24 * time.Hour)
	endDate := now

	tests := []struct {
		name           string
		startDate      time.Time
		endDate        time.Time
		mockSetup      func(*mocks.Querier)
		expectedResult []core.PrivacyConsent
		expectedError  error
	}{
		{
			name:      "successful get withdrawn consents",
			startDate: startDate,
			endDate:   endDate,
			mockSetup: func(m *mocks.Querier) {
				consentRows := []sqlc.PrivacyConsent{
					{
						ID:                   pgtype.UUID{Bytes: consentID1, Valid: true},
						UserID:               pgtype.UUID{Bytes: userID1, Valid: true},
						HealthDataConsent:    pgtype.Bool{Bool: false, Valid: true},
						ConsentWithdrawn:     pgtype.Bool{Bool: true, Valid: true},
						ConsentWithdrawnDate: pgtype.Timestamp{Time: now.Add(-20 * 24 * time.Hour), Valid: true},
						WithdrawalReason:     pgtype.Text{String: "Privacy concerns", Valid: true},
						CreatedAt:            pgtype.Timestamp{Time: now.Add(-100 * 24 * time.Hour), Valid: true},
					},
					{
						ID:                   pgtype.UUID{Bytes: consentID2, Valid: true},
						UserID:               pgtype.UUID{Bytes: userID2, Valid: true},
						HealthDataConsent:    pgtype.Bool{Bool: false, Valid: true},
						ConsentWithdrawn:     pgtype.Bool{Bool: true, Valid: true},
						ConsentWithdrawnDate: pgtype.Timestamp{Time: now.Add(-10 * 24 * time.Hour), Valid: true},
						WithdrawalReason:     pgtype.Text{String: "Switching providers", Valid: true},
						CreatedAt:            pgtype.Timestamp{Time: now.Add(-80 * 24 * time.Hour), Valid: true},
					},
				}
				m.On("GetWithdrawnConsents", ctx, mock.MatchedBy(func(p sqlc.GetWithdrawnConsentsParams) bool {
					return p.ConsentWithdrawnDate.Time.Equal(startDate) &&
						p.ConsentWithdrawnDate_2.Time.Equal(endDate)
				})).Return(consentRows, nil)
			},
			expectedResult: []core.PrivacyConsent{
				{
					ID:                   consentID1,
					UserID:               userID1,
					HealthDataConsent:    false,
					ConsentWithdrawn:     true,
					ConsentWithdrawnDate: timePtr(now.Add(-20 * 24 * time.Hour)),
					WithdrawalReason:     stringPtr("Privacy concerns"),
					CreatedAt:            now.Add(-100 * 24 * time.Hour),
				},
				{
					ID:                   consentID2,
					UserID:               userID2,
					HealthDataConsent:    false,
					ConsentWithdrawn:     true,
					ConsentWithdrawnDate: timePtr(now.Add(-10 * 24 * time.Hour)),
					WithdrawalReason:     stringPtr("Switching providers"),
					CreatedAt:            now.Add(-80 * 24 * time.Hour),
				},
			},
			expectedError: nil,
		},
		{
			name:      "no withdrawn consents found in date range",
			startDate: startDate,
			endDate:   endDate,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetWithdrawnConsents", ctx, mock.Anything).Return([]sqlc.PrivacyConsent{}, nil)
			},
			expectedResult: []core.PrivacyConsent{},
			expectedError:  nil,
		},
		{
			name:      "database error",
			startDate: startDate,
			endDate:   endDate,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetWithdrawnConsents", ctx, mock.Anything).Return([]sqlc.PrivacyConsent{}, assert.AnError)
			},
			expectedResult: nil,
			expectedError:  fmt.Errorf("get withdrawn consents failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &consentRepository{querier: mockQuerier}

			result, err := repo.GetWithdrawnConsents(ctx, tt.startDate, tt.endDate)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedResult), len(result))
				for i, expected := range tt.expectedResult {
					assertPrivacyConsentEqual(t, expected, result[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}
