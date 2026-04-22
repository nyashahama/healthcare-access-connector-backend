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
		mockSetup      func(*mocks.MockQuerier)
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
			mockSetup: func(m *mocks.MockQuerier) {
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
			mockSetup: func(m *mocks.MockQuerier) {
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
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreatePrivacyConsent", ctx, mock.Anything).Return(sqlc.CreatePrivacyConsentRow{}, assert.AnError)
			},
			expectedResult: core.PrivacyConsent{},
			expectedError:  fmt.Errorf("create privacy consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
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
		mockSetup      func(*mocks.MockQuerier)
		expectedResult core.PrivacyConsent
		expectedError  error
	}{
		{
			name:   "successful get privacy consent",
			userID: userID,
			mockSetup: func(m *mocks.MockQuerier) {
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
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPrivacyConsent", ctx, mock.Anything).Return(sqlc.PrivacyConsent{}, pgx.ErrNoRows)
			},
			expectedResult: core.PrivacyConsent{},
			expectedError:  domain.ErrNotFound,
		},
		{
			name:   "database error",
			userID: userID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPrivacyConsent", ctx, mock.Anything).Return(sqlc.PrivacyConsent{}, assert.AnError)
			},
			expectedResult: core.PrivacyConsent{},
			expectedError:  fmt.Errorf("get privacy consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
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
		mockSetup     func(*mocks.MockQuerier)
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
			mockSetup: func(m *mocks.MockQuerier) {
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
			mockSetup:     func(m *mocks.MockQuerier) {},
			expectedError: errors.New("convert data sharing consent"),
		},
		{
			name: "database error",
			consent: core.PrivacyConsent{
				UserID: userID,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdatePrivacyConsent", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update privacy consent failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
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
