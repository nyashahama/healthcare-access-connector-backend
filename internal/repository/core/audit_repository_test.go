package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Helper function to assert equality between two core.UserActivity structs
func assertUserActivityEqual(t *testing.T, expected, got core.UserActivity, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected.ID, got.ID, msgAndArgs...)
	if expected.UserID == nil {
		assert.Nil(t, got.UserID, msgAndArgs...)
	} else {
		assert.NotNil(t, got.UserID, msgAndArgs...)
		assert.Equal(t, *expected.UserID, *got.UserID, msgAndArgs...)
	}
	assert.Equal(t, expected.ActivityType, got.ActivityType, msgAndArgs...)
	assert.Equal(t, expected.ActivityDetails, got.ActivityDetails, msgAndArgs...)
	if expected.IPAddress == nil {
		assert.Nil(t, got.IPAddress, msgAndArgs...)
	} else {
		assert.NotNil(t, got.IPAddress, msgAndArgs...)
		assert.Equal(t, *expected.IPAddress, *got.IPAddress, msgAndArgs...)
	}
	assert.Equal(t, expected.UserAgent, got.UserAgent, msgAndArgs...)
	assert.Equal(t, expected.DeviceType, got.DeviceType, msgAndArgs...)
	assert.Equal(t, expected.DeviceID, got.DeviceID, msgAndArgs...)
	assert.Equal(t, expected.Location, got.Location, msgAndArgs...)
	assert.Equal(t, expected.ResourceType, got.ResourceType, msgAndArgs...)
	if expected.ResourceID == nil {
		assert.Nil(t, got.ResourceID, msgAndArgs...)
	} else {
		assert.NotNil(t, got.ResourceID, msgAndArgs...)
		assert.Equal(t, *expected.ResourceID, *got.ResourceID, msgAndArgs...)
	}
	assert.WithinDuration(t, expected.PerformedAt, got.PerformedAt, time.Second, msgAndArgs...)
}

// Helper function to assert equality between two core.DataAccessLog structs
func assertDataAccessLogEqual(t *testing.T, expected, got core.DataAccessLog, msgAndArgs ...interface{}) {
	t.Helper()
	assert.Equal(t, expected.ID, got.ID, msgAndArgs...)
	if expected.AccessedByUserID == nil {
		assert.Nil(t, got.AccessedByUserID, msgAndArgs...)
	} else {
		assert.NotNil(t, got.AccessedByUserID, msgAndArgs...)
		assert.Equal(t, *expected.AccessedByUserID, *got.AccessedByUserID, msgAndArgs...)
	}
	assert.Equal(t, expected.AccessedByRole, got.AccessedByRole, msgAndArgs...)
	assert.Equal(t, expected.AccessedUserID, got.AccessedUserID, msgAndArgs...)
	assert.Equal(t, expected.AccessedResourceType, got.AccessedResourceType, msgAndArgs...)
	if expected.AccessedResourceID == nil {
		assert.Nil(t, got.AccessedResourceID, msgAndArgs...)
	} else {
		assert.NotNil(t, got.AccessedResourceID, msgAndArgs...)
		assert.Equal(t, *expected.AccessedResourceID, *got.AccessedResourceID, msgAndArgs...)
	}
	assert.Equal(t, expected.AccessType, got.AccessType, msgAndArgs...)
	assert.Equal(t, expected.AccessReason, got.AccessReason, msgAndArgs...)
	assert.Equal(t, expected.IsEmergencyAccess, got.IsEmergencyAccess, msgAndArgs...)
	if expected.IPAddress == nil {
		assert.Nil(t, got.IPAddress, msgAndArgs...)
	} else {
		assert.NotNil(t, got.IPAddress, msgAndArgs...)
		assert.Equal(t, *expected.IPAddress, *got.IPAddress, msgAndArgs...)
	}
	assert.Equal(t, expected.UserAgent, got.UserAgent, msgAndArgs...)
	assert.Equal(t, expected.Location, got.Location, msgAndArgs...)
	assert.WithinDuration(t, expected.AccessedAt, got.AccessedAt, time.Second, msgAndArgs...)
}

func TestAuditRepository_LogUserActivity(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	fmt.Println(now)
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	resourceID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr, _ := netip.ParseAddr(ipStr)
	fmt.Println(ipAddr)
	activityDetails := map[string]interface{}{"key": "value"}
	location := map[string]interface{}{"city": "Test City"}
	activityDetailsBytes, _ := json.Marshal(activityDetails)
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name          string
		activity      core.UserActivity
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful log user activity with all fields",
			activity: core.UserActivity{
				UserID:          &userID,
				ActivityType:    "login",
				ActivityDetails: activityDetails,
				IPAddress:       &ipStr,
				UserAgent:       stringPtr("Mozilla/5.0"),
				DeviceType:      stringPtr("mobile"),
				DeviceID:        stringPtr("device123"),
				Location:        location,
				ResourceType:    stringPtr("patient_record"),
				ResourceID:      &resourceID,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("LogUserActivity", ctx, mock.MatchedBy(func(p sqlc.LogUserActivityParams) bool {
					return p.UserID.Bytes == userID &&
						p.ActivityType == "login" &&
						string(p.ActivityDetails) == string(activityDetailsBytes) &&
						p.IpAddress.String() == ipStr &&
						p.UserAgent.String == "Mozilla/5.0" &&
						p.DeviceType.String == "mobile" &&
						p.DeviceID.String == "device123" &&
						string(p.Location) == string(locationBytes) &&
						p.ResourceType.String == "patient_record" &&
						p.ResourceID.Bytes == resourceID
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "successful log user activity with minimal fields",
			activity: core.UserActivity{
				ActivityType: "logout",
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("LogUserActivity", ctx, mock.MatchedBy(func(p sqlc.LogUserActivityParams) bool {
					return !p.UserID.Valid &&
						p.ActivityType == "logout" &&
						string(p.ActivityDetails) == "null" && // Changed from len == 0
						p.IpAddress == nil &&
						!p.UserAgent.Valid &&
						!p.DeviceType.Valid &&
						!p.DeviceID.Valid &&
						string(p.Location) == "null" && // Changed from len == 0
						!p.ResourceType.Valid &&
						!p.ResourceID.Valid
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "marshal error for activity details",
			activity: core.UserActivity{
				ActivityType:    "invalid",
				ActivityDetails: map[string]interface{}{"invalid": make(chan int)}, // Unmarshallable
			},
			mockSetup:     func(m *mocks.Querier) {},
			expectedError: errors.New("marshal activity details"),
		},
		{
			name: "marshal error for location",
			activity: core.UserActivity{
				ActivityType: "invalid",
				Location:     map[string]interface{}{"invalid": make(chan int)}, // Unmarshallable
			},
			mockSetup:     func(m *mocks.Querier) {},
			expectedError: errors.New("marshal location"),
		},
		{
			name: "database error",
			activity: core.UserActivity{
				ActivityType: "login",
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("LogUserActivity", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("log user activity failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			err := repo.LogUserActivity(ctx, tt.activity)

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

func TestAuditRepository_GetUserActivities(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	resourceID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	activityDetails := map[string]interface{}{"key": "value"}
	location := map[string]interface{}{"city": "Test City"}
	activityDetailsBytes, _ := json.Marshal(activityDetails)
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name          string
		userID        uuid.UUID
		limit         int
		offset        int
		mockSetup     func(*mocks.Querier)
		expectedActs  []core.UserActivity
		expectedError error
	}{
		{
			name:   "successful get user activities",
			userID: userID,
			limit:  10,
			offset: 0,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.UserActivity{
					{
						ID:              uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
						UserID:          pgtype.UUID{Bytes: userID, Valid: true},
						ActivityType:    "login",
						ActivityDetails: activityDetailsBytes,
						IpAddress:       &ipAddr,
						UserAgent:       pgtype.Text{String: "Mozilla/5.0", Valid: true},
						DeviceType:      pgtype.Text{String: "mobile", Valid: true},
						DeviceID:        pgtype.Text{String: "device123", Valid: true},
						Location:        locationBytes,
						ResourceType:    pgtype.Text{String: "patient_record", Valid: true},
						ResourceID:      pgtype.UUID{Bytes: resourceID, Valid: true},
						PerformedAt:     pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetUserActivities", ctx, sqlc.GetUserActivitiesParams{
					UserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Limit:  int32(10),
					Offset: int32(0),
				}).Return(expectedRows, nil)
			},
			expectedActs: []core.UserActivity{
				{
					ID:              uuid.MustParse("323e4567-e89b-12d3-a456-426614174000"),
					UserID:          &userID,
					ActivityType:    "login",
					ActivityDetails: activityDetails,
					IPAddress:       &ipStr,
					UserAgent:       stringPtr("Mozilla/5.0"),
					DeviceType:      stringPtr("mobile"),
					DeviceID:        stringPtr("device123"),
					Location:        location,
					ResourceType:    stringPtr("patient_record"),
					ResourceID:      &resourceID,
					PerformedAt:     now,
				},
			},
			expectedError: nil,
		},
		{
			name:   "no activities found",
			userID: userID,
			limit:  10,
			offset: 0,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserActivities", ctx, mock.Anything).Return([]sqlc.UserActivity{}, nil)
			},
			expectedActs:  []core.UserActivity{},
			expectedError: nil,
		},
		{
			name:   "database error",
			userID: userID,
			limit:  10,
			offset: 0,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetUserActivities", ctx, mock.Anything).Return([]sqlc.UserActivity{}, assert.AnError)
			},
			expectedActs:  nil,
			expectedError: fmt.Errorf("get user activities failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotActs, err := repo.GetUserActivities(ctx, tt.userID, tt.limit, tt.offset)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotActs)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedActs), len(gotActs))
				for i, expected := range tt.expectedActs {
					assertUserActivityEqual(t, expected, gotActs[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}
