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

func TestAuditRepository_GetActivitiesByType(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	startDate := now.Add(-time.Hour * 24)
	endDate := now
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
		activityType  string
		startDate     time.Time
		endDate       time.Time
		mockSetup     func(*mocks.Querier)
		expectedActs  []core.UserActivity
		expectedError error
	}{
		{
			name:         "successful get activities by type",
			activityType: "login",
			startDate:    startDate,
			endDate:      endDate,
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
				m.On("GetActivitiesByType", ctx, mock.MatchedBy(func(p sqlc.GetActivitiesByTypeParams) bool {
					return p.ActivityType == "login" &&
						p.PerformedAt.Time.Equal(startDate) &&
						p.PerformedAt_2.Time.Equal(endDate)
				})).Return(expectedRows, nil)
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
			name:         "database error",
			activityType: "login",
			startDate:    startDate,
			endDate:      endDate,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetActivitiesByType", ctx, mock.Anything).Return([]sqlc.UserActivity{}, assert.AnError)
			},
			expectedActs:  nil,
			expectedError: fmt.Errorf("get activities by type failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotActs, err := repo.GetActivitiesByType(ctx, tt.activityType, tt.startDate, tt.endDate)

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

func TestAuditRepository_GetActivitiesByResource(t *testing.T) {
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
		resourceType  string
		resourceID    uuid.UUID
		mockSetup     func(*mocks.Querier)
		expectedActs  []core.UserActivity
		expectedError error
	}{
		{
			name:         "successful get activities by resource",
			resourceType: "patient_record",
			resourceID:   resourceID,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.UserActivity{
					{
						ID:              uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
						UserID:          pgtype.UUID{Bytes: userID, Valid: true},
						ActivityType:    "access",
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
				m.On("GetActivitiesByResource", ctx, sqlc.GetActivitiesByResourceParams{
					ResourceType: pgtype.Text{String: "patient_record", Valid: true},
					ResourceID:   uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
				}).Return(expectedRows, nil)
			},
			expectedActs: []core.UserActivity{
				{
					ID:              uuid.MustParse("323e4567-e89b-12d3-a456-426614174000"),
					UserID:          &userID,
					ActivityType:    "access",
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
			name:         "database error",
			resourceType: "patient_record",
			resourceID:   resourceID,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetActivitiesByResource", ctx, mock.Anything).Return([]sqlc.UserActivity{}, assert.AnError)
			},
			expectedActs:  nil,
			expectedError: fmt.Errorf("get activities by resource failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotActs, err := repo.GetActivitiesByResource(ctx, tt.resourceType, tt.resourceID)

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

func TestAuditRepository_LogDataAccess(t *testing.T) {
	ctx := context.Background()
	accessedUserID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	accessedByUserID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	accessedResourceID := uuid.MustParse("323e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr, _ := netip.ParseAddr(ipStr)
	fmt.Print(ipAddr)
	location := map[string]interface{}{"city": "Test City"}
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name          string
		log           core.DataAccessLog
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name: "successful log data access with all fields",
			log: core.DataAccessLog{
				AccessedByUserID:     &accessedByUserID,
				AccessedByRole:       stringPtr("doctor"),
				AccessedUserID:       accessedUserID,
				AccessedResourceType: stringPtr("medical_record"),
				AccessedResourceID:   &accessedResourceID,
				AccessType:           "read",
				AccessReason:         stringPtr("routine check"),
				IsEmergencyAccess:    true,
				IPAddress:            &ipStr,
				UserAgent:            stringPtr("Mozilla/5.0"),
				Location:             location,
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("LogDataAccess", ctx, mock.MatchedBy(func(p sqlc.LogDataAccessParams) bool {
					return p.AccessedByUserID.Bytes == accessedByUserID &&
						p.AccessedByRole.String == "doctor" &&
						p.AccessedUserID.Bytes == accessedUserID &&
						p.AccessedResourceType.String == "medical_record" &&
						p.AccessedResourceID.Bytes == accessedResourceID &&
						p.AccessType.String == "read" &&
						p.AccessReason.String == "routine check" &&
						p.IsEmergencyAccess.Bool == true &&
						p.IpAddress.String() == ipStr &&
						p.UserAgent.String == "Mozilla/5.0" &&
						string(p.Location) == string(locationBytes)
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "marshal error for location",
			log: core.DataAccessLog{
				AccessedUserID: accessedUserID,
				AccessType:     "read",
				Location:       map[string]interface{}{"invalid": make(chan int)},
			},
			mockSetup:     func(m *mocks.Querier) {},
			expectedError: errors.New("marshal location"),
		},
		{
			name: "database error",
			log: core.DataAccessLog{
				AccessedUserID: accessedUserID,
				AccessType:     "read",
			},
			mockSetup: func(m *mocks.Querier) {
				m.On("LogDataAccess", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("log data access failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			err := repo.LogDataAccess(ctx, tt.log)

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

func TestAuditRepository_GetDataAccessLogs(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	accessedUserID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	accessedByUserID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	accessedResourceID := uuid.MustParse("323e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	location := map[string]interface{}{"city": "Test City"}
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name           string
		accessedUserID uuid.UUID
		limit          int
		offset         int
		mockSetup      func(*mocks.Querier)
		expectedLogs   []core.DataAccessLog
		expectedError  error
	}{
		{
			name:           "successful get data access logs",
			accessedUserID: accessedUserID,
			limit:          10,
			offset:         0,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.DataAccessLog{
					{
						ID:                   uuidPgtypeFromString("423e4567-e89b-12d3-a456-426614174000"),
						AccessedByUserID:     pgtype.UUID{Bytes: accessedByUserID, Valid: true},
						AccessedByRole:       pgtype.Text{String: "doctor", Valid: true},
						AccessedUserID:       pgtype.UUID{Bytes: accessedUserID, Valid: true},
						AccessedResourceType: pgtype.Text{String: "medical_record", Valid: true},
						AccessedResourceID:   pgtype.UUID{Bytes: accessedResourceID, Valid: true},
						AccessType:           pgtype.Text{String: "read", Valid: true},
						AccessReason:         pgtype.Text{String: "routine check", Valid: true},
						IsEmergencyAccess:    pgtype.Bool{Bool: false, Valid: true},
						IpAddress:            &ipAddr,
						UserAgent:            pgtype.Text{String: "Mozilla/5.0", Valid: true},
						Location:             locationBytes,
						AccessedAt:           pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetDataAccessLogs", ctx, sqlc.GetDataAccessLogsParams{
					AccessedUserID: uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
					Limit:          int32(10),
					Offset:         int32(0),
				}).Return(expectedRows, nil)
			},
			expectedLogs: []core.DataAccessLog{
				{
					ID:                   uuid.MustParse("423e4567-e89b-12d3-a456-426614174000"),
					AccessedByUserID:     &accessedByUserID,
					AccessedByRole:       stringPtr("doctor"),
					AccessedUserID:       accessedUserID,
					AccessedResourceType: stringPtr("medical_record"),
					AccessedResourceID:   &accessedResourceID,
					AccessType:           "read",
					AccessReason:         stringPtr("routine check"),
					IsEmergencyAccess:    false,
					IPAddress:            &ipStr,
					UserAgent:            stringPtr("Mozilla/5.0"),
					Location:             location,
					AccessedAt:           now,
				},
			},
			expectedError: nil,
		},
		{
			name:           "no logs found",
			accessedUserID: accessedUserID,
			limit:          10,
			offset:         0,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetDataAccessLogs", ctx, mock.Anything).Return([]sqlc.DataAccessLog{}, nil)
			},
			expectedLogs:  []core.DataAccessLog{},
			expectedError: nil,
		},
		{
			name:           "database error",
			accessedUserID: accessedUserID,
			limit:          10,
			offset:         0,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetDataAccessLogs", ctx, mock.Anything).Return([]sqlc.DataAccessLog{}, assert.AnError)
			},
			expectedLogs:  nil,
			expectedError: fmt.Errorf("get data access logs failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotLogs, err := repo.GetDataAccessLogs(ctx, tt.accessedUserID, tt.limit, tt.offset)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotLogs)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedLogs), len(gotLogs))
				for i, expected := range tt.expectedLogs {
					assertDataAccessLogEqual(t, expected, gotLogs[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuditRepository_GetDataAccessLogsByAccessor(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	accessedUserID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	accessedByUserID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	location := map[string]interface{}{"city": "Test City"}
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name             string
		accessedByUserID uuid.UUID
		limit            int
		offset           int
		mockSetup        func(*mocks.Querier)
		expectedLogs     []core.DataAccessLog
		expectedError    error
	}{
		{
			name:             "successful get data access logs by accessor",
			accessedByUserID: accessedByUserID,
			limit:            10,
			offset:           0,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.DataAccessLog{
					{
						ID:                   uuidPgtypeFromString("423e4567-e89b-12d3-a456-426614174000"),
						AccessedByUserID:     pgtype.UUID{Bytes: accessedByUserID, Valid: true},
						AccessedByRole:       pgtype.Text{String: "doctor", Valid: true},
						AccessedUserID:       pgtype.UUID{Bytes: accessedUserID, Valid: true},
						AccessedResourceType: pgtype.Text{String: "medical_record", Valid: true},
						AccessType:           pgtype.Text{String: "read", Valid: true},
						IpAddress:            &ipAddr,
						UserAgent:            pgtype.Text{String: "Mozilla/5.0", Valid: true},
						Location:             locationBytes,
						AccessedAt:           pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetAccessLogsByAccessedByUser", ctx, sqlc.GetAccessLogsByAccessedByUserParams{
					AccessedByUserID: uuidPgtypeFromString("223e4567-e89b-12d3-a456-426614174000"),
					Limit:            int32(10),
					Offset:           int32(0),
				}).Return(expectedRows, nil)
			},
			expectedLogs: []core.DataAccessLog{
				{
					ID:                   uuid.MustParse("423e4567-e89b-12d3-a456-426614174000"),
					AccessedByUserID:     &accessedByUserID,
					AccessedByRole:       stringPtr("doctor"),
					AccessedUserID:       accessedUserID,
					AccessedResourceType: stringPtr("medical_record"),
					AccessType:           "read",
					IPAddress:            &ipStr,
					UserAgent:            stringPtr("Mozilla/5.0"),
					Location:             location,
					AccessedAt:           now,
				},
			},
			expectedError: nil,
		},
		{
			name:             "database error",
			accessedByUserID: accessedByUserID,
			limit:            10,
			offset:           0,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetAccessLogsByAccessedByUser", ctx, mock.Anything).Return([]sqlc.DataAccessLog{}, assert.AnError)
			},
			expectedLogs:  nil,
			expectedError: fmt.Errorf("get data access logs by accessor failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotLogs, err := repo.GetDataAccessLogsByAccessor(ctx, tt.accessedByUserID, tt.limit, tt.offset)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotLogs)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedLogs), len(gotLogs))
				for i, expected := range tt.expectedLogs {
					assertDataAccessLogEqual(t, expected, gotLogs[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuditRepository_GetEmergencyAccessLogs(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	accessedUserID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	accessedByUserID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	location := map[string]interface{}{"city": "Test City"}
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name          string
		limit         int
		offset        int
		mockSetup     func(*mocks.Querier)
		expectedLogs  []core.DataAccessLog
		expectedError error
	}{
		{
			name:   "successful get emergency access logs",
			limit:  10,
			offset: 0,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.DataAccessLog{
					{
						ID:                   uuidPgtypeFromString("423e4567-e89b-12d3-a456-426614174000"),
						AccessedByUserID:     pgtype.UUID{Bytes: accessedByUserID, Valid: true},
						AccessedByRole:       pgtype.Text{String: "emergency_responder", Valid: true},
						AccessedUserID:       pgtype.UUID{Bytes: accessedUserID, Valid: true},
						AccessedResourceType: pgtype.Text{String: "medical_record", Valid: true},
						AccessType:           pgtype.Text{String: "read", Valid: true},
						AccessReason:         pgtype.Text{String: "emergency", Valid: true},
						IsEmergencyAccess:    pgtype.Bool{Bool: true, Valid: true},
						IpAddress:            &ipAddr,
						UserAgent:            pgtype.Text{String: "Mozilla/5.0", Valid: true},
						Location:             locationBytes,
						AccessedAt:           pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetEmergencyAccessLogs", ctx, sqlc.GetEmergencyAccessLogsParams{
					Limit:  int32(10),
					Offset: int32(0),
				}).Return(expectedRows, nil)
			},
			expectedLogs: []core.DataAccessLog{
				{
					ID:                   uuid.MustParse("423e4567-e89b-12d3-a456-426614174000"),
					AccessedByUserID:     &accessedByUserID,
					AccessedByRole:       stringPtr("emergency_responder"),
					AccessedUserID:       accessedUserID,
					AccessedResourceType: stringPtr("medical_record"),
					AccessType:           "read",
					AccessReason:         stringPtr("emergency"),
					IsEmergencyAccess:    true,
					IPAddress:            &ipStr,
					UserAgent:            stringPtr("Mozilla/5.0"),
					Location:             location,
					AccessedAt:           now,
				},
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			limit:  10,
			offset: 0,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetEmergencyAccessLogs", ctx, mock.Anything).Return([]sqlc.DataAccessLog{}, assert.AnError)
			},
			expectedLogs:  nil,
			expectedError: fmt.Errorf("get emergency access logs failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotLogs, err := repo.GetEmergencyAccessLogs(ctx, tt.limit, tt.offset)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotLogs)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedLogs), len(gotLogs))
				for i, expected := range tt.expectedLogs {
					assertDataAccessLogEqual(t, expected, gotLogs[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuditRepository_GetAccessLogsByResourceType(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	startDate := now.Add(-time.Hour * 24)
	endDate := now
	accessedUserID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	accessedByUserID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	location := map[string]interface{}{"city": "Test City"}
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name          string
		resourceType  string
		startDate     time.Time
		endDate       time.Time
		mockSetup     func(*mocks.Querier)
		expectedLogs  []core.DataAccessLog
		expectedError error
	}{
		{
			name:         "successful get access logs by resource type",
			resourceType: "medical_record",
			startDate:    startDate,
			endDate:      endDate,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.DataAccessLog{
					{
						ID:                   uuidPgtypeFromString("423e4567-e89b-12d3-a456-426614174000"),
						AccessedByUserID:     pgtype.UUID{Bytes: accessedByUserID, Valid: true},
						AccessedByRole:       pgtype.Text{String: "doctor", Valid: true},
						AccessedUserID:       pgtype.UUID{Bytes: accessedUserID, Valid: true},
						AccessedResourceType: pgtype.Text{String: "medical_record", Valid: true},
						AccessType:           pgtype.Text{String: "read", Valid: true},
						IpAddress:            &ipAddr,
						UserAgent:            pgtype.Text{String: "Mozilla/5.0", Valid: true},
						Location:             locationBytes,
						AccessedAt:           pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("SearchDataAccessLogs", ctx, mock.MatchedBy(func(p sqlc.SearchDataAccessLogsParams) bool {
					return p.Column4 == "medical_record" &&
						p.Column6.Time.Equal(startDate) &&
						p.Column7.Time.Equal(endDate) &&
						p.Limit == 10000 &&
						p.Offset == 0
				})).Return(expectedRows, nil)
			},
			expectedLogs: []core.DataAccessLog{
				{
					ID:                   uuid.MustParse("423e4567-e89b-12d3-a456-426614174000"),
					AccessedByUserID:     &accessedByUserID,
					AccessedByRole:       stringPtr("doctor"),
					AccessedUserID:       accessedUserID,
					AccessedResourceType: stringPtr("medical_record"),
					AccessType:           "read",
					IPAddress:            &ipStr,
					UserAgent:            stringPtr("Mozilla/5.0"),
					Location:             location,
					AccessedAt:           now,
				},
			},
			expectedError: nil,
		},
		{
			name:         "database error",
			resourceType: "medical_record",
			startDate:    startDate,
			endDate:      endDate,
			mockSetup: func(m *mocks.Querier) {
				m.On("SearchDataAccessLogs", ctx, mock.Anything).Return([]sqlc.DataAccessLog{}, assert.AnError)
			},
			expectedLogs:  nil,
			expectedError: fmt.Errorf("get access logs by resource type failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotLogs, err := repo.GetAccessLogsByResourceType(ctx, tt.resourceType, tt.startDate, tt.endDate)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotLogs)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedLogs), len(gotLogs))
				for i, expected := range tt.expectedLogs {
					assertDataAccessLogEqual(t, expected, gotLogs[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuditRepository_GetSuspiciousActivities(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	activityDetails := map[string]interface{}{"key": "value"}
	location := map[string]interface{}{"city": "Test City"}
	activityDetailsBytes, _ := json.Marshal(activityDetails)
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name          string
		threshold     int
		mockSetup     func(*mocks.Querier)
		expectedActs  []core.UserActivity
		expectedError error
	}{
		{
			name:      "successful get suspicious activities",
			threshold: 50,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.UserActivity{
					{
						ID:              uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
						UserID:          pgtype.UUID{Bytes: userID, Valid: true},
						ActivityType:    "suspicious_login",
						ActivityDetails: activityDetailsBytes,
						IpAddress:       &ipAddr,
						UserAgent:       pgtype.Text{String: "Mozilla/5.0", Valid: true},
						Location:        locationBytes,
						PerformedAt:     pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetRecentActivities", ctx, mock.MatchedBy(func(p sqlc.GetRecentActivitiesParams) bool {
					return p.Limit == int32(50) && p.Offset == 0
				})).Return(expectedRows, nil)
			},
			expectedActs: []core.UserActivity{
				{
					ID:              uuid.MustParse("323e4567-e89b-12d3-a456-426614174000"),
					UserID:          &userID,
					ActivityType:    "suspicious_login",
					ActivityDetails: activityDetails,
					IPAddress:       &ipStr,
					UserAgent:       stringPtr("Mozilla/5.0"),
					Location:        location,
					PerformedAt:     now,
				},
			},
			expectedError: nil,
		},
		{
			name:      "database error",
			threshold: 50,
			mockSetup: func(m *mocks.Querier) {
				m.On("GetRecentActivities", ctx, mock.Anything).Return([]sqlc.UserActivity{}, assert.AnError)
			},
			expectedActs:  nil,
			expectedError: fmt.Errorf("get suspicious activities failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotActs, err := repo.GetSuspiciousActivities(ctx, tt.threshold)

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

func TestAuditRepository_GetFailedLoginAttempts(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	activityDetails := map[string]interface{}{"reason": "invalid password"}
	location := map[string]interface{}{"city": "Test City"}
	activityDetailsBytes, _ := json.Marshal(activityDetails)
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name          string
		userID        *uuid.UUID
		within        time.Duration
		mockSetup     func(*mocks.Querier)
		expectedActs  []core.UserActivity
		expectedError error
	}{
		{
			name:   "successful get failed login attempts for specific user",
			userID: &userID,
			within: 24 * time.Hour,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.UserActivity{
					{
						ID:              uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
						UserID:          pgtype.UUID{Bytes: userID, Valid: true},
						ActivityType:    "login_failure",
						ActivityDetails: activityDetailsBytes,
						IpAddress:       &ipAddr,
						UserAgent:       pgtype.Text{String: "Mozilla/5.0", Valid: true},
						Location:        locationBytes,
						PerformedAt:     pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("SearchUserActivities", ctx, mock.MatchedBy(func(p sqlc.SearchUserActivitiesParams) bool {
					return p.Column1.Valid &&
						p.Column1.Bytes == userID &&
						p.Column2 == "login_failure" &&
						p.Limit == 1000 &&
						p.Offset == 0
				})).Return(expectedRows, nil)
			},
			expectedActs: []core.UserActivity{
				{
					ID:              uuid.MustParse("323e4567-e89b-12d3-a456-426614174000"),
					UserID:          &userID,
					ActivityType:    "login_failure",
					ActivityDetails: activityDetails,
					IPAddress:       &ipStr,
					UserAgent:       stringPtr("Mozilla/5.0"),
					Location:        location,
					PerformedAt:     now,
				},
			},
			expectedError: nil,
		},
		{
			name:   "successful get failed login attempts for all users",
			userID: nil,
			within: 24 * time.Hour,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.UserActivity{
					{
						ID:              uuidPgtypeFromString("323e4567-e89b-12d3-a456-426614174000"),
						UserID:          pgtype.UUID{Bytes: userID, Valid: true},
						ActivityType:    "login_failure",
						ActivityDetails: activityDetailsBytes,
						IpAddress:       &ipAddr,
						Location:        locationBytes,
						PerformedAt:     pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("SearchUserActivities", ctx, mock.MatchedBy(func(p sqlc.SearchUserActivitiesParams) bool {
					return !p.Column1.Valid &&
						p.Column2 == "login_failure" &&
						p.Limit == 1000 &&
						p.Offset == 0
				})).Return(expectedRows, nil)
			},
			expectedActs: []core.UserActivity{
				{
					ID:              uuid.MustParse("323e4567-e89b-12d3-a456-426614174000"),
					UserID:          &userID,
					ActivityType:    "login_failure",
					ActivityDetails: activityDetails,
					IPAddress:       &ipStr,
					Location:        location,
					PerformedAt:     now,
				},
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			userID: &userID,
			within: 24 * time.Hour,
			mockSetup: func(m *mocks.Querier) {
				m.On("SearchUserActivities", ctx, mock.Anything).Return([]sqlc.UserActivity{}, assert.AnError)
			},
			expectedActs:  nil,
			expectedError: fmt.Errorf("get failed login attempts failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotActs, err := repo.GetFailedLoginAttempts(ctx, tt.userID, tt.within)

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

func TestAuditRepository_GetUnauthorizedAccessAttempts(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	accessedUserID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	accessedByUserID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")
	ipStr := "192.168.1.1"
	ipAddr := netip.MustParseAddr(ipStr)
	location := map[string]interface{}{"city": "Test City"}
	locationBytes, _ := json.Marshal(location)

	tests := []struct {
		name          string
		within        time.Duration
		mockSetup     func(*mocks.Querier)
		expectedLogs  []core.DataAccessLog
		expectedError error
	}{
		{
			name:   "successful get unauthorized access attempts",
			within: 24 * time.Hour,
			mockSetup: func(m *mocks.Querier) {
				expectedRows := []sqlc.DataAccessLog{
					{
						ID:                   uuidPgtypeFromString("423e4567-e89b-12d3-a456-426614174000"),
						AccessedByUserID:     pgtype.UUID{Bytes: accessedByUserID, Valid: true},
						AccessedByRole:       pgtype.Text{String: "hacker", Valid: true},
						AccessedUserID:       pgtype.UUID{Bytes: accessedUserID, Valid: true},
						AccessedResourceType: pgtype.Text{String: "medical_record", Valid: true},
						AccessType:           pgtype.Text{String: "unauthorized", Valid: true},
						AccessReason:         pgtype.Text{String: "malicious attempt", Valid: true},
						IpAddress:            &ipAddr,
						UserAgent:            pgtype.Text{String: "BadBot/1.0", Valid: true},
						Location:             locationBytes,
						AccessedAt:           pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("SearchDataAccessLogs", ctx, mock.MatchedBy(func(p sqlc.SearchDataAccessLogsParams) bool {
					return p.Column3 == "unauthorized" &&
						p.Limit == 1000 &&
						p.Offset == 0
				})).Return(expectedRows, nil)
			},
			expectedLogs: []core.DataAccessLog{
				{
					ID:                   uuid.MustParse("423e4567-e89b-12d3-a456-426614174000"),
					AccessedByUserID:     &accessedByUserID,
					AccessedByRole:       stringPtr("hacker"),
					AccessedUserID:       accessedUserID,
					AccessedResourceType: stringPtr("medical_record"),
					AccessType:           "unauthorized",
					AccessReason:         stringPtr("malicious attempt"),
					IPAddress:            &ipStr,
					UserAgent:            stringPtr("BadBot/1.0"),
					Location:             location,
					AccessedAt:           now,
				},
			},
			expectedError: nil,
		},
		{
			name:   "database error",
			within: 24 * time.Hour,
			mockSetup: func(m *mocks.Querier) {
				m.On("SearchDataAccessLogs", ctx, mock.Anything).Return([]sqlc.DataAccessLog{}, assert.AnError)
			},
			expectedLogs:  nil,
			expectedError: fmt.Errorf("get unauthorized access attempts failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			gotLogs, err := repo.GetUnauthorizedAccessAttempts(ctx, tt.within)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, gotLogs)
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tt.expectedLogs), len(gotLogs))
				for i, expected := range tt.expectedLogs {
					assertDataAccessLogEqual(t, expected, gotLogs[i])
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestAuditRepository_ArchiveOldLogs(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name          string
		olderThan     time.Duration
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:      "successful archive old logs",
			olderThan: 90 * 24 * time.Hour,
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteOldDataAccessLogs", ctx, mock.AnythingOfType("pgtype.Timestamp")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "database error",
			olderThan: 90 * 24 * time.Hour,
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteOldDataAccessLogs", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("archive old logs failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			err := repo.ArchiveOldLogs(ctx, tt.olderThan)

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

func TestAuditRepository_DeleteArchivedLogs(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name          string
		olderThan     time.Duration
		mockSetup     func(*mocks.Querier)
		expectedError error
	}{
		{
			name:      "successful delete archived logs",
			olderThan: 365 * 24 * time.Hour,
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteOldDataAccessLogs", ctx, mock.AnythingOfType("pgtype.Timestamp")).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "database error",
			olderThan: 365 * 24 * time.Hour,
			mockSetup: func(m *mocks.Querier) {
				m.On("DeleteOldDataAccessLogs", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("delete archived logs failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := &auditRepository{querier: mockQuerier}

			err := repo.DeleteArchivedLogs(ctx, tt.olderThan)

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
