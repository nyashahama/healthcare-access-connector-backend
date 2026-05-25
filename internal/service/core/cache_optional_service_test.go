package core

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	domaincore "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type mockConsentRepositoryForCoreCache struct {
	getPrivacyConsentFunc    func(ctx context.Context, userID uuid.UUID) (domaincore.PrivacyConsent, error)
	updatePrivacyConsentFunc func(ctx context.Context, consent domaincore.PrivacyConsent) error
}

func (m *mockConsentRepositoryForCoreCache) CreatePrivacyConsent(ctx context.Context, consent domaincore.PrivacyConsent) (domaincore.PrivacyConsent, error) {
	return consent, nil
}

func (m *mockConsentRepositoryForCoreCache) GetPrivacyConsent(ctx context.Context, userID uuid.UUID) (domaincore.PrivacyConsent, error) {
	return m.getPrivacyConsentFunc(ctx, userID)
}

func (m *mockConsentRepositoryForCoreCache) UpdatePrivacyConsent(ctx context.Context, consent domaincore.PrivacyConsent) error {
	if m.updatePrivacyConsentFunc != nil {
		return m.updatePrivacyConsentFunc(ctx, consent)
	}
	return nil
}

type mockNotificationRepositoryForCoreCache struct {
	getPreferencesFunc    func(ctx context.Context, userID uuid.UUID) (domaincore.NotificationPreferences, error)
	updatePreferencesFunc func(ctx context.Context, prefs domaincore.NotificationPreferences) error
}

func (m *mockNotificationRepositoryForCoreCache) CreateNotificationPreferences(ctx context.Context, prefs domaincore.NotificationPreferences) (domaincore.NotificationPreferences, error) {
	return prefs, nil
}

func (m *mockNotificationRepositoryForCoreCache) GetNotificationPreferences(ctx context.Context, userID uuid.UUID) (domaincore.NotificationPreferences, error) {
	return m.getPreferencesFunc(ctx, userID)
}

func (m *mockNotificationRepositoryForCoreCache) UpdateNotificationPreferences(ctx context.Context, prefs domaincore.NotificationPreferences) error {
	if m.updatePreferencesFunc != nil {
		return m.updatePreferencesFunc(ctx, prefs)
	}
	return nil
}

func (m *mockNotificationRepositoryForCoreCache) DeleteNotificationPreferences(ctx context.Context, userID uuid.UUID) error {
	return nil
}

type mockAuditRepositoryForCoreCache struct {
	getUserActivitiesFunc func(ctx context.Context, userID uuid.UUID, limit, offset int) ([]domaincore.UserActivity, error)
}

func (m *mockAuditRepositoryForCoreCache) LogUserActivity(ctx context.Context, activity domaincore.UserActivity) error {
	return nil
}

func (m *mockAuditRepositoryForCoreCache) GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]domaincore.UserActivity, error) {
	return m.getUserActivitiesFunc(ctx, userID, limit, offset)
}

func (m *mockAuditRepositoryForCoreCache) LogDataAccess(ctx context.Context, access domaincore.DataAccessLog) error {
	return nil
}

var _ repository.ConsentRepository = (*mockConsentRepositoryForCoreCache)(nil)
var _ repository.NotificationRepository = (*mockNotificationRepositoryForCoreCache)(nil)
var _ repository.AuditRepository = (*mockAuditRepositoryForCoreCache)(nil)

func TestConsentServiceGetPrivacyConsentWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	version := "1.0"
	expected := domaincore.PrivacyConsent{
		ID:                       uuid.New(),
		UserID:                   userID,
		HealthDataConsent:        true,
		HealthDataConsentVersion: &version,
	}

	svc := &consentService{
		consentRepo: &mockConsentRepositoryForCoreCache{
			getPrivacyConsentFunc: func(ctx context.Context, got uuid.UUID) (domaincore.PrivacyConsent, error) {
				require.Equal(t, userID, got)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetPrivacyConsent(context.Background(), userID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
}

func TestConsentServiceUpdatePrivacyConsentWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	version := "1.0"
	consent := domaincore.PrivacyConsent{
		ID:                       uuid.New(),
		UserID:                   userID,
		HealthDataConsent:        true,
		HealthDataConsentVersion: &version,
		UpdatedAt:                time.Now(),
	}

	svc := &consentService{
		consentRepo: &mockConsentRepositoryForCoreCache{
			getPrivacyConsentFunc: func(ctx context.Context, got uuid.UUID) (domaincore.PrivacyConsent, error) {
				require.Equal(t, userID, got)
				return consent, nil
			},
			updatePrivacyConsentFunc: func(ctx context.Context, got domaincore.PrivacyConsent) error {
				require.Equal(t, consent.ID, got.ID)
				return nil
			},
		},
		auditRepo: &mockAuditRepositoryForCoreCache{},
		cache:     nil,
		logger:    &logger,
	}

	err := svc.UpdatePrivacyConsent(context.Background(), consent)
	require.NoError(t, err)
}

func TestNotificationServiceGetPreferencesWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	expected := domaincore.NotificationPreferences{
		ID:             uuid.New(),
		UserID:         userID,
		SMSEnabled:     true,
		EmailEnabled:   true,
		PushEnabled:    true,
		HealthTips:     true,
		EmergencyAlerts: true,
	}

	svc := &notificationService{
		notificationRepo: &mockNotificationRepositoryForCoreCache{
			getPreferencesFunc: func(ctx context.Context, got uuid.UUID) (domaincore.NotificationPreferences, error) {
				require.Equal(t, userID, got)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetPreferences(context.Background(), userID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
}

func TestNotificationServiceUpdatePreferencesWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	prefs := domaincore.NotificationPreferences{
		ID:               uuid.New(),
		UserID:           uuid.New(),
		SMSEnabled:       true,
		EmailEnabled:     true,
		PushEnabled:      true,
		HealthTips:       true,
		SystemMaintenance: true,
	}

	svc := &notificationService{
		notificationRepo: &mockNotificationRepositoryForCoreCache{
			updatePreferencesFunc: func(ctx context.Context, got domaincore.NotificationPreferences) error {
				require.Equal(t, prefs.ID, got.ID)
				return nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	err := svc.UpdatePreferences(context.Background(), prefs)
	require.NoError(t, err)
}

func TestAuditServiceGetUserActivitiesWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	expected := []domaincore.UserActivity{
		{
			ID:           uuid.New(),
			UserID:       &userID,
			ActivityType: "login",
			PerformedAt:  time.Now(),
		},
	}

	svc := &auditService{
		auditRepo: &mockAuditRepositoryForCoreCache{
			getUserActivitiesFunc: func(ctx context.Context, got uuid.UUID, limit, offset int) ([]domaincore.UserActivity, error) {
				require.Equal(t, userID, got)
				require.Equal(t, 25, limit)
				require.Equal(t, 0, offset)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetUserActivities(context.Background(), userID, 25, 0)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}
