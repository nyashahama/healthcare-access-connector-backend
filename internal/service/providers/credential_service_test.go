package providers

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	domaincore "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	domainproviders "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type mockCredentialRepository struct {
	getStaffCredentialsFunc func(ctx context.Context, staffID uuid.UUID) ([]domainproviders.ProfessionalCredential, error)
	getCredentialByIDFunc func(ctx context.Context, id uuid.UUID) (domainproviders.ProfessionalCredential, error)
	deleteCredentialFunc  func(ctx context.Context, id uuid.UUID) error
}

func (m *mockCredentialRepository) CreateCredential(ctx context.Context, credential domainproviders.ProfessionalCredential) (domainproviders.ProfessionalCredential, error) {
	return credential, nil
}

func (m *mockCredentialRepository) GetCredentialByID(ctx context.Context, id uuid.UUID) (domainproviders.ProfessionalCredential, error) {
	return m.getCredentialByIDFunc(ctx, id)
}

func (m *mockCredentialRepository) GetStaffCredentials(ctx context.Context, staffID uuid.UUID) ([]domainproviders.ProfessionalCredential, error) {
	if m.getStaffCredentialsFunc != nil {
		return m.getStaffCredentialsFunc(ctx, staffID)
	}
	return nil, nil
}

func (m *mockCredentialRepository) DeleteCredential(ctx context.Context, id uuid.UUID) error {
	if m.deleteCredentialFunc != nil {
		return m.deleteCredentialFunc(ctx, id)
	}
	return nil
}

type mockStaffRepositoryForCredential struct {
	getStaffByIDFunc func(ctx context.Context, id uuid.UUID) (domainproviders.ClinicStaff, error)
}

func (m *mockStaffRepositoryForCredential) CreateStaffMember(ctx context.Context, staff domainproviders.ClinicStaff) (domainproviders.ClinicStaff, error) {
	return domainproviders.ClinicStaff{}, nil
}
func (m *mockStaffRepositoryForCredential) GetStaffByID(ctx context.Context, id uuid.UUID) (domainproviders.ClinicStaff, error) {
	return m.getStaffByIDFunc(ctx, id)
}
func (m *mockStaffRepositoryForCredential) GetStaffByUserID(ctx context.Context, userID uuid.UUID) (domainproviders.ClinicStaff, error) {
	return domainproviders.ClinicStaff{}, nil
}
func (m *mockStaffRepositoryForCredential) GetAllClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicStaff, error) {
	return nil, nil
}
func (m *mockStaffRepositoryForCredential) UpdateStaffMember(ctx context.Context, staff domainproviders.ClinicStaff) error {
	return nil
}
func (m *mockStaffRepositoryForCredential) DeleteStaffMember(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockStaffRepositoryForCredential) GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]domainproviders.ClinicStaff, error) {
	return nil, nil
}
func (m *mockStaffRepositoryForCredential) GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicStaff, error) {
	return nil, nil
}
func (m *mockStaffRepositoryForCredential) StaffExists(ctx context.Context, id uuid.UUID) (bool, error) {
	return false, nil
}
func (m *mockStaffRepositoryForCredential) CreateStaffInvitation(ctx context.Context, invitation domainproviders.StaffInvitation) (domainproviders.ClinicStaff, error) {
	return domainproviders.ClinicStaff{}, nil
}
func (m *mockStaffRepositoryForCredential) GetStaffInvitationByToken(ctx context.Context, token string) (*domainproviders.StaffInvitationDetails, error) {
	return nil, nil
}
func (m *mockStaffRepositoryForCredential) AcceptStaffInvitation(ctx context.Context, token string, userID uuid.UUID) error {
	return nil
}
func (m *mockStaffRepositoryForCredential) DeclineStaffInvitation(ctx context.Context, token string) error {
	return nil
}
func (m *mockStaffRepositoryForCredential) GetPendingInvitationsByClinic(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicStaff, error) {
	return nil, nil
}
func (m *mockStaffRepositoryForCredential) GetStaffInvitationsByEmail(ctx context.Context, email string) ([]domainproviders.StaffInvitationDetails, error) {
	return nil, nil
}
func (m *mockStaffRepositoryForCredential) CancelStaffInvitation(ctx context.Context, token string) error {
	return nil
}
func (m *mockStaffRepositoryForCredential) ResendStaffInvitation(ctx context.Context, invitationID uuid.UUID) (string, error) {
	return "", nil
}
func (m *mockStaffRepositoryForCredential) CheckStaffEmailExists(ctx context.Context, clinicID uuid.UUID, email string) (bool, error) {
	return false, nil
}
func (m *mockStaffRepositoryForCredential) GetStaffByUserAndClinic(ctx context.Context, userID, clinicID uuid.UUID) (*domainproviders.ClinicStaff, error) {
	return nil, nil
}
func (m *mockStaffRepositoryForCredential) UpdateStaffPermissions(ctx context.Context, staffID uuid.UUID, permissions domainproviders.StaffPermissions) error {
	return nil
}
func (m *mockStaffRepositoryForCredential) ExpireStaffInvitations(ctx context.Context) error {
	return nil
}

type mockAuditRepositoryForCredential struct{}

func (m *mockAuditRepositoryForCredential) LogUserActivity(ctx context.Context, activity domaincore.UserActivity) error {
	return nil
}
func (m *mockAuditRepositoryForCredential) GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]domaincore.UserActivity, error) {
	return nil, nil
}
func (m *mockAuditRepositoryForCredential) LogDataAccess(ctx context.Context, access domaincore.DataAccessLog) error {
	return nil
}

type mockCacheServiceForCredential struct {
	deletedKeys []string
}

func (m *mockCacheServiceForCredential) Get(ctx context.Context, key string, dest interface{}) error {
	return cache.ErrCacheMiss
}
func (m *mockCacheServiceForCredential) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return nil
}
func (m *mockCacheServiceForCredential) Delete(ctx context.Context, key string) error {
	m.deletedKeys = append(m.deletedKeys, key)
	return nil
}
func (m *mockCacheServiceForCredential) Exists(ctx context.Context, key string) (bool, error) {
	return false, nil
}
func (m *mockCacheServiceForCredential) Ping(ctx context.Context) error {
	return nil
}
func (m *mockCacheServiceForCredential) IsAvailable() bool {
	return true
}

var _ repository.CredentialRepository = (*mockCredentialRepository)(nil)
var _ repository.StaffRepository = (*mockStaffRepositoryForCredential)(nil)
var _ repository.AuditRepository = (*mockAuditRepositoryForCredential)(nil)
var _ cache.Service = (*mockCacheServiceForCredential)(nil)

func TestCredentialServiceDeleteCredentialUsesGetByIDForAuditAndCacheInvalidation(t *testing.T) {
	logger := zerolog.New(io.Discard)
	credentialID := uuid.New()
	staffID := uuid.New()
	cacheSvc := &mockCacheServiceForCredential{}

	svc := &credentialService{
		credentialRepo: &mockCredentialRepository{
			getCredentialByIDFunc: func(ctx context.Context, id uuid.UUID) (domainproviders.ProfessionalCredential, error) {
				require.Equal(t, credentialID, id)
				return domainproviders.ProfessionalCredential{
					ID:             credentialID,
					StaffID:        staffID,
					CredentialType: "medical_license",
				}, nil
			},
			deleteCredentialFunc: func(ctx context.Context, id uuid.UUID) error {
				require.Equal(t, credentialID, id)
				return nil
			},
		},
		staffRepo: &mockStaffRepositoryForCredential{
			getStaffByIDFunc: func(ctx context.Context, id uuid.UUID) (domainproviders.ClinicStaff, error) {
				require.Equal(t, staffID, id)
				return domainproviders.ClinicStaff{ID: staffID}, nil
			},
		},
		auditRepo: &mockAuditRepositoryForCredential{},
		cache:     cacheSvc,
		logger:    &logger,
	}

	err := svc.DeleteCredential(context.Background(), credentialID)
	require.NoError(t, err)
	require.Contains(t, cacheSvc.deletedKeys, "credentials:staff:"+staffID.String())
}

func TestCredentialServiceGetStaffCredentialsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	staffID := uuid.New()

	svc := &credentialService{
		credentialRepo: &mockCredentialRepository{
			getStaffCredentialsFunc: func(ctx context.Context, got uuid.UUID) ([]domainproviders.ProfessionalCredential, error) {
				require.Equal(t, staffID, got)
				return []domainproviders.ProfessionalCredential{
					{
						ID:             uuid.New(),
						StaffID:        staffID,
						CredentialType: "medical_license",
					},
				}, nil
			},
		},
		staffRepo: &mockStaffRepositoryForCredential{
			getStaffByIDFunc: func(ctx context.Context, got uuid.UUID) (domainproviders.ClinicStaff, error) {
				require.Equal(t, staffID, got)
				return domainproviders.ClinicStaff{ID: staffID}, nil
			},
		},
		auditRepo: &mockAuditRepositoryForCredential{},
		cache:     nil,
		logger:    &logger,
	}

	result, err := svc.GetStaffCredentials(context.Background(), staffID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, staffID, result[0].StaffID)
	require.Equal(t, "medical_license", result[0].CredentialType)
}
