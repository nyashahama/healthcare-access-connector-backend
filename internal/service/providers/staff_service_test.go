package providers

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockClinicRepositoryForStaff struct {
	getClinicByIDFunc        func(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
}

func (m *mockClinicRepositoryForStaff) GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
	if m.getClinicByIDFunc != nil {
		return m.getClinicByIDFunc(ctx, id)
	}
	return providers.Clinic{}, domain.ErrClinicNotFound
}

func (m *mockClinicRepositoryForStaff) CreateClinic(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error) {
	return providers.Clinic{}, nil
}

func (m *mockClinicRepositoryForStaff) UpdateClinic(ctx context.Context, clinic providers.Clinic) error {
	return nil
}

func (m *mockClinicRepositoryForStaff) DeleteClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepositoryForStaff) VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	return nil
}

func (m *mockClinicRepositoryForStaff) RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	return nil
}

func (m *mockClinicRepositoryForStaff) UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func (m *mockClinicRepositoryForStaff) DeactivateClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepositoryForStaff) ReactivateClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepositoryForStaff) SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error) {
	return nil, nil
}

func (m *mockClinicRepositoryForStaff) GetClinics(ctx context.Context) ([]providers.Clinic, error) {
	return nil, nil
}

func (m *mockClinicRepositoryForStaff) GetClinicByOwner(ctx context.Context, ownerUserID uuid.UUID) (*providers.Clinic, error) {
	return nil, nil
}

func (m *mockClinicRepositoryForStaff) GetClinicWithOwnerInfo(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicWithOwner, error) {
	return nil, nil
}

func (m *mockClinicRepositoryForStaff) UpdateClinicOwner(ctx context.Context, clinicID, newOwnerUserID uuid.UUID) error {
	return nil
}

func (m *mockClinicRepositoryForStaff) GetClinicVerificationStatus(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicVerification, error) {
	return nil, nil
}

type mockUserRepositoryForStaff struct {
	getUserByIDFunc func(ctx context.Context, id uuid.UUID) (core.User, error)
}

func (m *mockUserRepositoryForStaff) GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error) {
	if m.getUserByIDFunc != nil {
		return m.getUserByIDFunc(ctx, id)
	}
	return core.User{}, domain.ErrUserNotFound
}

func (m *mockUserRepositoryForStaff) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepositoryForStaff) UpdateUser(ctx context.Context, user core.User) error {
	return nil
}

func (m *mockUserRepositoryForStaff) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepositoryForStaff) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepositoryForStaff) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepositoryForStaff) SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepositoryForStaff) CountUsers(ctx context.Context, role string) (int64, error) {
	return 0, nil
}

func (m *mockUserRepositoryForStaff) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	return core.User{}, patients.PatientProfile{}, nil
}

func (m *mockUserRepositoryForStaff) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	return nil
}

func (m *mockUserRepositoryForStaff) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	return nil
}

func (m *mockUserRepositoryForStaff) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	return nil
}

func (m *mockUserRepositoryForStaff) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	return nil
}

func (m *mockUserRepositoryForStaff) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	return nil
}

func (m *mockUserRepositoryForStaff) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepositoryForStaff) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error) {
	return nil, nil
}

type mockAuditRepositoryForStaff struct{}

func (m *mockAuditRepositoryForStaff) LogUserActivity(ctx context.Context, activity core.UserActivity) error {
	return nil
}

func (m *mockAuditRepositoryForStaff) GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error) {
	return nil, nil
}

func (m *mockAuditRepositoryForStaff) GetResourceActivities(ctx context.Context, resourceType string, resourceID uuid.UUID) ([]core.UserActivity, error) {
	return nil, nil
}

func (m *mockAuditRepositoryForStaff) LogDataAccess(ctx context.Context, access core.DataAccessLog) error {
	return nil
}

type mockStaffRepositoryFull struct {
	createStaffInvitationFunc    func(ctx context.Context, invitation providers.StaffInvitation) (providers.ClinicStaff, error)
	getStaffInvitationByTokenFunc func(ctx context.Context, token string) (*providers.StaffInvitationDetails, error)
	acceptStaffInvitationFunc   func(ctx context.Context, token string, userID uuid.UUID) error
	getStaffByUserAndClinicFunc   func(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error)
	getStaffByIDFunc            func(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error)
	getAllClinicStaffFunc       func(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	getPendingInvitationsByClinicFunc func(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error)
	deleteStaffMemberFunc        func(ctx context.Context, id uuid.UUID) error
	checkStaffEmailExistsFunc    func(ctx context.Context, clinicID uuid.UUID, email string) (bool, error)
}

func (m *mockStaffRepositoryFull) CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error) {
	return providers.ClinicStaff{}, nil
}

func (m *mockStaffRepositoryFull) GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error) {
	if m.getStaffByIDFunc != nil {
		return m.getStaffByIDFunc(ctx, id)
	}
	return providers.ClinicStaff{}, domain.ErrStaffNotFound
}

func (m *mockStaffRepositoryFull) GetAllClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	if m.getAllClinicStaffFunc != nil {
		return m.getAllClinicStaffFunc(ctx, clinicID)
	}
	return nil, nil
}

func (m *mockStaffRepositoryFull) GetStaffByUserID(ctx context.Context, userID uuid.UUID) (providers.ClinicStaff, error) {
	return providers.ClinicStaff{}, nil
}

func (m *mockStaffRepositoryFull) UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error {
	return nil
}

func (m *mockStaffRepositoryFull) DeleteStaffMember(ctx context.Context, id uuid.UUID) error {
	if m.deleteStaffMemberFunc != nil {
		return m.deleteStaffMemberFunc(ctx, id)
	}
	return nil
}

func (m *mockStaffRepositoryFull) GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepositoryFull) GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepositoryFull) StaffExists(ctx context.Context, id uuid.UUID) (bool, error) {
	return false, nil
}

func (m *mockStaffRepositoryFull) CreateStaffInvitation(ctx context.Context, invitation providers.StaffInvitation) (providers.ClinicStaff, error) {
	if m.createStaffInvitationFunc != nil {
		return m.createStaffInvitationFunc(ctx, invitation)
	}
	return providers.ClinicStaff{}, nil
}

func (m *mockStaffRepositoryFull) GetStaffInvitationByToken(ctx context.Context, token string) (*providers.StaffInvitationDetails, error) {
	if m.getStaffInvitationByTokenFunc != nil {
		return m.getStaffInvitationByTokenFunc(ctx, token)
	}
	return nil, domain.ErrInvitationNotFound
}

func (m *mockStaffRepositoryFull) AcceptStaffInvitation(ctx context.Context, token string, userID uuid.UUID) error {
	if m.acceptStaffInvitationFunc != nil {
		return m.acceptStaffInvitationFunc(ctx, token, userID)
	}
	return nil
}

func (m *mockStaffRepositoryFull) DeclineStaffInvitation(ctx context.Context, token string) error {
	return nil
}

func (m *mockStaffRepositoryFull) GetPendingInvitationsByClinic(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	if m.getPendingInvitationsByClinicFunc != nil {
		return m.getPendingInvitationsByClinicFunc(ctx, clinicID)
	}
	return nil, nil
}

func (m *mockStaffRepositoryFull) GetStaffInvitationsByEmail(ctx context.Context, email string) ([]providers.StaffInvitationDetails, error) {
	return nil, nil
}

func (m *mockStaffRepositoryFull) CancelStaffInvitation(ctx context.Context, token string) error {
	return nil
}

func (m *mockStaffRepositoryFull) ResendStaffInvitation(ctx context.Context, invitationID uuid.UUID) (string, error) {
	return "", nil
}

func (m *mockStaffRepositoryFull) GetStaffByUserAndClinic(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
	if m.getStaffByUserAndClinicFunc != nil {
		return m.getStaffByUserAndClinicFunc(ctx, userID, clinicID)
	}
	return nil, domain.ErrStaffNotFound
}

func (m *mockStaffRepositoryFull) UpdateStaffPermissions(ctx context.Context, staffID uuid.UUID, permissions providers.StaffPermissions) error {
	return nil
}

func (m *mockStaffRepositoryFull) ExpireStaffInvitations(ctx context.Context) error {
	return nil
}

func (m *mockStaffRepositoryFull) CheckStaffEmailExists(ctx context.Context, clinicID uuid.UUID, email string) (bool, error) {
	if m.checkStaffEmailExistsFunc != nil {
		return m.checkStaffEmailExistsFunc(ctx, clinicID, email)
	}
	return false, nil
}

type mockCacheServiceForStaff struct{}

func (m *mockCacheServiceForStaff) Get(ctx context.Context, key string, dest interface{}) error {
	return cache.ErrCacheMiss
}

func (m *mockCacheServiceForStaff) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return nil
}

func (m *mockCacheServiceForStaff) Delete(ctx context.Context, key string) error {
	return nil
}

func (m *mockCacheServiceForStaff) Exists(ctx context.Context, key string) (bool, error) {
	return false, nil
}

func (m *mockCacheServiceForStaff) Ping(ctx context.Context) error {
	return nil
}

func (m *mockCacheServiceForStaff) IsAvailable() bool {
	return true
}

func newStaffServiceForTest(t *testing.T) *staffService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &staffService{
		staffRepo:  &mockStaffRepositoryFull{},
		clinicRepo: &mockClinicRepositoryForStaff{},
		userRepo:   &mockUserRepositoryForStaff{},
		auditRepo:  &mockAuditRepositoryForStaff{},
		cache:      &mockCacheServiceForStaff{},
		logger:     &logger,
	}
}

func newStaffServiceWithMocks(t *testing.T) (*staffService, *mockStaffRepositoryFull, *mockClinicRepositoryForStaff, *mockUserRepositoryForStaff) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockStaffRepo := &mockStaffRepositoryFull{}
	mockClinicRepo := &mockClinicRepositoryForStaff{}
	mockUserRepo := &mockUserRepositoryForStaff{}

	return &staffService{
		staffRepo:  mockStaffRepo,
		clinicRepo: mockClinicRepo,
		userRepo:   mockUserRepo,
		auditRepo:  &mockAuditRepositoryForStaff{},
		cache:      &mockCacheServiceForStaff{},
		logger:     &logger,
	}, mockStaffRepo, mockClinicRepo, mockUserRepo
}

func TestStaffService_InviteStaff(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockStaffRepo, mockClinicRepo, mockUserRepo := newStaffServiceWithMocks(t)

		clinicID := uuid.New()
		invitedBy := uuid.New()
		inviterStaffID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{ID: id}, nil
		}

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{
				ID:         clinicID,
				IsVerified: true,
			}, nil
		}

		mockStaffRepo.getStaffByUserAndClinicFunc = func(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
			return &providers.ClinicStaff{
				ID:            inviterStaffID,
				ClinicID:      clinicID,
				UserID:        &invitedBy,
				CanManageStaff: true,
			}, nil
		}

		mockStaffRepo.checkStaffEmailExistsFunc = func(ctx context.Context, clinicID uuid.UUID, email string) (bool, error) {
			return false, nil
		}

		mockStaffRepo.createStaffInvitationFunc = func(ctx context.Context, invitation providers.StaffInvitation) (providers.ClinicStaff, error) {
			email := invitation.WorkEmail
			return providers.ClinicStaff{
				ID:         uuid.New(),
				ClinicID:   clinicID,
				WorkEmail:  &email,
			}, nil
		}

		invitation := providers.StaffInvitation{
			ClinicID:   clinicID,
			WorkEmail:  "newstaff@example.com",
			FirstName: "New",
			LastName:  "Staff",
			StaffRole: providers.StaffRoleDoctor,
			InvitedBy: invitedBy,
		}

		result, err := svc.CreateStaffInvitation(context.Background(), invitation)
		require.NoError(t, err)
		assert.Equal(t, "newstaff@example.com", *result.WorkEmail)
	})

	t.Run("unauthorized - inviter not staff", func(t *testing.T) {
		svc, _, mockClinicRepo, _ := newStaffServiceWithMocks(t)

		clinicID := uuid.New()
		invitedBy := uuid.New()

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{
				ID:         clinicID,
				IsVerified: true,
			}, nil
		}

		mockStaffRepo := &mockStaffRepositoryFull{}
		mockStaffRepo.getStaffByUserAndClinicFunc = func(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
			return nil, domain.ErrStaffNotFound
		}
		svc.staffRepo = mockStaffRepo

		invitation := providers.StaffInvitation{
			ClinicID:   clinicID,
			WorkEmail:  "newstaff@example.com",
			FirstName: "New",
			LastName:  "Staff",
			StaffRole: providers.StaffRoleDoctor,
			InvitedBy: invitedBy,
		}

		_, err := svc.CreateStaffInvitation(context.Background(), invitation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "You are not authorized")
	})

	t.Run("unauthorized - inviter lacks permission", func(t *testing.T) {
		svc, _, mockClinicRepo, _ := newStaffServiceWithMocks(t)

		clinicID := uuid.New()
		invitedBy := uuid.New()
		inviterStaffID := uuid.New()

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{
				ID:         clinicID,
				IsVerified: true,
			}, nil
		}

		mockStaffRepo := &mockStaffRepositoryFull{}
		mockStaffRepo.getStaffByUserAndClinicFunc = func(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
			return &providers.ClinicStaff{
				ID:            inviterStaffID,
				ClinicID:      clinicID,
				UserID:        &invitedBy,
				CanManageStaff: false,
			}, nil
		}
		svc.staffRepo = mockStaffRepo

		invitation := providers.StaffInvitation{
			ClinicID:   clinicID,
			WorkEmail:  "newstaff@example.com",
			FirstName: "New",
			LastName:  "Staff",
			StaffRole: providers.StaffRoleDoctor,
			InvitedBy: invitedBy,
		}

		_, err := svc.CreateStaffInvitation(context.Background(), invitation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "You do not have permission")
	})

	t.Run("duplicate email", func(t *testing.T) {
		svc, _, mockClinicRepo, _ := newStaffServiceWithMocks(t)

		clinicID := uuid.New()
		invitedBy := uuid.New()
		inviterStaffID := uuid.New()

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{
				ID:         clinicID,
				IsVerified: true,
			}, nil
		}

		mockStaffRepo := &mockStaffRepositoryFull{}
		mockStaffRepo.getStaffByUserAndClinicFunc = func(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
			return &providers.ClinicStaff{
				ID:            inviterStaffID,
				ClinicID:      clinicID,
				UserID:        &invitedBy,
				CanManageStaff: true,
			}, nil
		}

		mockStaffRepo.checkStaffEmailExistsFunc = func(ctx context.Context, clinicID uuid.UUID, email string) (bool, error) {
			return true, nil
		}
		svc.staffRepo = mockStaffRepo

		invitation := providers.StaffInvitation{
			ClinicID:   clinicID,
			WorkEmail:  "existing@example.com",
			FirstName: "New",
			LastName:  "Staff",
			StaffRole: providers.StaffRoleDoctor,
			InvitedBy: invitedBy,
		}

		_, err := svc.CreateStaffInvitation(context.Background(), invitation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})

	t.Run("clinic not verified", func(t *testing.T) {
		svc, _, mockClinicRepo, _ := newStaffServiceWithMocks(t)

		clinicID := uuid.New()
		invitedBy := uuid.New()

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{
				ID:         clinicID,
				IsVerified: false,
			}, nil
		}

		invitation := providers.StaffInvitation{
			ClinicID:   clinicID,
			WorkEmail:  "newstaff@example.com",
			FirstName: "New",
			LastName:  "Staff",
			StaffRole: providers.StaffRoleDoctor,
			InvitedBy: invitedBy,
		}

		_, err := svc.CreateStaffInvitation(context.Background(), invitation)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Clinic must be verified")
	})
}

func TestStaffService_CreateStaffMemberNilUserID(t *testing.T) {
	svc := newStaffServiceForTest(t)

	staff := providers.ClinicStaff{
		ClinicID:   uuid.New(),
		UserID:     nil,
		FirstName:  "Jane",
		LastName:   "Doe",
		StaffRole:  providers.StaffRoleDoctor,
	}

	_, err := svc.CreateStaffMember(context.Background(), staff)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "User ID is required")
}

func TestStaffService_GetPendingInvitationsByClinicWithoutCache(t *testing.T) {
	svc, mockStaffRepo, _, _ := newStaffServiceWithMocks(t)
	svc.cache = nil

	clinicID := uuid.New()
	expectedID := uuid.New()
	mockStaffRepo.getAllClinicStaffFunc = nil
	mockStaffRepo.getPendingInvitationsByClinicFunc = func(ctx context.Context, got uuid.UUID) ([]providers.ClinicStaff, error) {
		require.Equal(t, clinicID, got)
		return []providers.ClinicStaff{{ID: expectedID, ClinicID: clinicID}}, nil
	}

	result, err := svc.GetPendingInvitationsByClinic(context.Background(), clinicID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, expectedID, result[0].ID)
}

func TestStaffService_GetStaffByUserAndClinicWithoutCache(t *testing.T) {
	svc, mockStaffRepo, _, _ := newStaffServiceWithMocks(t)
	svc.cache = nil

	userID := uuid.New()
	clinicID := uuid.New()
	staffID := uuid.New()
	mockStaffRepo.getStaffByUserAndClinicFunc = func(ctx context.Context, gotUserID, gotClinicID uuid.UUID) (*providers.ClinicStaff, error) {
		require.Equal(t, userID, gotUserID)
		require.Equal(t, clinicID, gotClinicID)
		return &providers.ClinicStaff{ID: staffID, ClinicID: clinicID, UserID: &userID}, nil
	}

	result, err := svc.GetStaffByUserAndClinic(context.Background(), userID, clinicID)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, staffID, result.ID)
}

func TestStaffService_GetAllClinicStaffWithoutCache(t *testing.T) {
	svc, mockStaffRepo, _, _ := newStaffServiceWithMocks(t)
	svc.cache = nil

	clinicID := uuid.New()
	staffID := uuid.New()
	mockStaffRepo.getAllClinicStaffFunc = func(ctx context.Context, got uuid.UUID) ([]providers.ClinicStaff, error) {
		require.Equal(t, clinicID, got)
		return []providers.ClinicStaff{{ID: staffID, ClinicID: clinicID}}, nil
	}

	result, err := svc.GetAllClinicStaff(context.Background(), clinicID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, staffID, result[0].ID)
}

func TestStaffService_AcceptInvitation(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockStaffRepo, _, mockUserRepo := newStaffServiceWithMocks(t)

		token := "valid-token"
		userID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{ID: id}, nil
		}

		mockStaffRepo.getStaffInvitationByTokenFunc = func(ctx context.Context, token string) (*providers.StaffInvitationDetails, error) {
			clinicID := uuid.New()
			return &providers.StaffInvitationDetails{
				StaffInvitation: providers.StaffInvitation{
					ClinicID:         clinicID,
					WorkEmail:        "newstaff@example.com",
					StaffRole:        providers.StaffRoleDoctor,
					InvitationToken:  "valid-token",
				},
			}, nil
		}

		mockStaffRepo.acceptStaffInvitationFunc = func(ctx context.Context, token string, userID uuid.UUID) error {
			return nil
		}

		mockStaffRepo.getStaffByUserAndClinicFunc = func(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
			return &providers.ClinicStaff{
				ID:               uuid.New(),
				ClinicID:         clinicID,
				UserID:           &userID,
				WorkEmail:        testStringPtr("newstaff@example.com"),
				StaffRole:        providers.StaffRoleDoctor,
				InvitationStatus: testStringPtr(providers.InvitationStatusAccepted),
			}, nil
		}

		result, err := svc.AcceptStaffInvitation(context.Background(), token, userID)
		require.NoError(t, err)
		assert.NotNil(t, result.ID)
	})

	t.Run("invalid token", func(t *testing.T) {
		svc, mockStaffRepo, mockClinicRepo, mockUserRepo := newStaffServiceWithMocks(t)
		_ = mockStaffRepo
		_ = mockClinicRepo
		_ = mockUserRepo

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{}, domain.ErrUserNotFound
		}

		_, err := svc.AcceptStaffInvitation(context.Background(), "invalid-token", uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "User not found")
	})

	t.Run("expired token", func(t *testing.T) {
		svc, mockStaffRepo, _, mockUserRepo := newStaffServiceWithMocks(t)

		token := "expired-token"
		userID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{ID: id}, nil
		}

		mockStaffRepo.getStaffInvitationByTokenFunc = func(ctx context.Context, token string) (*providers.StaffInvitationDetails, error) {
			return &providers.StaffInvitationDetails{
				StaffInvitation: providers.StaffInvitation{
					ClinicID:         uuid.New(),
					WorkEmail:        "newstaff@example.com",
					InvitationToken: "expired-token",
				},
			}, nil
		}

		mockStaffRepo.acceptStaffInvitationFunc = func(ctx context.Context, token string, userID uuid.UUID) error {
			return domain.ErrInvitationExpired
		}

		_, err := svc.AcceptStaffInvitation(context.Background(), token, userID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})
}

func TestStaffService_RemoveStaff(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockStaffRepo, _, _ := newStaffServiceWithMocks(t)

		staffID := uuid.New()
		clinicID := uuid.New()

		mockStaffRepo.getStaffByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error) {
			return providers.ClinicStaff{
				ID:         staffID,
				ClinicID:   clinicID,
				StaffRole: providers.StaffRoleDoctor,
			}, nil
		}

		mockStaffRepo.deleteStaffMemberFunc = func(ctx context.Context, id uuid.UUID) error {
			return nil
		}

		err := svc.DeleteStaffMember(context.Background(), staffID)
		require.NoError(t, err)
	})

	t.Run("success - delete owner", func(t *testing.T) {
		svc, mockStaffRepo, _, _ := newStaffServiceWithMocks(t)

		clinicID := uuid.New()
		staffID := uuid.New()

		mockStaffRepo.getStaffByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error) {
			return providers.ClinicStaff{
				ID:         staffID,
				ClinicID:   clinicID,
				StaffRole: providers.StaffRoleOwner,
			}, nil
		}

		mockStaffRepo.deleteStaffMemberFunc = func(ctx context.Context, id uuid.UUID) error {
			return nil
		}

		err := svc.DeleteStaffMember(context.Background(), staffID)
		require.NoError(t, err)
	})
}

func testStringPtr(s string) *string {
	return &s
}

var _ repository.ClinicRepository = (*mockClinicRepositoryForStaff)(nil)
var _ repository.UserRepository = (*mockUserRepositoryForStaff)(nil)
var _ repository.StaffRepository = (*mockStaffRepositoryFull)(nil)
var _ cache.Service = (*mockCacheServiceForStaff)(nil)
