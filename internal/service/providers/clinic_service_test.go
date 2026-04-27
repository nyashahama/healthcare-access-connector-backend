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

type mockClinicRepository struct {
	createClinicFunc       func(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error)
	getClinicByIDFunc     func(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
	updateClinicFunc       func(ctx context.Context, clinic providers.Clinic) error
	deleteClinicFunc        func(ctx context.Context, id uuid.UUID) error
	verifyClinicFunc     func(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
	getClinicByOwnerFunc func(ctx context.Context, ownerUserID uuid.UUID) (*providers.Clinic, error)
}

func (m *mockClinicRepository) CreateClinic(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error) {
	if m.createClinicFunc != nil {
		return m.createClinicFunc(ctx, clinic, createdBy, ownerUserID)
	}
	return providers.Clinic{}, nil
}

func (m *mockClinicRepository) GetClinicByID(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
	if m.getClinicByIDFunc != nil {
		return m.getClinicByIDFunc(ctx, id)
	}
	return providers.Clinic{}, domain.ErrClinicNotFound
}

func (m *mockClinicRepository) UpdateClinic(ctx context.Context, clinic providers.Clinic) error {
	if m.updateClinicFunc != nil {
		return m.updateClinicFunc(ctx, clinic)
	}
	return nil
}

func (m *mockClinicRepository) DeleteClinic(ctx context.Context, id uuid.UUID) error {
	if m.deleteClinicFunc != nil {
		return m.deleteClinicFunc(ctx, id)
	}
	return nil
}

func (m *mockClinicRepository) VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	if m.verifyClinicFunc != nil {
		return m.verifyClinicFunc(ctx, id, verifiedBy, notes)
	}
	return nil
}

func (m *mockClinicRepository) RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	return nil
}

func (m *mockClinicRepository) UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func (m *mockClinicRepository) DeactivateClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepository) ReactivateClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepository) SearchClinics(ctx context.Context, params providers.ClinicSearchParams) ([]providers.ClinicSearchResult, error) {
	return nil, nil
}

func (m *mockClinicRepository) GetClinics(ctx context.Context) ([]providers.Clinic, error) {
	return nil, nil
}

func (m *mockClinicRepository) GetClinicByOwner(ctx context.Context, ownerUserID uuid.UUID) (*providers.Clinic, error) {
	if m.getClinicByOwnerFunc != nil {
		return m.getClinicByOwnerFunc(ctx, ownerUserID)
	}
	return nil, domain.ErrClinicNotFound
}

func (m *mockClinicRepository) GetClinicWithOwnerInfo(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicWithOwner, error) {
	return nil, nil
}

func (m *mockClinicRepository) UpdateClinicOwner(ctx context.Context, clinicID, newOwnerUserID uuid.UUID) error {
	return nil
}

func (m *mockClinicRepository) GetClinicVerificationStatus(ctx context.Context, clinicID uuid.UUID) (*providers.ClinicVerification, error) {
	return nil, nil
}

type mockUserRepository struct {
	getUserByIDFunc func(ctx context.Context, id uuid.UUID) (core.User, error)
}

func (m *mockUserRepository) GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error) {
	if m.getUserByIDFunc != nil {
		return m.getUserByIDFunc(ctx, id)
	}
	return core.User{}, domain.ErrUserNotFound
}

func (m *mockUserRepository) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepository) UpdateUser(ctx context.Context, user core.User) error {
	return nil
}

func (m *mockUserRepository) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepository) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepository) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepository) SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepository) CountUsers(ctx context.Context, role string) (int64, error) {
	return 0, nil
}

func (m *mockUserRepository) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	return core.User{}, patients.PatientProfile{}, nil
}

func (m *mockUserRepository) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	return nil
}

func (m *mockUserRepository) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	return nil
}

func (m *mockUserRepository) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	return nil
}

func (m *mockUserRepository) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	return nil
}

func (m *mockUserRepository) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	return nil
}

func (m *mockUserRepository) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepository) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error) {
	return nil, nil
}

type mockAuthRepository struct {
	updateUserPrimaryClinicFunc      func(ctx context.Context, userID, clinicID uuid.UUID) error
	updateUserOnboardingStepFunc      func(ctx context.Context, userID uuid.UUID, step string) error
}

func (m *mockAuthRepository) UpdateUserPrimaryClinic(ctx context.Context, userID, clinicID uuid.UUID) error {
	if m.updateUserPrimaryClinicFunc != nil {
		return m.updateUserPrimaryClinicFunc(ctx, userID, clinicID)
	}
	return nil
}

func (m *mockAuthRepository) UpdateUserOnboardingStep(ctx context.Context, userID uuid.UUID, step string) error {
	if m.updateUserOnboardingStepFunc != nil {
		return m.updateUserOnboardingStepFunc(ctx, userID, step)
	}
	return nil
}

func (m *mockAuthRepository) CreateUser(ctx context.Context, user core.User, passwordHash string) (core.User, error) {
	return core.User{}, nil
}

func (m *mockAuthRepository) GetUserByEmail(ctx context.Context, email string) (core.User, string, error) {
	return core.User{}, "", nil
}

func (m *mockAuthRepository) GetUserByPhone(ctx context.Context, phone string) (core.User, error) {
	return core.User{}, nil
}

func (m *mockAuthRepository) GetUserByPhoneWithHash(ctx context.Context, phone string) (core.User, string, error) {
	return core.User{}, "", nil
}

func (m *mockAuthRepository) GetUserByVerificationToken(ctx context.Context, token string) (core.User, string, error) {
	return core.User{}, "", nil
}

func (m *mockAuthRepository) GetUserByPasswordResetToken(ctx context.Context, token string) (core.User, string, error) {
	return core.User{}, "", nil
}

func (m *mockAuthRepository) SetVerificationToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	return nil
}

func (m *mockAuthRepository) SetPasswordResetToken(ctx context.Context, id uuid.UUID, token string, expires time.Time) error {
	return nil
}

func (m *mockAuthRepository) VerifyUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockAuthRepository) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	return nil
}

func (m *mockAuthRepository) UpdateLastLogin(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockAuthRepository) CompleteUserOnboarding(ctx context.Context, userID uuid.UUID) error {
	return nil
}

func (m *mockAuthRepository) GetProviderWithClinic(ctx context.Context, userID uuid.UUID) (*core.ProviderWithClinic, error) {
	return nil, nil
}

func (m *mockAuthRepository) GetUserClinics(ctx context.Context, userID uuid.UUID) ([]core.UserClinic, error) {
	return nil, nil
}

type mockAuditRepository struct{}

func (m *mockAuditRepository) LogUserActivity(ctx context.Context, activity core.UserActivity) error {
	return nil
}

func (m *mockAuditRepository) GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error) {
	return nil, nil
}

func (m *mockAuditRepository) GetResourceActivities(ctx context.Context, resourceType string, resourceID uuid.UUID) ([]core.UserActivity, error) {
	return nil, nil
}

func (m *mockAuditRepository) LogDataAccess(ctx context.Context, access core.DataAccessLog) error {
	return nil
}

type mockStaffRepository struct{}

func (m *mockStaffRepository) CreateStaffMember(ctx context.Context, staff providers.ClinicStaff) (providers.ClinicStaff, error) {
	return providers.ClinicStaff{}, nil
}

func (m *mockStaffRepository) GetStaffByID(ctx context.Context, id uuid.UUID) (providers.ClinicStaff, error) {
	return providers.ClinicStaff{}, nil
}

func (m *mockStaffRepository) GetStaffByUserID(ctx context.Context, userID uuid.UUID) (providers.ClinicStaff, error) {
	return providers.ClinicStaff{}, nil
}

func (m *mockStaffRepository) GetAllClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepository) UpdateStaffMember(ctx context.Context, staff providers.ClinicStaff) error {
	return nil
}

func (m *mockStaffRepository) DeleteStaffMember(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockStaffRepository) GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]providers.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepository) GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepository) StaffExists(ctx context.Context, id uuid.UUID) (bool, error) {
	return false, nil
}

func (m *mockStaffRepository) CreateStaffInvitation(ctx context.Context, invitation providers.StaffInvitation) (providers.ClinicStaff, error) {
	return providers.ClinicStaff{}, nil
}

func (m *mockStaffRepository) GetStaffInvitationByToken(ctx context.Context, token string) (*providers.StaffInvitationDetails, error) {
	return nil, nil
}

func (m *mockStaffRepository) AcceptStaffInvitation(ctx context.Context, token string, userID uuid.UUID) error {
	return nil
}

func (m *mockStaffRepository) DeclineStaffInvitation(ctx context.Context, token string) error {
	return nil
}

func (m *mockStaffRepository) GetPendingInvitationsByClinic(ctx context.Context, clinicID uuid.UUID) ([]providers.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepository) GetStaffInvitationsByEmail(ctx context.Context, email string) ([]providers.StaffInvitationDetails, error) {
	return nil, nil
}

func (m *mockStaffRepository) CancelStaffInvitation(ctx context.Context, token string) error {
	return nil
}

func (m *mockStaffRepository) ResendStaffInvitation(ctx context.Context, invitationID uuid.UUID) (string, error) {
	return "", nil
}

func (m *mockStaffRepository) GetStaffByUserAndClinic(ctx context.Context, userID, clinicID uuid.UUID) (*providers.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepository) UpdateStaffPermissions(ctx context.Context, staffID uuid.UUID, permissions providers.StaffPermissions) error {
	return nil
}

func (m *mockStaffRepository) ExpireStaffInvitations(ctx context.Context) error {
	return nil
}

func (m *mockStaffRepository) CheckStaffEmailExists(ctx context.Context, clinicID uuid.UUID, email string) (bool, error) {
	return false, nil
}

type mockCacheService struct {
	getFunc    func(ctx context.Context, key string, dest interface{}) error
	setFunc    func(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	deleteFunc func(ctx context.Context, key string) error
	existsFunc func(ctx context.Context, key string) (bool, error)
}

func (m *mockCacheService) Get(ctx context.Context, key string, dest interface{}) error {
	if m.getFunc != nil {
		return m.getFunc(ctx, key, dest)
	}
	return cache.ErrCacheMiss
}

func (m *mockCacheService) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	if m.setFunc != nil {
		return m.setFunc(ctx, key, value, ttl)
	}
	return nil
}

func (m *mockCacheService) Delete(ctx context.Context, key string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, key)
	}
	return nil
}

func (m *mockCacheService) Exists(ctx context.Context, key string) (bool, error) {
	if m.existsFunc != nil {
		return m.existsFunc(ctx, key)
	}
	return false, nil
}

func (m *mockCacheService) Ping(ctx context.Context) error {
	return nil
}

func (m *mockCacheService) IsAvailable() bool {
	return true
}

func newClinicServiceForTest(t *testing.T) *clinicService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &clinicService{
		clinicRepo: &mockClinicRepository{},
		auditRepo:  &mockAuditRepository{},
		userRepo:   &mockUserRepository{},
		authRepo:   &mockAuthRepository{},
		staffRepo:  &mockStaffRepository{},
		cache:      &mockCacheService{},
		logger:     &logger,
	}
}

func newClinicServiceWithMocks(t *testing.T) (*clinicService, *mockClinicRepository, *mockUserRepository, *mockAuthRepository) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockClinicRepo := &mockClinicRepository{}
	mockUserRepo := &mockUserRepository{}
	mockAuthRepo := &mockAuthRepository{}

	return &clinicService{
		clinicRepo: mockClinicRepo,
		auditRepo:  &mockAuditRepository{},
		userRepo:   mockUserRepo,
		authRepo:   mockAuthRepo,
		staffRepo:  &mockStaffRepository{},
		cache:      &mockCacheService{},
		logger:     &logger,
	}, mockClinicRepo, mockUserRepo, mockAuthRepo
}

func TestClinicService_RegisterClinic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockClinicRepo, mockUserRepo, _ := newClinicServiceWithMocks(t)

		ownerUserID := uuid.New()
		createdBy := uuid.New()
		email := "clinic@example.com"
		phone := "+27123456789"

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{
				ID:    id,
				Email: &email,
				Phone: &phone,
				Role:  "provider",
			}, nil
		}

		mockClinicRepo.createClinicFunc = func(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error) {
			clinic.ID = uuid.New()
			return clinic, nil
		}

		clinic := providers.Clinic{
			ClinicName:     "Test Clinic",
			ClinicType:     "private",
			PhysicalAddress: "123 Test St",
		}

		result, err := svc.RegisterClinic(context.Background(), clinic, createdBy, ownerUserID)
		require.NoError(t, err)
		assert.NotEqual(t, uuid.Nil, result.ID)
		assert.Equal(t, "Test Clinic", result.ClinicName)
	})

	t.Run("validation error - missing clinic name", func(t *testing.T) {
		svc, _, _, _ := newClinicServiceWithMocks(t)

		clinic := providers.Clinic{
			ClinicType:      "private",
			PhysicalAddress: "123 Test St",
		}

		_, err := svc.RegisterClinic(context.Background(), clinic, uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Clinic name is required")
	})

	t.Run("validation error - missing clinic type", func(t *testing.T) {
		svc, _, _, _ := newClinicServiceWithMocks(t)

		clinic := providers.Clinic{
			ClinicName:      "Test Clinic",
			PhysicalAddress: "123 Test St",
		}

		_, err := svc.RegisterClinic(context.Background(), clinic, uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Clinic type is required")
	})

	t.Run("validation error - missing physical address", func(t *testing.T) {
		svc, _, _, _ := newClinicServiceWithMocks(t)

		clinic := providers.Clinic{
			ClinicName: "Test Clinic",
			ClinicType: "private",
		}

		_, err := svc.RegisterClinic(context.Background(), clinic, uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Physical address is required")
	})

	t.Run("validation error - owner not found", func(t *testing.T) {
		svc, _, mockUserRepo, _ := newClinicServiceWithMocks(t)

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{}, domain.ErrUserNotFound
		}

		clinic := providers.Clinic{
			ClinicName:      "Test Clinic",
			ClinicType:     "private",
			PhysicalAddress: "123 Test St",
		}

		_, err := svc.RegisterClinic(context.Background(), clinic, uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Owner user not found")
	})

	t.Run("validation error - invalid owner role", func(t *testing.T) {
		svc, _, mockUserRepo, _ := newClinicServiceWithMocks(t)

		email := "patient@example.com"

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{
				ID:    id,
				Email: &email,
				Role:  "patient",
			}, nil
		}

		clinic := providers.Clinic{
			ClinicName:      "Test Clinic",
			ClinicType:     "private",
			PhysicalAddress: "123 Test St",
		}

		_, err := svc.RegisterClinic(context.Background(), clinic, uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "provider role")
	})

	t.Run("duplicate registration number", func(t *testing.T) {
		svc, _, mockUserRepo, _ := newClinicServiceWithMocks(t)

		email := "clinic@example.com"

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{
				ID:    id,
				Email: &email,
				Role:  "provider",
			}, nil
		}

		mockClinicRepo := &mockClinicRepository{}
		mockClinicRepo.createClinicFunc = func(ctx context.Context, clinic providers.Clinic, createdBy, ownerUserID uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{}, domain.ErrDuplicateRegistrationNumber
		}

		svc.clinicRepo = mockClinicRepo

		clinic := providers.Clinic{
			ClinicName:      "Test Clinic",
			ClinicType:     "private",
			PhysicalAddress: "123 Test St",
		}

		_, err := svc.RegisterClinic(context.Background(), clinic, uuid.New(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Registration number already exists")
	})
}

func TestClinicService_GetClinicByID(t *testing.T) {
	t.Run("found", func(t *testing.T) {
		svc, mockClinicRepo, _, _ := newClinicServiceWithMocks(t)

		clinicID := uuid.New()
		expectedClinic := providers.Clinic{
			ID:              clinicID,
			ClinicName:      "Test Clinic",
			ClinicType:      "private",
			IsVerified:      true,
		}

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return expectedClinic, nil
		}

		result, err := svc.GetClinicByID(context.Background(), clinicID)
		require.NoError(t, err)
		assert.Equal(t, clinicID, result.ID)
		assert.Equal(t, "Test Clinic", result.ClinicName)
	})

	t.Run("not found", func(t *testing.T) {
		svc, mockClinicRepo, _, _ := newClinicServiceWithMocks(t)

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{}, domain.ErrClinicNotFound
		}

		_, err := svc.GetClinicByID(context.Background(), uuid.New())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Clinic not found")
	})
}

func TestClinicService_UpdateClinic(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockClinicRepo, _, _ := newClinicServiceWithMocks(t)

		clinicID := uuid.New()

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{
				ID:              clinicID,
				ClinicName:      "Old Name",
				ClinicType:      "private",
				PhysicalAddress: "123 Test St",
			}, nil
		}

		mockClinicRepo.updateClinicFunc = func(ctx context.Context, clinic providers.Clinic) error {
			return nil
		}

		clinic := providers.Clinic{
			ID:              clinicID,
			ClinicName:      "New Name",
			ClinicType:      "private",
			PhysicalAddress: "123 Test St",
		}

		err := svc.UpdateClinic(context.Background(), clinic)
		require.NoError(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		svc, mockClinicRepo, _, _ := newClinicServiceWithMocks(t)

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{}, domain.ErrClinicNotFound
		}

		clinic := providers.Clinic{
			ID:         uuid.New(),
			ClinicName: "Test",
			ClinicType: "private",
		}

		err := svc.UpdateClinic(context.Background(), clinic)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Clinic not found")
	})

	t.Run("validation error - missing clinic name", func(t *testing.T) {
		svc, _, _, _ := newClinicServiceWithMocks(t)

		clinic := providers.Clinic{
			ID:         uuid.New(),
			ClinicName: "",
			ClinicType: "private",
		}

		err := svc.UpdateClinic(context.Background(), clinic)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Clinic name is required")
	})

	t.Run("validation error - missing clinic type", func(t *testing.T) {
		svc, _, _, _ := newClinicServiceWithMocks(t)

		clinic := providers.Clinic{
			ID:         uuid.New(),
			ClinicName: "Test",
			ClinicType: "",
		}

		err := svc.UpdateClinic(context.Background(), clinic)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Clinic type is required")
	})
}

func TestClinicService_VerifyClinic(t *testing.T) {
	t.Run("success - admin", func(t *testing.T) {
		svc, mockClinicRepo, mockUserRepo, _ := newClinicServiceWithMocks(t)

		clinicID := uuid.New()
		adminUserID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			if id == adminUserID {
				return core.User{
					ID:   adminUserID,
					Role: "system_admin",
				}, nil
			}
			return core.User{}, domain.ErrUserNotFound
		}

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{
				ID:              clinicID,
				ClinicName:      "Test Clinic",
				VerificationStatus: "pending",
			}, nil
		}

		mockClinicRepo.verifyClinicFunc = func(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
			return nil
		}

		err := svc.VerifyClinic(context.Background(), clinicID, adminUserID, "Approved")
		require.NoError(t, err)
	})

	t.Run("success - ngo_partner", func(t *testing.T) {
		svc, mockClinicRepo, mockUserRepo, _ := newClinicServiceWithMocks(t)

		clinicID := uuid.New()
		ngoUserID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			if id == ngoUserID {
				return core.User{
					ID:   ngoUserID,
					Role: "ngo_partner",
				}, nil
			}
			return core.User{}, domain.ErrUserNotFound
		}

		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{
				ID:              clinicID,
				ClinicName:      "Test Clinic",
				VerificationStatus: "pending",
			}, nil
		}

		mockClinicRepo.verifyClinicFunc = func(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
			return nil
		}

		err := svc.VerifyClinic(context.Background(), clinicID, ngoUserID, "Approved")
		require.NoError(t, err)
	})

	t.Run("unauthorized - non-admin", func(t *testing.T) {
		svc, _, mockUserRepo, _ := newClinicServiceWithMocks(t)

		clinicID := uuid.New()
		providerUserID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{
				ID:   providerUserID,
				Role: "provider",
			}, nil
		}

		err := svc.VerifyClinic(context.Background(), clinicID, providerUserID, "Approved")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Only system administrators")
	})

	t.Run("unauthorized - patient", func(t *testing.T) {
		svc, _, mockUserRepo, _ := newClinicServiceWithMocks(t)

		clinicID := uuid.New()
		patientUserID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{
				ID:   patientUserID,
				Role: "patient",
			}, nil
		}

		err := svc.VerifyClinic(context.Background(), clinicID, patientUserID, "Approved")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Only system administrators")
	})

	t.Run("not found", func(t *testing.T) {
		svc, _, mockUserRepo, _ := newClinicServiceWithMocks(t)

		adminUserID := uuid.New()

		mockUserRepo.getUserByIDFunc = func(ctx context.Context, id uuid.UUID) (core.User, error) {
			return core.User{
				ID:   adminUserID,
				Role: "system_admin",
			}, nil
		}

		mockClinicRepo := &mockClinicRepository{}
		mockClinicRepo.getClinicByIDFunc = func(ctx context.Context, id uuid.UUID) (providers.Clinic, error) {
			return providers.Clinic{}, domain.ErrClinicNotFound
		}
		svc.clinicRepo = mockClinicRepo

		err := svc.VerifyClinic(context.Background(), uuid.New(), adminUserID, "Approved")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Clinic not found")
	})
}

var _ repository.ClinicRepository = (*mockClinicRepository)(nil)
var _ repository.UserRepository = (*mockUserRepository)(nil)
var _ repository.AuthRepository = (*mockAuthRepository)(nil)
var _ repository.AuditRepository = (*mockAuditRepository)(nil)
var _ repository.StaffRepository = (*mockStaffRepository)(nil)
var _ cache.Service = (*mockCacheService)(nil)