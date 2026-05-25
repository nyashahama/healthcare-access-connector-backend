package providers

import (
	"context"
	"io"
	"testing"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	domainproviders "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type mockServiceRepository struct {
	createClinicServiceFunc     func(ctx context.Context, service domainproviders.ClinicService) (domainproviders.ClinicService, error)
	getServiceByIDFunc          func(ctx context.Context, id uuid.UUID) (domainproviders.ClinicService, error)
	getClinicServicesFunc       func(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicService, error)
	getActiveClinicServicesFunc func(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicService, error)
	checkServiceNameExistsFunc  func(ctx context.Context, clinicID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error)
}

func (m *mockServiceRepository) CreateClinicService(ctx context.Context, service domainproviders.ClinicService) (domainproviders.ClinicService, error) {
	if m.createClinicServiceFunc != nil {
		return m.createClinicServiceFunc(ctx, service)
	}
	return service, nil
}

func (m *mockServiceRepository) GetServiceByID(ctx context.Context, id uuid.UUID) (domainproviders.ClinicService, error) {
	if m.getServiceByIDFunc != nil {
		return m.getServiceByIDFunc(ctx, id)
	}
	return domainproviders.ClinicService{}, nil
}

func (m *mockServiceRepository) UpdateClinicService(ctx context.Context, service domainproviders.ClinicService) error {
	return nil
}

func (m *mockServiceRepository) DeleteClinicService(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockServiceRepository) GetClinicServices(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicService, error) {
	if m.getClinicServicesFunc != nil {
		return m.getClinicServicesFunc(ctx, clinicID)
	}
	return nil, nil
}

func (m *mockServiceRepository) GetActiveClinicServices(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicService, error) {
	if m.getActiveClinicServicesFunc != nil {
		return m.getActiveClinicServicesFunc(ctx, clinicID)
	}
	return nil, nil
}

func (m *mockServiceRepository) ServiceExists(ctx context.Context, id uuid.UUID) (bool, error) {
	return false, nil
}

func (m *mockServiceRepository) CheckServiceNameExists(ctx context.Context, clinicID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error) {
	if m.checkServiceNameExistsFunc != nil {
		return m.checkServiceNameExistsFunc(ctx, clinicID, name, excludeID)
	}
	return false, nil
}

var _ repository.ServiceRepository = (*mockServiceRepository)(nil)

type mockClinicRepositoryForCatalog struct {
	getClinicByIDFunc func(ctx context.Context, id uuid.UUID) (domainproviders.Clinic, error)
}

func (m *mockClinicRepositoryForCatalog) GetClinicByID(ctx context.Context, id uuid.UUID) (domainproviders.Clinic, error) {
	if m.getClinicByIDFunc != nil {
		return m.getClinicByIDFunc(ctx, id)
	}
	return domainproviders.Clinic{}, nil
}

func (m *mockClinicRepositoryForCatalog) CreateClinic(ctx context.Context, clinic domainproviders.Clinic, createdBy, ownerUserID uuid.UUID) (domainproviders.Clinic, error) {
	return domainproviders.Clinic{}, nil
}

func (m *mockClinicRepositoryForCatalog) UpdateClinic(ctx context.Context, clinic domainproviders.Clinic) error {
	return nil
}

func (m *mockClinicRepositoryForCatalog) DeleteClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepositoryForCatalog) VerifyClinic(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	return nil
}

func (m *mockClinicRepositoryForCatalog) RejectClinicVerification(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error {
	return nil
}

func (m *mockClinicRepositoryForCatalog) UpdateClinicVerificationStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func (m *mockClinicRepositoryForCatalog) DeactivateClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepositoryForCatalog) ReactivateClinic(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockClinicRepositoryForCatalog) SearchClinics(ctx context.Context, params domainproviders.ClinicSearchParams) ([]domainproviders.ClinicSearchResult, error) {
	return nil, nil
}

func (m *mockClinicRepositoryForCatalog) GetClinics(ctx context.Context) ([]domainproviders.Clinic, error) {
	return nil, nil
}

func (m *mockClinicRepositoryForCatalog) GetClinicByOwner(ctx context.Context, ownerUserID uuid.UUID) (*domainproviders.Clinic, error) {
	return nil, nil
}

func (m *mockClinicRepositoryForCatalog) GetClinicWithOwnerInfo(ctx context.Context, clinicID uuid.UUID) (*domainproviders.ClinicWithOwner, error) {
	return nil, nil
}

func (m *mockClinicRepositoryForCatalog) UpdateClinicOwner(ctx context.Context, clinicID, newOwnerUserID uuid.UUID) error {
	return nil
}

func (m *mockClinicRepositoryForCatalog) GetClinicVerificationStatus(ctx context.Context, clinicID uuid.UUID) (*domainproviders.ClinicVerification, error) {
	return nil, nil
}

var _ repository.ClinicRepository = (*mockClinicRepositoryForCatalog)(nil)

type mockStaffRepositoryForCatalog struct {
	staffExistsFunc func(ctx context.Context, id uuid.UUID) (bool, error)
}

func (m *mockStaffRepositoryForCatalog) CreateStaffMember(ctx context.Context, staff domainproviders.ClinicStaff) (domainproviders.ClinicStaff, error) {
	return domainproviders.ClinicStaff{}, nil
}

func (m *mockStaffRepositoryForCatalog) GetStaffByID(ctx context.Context, id uuid.UUID) (domainproviders.ClinicStaff, error) {
	return domainproviders.ClinicStaff{}, nil
}

func (m *mockStaffRepositoryForCatalog) GetStaffByUserID(ctx context.Context, userID uuid.UUID) (domainproviders.ClinicStaff, error) {
	return domainproviders.ClinicStaff{}, nil
}

func (m *mockStaffRepositoryForCatalog) GetAllClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepositoryForCatalog) UpdateStaffMember(ctx context.Context, staff domainproviders.ClinicStaff) error {
	return nil
}

func (m *mockStaffRepositoryForCatalog) DeleteStaffMember(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockStaffRepositoryForCatalog) GetClinicStaff(ctx context.Context, clinicID uuid.UUID, role *string) ([]domainproviders.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepositoryForCatalog) GetActiveClinicStaff(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepositoryForCatalog) StaffExists(ctx context.Context, id uuid.UUID) (bool, error) {
	if m.staffExistsFunc != nil {
		return m.staffExistsFunc(ctx, id)
	}
	return false, nil
}

func (m *mockStaffRepositoryForCatalog) CreateStaffInvitation(ctx context.Context, invitation domainproviders.StaffInvitation) (domainproviders.ClinicStaff, error) {
	return domainproviders.ClinicStaff{}, nil
}

func (m *mockStaffRepositoryForCatalog) GetStaffInvitationByToken(ctx context.Context, token string) (*domainproviders.StaffInvitationDetails, error) {
	return nil, nil
}

func (m *mockStaffRepositoryForCatalog) AcceptStaffInvitation(ctx context.Context, token string, userID uuid.UUID) error {
	return nil
}

func (m *mockStaffRepositoryForCatalog) DeclineStaffInvitation(ctx context.Context, token string) error {
	return nil
}

func (m *mockStaffRepositoryForCatalog) GetPendingInvitationsByClinic(ctx context.Context, clinicID uuid.UUID) ([]domainproviders.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepositoryForCatalog) GetStaffInvitationsByEmail(ctx context.Context, email string) ([]domainproviders.StaffInvitationDetails, error) {
	return nil, nil
}

func (m *mockStaffRepositoryForCatalog) CancelStaffInvitation(ctx context.Context, token string) error {
	return nil
}

func (m *mockStaffRepositoryForCatalog) ResendStaffInvitation(ctx context.Context, invitationID uuid.UUID) (string, error) {
	return "", nil
}

func (m *mockStaffRepositoryForCatalog) GetStaffByUserAndClinic(ctx context.Context, userID, clinicID uuid.UUID) (*domainproviders.ClinicStaff, error) {
	return nil, nil
}

func (m *mockStaffRepositoryForCatalog) UpdateStaffPermissions(ctx context.Context, staffID uuid.UUID, permissions domainproviders.StaffPermissions) error {
	return nil
}

func (m *mockStaffRepositoryForCatalog) ExpireStaffInvitations(ctx context.Context) error {
	return nil
}

func (m *mockStaffRepositoryForCatalog) CheckStaffEmailExists(ctx context.Context, clinicID uuid.UUID, email string) (bool, error) {
	return false, nil
}

var _ repository.StaffRepository = (*mockStaffRepositoryForCatalog)(nil)

type mockAuditRepositoryForCatalog struct{}

func (m *mockAuditRepositoryForCatalog) LogUserActivity(ctx context.Context, activity core.UserActivity) error {
	return nil
}

func (m *mockAuditRepositoryForCatalog) GetUserActivities(ctx context.Context, userID uuid.UUID, limit, offset int) ([]core.UserActivity, error) {
	return nil, nil
}

func (m *mockAuditRepositoryForCatalog) GetResourceActivities(ctx context.Context, resourceType string, resourceID uuid.UUID) ([]core.UserActivity, error) {
	return nil, nil
}

func (m *mockAuditRepositoryForCatalog) LogDataAccess(ctx context.Context, access core.DataAccessLog) error {
	return nil
}

func TestServiceCatalogServiceGetServiceByIDWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	serviceID := uuid.New()
	expected := domainproviders.ClinicService{
		ID:          serviceID,
		ClinicID:    uuid.New(),
		ServiceName: "Consultation",
	}

	svc := &serviceCatalogService{
		serviceRepo: &mockServiceRepository{
			getServiceByIDFunc: func(ctx context.Context, got uuid.UUID) (domainproviders.ClinicService, error) {
				require.Equal(t, serviceID, got)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetServiceByID(context.Background(), serviceID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
	require.Equal(t, expected.ServiceName, result.ServiceName)
}

func TestServiceCatalogServiceGetClinicServicesWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	clinicID := uuid.New()
	expected := []domainproviders.ClinicService{
		{
			ID:          uuid.New(),
			ClinicID:    clinicID,
			ServiceName: "Primary Care",
		},
	}

	svc := &serviceCatalogService{
		serviceRepo: &mockServiceRepository{
			getClinicServicesFunc: func(ctx context.Context, got uuid.UUID) ([]domainproviders.ClinicService, error) {
				require.Equal(t, clinicID, got)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetClinicServices(context.Background(), clinicID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestServiceCatalogServiceCreateClinicServiceWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	clinicID := uuid.New()
	staffID := uuid.New()
	input := domainproviders.ClinicService{
		ClinicID:           clinicID,
		ServiceName:        "Vaccination",
		CostCurrency:       "ZAR",
		ProvidedByStaffIDs: []uuid.UUID{staffID},
	}

	svc := &serviceCatalogService{
		serviceRepo: &mockServiceRepository{
			checkServiceNameExistsFunc: func(ctx context.Context, gotClinicID uuid.UUID, name string, excludeID *uuid.UUID) (bool, error) {
				require.Equal(t, clinicID, gotClinicID)
				require.Equal(t, "Vaccination", name)
				require.Nil(t, excludeID)
				return false, nil
			},
			createClinicServiceFunc: func(ctx context.Context, service domainproviders.ClinicService) (domainproviders.ClinicService, error) {
				require.Equal(t, clinicID, service.ClinicID)
				require.Equal(t, "Vaccination", service.ServiceName)
				require.NotEqual(t, uuid.Nil, service.ID)
				return service, nil
			},
		},
		clinicRepo: &mockClinicRepositoryForCatalog{
			getClinicByIDFunc: func(ctx context.Context, got uuid.UUID) (domainproviders.Clinic, error) {
				require.Equal(t, clinicID, got)
				return domainproviders.Clinic{ID: clinicID}, nil
			},
		},
		staffRepo: &mockStaffRepositoryForCatalog{
			staffExistsFunc: func(ctx context.Context, got uuid.UUID) (bool, error) {
				require.Equal(t, staffID, got)
				return true, nil
			},
		},
		auditRepo: &mockAuditRepositoryForCatalog{},
		cache:     nil,
		logger:    &logger,
	}

	result, err := svc.CreateClinicService(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, clinicID, result.ClinicID)
	require.Equal(t, "Vaccination", result.ServiceName)
}
