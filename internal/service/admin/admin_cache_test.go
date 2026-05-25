package admin

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/admin"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type mockSystemAdminRepository struct {
	getByUserIDFunc func(ctx context.Context, userID uuid.UUID) (admin.SystemAdmin, error)
}

func (m *mockSystemAdminRepository) CreateSystemAdmin(ctx context.Context, sysAdmin admin.SystemAdmin) (admin.SystemAdmin, error) {
	return admin.SystemAdmin{}, nil
}
func (m *mockSystemAdminRepository) GetSystemAdmin(ctx context.Context, id uuid.UUID) (admin.SystemAdmin, error) {
	return admin.SystemAdmin{}, nil
}
func (m *mockSystemAdminRepository) GetSystemAdminByUserID(ctx context.Context, userID uuid.UUID) (admin.SystemAdmin, error) {
	return m.getByUserIDFunc(ctx, userID)
}
func (m *mockSystemAdminRepository) UpdateSystemAdmin(ctx context.Context, sysAdmin admin.SystemAdmin) error {
	return nil
}
func (m *mockSystemAdminRepository) DeleteSystemAdmin(ctx context.Context, id uuid.UUID) error {
	return nil
}
func (m *mockSystemAdminRepository) DeleteSystemAdminByUserID(ctx context.Context, userID uuid.UUID) error {
	return nil
}
func (m *mockSystemAdminRepository) SearchSystemAdmins(ctx context.Context, params admin.SystemAdminSearchParams) ([]admin.SystemAdmin, error) {
	return nil, nil
}

type mockNGOPartnerRepository struct {
	getByUserIDFunc func(ctx context.Context, userID uuid.UUID) (admin.NGOPartner, error)
}

func (m *mockNGOPartnerRepository) CreateNGOPartner(ctx context.Context, partner admin.NGOPartner) (admin.NGOPartner, error) {
	return admin.NGOPartner{}, nil
}
func (m *mockNGOPartnerRepository) GetNGOPartnerByUserID(ctx context.Context, userID uuid.UUID) (admin.NGOPartner, error) {
	return m.getByUserIDFunc(ctx, userID)
}

var _ repository.SystemAdminRepository = (*mockSystemAdminRepository)(nil)
var _ repository.NGOPartnerRepository = (*mockNGOPartnerRepository)(nil)

func TestSystemAdminServiceGetByUserIDWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	expected := admin.SystemAdmin{
		ID:         uuid.New(),
		UserID:     userID,
		AdminLevel: "super_admin",
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	svc := &systemAdminService{
		sysAdminRepo: &mockSystemAdminRepository{
			getByUserIDFunc: func(ctx context.Context, got uuid.UUID) (admin.SystemAdmin, error) {
				require.Equal(t, userID, got)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetSystemAdminByUserID(context.Background(), userID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
}

func TestNGOPartnerServiceGetByUserIDWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	userID := uuid.New()
	expected := admin.NGOPartner{
		ID:                uuid.New(),
		UserID:            userID,
		OrganizationName:  "Health NGO",
		PartnershipStatus: "active",
		CreatedAt:         time.Now(),
		UpdatedAt:         time.Now(),
	}

	svc := &ngoPartnerService{
		ngoRepo: &mockNGOPartnerRepository{
			getByUserIDFunc: func(ctx context.Context, got uuid.UUID) (admin.NGOPartner, error) {
				require.Equal(t, userID, got)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetNGOPartnerByUserID(context.Background(), userID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
}
