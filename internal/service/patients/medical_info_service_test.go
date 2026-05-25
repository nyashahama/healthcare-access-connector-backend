package patients

import (
	"context"
	"io"
	"testing"

	"github.com/google/uuid"
	domainpatients "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type mockPatientMedicalInfoRepository struct {
	createMedicalInfoFunc         func(ctx context.Context, info domainpatients.PatientMedicalInfo) (domainpatients.PatientMedicalInfo, error)
	getMedicalInfoByIDFunc        func(ctx context.Context, id uuid.UUID) (domainpatients.PatientMedicalInfo, error)
	getMedicalInfoByPatientIDFunc func(ctx context.Context, patientID uuid.UUID) (domainpatients.PatientMedicalInfo, error)
}

func (m *mockPatientMedicalInfoRepository) CreateMedicalInfo(ctx context.Context, info domainpatients.PatientMedicalInfo) (domainpatients.PatientMedicalInfo, error) {
	if m.createMedicalInfoFunc != nil {
		return m.createMedicalInfoFunc(ctx, info)
	}
	return info, nil
}

func (m *mockPatientMedicalInfoRepository) GetMedicalInfoByID(ctx context.Context, id uuid.UUID) (domainpatients.PatientMedicalInfo, error) {
	if m.getMedicalInfoByIDFunc != nil {
		return m.getMedicalInfoByIDFunc(ctx, id)
	}
	return domainpatients.PatientMedicalInfo{}, nil
}

func (m *mockPatientMedicalInfoRepository) GetMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) (domainpatients.PatientMedicalInfo, error) {
	if m.getMedicalInfoByPatientIDFunc != nil {
		return m.getMedicalInfoByPatientIDFunc(ctx, patientID)
	}
	return domainpatients.PatientMedicalInfo{}, nil
}

func (m *mockPatientMedicalInfoRepository) UpdateMedicalInfo(ctx context.Context, info domainpatients.PatientMedicalInfo) error {
	return nil
}

func (m *mockPatientMedicalInfoRepository) DeleteMedicalInfoByPatientID(ctx context.Context, patientID uuid.UUID) error {
	return nil
}

var _ repository.PatientMedicalInfoRepository = (*mockPatientMedicalInfoRepository)(nil)

func TestMedicalInfoServiceGetMedicalInfoByIDWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	medicalInfoID := uuid.New()
	expected := domainpatients.PatientMedicalInfo{
		ID:        medicalInfoID,
		PatientID: uuid.New(),
	}

	svc := &medicalInfoService{
		medicalInfoRepo: &mockPatientMedicalInfoRepository{
			getMedicalInfoByIDFunc: func(ctx context.Context, got uuid.UUID) (domainpatients.PatientMedicalInfo, error) {
				require.Equal(t, medicalInfoID, got)
				return expected, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetMedicalInfoByID(context.Background(), medicalInfoID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
	require.Equal(t, expected.PatientID, result.PatientID)
}

func TestMedicalInfoServiceGetMedicalInfoByPatientIDWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := domainpatients.PatientMedicalInfo{
		ID:        uuid.New(),
		PatientID: patientID,
	}

	svc := &medicalInfoService{
		medicalInfoRepo: &mockPatientMedicalInfoRepository{
			getMedicalInfoByPatientIDFunc: func(ctx context.Context, got uuid.UUID) (domainpatients.PatientMedicalInfo, error) {
				require.Equal(t, patientID, got)
				return expected, nil
			},
		},
		patientRepo: &mockPatientProfileRepository{
			getByIDFunc: func(ctx context.Context, got uuid.UUID) (domainpatients.PatientProfile, error) {
				require.Equal(t, patientID, got)
				return domainpatients.PatientProfile{ID: patientID}, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetMedicalInfoByPatientID(context.Background(), patientID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
	require.Equal(t, expected.PatientID, result.PatientID)
}

func TestMedicalInfoServiceCreateMedicalInfoWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	input := domainpatients.PatientMedicalInfo{
		PatientID: patientID,
	}

	svc := &medicalInfoService{
		medicalInfoRepo: &mockPatientMedicalInfoRepository{
			getMedicalInfoByPatientIDFunc: func(ctx context.Context, got uuid.UUID) (domainpatients.PatientMedicalInfo, error) {
				require.Equal(t, patientID, got)
				return domainpatients.PatientMedicalInfo{}, nil
			},
			createMedicalInfoFunc: func(ctx context.Context, info domainpatients.PatientMedicalInfo) (domainpatients.PatientMedicalInfo, error) {
				require.Equal(t, patientID, info.PatientID)
				require.NotEqual(t, uuid.Nil, info.ID)
				return info, nil
			},
		},
		patientRepo: &mockPatientProfileRepository{
			getByIDFunc: func(ctx context.Context, got uuid.UUID) (domainpatients.PatientProfile, error) {
				require.Equal(t, patientID, got)
				return domainpatients.PatientProfile{ID: patientID}, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.CreateMedicalInfo(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, patientID, result.PatientID)
	require.NotEqual(t, uuid.Nil, result.ID)
}
