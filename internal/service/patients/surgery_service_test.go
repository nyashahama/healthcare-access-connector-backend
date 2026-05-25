package patients

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	domainpatients "github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

type mockPatientSurgeryRepository struct {
	addPatientSurgeryFunc  func(ctx context.Context, surgery domainpatients.PatientSurgery) (domainpatients.PatientSurgery, error)
	getPatientSurgeriesFunc func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientSurgery, error)
	getRecentSurgeriesFunc func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientSurgery, error)
}

func (m *mockPatientSurgeryRepository) AddPatientSurgery(ctx context.Context, surgery domainpatients.PatientSurgery) (domainpatients.PatientSurgery, error) {
	if m.addPatientSurgeryFunc != nil {
		return m.addPatientSurgeryFunc(ctx, surgery)
	}
	return surgery, nil
}

func (m *mockPatientSurgeryRepository) UpdatePatientSurgery(ctx context.Context, surgery domainpatients.PatientSurgery) error {
	return nil
}

func (m *mockPatientSurgeryRepository) DeletePatientSurgery(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPatientSurgeryRepository) GetPatientSurgeries(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientSurgery, error) {
	if m.getPatientSurgeriesFunc != nil {
		return m.getPatientSurgeriesFunc(ctx, patientID)
	}
	return nil, nil
}

func (m *mockPatientSurgeryRepository) GetRecentSurgeries(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientSurgery, error) {
	if m.getRecentSurgeriesFunc != nil {
		return m.getRecentSurgeriesFunc(ctx, patientID)
	}
	return nil, nil
}

var _ repository.PatientSurgeryRepository = (*mockPatientSurgeryRepository)(nil)

func TestSurgeryServiceGetPatientSurgeriesWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientSurgery{
		{
			ID:            uuid.New(),
			PatientID:     patientID,
			ProcedureName: "Appendectomy",
			ProcedureDate: time.Now().Add(-24 * time.Hour),
		},
	}

	svc := &surgeryService{
		surgeryRepo: &mockPatientSurgeryRepository{
			getPatientSurgeriesFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientSurgery, error) {
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

	result, err := svc.GetPatientSurgeries(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestSurgeryServiceGetRecentSurgeriesWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientSurgery{
		{
			ID:            uuid.New(),
			PatientID:     patientID,
			ProcedureName: "Gallbladder removal",
			ProcedureDate: time.Now().Add(-48 * time.Hour),
		},
	}

	svc := &surgeryService{
		surgeryRepo: &mockPatientSurgeryRepository{
			getRecentSurgeriesFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientSurgery, error) {
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

	result, err := svc.GetRecentSurgeries(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestSurgeryServiceAddPatientSurgeryWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	input := domainpatients.PatientSurgery{
		PatientID:     patientID,
		ProcedureName: "Knee surgery",
		ProcedureDate: time.Now().Add(-24 * time.Hour),
	}

	svc := &surgeryService{
		surgeryRepo: &mockPatientSurgeryRepository{
			addPatientSurgeryFunc: func(ctx context.Context, surgery domainpatients.PatientSurgery) (domainpatients.PatientSurgery, error) {
				require.Equal(t, patientID, surgery.PatientID)
				require.Equal(t, "Knee surgery", surgery.ProcedureName)
				require.NotEqual(t, uuid.Nil, surgery.ID)
				return surgery, nil
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

	result, err := svc.AddPatientSurgery(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, patientID, result.PatientID)
	require.Equal(t, "Knee surgery", result.ProcedureName)
}
