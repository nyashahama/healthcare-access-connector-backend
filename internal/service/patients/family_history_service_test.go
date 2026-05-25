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

type mockPatientFamilyHistoryRepository struct {
	addFamilyHistoryFunc        func(ctx context.Context, history domainpatients.PatientFamilyHistory) (domainpatients.PatientFamilyHistory, error)
	getPatientFamilyHistoryFunc func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientFamilyHistory, error)
}

func (m *mockPatientFamilyHistoryRepository) AddFamilyHistory(ctx context.Context, history domainpatients.PatientFamilyHistory) (domainpatients.PatientFamilyHistory, error) {
	if m.addFamilyHistoryFunc != nil {
		return m.addFamilyHistoryFunc(ctx, history)
	}
	return history, nil
}

func (m *mockPatientFamilyHistoryRepository) UpdateFamilyHistory(ctx context.Context, history domainpatients.PatientFamilyHistory) error {
	return nil
}

func (m *mockPatientFamilyHistoryRepository) DeleteFamilyHistory(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPatientFamilyHistoryRepository) GetPatientFamilyHistory(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientFamilyHistory, error) {
	if m.getPatientFamilyHistoryFunc != nil {
		return m.getPatientFamilyHistoryFunc(ctx, patientID)
	}
	return nil, nil
}

var _ repository.PatientFamilyHistoryRepository = (*mockPatientFamilyHistoryRepository)(nil)

func TestFamilyHistoryServiceGetPatientFamilyHistoryWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientFamilyHistory{
		{
			ID:            uuid.New(),
			PatientID:     patientID,
			Relative:      "Mother",
			ConditionName: "Diabetes",
		},
	}

	svc := &familyHistoryService{
		familyHistoryRepo: &mockPatientFamilyHistoryRepository{
			getPatientFamilyHistoryFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientFamilyHistory, error) {
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

	result, err := svc.GetPatientFamilyHistory(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestFamilyHistoryServiceAddFamilyHistoryWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	input := domainpatients.PatientFamilyHistory{
		PatientID:     patientID,
		Relative:      "Father",
		ConditionName: "Hypertension",
	}

	svc := &familyHistoryService{
		familyHistoryRepo: &mockPatientFamilyHistoryRepository{
			addFamilyHistoryFunc: func(ctx context.Context, history domainpatients.PatientFamilyHistory) (domainpatients.PatientFamilyHistory, error) {
				require.Equal(t, patientID, history.PatientID)
				require.Equal(t, "Father", history.Relative)
				require.NotEqual(t, uuid.Nil, history.ID)
				return history, nil
			},
			getPatientFamilyHistoryFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientFamilyHistory, error) {
				require.Equal(t, patientID, got)
				return nil, nil
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

	result, err := svc.AddFamilyHistory(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, patientID, result.PatientID)
	require.Equal(t, "Father", result.Relative)
}

func TestFamilyHistoryServiceUpdateFamilyHistoryWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	historyID := uuid.New()
	input := domainpatients.PatientFamilyHistory{
		ID:            historyID,
		PatientID:     patientID,
		Relative:      "Sister",
		ConditionName: "Asthma",
	}

	svc := &familyHistoryService{
		familyHistoryRepo: &mockPatientFamilyHistoryRepository{
			getPatientFamilyHistoryFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientFamilyHistory, error) {
				require.Equal(t, patientID, got)
				return []domainpatients.PatientFamilyHistory{
					{
						ID:            historyID,
						PatientID:     patientID,
						Relative:      "Sister",
						ConditionName: "Asthma",
					},
				}, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	err := svc.UpdateFamilyHistory(context.Background(), input)
	require.NoError(t, err)
}
