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

type mockPatientConditionRepository struct {
	addPatientConditionFunc  func(ctx context.Context, condition domainpatients.PatientCondition) (domainpatients.PatientCondition, error)
	getPatientConditionsFunc func(ctx context.Context, patientID uuid.UUID, status *string) ([]domainpatients.PatientCondition, error)
	getActiveConditionsFunc  func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientCondition, error)
}

func (m *mockPatientConditionRepository) AddPatientCondition(ctx context.Context, condition domainpatients.PatientCondition) (domainpatients.PatientCondition, error) {
	if m.addPatientConditionFunc != nil {
		return m.addPatientConditionFunc(ctx, condition)
	}
	return condition, nil
}

func (m *mockPatientConditionRepository) UpdatePatientCondition(ctx context.Context, condition domainpatients.PatientCondition) error {
	return nil
}

func (m *mockPatientConditionRepository) DeletePatientCondition(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPatientConditionRepository) GetPatientConditions(ctx context.Context, patientID uuid.UUID, status *string) ([]domainpatients.PatientCondition, error) {
	if m.getPatientConditionsFunc != nil {
		return m.getPatientConditionsFunc(ctx, patientID, status)
	}
	return nil, nil
}

func (m *mockPatientConditionRepository) GetActiveConditions(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientCondition, error) {
	if m.getActiveConditionsFunc != nil {
		return m.getActiveConditionsFunc(ctx, patientID)
	}
	return nil, nil
}

var _ repository.PatientConditionRepository = (*mockPatientConditionRepository)(nil)

func TestConditionServiceGetPatientConditionsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientCondition{
		{
			ID:            uuid.New(),
			PatientID:     patientID,
			ConditionName: "Diabetes",
			Status:        "active",
		},
	}

	svc := &conditionService{
		conditionRepo: &mockPatientConditionRepository{
			getPatientConditionsFunc: func(ctx context.Context, got uuid.UUID, status *string) ([]domainpatients.PatientCondition, error) {
				require.Equal(t, patientID, got)
				require.Nil(t, status)
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

	result, err := svc.GetPatientConditions(context.Background(), patientID, nil)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestConditionServiceGetActiveConditionsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientCondition{
		{
			ID:            uuid.New(),
			PatientID:     patientID,
			ConditionName: "Asthma",
			Status:        "active",
		},
	}

	svc := &conditionService{
		conditionRepo: &mockPatientConditionRepository{
			getActiveConditionsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientCondition, error) {
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

	result, err := svc.GetActiveConditions(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestConditionServiceAddPatientConditionWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	input := domainpatients.PatientCondition{
		PatientID:     patientID,
		ConditionName: "Hypertension",
		Status:        "active",
	}

	svc := &conditionService{
		conditionRepo: &mockPatientConditionRepository{
			addPatientConditionFunc: func(ctx context.Context, condition domainpatients.PatientCondition) (domainpatients.PatientCondition, error) {
				require.Equal(t, patientID, condition.PatientID)
				require.Equal(t, "Hypertension", condition.ConditionName)
				require.NotEqual(t, uuid.Nil, condition.ID)
				return condition, nil
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

	result, err := svc.AddPatientCondition(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, patientID, result.PatientID)
	require.Equal(t, "Hypertension", result.ConditionName)
}
