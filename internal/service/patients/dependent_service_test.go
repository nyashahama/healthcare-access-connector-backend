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

type mockPatientDependentRepository struct {
	addPatientDependentFunc   func(ctx context.Context, dependent domainpatients.PatientDependent) (domainpatients.PatientDependent, error)
	getPatientDependentsFunc  func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientDependent, error)
	getDependentChildrenFunc  func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientDependent, error)
}

func (m *mockPatientDependentRepository) AddPatientDependent(ctx context.Context, dependent domainpatients.PatientDependent) (domainpatients.PatientDependent, error) {
	if m.addPatientDependentFunc != nil {
		return m.addPatientDependentFunc(ctx, dependent)
	}
	return dependent, nil
}

func (m *mockPatientDependentRepository) UpdatePatientDependent(ctx context.Context, dependent domainpatients.PatientDependent) error {
	return nil
}

func (m *mockPatientDependentRepository) DeletePatientDependent(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPatientDependentRepository) GetPatientDependents(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientDependent, error) {
	if m.getPatientDependentsFunc != nil {
		return m.getPatientDependentsFunc(ctx, patientID)
	}
	return nil, nil
}

func (m *mockPatientDependentRepository) GetDependentChildren(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientDependent, error) {
	if m.getDependentChildrenFunc != nil {
		return m.getDependentChildrenFunc(ctx, patientID)
	}
	return nil, nil
}

var _ repository.PatientDependentRepository = (*mockPatientDependentRepository)(nil)

func TestDependentServiceGetPatientDependentsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	dob := time.Now().AddDate(-10, 0, 0)
	expected := []domainpatients.PatientDependent{
		{
			ID:           uuid.New(),
			PatientID:    patientID,
			FirstName:    "Jane",
			LastName:     "Doe",
			Relationship: "daughter",
			DateOfBirth:  dob,
		},
	}

	svc := &dependentService{
		dependentRepo: &mockPatientDependentRepository{
			getPatientDependentsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientDependent, error) {
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

	result, err := svc.GetPatientDependents(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestDependentServiceGetDependentChildrenWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	childDOB := time.Now().AddDate(-8, 0, 0)
	adultDOB := time.Now().AddDate(-25, 0, 0)
	childID := uuid.New()

	svc := &dependentService{
		dependentRepo: &mockPatientDependentRepository{
			getDependentChildrenFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientDependent, error) {
				require.Equal(t, patientID, got)
				return []domainpatients.PatientDependent{
					{
						ID:           childID,
						PatientID:    patientID,
						FirstName:    "Child",
						LastName:     "One",
						Relationship: "daughter",
						DateOfBirth:  childDOB,
					},
					{
						ID:           uuid.New(),
						PatientID:    patientID,
						FirstName:    "Adult",
						LastName:     "Two",
						Relationship: "son",
						DateOfBirth:  adultDOB,
					},
				}, nil
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

	result, err := svc.GetDependentChildren(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, childID, result[0].ID)
}

func TestDependentServiceAddPatientDependentWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	dob := time.Now().AddDate(-7, 0, 0)
	input := domainpatients.PatientDependent{
		PatientID:    patientID,
		FirstName:    "Sam",
		LastName:     "Doe",
		Relationship: "son",
		DateOfBirth:  dob,
	}

	svc := &dependentService{
		dependentRepo: &mockPatientDependentRepository{
			addPatientDependentFunc: func(ctx context.Context, dependent domainpatients.PatientDependent) (domainpatients.PatientDependent, error) {
				require.Equal(t, patientID, dependent.PatientID)
				require.Equal(t, "Sam", dependent.FirstName)
				require.NotEqual(t, uuid.Nil, dependent.ID)
				return dependent, nil
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

	result, err := svc.AddPatientDependent(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, patientID, result.PatientID)
	require.Equal(t, "Sam", result.FirstName)
}
