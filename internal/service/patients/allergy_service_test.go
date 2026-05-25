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

type mockPatientAllergyRepository struct {
	getPatientAllergiesFunc       func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientAllergy, error)
	getActivePatientAllergiesFunc func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientAllergy, error)
	addPatientAllergyFunc         func(ctx context.Context, allergy domainpatients.PatientAllergy) (domainpatients.PatientAllergy, error)
}

func (m *mockPatientAllergyRepository) AddPatientAllergy(ctx context.Context, allergy domainpatients.PatientAllergy) (domainpatients.PatientAllergy, error) {
	if m.addPatientAllergyFunc != nil {
		return m.addPatientAllergyFunc(ctx, allergy)
	}
	return allergy, nil
}

func (m *mockPatientAllergyRepository) UpdatePatientAllergy(ctx context.Context, allergy domainpatients.PatientAllergy) error {
	return nil
}

func (m *mockPatientAllergyRepository) DeletePatientAllergy(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPatientAllergyRepository) GetPatientAllergies(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientAllergy, error) {
	return m.getPatientAllergiesFunc(ctx, patientID)
}

func (m *mockPatientAllergyRepository) GetActivePatientAllergies(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientAllergy, error) {
	return m.getActivePatientAllergiesFunc(ctx, patientID)
}

var _ repository.PatientAllergyRepository = (*mockPatientAllergyRepository)(nil)

func TestAllergyServiceGetPatientAllergiesWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientAllergy{
		{
			ID:          uuid.New(),
			PatientID:   patientID,
			AllergyName: "Peanuts",
			Severity:    "severe",
			Status:      "active",
		},
	}

	svc := &allergyService{
		allergyRepo: &mockPatientAllergyRepository{
			getPatientAllergiesFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientAllergy, error) {
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

	result, err := svc.GetPatientAllergies(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestAllergyServiceGetActivePatientAllergiesWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientAllergy{
		{
			ID:          uuid.New(),
			PatientID:   patientID,
			AllergyName: "Dust",
			Severity:    "mild",
			Status:      "active",
		},
	}

	svc := &allergyService{
		allergyRepo: &mockPatientAllergyRepository{
			getActivePatientAllergiesFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientAllergy, error) {
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

	result, err := svc.GetActivePatientAllergies(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestAllergyServiceAddPatientAllergyWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	input := domainpatients.PatientAllergy{
		PatientID:   patientID,
		AllergyName: "Penicillin",
		Severity:    "moderate",
		Status:      "active",
	}

	svc := &allergyService{
		allergyRepo: &mockPatientAllergyRepository{
			addPatientAllergyFunc: func(ctx context.Context, allergy domainpatients.PatientAllergy) (domainpatients.PatientAllergy, error) {
				require.Equal(t, patientID, allergy.PatientID)
				require.Equal(t, "Penicillin", allergy.AllergyName)
				require.NotEqual(t, uuid.Nil, allergy.ID)
				return allergy, nil
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

	result, err := svc.AddPatientAllergy(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, patientID, result.PatientID)
	require.Equal(t, "Penicillin", result.AllergyName)
}
