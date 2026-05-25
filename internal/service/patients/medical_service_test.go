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

type mockPatientMedicationRepository struct {
	addPatientMedicationFunc  func(ctx context.Context, medication domainpatients.PatientMedication) (domainpatients.PatientMedication, error)
	getPatientMedicationsFunc func(ctx context.Context, patientID uuid.UUID, status *string) ([]domainpatients.PatientMedication, error)
	getActiveMedicationsFunc  func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientMedication, error)
}

func (m *mockPatientMedicationRepository) AddPatientMedication(ctx context.Context, medication domainpatients.PatientMedication) (domainpatients.PatientMedication, error) {
	if m.addPatientMedicationFunc != nil {
		return m.addPatientMedicationFunc(ctx, medication)
	}
	return medication, nil
}

func (m *mockPatientMedicationRepository) UpdatePatientMedication(ctx context.Context, medication domainpatients.PatientMedication) error {
	return nil
}

func (m *mockPatientMedicationRepository) DeletePatientMedication(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPatientMedicationRepository) GetPatientMedications(ctx context.Context, patientID uuid.UUID, status *string) ([]domainpatients.PatientMedication, error) {
	if m.getPatientMedicationsFunc != nil {
		return m.getPatientMedicationsFunc(ctx, patientID, status)
	}
	return nil, nil
}

func (m *mockPatientMedicationRepository) GetActiveMedications(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientMedication, error) {
	if m.getActiveMedicationsFunc != nil {
		return m.getActiveMedicationsFunc(ctx, patientID)
	}
	return nil, nil
}

var _ repository.PatientMedicationRepository = (*mockPatientMedicationRepository)(nil)

func TestMedicationServiceGetPatientMedicationsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientMedication{
		{
			ID:             uuid.New(),
			PatientID:      patientID,
			MedicationName: "Metformin",
			Status:         "active",
		},
	}

	svc := &medicationService{
		medicationRepo: &mockPatientMedicationRepository{
			getPatientMedicationsFunc: func(ctx context.Context, got uuid.UUID, status *string) ([]domainpatients.PatientMedication, error) {
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

	result, err := svc.GetPatientMedications(context.Background(), patientID, nil)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestMedicationServiceGetActiveMedicationsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientMedication{
		{
			ID:             uuid.New(),
			PatientID:      patientID,
			MedicationName: "Insulin",
			Status:         "active",
		},
	}

	svc := &medicationService{
		medicationRepo: &mockPatientMedicationRepository{
			getActiveMedicationsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientMedication, error) {
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

	result, err := svc.GetActiveMedications(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestMedicationServiceAddPatientMedicationWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	startDate := time.Now().Add(-24 * time.Hour)
	input := domainpatients.PatientMedication{
		PatientID:       patientID,
		MedicationName:  "Aspirin",
		Status:          "active",
		StartDate:       &startDate,
	}

	svc := &medicationService{
		medicationRepo: &mockPatientMedicationRepository{
			addPatientMedicationFunc: func(ctx context.Context, medication domainpatients.PatientMedication) (domainpatients.PatientMedication, error) {
				require.Equal(t, patientID, medication.PatientID)
				require.Equal(t, "Aspirin", medication.MedicationName)
				require.NotEqual(t, uuid.Nil, medication.ID)
				return medication, nil
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

	result, err := svc.AddPatientMedication(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, patientID, result.PatientID)
	require.Equal(t, "Aspirin", result.MedicationName)
}
