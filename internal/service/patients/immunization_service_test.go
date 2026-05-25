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

type mockPatientImmunizationRepository struct {
	addPatientImmunizationFunc  func(ctx context.Context, immunization domainpatients.PatientImmunization) (domainpatients.PatientImmunization, error)
	getPatientImmunizationsFunc func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientImmunization, error)
	getUpcomingImmunizationsFunc func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientImmunization, error)
}

func (m *mockPatientImmunizationRepository) AddPatientImmunization(ctx context.Context, immunization domainpatients.PatientImmunization) (domainpatients.PatientImmunization, error) {
	if m.addPatientImmunizationFunc != nil {
		return m.addPatientImmunizationFunc(ctx, immunization)
	}
	return immunization, nil
}

func (m *mockPatientImmunizationRepository) UpdatePatientImmunization(ctx context.Context, immunization domainpatients.PatientImmunization) error {
	return nil
}

func (m *mockPatientImmunizationRepository) DeletePatientImmunization(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPatientImmunizationRepository) GetPatientImmunizations(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientImmunization, error) {
	if m.getPatientImmunizationsFunc != nil {
		return m.getPatientImmunizationsFunc(ctx, patientID)
	}
	return nil, nil
}

func (m *mockPatientImmunizationRepository) GetUpcomingImmunizations(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientImmunization, error) {
	if m.getUpcomingImmunizationsFunc != nil {
		return m.getUpcomingImmunizationsFunc(ctx, patientID)
	}
	return nil, nil
}

var _ repository.PatientImmunizationRepository = (*mockPatientImmunizationRepository)(nil)

func TestImmunizationServiceGetPatientImmunizationsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.PatientImmunization{
		{
			ID:                 uuid.New(),
			PatientID:          patientID,
			VaccineName:        "MMR",
			AdministrationDate: time.Now().Add(-24 * time.Hour),
		},
	}

	svc := &immunizationService{
		immunizationRepo: &mockPatientImmunizationRepository{
			getPatientImmunizationsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientImmunization, error) {
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

	result, err := svc.GetPatientImmunizations(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestImmunizationServiceGetUpcomingImmunizationsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	nextDue := time.Now().Add(72 * time.Hour)
	expected := []domainpatients.PatientImmunization{
		{
			ID:                 uuid.New(),
			PatientID:          patientID,
			VaccineName:        "Hepatitis B",
			AdministrationDate: time.Now().Add(-24 * time.Hour),
			NextDueDate:        &nextDue,
		},
	}

	svc := &immunizationService{
		immunizationRepo: &mockPatientImmunizationRepository{
			getUpcomingImmunizationsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientImmunization, error) {
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

	result, err := svc.GetUpcomingImmunizations(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestImmunizationServiceAddPatientImmunizationWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	doseNumber := 1
	totalDoses := 2
	input := domainpatients.PatientImmunization{
		PatientID:          patientID,
		VaccineName:        "Polio",
		AdministrationDate: time.Now().Add(-24 * time.Hour),
		DoseNumber:         &doseNumber,
		TotalDoses:         &totalDoses,
	}

	svc := &immunizationService{
		immunizationRepo: &mockPatientImmunizationRepository{
			addPatientImmunizationFunc: func(ctx context.Context, immunization domainpatients.PatientImmunization) (domainpatients.PatientImmunization, error) {
				require.Equal(t, patientID, immunization.PatientID)
				require.Equal(t, "Polio", immunization.VaccineName)
				require.NotEqual(t, uuid.Nil, immunization.ID)
				return immunization, nil
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

	result, err := svc.AddPatientImmunization(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, patientID, result.PatientID)
	require.Equal(t, "Polio", result.VaccineName)
}
