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

type mockEmergencyContactRepository struct {
	addEmergencyContactFunc         func(ctx context.Context, contact domainpatients.EmergencyContact) (domainpatients.EmergencyContact, error)
	getPatientEmergencyContactsFunc func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.EmergencyContact, error)
	getPrimaryEmergencyContactFunc  func(ctx context.Context, patientID uuid.UUID) (domainpatients.EmergencyContact, error)
}

func (m *mockEmergencyContactRepository) AddEmergencyContact(ctx context.Context, contact domainpatients.EmergencyContact) (domainpatients.EmergencyContact, error) {
	if m.addEmergencyContactFunc != nil {
		return m.addEmergencyContactFunc(ctx, contact)
	}
	return contact, nil
}

func (m *mockEmergencyContactRepository) UpdateEmergencyContact(ctx context.Context, contact domainpatients.EmergencyContact) error {
	return nil
}

func (m *mockEmergencyContactRepository) DeleteEmergencyContact(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockEmergencyContactRepository) GetPatientEmergencyContacts(ctx context.Context, patientID uuid.UUID) ([]domainpatients.EmergencyContact, error) {
	if m.getPatientEmergencyContactsFunc != nil {
		return m.getPatientEmergencyContactsFunc(ctx, patientID)
	}
	return nil, nil
}

func (m *mockEmergencyContactRepository) GetPrimaryEmergencyContact(ctx context.Context, patientID uuid.UUID) (domainpatients.EmergencyContact, error) {
	if m.getPrimaryEmergencyContactFunc != nil {
		return m.getPrimaryEmergencyContactFunc(ctx, patientID)
	}
	return domainpatients.EmergencyContact{}, nil
}

var _ repository.EmergencyContactRepository = (*mockEmergencyContactRepository)(nil)

func TestEmergencyContactServiceGetPatientEmergencyContactsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := []domainpatients.EmergencyContact{
		{
			ID:           uuid.New(),
			PatientID:    patientID,
			ContactName:  "Jane Doe",
			Relationship: "Mother",
			PhoneNumber:  "+263771234567",
			IsPrimary:    true,
		},
	}

	svc := &emergencyContactService{
		emergencyContactRepo: &mockEmergencyContactRepository{
			getPatientEmergencyContactsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.EmergencyContact, error) {
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

	result, err := svc.GetPatientEmergencyContacts(context.Background(), patientID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestEmergencyContactServiceGetPrimaryEmergencyContactWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	expected := domainpatients.EmergencyContact{
		ID:           uuid.New(),
		PatientID:    patientID,
		ContactName:  "John Doe",
		Relationship: "Father",
		PhoneNumber:  "+263772345678",
		IsPrimary:    true,
	}

	svc := &emergencyContactService{
		emergencyContactRepo: &mockEmergencyContactRepository{
			getPrimaryEmergencyContactFunc: func(ctx context.Context, got uuid.UUID) (domainpatients.EmergencyContact, error) {
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

	result, err := svc.GetPrimaryEmergencyContact(context.Background(), patientID)
	require.NoError(t, err)
	require.Equal(t, expected.ID, result.ID)
	require.Equal(t, expected.ContactName, result.ContactName)
}

func TestEmergencyContactServiceAddEmergencyContactWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	patientID := uuid.New()
	accessLevel := "full"
	input := domainpatients.EmergencyContact{
		PatientID:    patientID,
		ContactName:  "Alice Doe",
		Relationship: "Sister",
		PhoneNumber:  "+263773456789",
		AccessLevel:  &accessLevel,
	}

	svc := &emergencyContactService{
		emergencyContactRepo: &mockEmergencyContactRepository{
			getPatientEmergencyContactsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.EmergencyContact, error) {
				require.Equal(t, patientID, got)
				return nil, nil
			},
			addEmergencyContactFunc: func(ctx context.Context, contact domainpatients.EmergencyContact) (domainpatients.EmergencyContact, error) {
				require.Equal(t, patientID, contact.PatientID)
				require.Equal(t, "Alice Doe", contact.ContactName)
				require.NotEqual(t, uuid.Nil, contact.ID)
				require.True(t, contact.IsPrimary)
				return contact, nil
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

	result, err := svc.AddEmergencyContact(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, patientID, result.PatientID)
	require.Equal(t, "Alice Doe", result.ContactName)
	require.True(t, result.IsPrimary)
}
