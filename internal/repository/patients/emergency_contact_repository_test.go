package patients

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestEmergencyContactRepository_AddEmergencyContact(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	contactID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		contact    patients.EmergencyContact
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			contact: patients.EmergencyContact{
				PatientID:    patientID,
				ContactName:  "Jane Doe",
				Relationship: "Spouse",
				PhoneNumber:  "555-1234",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRow := sqlc.EmergencyContact{
					ID:           uuidPgtypeFromString(contactID.String()),
					PatientID:   uuidPgtypeFromString(patientID.String()),
					ContactName: "Jane Doe",
					Relationship: "Spouse",
					PhoneNumber:  "555-1234",
					CreatedAt:   pgtype.Timestamp{Time: now, Valid: true},
					UpdatedAt:   pgtype.Timestamp{Time: now, Valid: true},
				}
				m.On("AddEmergencyContact", ctx, mock.Anything).Return(expectedRow, nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			contact: patients.EmergencyContact{
				PatientID:   patientID,
				ContactName: "Jane Doe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddEmergencyContact", ctx, mock.Anything).Return(sqlc.EmergencyContact{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			contact: patients.EmergencyContact{
				PatientID:   patientID,
				ContactName: "Jane Doe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AddEmergencyContact", ctx, mock.Anything).Return(sqlc.EmergencyContact{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewEmergencyContactRepositoryWithQuerier(mockQuerier)

			gotContact, err := repo.AddEmergencyContact(ctx, tt.contact)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, "Jane Doe", gotContact.ContactName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestEmergencyContactRepository_GetPatientEmergencyContacts(t *testing.T) {
	ctx := context.Background()
	now := nowTime()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	contactID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		patientID  uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name:      "success",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				expectedRows := []sqlc.GetPatientEmergencyContactsRow{
					{
						ID:            uuidPgtypeFromString(contactID.String()),
						PatientID:     uuidPgtypeFromString(patientID.String()),
						ContactName:  "Jane Doe",
						Relationship: "Spouse",
						PhoneNumber:  "555-1234",
						CreatedAt:    pgtype.Timestamp{Time: now, Valid: true},
						UpdatedAt:    pgtype.Timestamp{Time: now, Valid: true},
					},
				}
				m.On("GetPatientEmergencyContacts", ctx, uuidPgtypeFromString(patientID.String())).Return(expectedRows, nil)
			},
			expectErr: false,
		},
		{
			name:      "not found",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientEmergencyContacts", ctx, uuidPgtypeFromString(patientID.String())).Return([]sqlc.GetPatientEmergencyContactsRow{}, pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name:      "database error",
			patientID: patientID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientEmergencyContacts", ctx, mock.Anything).Return([]sqlc.GetPatientEmergencyContactsRow{}, assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewEmergencyContactRepositoryWithQuerier(mockQuerier)

			gotContacts, err := repo.GetPatientEmergencyContacts(ctx, tt.patientID)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
				assert.Len(t, gotContacts, 1)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestEmergencyContactRepository_UpdateEmergencyContact(t *testing.T) {
	ctx := context.Background()
	contactID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		contact    patients.EmergencyContact
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			contact: patients.EmergencyContact{
				ID:           contactID,
				ContactName:  "Jane Doe",
				Relationship: "Spouse",
				PhoneNumber:  "555-5678",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateEmergencyContact", ctx, mock.Anything).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			contact: patients.EmergencyContact{
				ID:          contactID,
				ContactName: "Jane Doe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateEmergencyContact", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			contact: patients.EmergencyContact{
				ID:          contactID,
				ContactName: "Jane Doe",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateEmergencyContact", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewEmergencyContactRepositoryWithQuerier(mockQuerier)

			err := repo.UpdateEmergencyContact(ctx, tt.contact)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestEmergencyContactRepository_DeleteEmergencyContact(t *testing.T) {
	ctx := context.Background()
	contactID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name       string
		id         uuid.UUID
		mockSetup  func(*mocks.MockQuerier)
		expectErr  bool
		errIsFound bool
	}{
		{
			name: "success",
			id:   contactID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteEmergencyContact", ctx, uuidPgtypeFromString(contactID.String())).Return(nil)
			},
			expectErr: false,
		},
		{
			name: "not found",
			id:   contactID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteEmergencyContact", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectErr:  true,
			errIsFound: true,
		},
		{
			name: "database error",
			id:   contactID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteEmergencyContact", ctx, mock.Anything).Return(assert.AnError)
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewEmergencyContactRepositoryWithQuerier(mockQuerier)

			err := repo.DeleteEmergencyContact(ctx, tt.id)

			if tt.expectErr {
				require.Error(t, err)
				if tt.errIsFound {
					assert.True(t, errors.Is(err, domain.ErrNotFound))
				}
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}