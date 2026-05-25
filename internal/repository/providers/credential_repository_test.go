package providers

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestCredentialRepository_CreateCredential(t *testing.T) {
	ctx := context.Background()
	credentialID := uuid.New()
	staffID := uuid.New()

	tests := []struct {
		name          string
		credential    providers.ProfessionalCredential
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name: "successful credential creation",
			credential: providers.ProfessionalCredential{
				ID:               credentialID,
				StaffID:          staffID,
				CredentialType:   "medical_license",
				CredentialNumber: stringPtr("LIC12345"),
				IssuingAuthority: "Medical Board",
				IssueDate:        nil,
				ExpiryDate:       nil,
				Status:           "active",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateCredential", ctx, mock.Anything).Return(sqlc.ProfessionalCredential{
					ID:                uuidToPgtype(credentialID),
					StaffID:           uuidToPgtype(staffID),
					CredentialType:    "medical_license",
					CredentialNumber:  pgtype.Text{String: "LIC12345", Valid: true},
					IssuingAuthority:  "Medical Board",
					Status:            pgtype.Text{String: "active", Valid: true},
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "database error",
			credential: providers.ProfessionalCredential{
				StaffID:          staffID,
				CredentialType:   "medical_license",
				CredentialNumber: stringPtr("LIC12345"),
				IssuingAuthority: "Medical Board",
				Status:           "active",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateCredential", ctx, mock.Anything).
					Return(sqlc.ProfessionalCredential{}, assert.AnError)
			},
			expectedError: assert.AnError,
		},
		{
			name: "foreign key violation",
			credential: providers.ProfessionalCredential{
				StaffID:          staffID,
				CredentialType:   "medical_license",
				CredentialNumber: stringPtr("LIC12345"),
				IssuingAuthority: "Medical Board",
				Status:           "active",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				pgErr := &pgconn.PgError{Code: "23503", ConstraintName: "staff_id"}
				m.On("CreateCredential", ctx, mock.Anything).
					Return(sqlc.ProfessionalCredential{}, pgErr)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewCredentialRepositoryWithQuerier(mockQuerier)

			credential, err := repo.CreateCredential(ctx, tt.credential)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "medical_license", credential.CredentialType)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestCredentialRepository_GetStaffCredentials(t *testing.T) {
	ctx := context.Background()
	staffID := uuid.New()
	credentialID1 := uuid.New()
	credentialID2 := uuid.New()

	tests := []struct {
		name          string
		staffID       uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedCreds []providers.ProfessionalCredential
		expectedError error
	}{
		{
			name:    "credentials found",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetStaffCredentials", ctx, uuidToPgtype(staffID)).Return([]sqlc.ProfessionalCredential{
					{
						ID:                uuidToPgtype(credentialID1),
						StaffID:           uuidToPgtype(staffID),
						CredentialType:    "medical_license",
						CredentialNumber:  pgtype.Text{String: "LIC12345", Valid: true},
						IssuingAuthority:  "Medical Board",
						Status:            pgtype.Text{String: "active", Valid: true},
					},
					{
						ID:                uuidToPgtype(credentialID2),
						StaffID:           uuidToPgtype(staffID),
						CredentialType:    "specialization",
						CredentialNumber:  pgtype.Text{String: "SPEC67890", Valid: true},
						IssuingAuthority:  "Specialization Board",
						Status:            pgtype.Text{String: "active", Valid: true},
					},
				}, nil)
			},
			expectedCreds: []providers.ProfessionalCredential{
				{
					ID:               credentialID1,
					StaffID:          staffID,
					CredentialType:   "medical_license",
					CredentialNumber: stringPtr("LIC12345"),
					IssuingAuthority: "Medical Board",
					Status:           "active",
				},
				{
					ID:               credentialID2,
					StaffID:          staffID,
					CredentialType:   "specialization",
					CredentialNumber: stringPtr("SPEC67890"),
					IssuingAuthority: "Specialization Board",
					Status:           "active",
				},
			},
			expectedError: nil,
		},
		{
			name:    "empty list",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetStaffCredentials", ctx, uuidToPgtype(staffID)).Return([]sqlc.ProfessionalCredential{}, nil)
			},
			expectedCreds: []providers.ProfessionalCredential{},
			expectedError: nil,
		},
		{
			name:    "database error",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetStaffCredentials", ctx, mock.Anything).Return([]sqlc.ProfessionalCredential{}, assert.AnError)
			},
			expectedCreds: nil,
			expectedError: fmt.Errorf("get staff credentials failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewCredentialRepositoryWithQuerier(mockQuerier)

			credentials, err := repo.GetStaffCredentials(ctx, tt.staffID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(tt.expectedCreds), len(credentials))
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestCredentialRepository_GetCredentialByID(t *testing.T) {
	ctx := context.Background()
	credentialID := uuid.New()
	staffID := uuid.New()

	t.Run("credential found", func(t *testing.T) {
		mockQuerier := mocks.NewMockQuerier(t)
		mockQuerier.On("GetCredentialByID", ctx, uuidToPgtype(credentialID)).Return(sqlc.ProfessionalCredential{
			ID:               uuidToPgtype(credentialID),
			StaffID:          uuidToPgtype(staffID),
			CredentialType:   "medical_license",
			IssuingAuthority: "Medical Board",
			Status:           pgtype.Text{String: "active", Valid: true},
		}, nil)

		repo := NewCredentialRepositoryWithQuerier(mockQuerier)
		credential, err := repo.GetCredentialByID(ctx, credentialID)

		require.NoError(t, err)
		assert.Equal(t, credentialID, credential.ID)
		mockQuerier.AssertExpectations(t)
	})

	t.Run("database error", func(t *testing.T) {
		mockQuerier := mocks.NewMockQuerier(t)
		mockQuerier.On("GetCredentialByID", ctx, uuidToPgtype(credentialID)).Return(sqlc.ProfessionalCredential{}, assert.AnError)

		repo := NewCredentialRepositoryWithQuerier(mockQuerier)
		_, err := repo.GetCredentialByID(ctx, credentialID)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "get credential by id failed")
		mockQuerier.AssertExpectations(t)
	})
}
