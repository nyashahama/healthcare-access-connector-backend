package providers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func stringPtr(s string) *string {
	return &s
}

func uuidPtr(id uuid.UUID) *uuid.UUID {
	return &id
}

func uuidToPgtype(id uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: id, Valid: true}
}

func TestClinicRepository_CreateClinic(t *testing.T) {
	ctx := context.Background()
	clinicID := uuid.New()
	ownerID := uuid.New()
	expiryDate := time.Now().AddDate(1, 0, 0)

	tests := []struct {
		name          string
		clinic        providers.Clinic
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name: "successful clinic creation",
			clinic: providers.Clinic{
				ID:                 clinicID,
				ClinicName:         "Test Clinic",
				ClinicType:         "private_clinic",
				PhysicalAddress:    "123 Main St",
				Country:            "South Africa",
				OwnerUserID:        uuidPtr(ownerID),
				VerificationStatus: "pending",
				AccreditationExpiry: &expiryDate,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateClinic", ctx, mock.Anything).Return(sqlc.Clinic{
					ID: uuidToPgtype(clinicID),
					ClinicName:       "Test Clinic",
					ClinicType:       "private_clinic",
					PhysicalAddress:  "123 Main St",
					VerificationStatus: pgtype.Text{String: "pending", Valid: true},
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "database error on insert",
			clinic: providers.Clinic{
				ClinicName:         "Test Clinic",
				ClinicType:         "private_clinic",
				PhysicalAddress:    "123 Main St",
				Country:            "South Africa",
				AccreditationExpiry: &expiryDate,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateClinic", ctx, mock.Anything).
					Return(sqlc.Clinic{}, assert.AnError)
			},
			expectedError: assert.AnError,
		},
		{
			name: "nil clinic returns error",
			clinic: providers.Clinic{
				ClinicName:         "Test Clinic",
				ClinicType:         "private_clinic",
				PhysicalAddress:    "123 Main St",
				Country:            "South Africa",
				AccreditationExpiry: &expiryDate,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateClinic", ctx, mock.Anything).
					Return(sqlc.Clinic{}, assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewClinicRepositoryWithQuerier(mockQuerier)

			clinic, err := repo.CreateClinic(ctx, tt.clinic, uuid.New(), ownerID)

			if tt.expectedError != nil {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "Test Clinic", clinic.ClinicName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestClinicRepository_GetClinicByID(t *testing.T) {
	ctx := context.Background()
	clinicID := uuid.New()

	tests := []struct {
		name          string
		id            uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedClinic providers.Clinic
		expectedError error
	}{
		{
			name: "clinic found",
			id:   clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetClinicByID", ctx, uuidToPgtype(clinicID)).Return(sqlc.Clinic{
					ID:                uuidToPgtype(clinicID),
					ClinicName:        "Test Clinic",
					ClinicType:        "private_clinic",
					PhysicalAddress:   "123 Main St",
					VerificationStatus: pgtype.Text{String: "verified", Valid: true},
					IsVerified:         pgtype.Bool{Bool: true, Valid: true},
				}, nil)
			},
			expectedClinic: providers.Clinic{
				ID:                 clinicID,
				ClinicName:         "Test Clinic",
				ClinicType:         "private_clinic",
				PhysicalAddress:    "123 Main St",
				VerificationStatus: "verified",
				IsVerified:         true,
			},
			expectedError: nil,
		},
		{
			name: "clinic not found",
			id:   clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetClinicByID", ctx, uuidToPgtype(clinicID)).Return(sqlc.Clinic{}, pgx.ErrNoRows)
			},
			expectedClinic: providers.Clinic{},
			expectedError: domain.ErrClinicNotFound,
		},
		{
			name: "database error",
			id:   clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetClinicByID", ctx, mock.Anything).Return(sqlc.Clinic{}, assert.AnError)
			},
			expectedClinic: providers.Clinic{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewClinicRepositoryWithQuerier(mockQuerier)

			clinic, err := repo.GetClinicByID(ctx, tt.id)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == domain.ErrClinicNotFound {
					assert.Equal(t, domain.ErrClinicNotFound, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedClinic.ClinicName, clinic.ClinicName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestClinicRepository_UpdateClinic(t *testing.T) {
	ctx := context.Background()
	clinicID := uuid.New()

	tests := []struct {
		name          string
		clinic        providers.Clinic
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name: "successful update",
			clinic: providers.Clinic{
				ID:           clinicID,
				ClinicName:   "Updated Clinic",
				ClinicType:   "private_clinic",
				Description:  stringPtr("Updated description"),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateClinic", ctx, mock.MatchedBy(func(params sqlc.UpdateClinicParams) bool {
					return params.ClinicName == "Updated Clinic"
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "clinic not found",
			clinic: providers.Clinic{
				ID:         clinicID,
				ClinicName: "Test Clinic",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateClinic", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectedError: fmt.Errorf("update clinic failed: %w", pgx.ErrNoRows),
		},
		{
			name: "database error",
			clinic: providers.Clinic{
				ID:         clinicID,
				ClinicName: "Test Clinic",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateClinic", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update clinic failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewClinicRepositoryWithQuerier(mockQuerier)

			err := repo.UpdateClinic(ctx, tt.clinic)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestClinicRepository_SearchClinics(t *testing.T) {
	ctx := context.Background()
	clinicID := uuid.New()

	tests := []struct {
		name          string
		params        providers.ClinicSearchParams
		mockSetup     func(*mocks.MockQuerier)
		expectedResults []providers.ClinicSearchResult
		expectedError error
	}{
		{
			name: "results found",
			params: providers.ClinicSearchParams{
				Query:  "test",
				Limit:  10,
				Offset: 0,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("SearchClinics", ctx, sqlc.SearchClinicsParams{
					Column1: pgtype.Text{String: "test", Valid: true},
					Column2: "",
					Column3: "",
					Column4: "",
					Limit:   10,
					Offset:  0,
				}).Return([]sqlc.SearchClinicsRow{
					{
						ID:                uuidToPgtype(clinicID),
						ClinicName:        "Test Clinic 1",
						ClinicType:        "private_clinic",
						PhysicalAddress:   "123 Main St",
						VerificationStatus: pgtype.Text{String: "verified", Valid: true},
						AcceptsMedicalAid: pgtype.Bool{Bool: true, Valid: true},
					},
				}, nil)
			},
			expectedResults: []providers.ClinicSearchResult{
				{
					Clinic: providers.Clinic{
						ID:                 clinicID,
						ClinicName:         "Test Clinic 1",
						ClinicType:         "private_clinic",
						PhysicalAddress:    "123 Main St",
						VerificationStatus: "verified",
						AcceptsMedicalAid:  true,
					},
				},
			},
			expectedError: nil,
		},
		{
			name: "empty results",
			params: providers.ClinicSearchParams{
				Query:  "nonexistent",
				Limit:  10,
				Offset: 0,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("SearchClinics", ctx, mock.Anything).Return([]sqlc.SearchClinicsRow{}, nil)
			},
			expectedResults: []providers.ClinicSearchResult{},
			expectedError: nil,
		},
		{
			name: "database error",
			params: providers.ClinicSearchParams{
				Query:  "test",
				Limit:  10,
				Offset: 0,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("SearchClinics", ctx, mock.Anything).Return([]sqlc.SearchClinicsRow{}, assert.AnError)
			},
			expectedResults: nil,
			expectedError: fmt.Errorf("search clinics failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewClinicRepositoryWithQuerier(mockQuerier)

			results, err := repo.SearchClinics(ctx, tt.params)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
				assert.Nil(t, results)
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(tt.expectedResults), len(results))
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestClinicRepository_GetClinicByOwner(t *testing.T) {
	ctx := context.Background()
	clinicID := uuid.New()
	ownerID := uuid.New()

	tests := []struct {
		name          string
		ownerUserID   uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedClinic *providers.Clinic
		expectedError error
	}{
		{
			name: "clinic found",
			ownerUserID: ownerID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetClinicByOwner", ctx, uuidToPgtype(ownerID)).Return(sqlc.Clinic{
					ID:                uuidToPgtype(clinicID),
					OwnerUserID:       uuidPtrToPgtypeUUID(uuidPtr(ownerID)),
					ClinicName:        "Test Clinic",
					ClinicType:        "private_clinic",
					PhysicalAddress:   "123 Main St",
					VerificationStatus: pgtype.Text{String: "verified", Valid: true},
				}, nil)
			},
			expectedClinic: &providers.Clinic{
				ID:                 clinicID,
				OwnerUserID:        uuidPtr(ownerID),
				ClinicName:         "Test Clinic",
				ClinicType:         "private_clinic",
				PhysicalAddress:    "123 Main St",
				VerificationStatus: "verified",
			},
			expectedError: nil,
		},
		{
			name: "clinic not found",
			ownerUserID: ownerID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetClinicByOwner", ctx, uuidToPgtype(ownerID)).Return(sqlc.Clinic{}, pgx.ErrNoRows)
			},
			expectedClinic: nil,
			expectedError: domain.ErrClinicNotFound,
		},
		{
			name: "database error",
			ownerUserID: ownerID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetClinicByOwner", ctx, mock.Anything).Return(sqlc.Clinic{}, assert.AnError)
			},
			expectedClinic: nil,
			expectedError: fmt.Errorf("get clinic by owner: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewClinicRepositoryWithQuerier(mockQuerier)

			clinic, err := repo.GetClinicByOwner(ctx, tt.ownerUserID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == domain.ErrClinicNotFound {
					assert.Equal(t, domain.ErrClinicNotFound, err)
				} else {
					assert.Contains(t, err.Error(), tt.expectedError.Error())
				}
				assert.Nil(t, clinic)
			} else {
				require.NoError(t, err)
				require.NotNil(t, clinic)
				assert.Equal(t, tt.expectedClinic.ClinicName, clinic.ClinicName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}