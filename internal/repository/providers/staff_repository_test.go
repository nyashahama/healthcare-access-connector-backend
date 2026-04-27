package providers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestStaffRepository_CreateStaffMember(t *testing.T) {
	ctx := context.Background()
	staffID := uuid.New()
	clinicID := uuid.New()
	userID := uuid.New()

	tests := []struct {
		name          string
		staff         providers.ClinicStaff
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name: "successful staff member creation",
			staff: providers.ClinicStaff{
				ID:           staffID,
				ClinicID:     clinicID,
				UserID:       &userID,
				FirstName:    "John",
				LastName:     "Doe",
				StaffRole:    "doctor",
				WorkEmail:    stringPtr("john@clinic.com"),
				WorkPhone:    stringPtr("+1234567890"),
				HPCSNumber:   stringPtr("HPCS123"),
				EmploymentStatus: "full_time",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateStaffMember", ctx, mock.Anything).Return(sqlc.ClinicStaff{
					ID:                uuidToPgtype(staffID),
					ClinicID:          uuidToPgtype(clinicID),
					UserID:            uuidPtrToPgtypeUUID(&userID),
					FirstName:         "John",
					LastName:          "Doe",
					StaffRole:         "doctor",
					WorkEmail:         pgtype.Text{String: "john@clinic.com", Valid: true},
					WorkPhone:         pgtype.Text{String: "+1234567890", Valid: true},
					HpcsNumber:        pgtype.Text{String: "HPCS123", Valid: true},
					EmploymentStatus: pgtype.Text{String: "full_time", Valid: true},
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "database error on insert",
			staff: providers.ClinicStaff{
				ClinicID:  clinicID,
				FirstName: "John",
				LastName:  "Doe",
				StaffRole: "doctor",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateStaffMember", ctx, mock.Anything).
					Return(sqlc.ClinicStaff{}, assert.AnError)
			},
			expectedError: assert.AnError,
		},
		{
			name: "foreign key violation",
			staff: providers.ClinicStaff{
				ClinicID:  clinicID,
				FirstName: "John",
				LastName:  "Doe",
				StaffRole: "doctor",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				pgErr := &pgconn.PgError{Code: "23503", ConstraintName: "clinic_id"}
				m.On("CreateStaffMember", ctx, mock.Anything).
					Return(sqlc.ClinicStaff{}, pgErr)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewStaffRepositoryWithQuerier(mockQuerier)

			staff, err := repo.CreateStaffMember(ctx, tt.staff)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "John", staff.FirstName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestStaffRepository_GetStaffByUserID(t *testing.T) {
	ctx := context.Background()
	staffID := uuid.New()
	clinicID := uuid.New()
	userID := uuid.New()

	tests := []struct {
		name          string
		userID        uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedStaff providers.ClinicStaff
		expectedError error
	}{
		{
			name:   "staff found",
			userID: userID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetStaffByUserID", ctx, uuidToPgtype(userID)).Return(sqlc.ClinicStaff{
					ID:         uuidToPgtype(staffID),
					ClinicID:   uuidToPgtype(clinicID),
					UserID:     uuidPtrToPgtypeUUID(&userID),
					FirstName:  "John",
					LastName:   "Doe",
					StaffRole:  "doctor",
					EmploymentStatus: pgtype.Text{String: "full_time", Valid: true},
				}, nil)
			},
			expectedStaff: providers.ClinicStaff{
				ID:             staffID,
				ClinicID:       clinicID,
				UserID:         &userID,
				FirstName:      "John",
				LastName:       "Doe",
				StaffRole:      "doctor",
				EmploymentStatus: "full_time",
			},
			expectedError: nil,
		},
		{
			name:   "staff not found",
			userID: userID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetStaffByUserID", ctx, uuidToPgtype(userID)).Return(sqlc.ClinicStaff{}, pgx.ErrNoRows)
			},
			expectedStaff: providers.ClinicStaff{},
			expectedError: domain.ErrStaffNotFound,
		},
		{
			name:   "database error",
			userID: userID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetStaffByUserID", ctx, mock.Anything).Return(sqlc.ClinicStaff{}, assert.AnError)
			},
			expectedStaff: providers.ClinicStaff{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewStaffRepositoryWithQuerier(mockQuerier)

			staff, err := repo.GetStaffByUserID(ctx, tt.userID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == domain.ErrStaffNotFound {
					assert.Equal(t, domain.ErrStaffNotFound, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedStaff.FirstName, staff.FirstName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestStaffRepository_GetAllClinicStaff(t *testing.T) {
	ctx := context.Background()
	clinicID := uuid.New()
	staffID1 := uuid.New()
	staffID2 := uuid.New()

	tests := []struct {
		name          string
		clinicID      uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedStaff []providers.ClinicStaff
		expectedError error
	}{
		{
			name:     "staff found",
			clinicID: clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAllClinicStaff", ctx, uuidToPgtype(clinicID)).Return([]sqlc.GetAllClinicStaffRow{
					{
						ID:                     uuidToPgtype(staffID1),
						ClinicID:               uuidToPgtype(clinicID),
						FirstName:              "John",
						LastName:               "Doe",
						StaffRole:              "doctor",
						EmploymentStatus:       pgtype.Text{String: "full_time", Valid: true},
						IsAcceptingNewPatients: pgtype.Bool{Bool: true, Valid: true},
					},
					{
						ID:                     uuidToPgtype(staffID2),
						ClinicID:               uuidToPgtype(clinicID),
						FirstName:              "Jane",
						LastName:               "Smith",
						StaffRole:              "nurse",
						EmploymentStatus:       pgtype.Text{String: "full_time", Valid: true},
						IsAcceptingNewPatients: pgtype.Bool{Bool: false, Valid: true},
					},
				}, nil)
			},
			expectedStaff: []providers.ClinicStaff{
				{
					ID:         staffID1,
					ClinicID:   clinicID,
					FirstName:  "John",
					LastName:   "Doe",
					StaffRole:  "doctor",
					EmploymentStatus: "full_time",
					IsAcceptingNewPatients: true,
				},
				{
					ID:         staffID2,
					ClinicID:   clinicID,
					FirstName:  "Jane",
					LastName:   "Smith",
					StaffRole:  "nurse",
					EmploymentStatus: "full_time",
					IsAcceptingNewPatients: false,
				},
			},
			expectedError: nil,
		},
		{
			name:     "empty list",
			clinicID: clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAllClinicStaff", ctx, uuidToPgtype(clinicID)).Return([]sqlc.GetAllClinicStaffRow{}, nil)
			},
			expectedStaff: []providers.ClinicStaff{},
			expectedError: nil,
		},
		{
			name:     "database error",
			clinicID: clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetAllClinicStaff", ctx, mock.Anything).Return([]sqlc.GetAllClinicStaffRow{}, assert.AnError)
			},
			expectedStaff: nil,
			expectedError: fmt.Errorf("get all clinic staff failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewStaffRepositoryWithQuerier(mockQuerier)

			staff, err := repo.GetAllClinicStaff(ctx, tt.clinicID)

			if tt.expectedError != nil {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(tt.expectedStaff), len(staff))
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestStaffRepository_UpdateStaffMember(t *testing.T) {
	ctx := context.Background()
	staffID := uuid.New()

	tests := []struct {
		name          string
		staff         providers.ClinicStaff
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name: "successful update",
			staff: providers.ClinicStaff{
				ID:          staffID,
				FirstName:   "John",
				LastName:    "Doe Updated",
				Bio:         stringPtr("Updated bio"),
				IsAcceptingNewPatients: true,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateStaffMember", ctx, mock.MatchedBy(func(params sqlc.UpdateStaffMemberParams) bool {
					return params.FirstName == "John" && params.LastName == "Doe Updated"
				})).Return(nil)
			},
			expectedError: nil,
		},
		{
			name: "staff not found",
			staff: providers.ClinicStaff{
				ID:        staffID,
				FirstName: "John",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateStaffMember", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectedError: fmt.Errorf("update staff member failed: %w", pgx.ErrNoRows),
		},
		{
			name: "database error",
			staff: providers.ClinicStaff{
				ID:        staffID,
				FirstName: "John",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateStaffMember", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("update staff member failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewStaffRepositoryWithQuerier(mockQuerier)

			err := repo.UpdateStaffMember(ctx, tt.staff)

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

func TestStaffRepository_DeleteStaffMember(t *testing.T) {
	ctx := context.Background()
	staffID := uuid.New()

	tests := []struct {
		name          string
		staffID       uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name:    "successful deletion",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteStaffMember", ctx, uuidToPgtype(staffID)).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:    "database error",
			staffID: staffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("DeleteStaffMember", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: fmt.Errorf("delete staff member failed: %w", assert.AnError),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewStaffRepositoryWithQuerier(mockQuerier)

			err := repo.DeleteStaffMember(ctx, tt.staffID)

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

func TestStaffRepository_CreateStaffInvitation(t *testing.T) {
	ctx := context.Background()
	clinicID := uuid.New()
	invitedBy := uuid.New()
	invitationID := uuid.New()
	expiry := time.Now().Add(24 * time.Hour)

	tests := []struct {
		name          string
		invitation    providers.StaffInvitation
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name: "successful invitation creation",
			invitation: providers.StaffInvitation{
				ClinicID:     clinicID,
				WorkEmail:    "john@clinic.com",
				FirstName:    "John",
				LastName:     "Doe",
				StaffRole:    "doctor",
				InvitationToken: "token123",
				InvitedBy:   invitedBy,
				InvitationExpires: expiry,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateStaffInvitation", ctx, mock.Anything).Return(sqlc.ClinicStaff{
					ID:                uuidToPgtype(invitationID),
					ClinicID:          uuidToPgtype(clinicID),
					WorkEmail:         pgtype.Text{String: "john@clinic.com", Valid: true},
					FirstName:         "John",
					LastName:          "Doe",
					StaffRole:         "doctor",
					InvitationToken:    pgtype.Text{String: "token123", Valid: true},
					InvitedBy:         uuidPtrToPgtypeUUID(&invitedBy),
					InvitationExpires: pgtype.Timestamp{Time: expiry, Valid: true},
				}, nil)
			},
			expectedError: nil,
		},
		{
			name: "database error",
			invitation: providers.StaffInvitation{
				ClinicID:  clinicID,
				WorkEmail: "john@clinic.com",
				FirstName: "John",
				LastName:  "Doe",
				StaffRole: "doctor",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateStaffInvitation", ctx, mock.Anything).
					Return(sqlc.ClinicStaff{}, assert.AnError)
			},
			expectedError: assert.AnError,
		},
		{
			name: "duplicate email",
			invitation: providers.StaffInvitation{
				ClinicID:  clinicID,
				WorkEmail: "john@clinic.com",
				FirstName: "John",
				LastName:  "Doe",
				StaffRole: "doctor",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				pgErr := &pgconn.PgError{Code: "23505", ConstraintName: "work_email"}
				m.On("CreateStaffInvitation", ctx, mock.Anything).
					Return(sqlc.ClinicStaff{}, pgErr)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)
			repo := NewStaffRepositoryWithQuerier(mockQuerier)

			staff, err := repo.CreateStaffInvitation(ctx, tt.invitation)

			if tt.expectedError != nil {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "John", staff.FirstName)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}