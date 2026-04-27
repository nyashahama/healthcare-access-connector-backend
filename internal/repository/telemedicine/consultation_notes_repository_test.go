package telemedicine

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func buildNoteRow(id, consultationID, authoredByStaffID string, isFinalised bool) sqlc.ConsultationNote {
	now := nowTime()
	return sqlc.ConsultationNote{
		ID:                  uuidPgtypeFromString(id),
		ConsultationID:      uuidPgtypeFromString(consultationID),
		AuthoredByStaffID:   uuidPgtypeFromString(authoredByStaffID),
		Subjective:          pgtype.Text{Valid: false},
		Objective:           pgtype.Text{Valid: false},
		Assessment:          pgtype.Text{Valid: false},
		Plan:                pgtype.Text{Valid: false},
		DiagnosisCodes:     []string{},
		PrescriptionIssued:  false,
		PrescriptionDetails: []byte{},
		ReferralRequired:    false,
		ReferralType:        pgtype.Text{Valid: false},
		ReferralNotes:       pgtype.Text{Valid: false},
		FollowUpRecommended: false,
		FollowUpTimeframe:   pgtype.Text{Valid: false},
		IsFinalised:         isFinalised,
		FinalisedAt:         pgtype.Timestamp{Valid: false},
		CreatedAt:           pgtype.Timestamp{Time: now, Valid: true},
		UpdatedAt:           pgtype.Timestamp{Time: now, Valid: true},
	}
}

func buildNote(id string, consultationID uuid.UUID, isFinalised bool) telemedicine.ConsultationNote {
	now := nowTime()
	return telemedicine.ConsultationNote{
		ID:                  uuid.MustParse(id),
		ConsultationID:      consultationID,
		AuthoredByStaffID:   uuid.MustParse("123e4567-e89b-12d3-a456-426614174003"),
		PrescriptionIssued:  false,
		ReferralRequired:    false,
		FollowUpRecommended: false,
		IsFinalised:         isFinalised,
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

func TestConsultationNotesRepository_CreateNote(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174001")
	authoredByStaffID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174003")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		authoredByStaffID uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.ConsultationNote
		expectedError error
	}{
		{
			name:           "success",
			consultationID: consultationID,
			authoredByStaffID: authoredByStaffID,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildNoteRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174003",
					false,
				)
				m.On("CreateConsultationNote", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildNote("123e4567-e89b-12d3-a456-426614174000", consultationID, false),
			expectedError: nil,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			authoredByStaffID: authoredByStaffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateConsultationNote", ctx, mock.Anything).Return(sqlc.ConsultationNote{}, assert.AnError)
			},
			expected:      telemedicine.ConsultationNote{},
			expectedError: assert.AnError,
		},
		{
			name:           "foreign key violation",
			consultationID: consultationID,
			authoredByStaffID: authoredByStaffID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateConsultationNote", ctx, mock.Anything).Return(sqlc.ConsultationNote{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.ConsultationNote{},
			expectedError: domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationNotesRepositoryWithQuerier(mockQuerier)

			got, err := repo.CreateNote(ctx, tt.consultationID, tt.authoredByStaffID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "create note")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.ConsultationID, got.ConsultationID)
				assert.Equal(t, tt.expected.AuthoredByStaffID, got.AuthoredByStaffID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationNotesRepository_GetNoteByConsultationID(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174001")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.ConsultationNote
		expectedError error
	}{
		{
			name:           "found",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildNoteRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174003",
					false,
				)
				row.Subjective = pgtype.Text{String: "Patient reports headache", Valid: true}
				row.Objective = pgtype.Text{String: "Vital signs normal", Valid: true}
				m.On("GetNoteByConsultationID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001")).Return(row, nil)
			},
			expected: buildNote("123e4567-e89b-12d3-a456-426614174000", consultationID, false),
			expectedError: nil,
		},
		{
			name:           "not found",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetNoteByConsultationID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001")).Return(sqlc.ConsultationNote{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.ConsultationNote{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetNoteByConsultationID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001")).Return(sqlc.ConsultationNote{}, assert.AnError)
			},
			expected:      telemedicine.ConsultationNote{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationNotesRepositoryWithQuerier(mockQuerier)

			got, err := repo.GetNoteByConsultationID(ctx, tt.consultationID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get note by consultation id")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.ConsultationID, got.ConsultationID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationNotesRepository_UpdateNote(t *testing.T) {
	ctx := context.Background()
	noteID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		noteID        uuid.UUID
		update        telemedicine.ConsultationNote
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.ConsultationNote
		expectedError error
	}{
		{
			name:   "success",
			noteID: noteID,
			update: telemedicine.ConsultationNote{
				Subjective: stringPtr("Updated subjective"),
				Objective: stringPtr("Updated objective"),
				Assessment: stringPtr("Updated assessment"),
				Plan: stringPtr("Updated plan"),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildNoteRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174003",
					false,
				)
				row.Subjective = pgtype.Text{String: "Updated subjective", Valid: true}
				row.Objective = pgtype.Text{String: "Updated objective", Valid: true}
				row.Assessment = pgtype.Text{String: "Updated assessment", Valid: true}
				row.Plan = pgtype.Text{String: "Updated plan", Valid: true}
				m.On("UpdateConsultationNote", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildNote("123e4567-e89b-12d3-a456-426614174000", uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"), false),
			expectedError: nil,
		},
		{
			name:   "not found",
			noteID: noteID,
			update: telemedicine.ConsultationNote{
				Assessment: stringPtr("Updated assessment"),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateConsultationNote", ctx, mock.Anything).Return(sqlc.ConsultationNote{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.ConsultationNote{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:   "database error",
			noteID: noteID,
			update: telemedicine.ConsultationNote{
				Assessment: stringPtr("Updated assessment"),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateConsultationNote", ctx, mock.Anything).Return(sqlc.ConsultationNote{}, assert.AnError)
			},
			expected:      telemedicine.ConsultationNote{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationNotesRepositoryWithQuerier(mockQuerier)

			got, err := repo.UpdateNote(ctx, tt.noteID, tt.update)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "update note")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationNotesRepository_FinaliseNote(t *testing.T) {
	ctx := context.Background()
	noteID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		noteID        uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.ConsultationNote
		expectedError error
	}{
		{
			name:   "success",
			noteID: noteID,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildNoteRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174003",
					true,
				)
				row.FinalisedAt = pgtype.Timestamp{Time: nowTime(), Valid: true}
				m.On("FinaliseConsultationNote", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(row, nil)
			},
			expected:      buildNote("123e4567-e89b-12d3-a456-426614174000", uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"), true),
			expectedError: nil,
		},
		{
			name:   "not found",
			noteID: noteID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("FinaliseConsultationNote", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.ConsultationNote{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.ConsultationNote{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:   "database error",
			noteID: noteID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("FinaliseConsultationNote", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.ConsultationNote{}, assert.AnError)
			},
			expected:      telemedicine.ConsultationNote{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationNotesRepositoryWithQuerier(mockQuerier)

			got, err := repo.FinaliseNote(ctx, tt.noteID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "finalise note")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.True(t, got.IsFinalised)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationNotesRepository_IsNoteFinalised(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174001")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      bool
		expectedError error
	}{
		{
			name:           "finalised",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("IsNoteFinalisedForConsultation", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001")).Return(true, nil)
			},
			expected:      true,
			expectedError: nil,
		},
		{
			name:           "not finalised",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("IsNoteFinalisedForConsultation", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001")).Return(false, nil)
			},
			expected:      false,
			expectedError: nil,
		},
		{
			name:           "not found",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("IsNoteFinalisedForConsultation", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001")).Return(false, pgx.ErrNoRows)
			},
			expected:      false,
			expectedError: domain.ErrNotFound,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("IsNoteFinalisedForConsultation", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174001")).Return(false, assert.AnError)
			},
			expected:      false,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationNotesRepositoryWithQuerier(mockQuerier)

			got, err := repo.IsNoteFinalised(ctx, tt.consultationID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "is note finalised")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, got)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}