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

func buildSymptomSessionRow(id, patientID, userID string, status string) sqlc.SymptomCheckerSession {
	now := nowTime()
	return sqlc.SymptomCheckerSession{
		ID:                  uuidPgtypeFromString(id),
		PatientID:           uuidPgtypeFromString(patientID),
		UserID:              uuidPgtypeFromString(userID),
		DependentID:         pgtype.UUID{Valid: false},
		ChiefComplaint:      "Test complaint",
		SymptomDuration:     pgtype.Text{String: "2 days", Valid: true},
		SymptomsReported:    []byte{},
		BodySystemsAffected: []string{},
		SeverityScore:       pgtype.Int4{Int32: int32(3), Valid: true},
		IsForDependent:      false,
		TriageLevel:         "low",
		AiSummary:           pgtype.Text{Valid: false},
		RecommendedAction:   pgtype.Text{String: "self_care", Valid: true},
		Status:              status,
		RawAnswers:          []byte{},
		CreatedAt:           pgtype.Timestamp{Time: now, Valid: true},
		UpdatedAt:           pgtype.Timestamp{Time: now, Valid: true},
	}
}

func buildSymptomSession(id string, status telemedicine.SessionStatus) telemedicine.SymptomCheckerSession {
	now := nowTime()
	return telemedicine.SymptomCheckerSession{
		ID:                uuid.MustParse(id),
		PatientID:         uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
		UserID:            uuid.MustParse("123e4567-e89b-12d3-a456-426614174003"),
		ChiefComplaint:    "Test complaint",
		SeverityScore:     intPtr(3),
		TriageLevel:       telemedicine.TriageLow,
		RecommendedAction: telemedicine.ActionSelfCare,
		Status:            status,
		CreatedAt:          now,
		UpdatedAt:         now,
	}
}

func TestSymptomCheckerRepository_CreateSession(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name          string
		session       telemedicine.SymptomCheckerSession
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.SymptomCheckerSession
		expectedError error
	}{
		{
			name: "success",
			session: telemedicine.SymptomCheckerSession{
				PatientID:         uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
				UserID:            uuid.MustParse("123e4567-e89b-12d3-a456-426614174003"),
				ChiefComplaint:    "Test complaint",
				SeverityScore:     intPtr(3),
				TriageLevel:       telemedicine.TriageLow,
				RecommendedAction: telemedicine.ActionSelfCare,
				Status:            telemedicine.StatusCompleted,
			},
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildSymptomSessionRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174002",
					"123e4567-e89b-12d3-a456-426614174003",
					"completed",
				)
				m.On("CreateSymptomSession", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildSymptomSession("123e4567-e89b-12d3-a456-426614174000", telemedicine.StatusCompleted),
			expectedError: nil,
		},
		{
			name: "database error",
			session: telemedicine.SymptomCheckerSession{
				PatientID:      uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
				UserID:         uuid.MustParse("123e4567-e89b-12d3-a456-426614174003"),
				ChiefComplaint: "Test complaint",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateSymptomSession", ctx, mock.Anything).Return(sqlc.SymptomCheckerSession{}, assert.AnError)
			},
			expected:      telemedicine.SymptomCheckerSession{},
			expectedError: assert.AnError,
		},
		{
			name: "foreign key violation",
			session: telemedicine.SymptomCheckerSession{
				PatientID:      uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
				UserID:         uuid.MustParse("123e4567-e89b-12d3-a456-426614174003"),
				ChiefComplaint: "Test complaint",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateSymptomSession", ctx, mock.Anything).Return(sqlc.SymptomCheckerSession{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.SymptomCheckerSession{},
			expectedError: domain.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewSymptomCheckerRepositoryWithQuerier(mockQuerier)

			got, err := repo.CreateSession(ctx, tt.session)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "create session")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.PatientID, got.PatientID)
				assert.Equal(t, tt.expected.ChiefComplaint, got.ChiefComplaint)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestSymptomCheckerRepository_GetSessionByID(t *testing.T) {
	ctx := context.Background()
	sessionID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		sessionID     uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.SymptomCheckerSession
		expectedError error
	}{
		{
			name:      "found",
			sessionID: sessionID,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildSymptomSessionRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174002",
					"123e4567-e89b-12d3-a456-426614174003",
					"completed",
				)
				row.AiSummary = pgtype.Text{String: "AI summary text", Valid: true}
				m.On("GetSymptomSessionByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(row, nil)
			},
			expected:      buildSymptomSession("123e4567-e89b-12d3-a456-426614174000", telemedicine.StatusCompleted),
			expectedError: nil,
		},
		{
			name:      "not found",
			sessionID: sessionID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetSymptomSessionByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.SymptomCheckerSession{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.SymptomCheckerSession{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:      "database error",
			sessionID: sessionID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetSymptomSessionByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.SymptomCheckerSession{}, assert.AnError)
			},
			expected:      telemedicine.SymptomCheckerSession{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewSymptomCheckerRepositoryWithQuerier(mockQuerier)

			got, err := repo.GetSessionByID(ctx, tt.sessionID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get session by id")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.PatientID, got.PatientID)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestSymptomCheckerRepository_UpdateSessionStatus(t *testing.T) {
	ctx := context.Background()
	sessionID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		sessionID     uuid.UUID
		status        telemedicine.SessionStatus
		mockSetup     func(*mocks.MockQuerier)
		expectedError error
	}{
		{
			name:      "success to completed",
			sessionID: sessionID,
			status:    telemedicine.StatusCompleted,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateSessionStatus", ctx, mock.Anything).Return(nil)
			},
			expectedError: nil,
		},
		{
			name:      "not found",
			sessionID: sessionID,
			status:    telemedicine.StatusCompleted,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateSessionStatus", ctx, mock.Anything).Return(pgx.ErrNoRows)
			},
			expectedError: domain.ErrNotFound,
		},
		{
			name:      "database error",
			sessionID: sessionID,
			status:    telemedicine.StatusCompleted,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("UpdateSessionStatus", ctx, mock.Anything).Return(assert.AnError)
			},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewSymptomCheckerRepositoryWithQuerier(mockQuerier)

			err := repo.UpdateSessionStatus(ctx, tt.sessionID, tt.status)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "update session status")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestSymptomCheckerRepository_GetPatientSessions(t *testing.T) {
	ctx := context.Background()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174002")

	tests := []struct {
		name          string
		patientID     uuid.UUID
		limit         int
		offset        int
		mockSetup     func(*mocks.MockQuerier)
		expected      []telemedicine.SymptomSessionSummary
		expectedError error
	}{
		{
			name:      "found sessions",
			patientID: patientID,
			limit:     10,
			offset:    0,
			mockSetup: func(m *mocks.MockQuerier) {
				rows := []sqlc.GetPatientSessionsRow{
					{
						ID:                uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
						ChiefComplaint:    "Headache",
						TriageLevel:       "low",
						RecommendedAction: pgtype.Text{String: "self_care", Valid: true},
						SeverityScore:     pgtype.Int4{Int32: int32(2), Valid: true},
						Status:            "completed",
						IsForDependent:    false,
						DependentID:       pgtype.UUID{Valid: false},
						CreatedAt:         pgtype.Timestamp{Time: nowTime(), Valid: true},
					},
				}
				m.On("GetPatientSessions", ctx, mock.Anything).Return(rows, nil)
			},
			expected: []telemedicine.SymptomSessionSummary{
				{
					ID:                uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
					ChiefComplaint:    "Headache",
					TriageLevel:       telemedicine.TriageLow,
					RecommendedAction: telemedicine.ActionSelfCare,
					SeverityScore:     intPtr(2),
					Status:            telemedicine.StatusCompleted,
					IsForDependent:    false,
				},
			},
			expectedError: nil,
		},
		{
			name:      "empty",
			patientID: patientID,
			limit:     10,
			offset:    0,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientSessions", ctx, mock.Anything).Return([]sqlc.GetPatientSessionsRow{}, nil)
			},
			expected:      []telemedicine.SymptomSessionSummary{},
			expectedError: nil,
		},
		{
			name:      "database error",
			patientID: patientID,
			limit:     10,
			offset:    0,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientSessions", ctx, mock.Anything).Return(nil, assert.AnError)
			},
			expected:      nil,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewSymptomCheckerRepositoryWithQuerier(mockQuerier)

			got, err := repo.GetPatientSessions(ctx, tt.patientID, tt.limit, tt.offset)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get patient sessions")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, len(tt.expected), len(got))
				if len(got) > 0 {
					assert.Equal(t, tt.expected[0].ID, got[0].ID)
					assert.Equal(t, tt.expected[0].ChiefComplaint, got[0].ChiefComplaint)
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}