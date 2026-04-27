package telemedicine

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	pgconn "github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	sqlc "github.com/nyashahama/healthcare-access-connector-backend/internal/db"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/db/mocks"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/telemedicine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func uuidPgtypeFromString(s string) pgtype.UUID {
	return pgtype.UUID{Bytes: uuid.MustParse(s), Valid: true}
}

func nowTime() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func float64Ptr(f float64) *float64 {
	return &f
}

func buildConsultationRow(id, symptomSessionID, patientID string, status string) sqlc.Consultation {
	now := nowTime()
	return sqlc.Consultation{
		ID:               uuidPgtypeFromString(id),
		SymptomSessionID: uuidPgtypeFromString(symptomSessionID),
		PatientID:        uuidPgtypeFromString(patientID),
		ProviderStaffID:  pgtype.UUID{Valid: false},
		ClinicID:         pgtype.UUID{Valid: false},
		Channel:          "chat",
		RequestedAt:      pgtype.Timestamp{Time: now, Valid: true},
		AcceptedAt:       pgtype.Timestamp{Valid: false},
		StartedAt:        pgtype.Timestamp{Valid: false},
		EndedAt:          pgtype.Timestamp{Valid: false},
		DurationSeconds:  pgtype.Int4{Valid: false},
		Status:           status,
		TriageLevelAtStart: pgtype.Text{String: "low", Valid: true},
		EndedBy:          pgtype.UUID{Valid: false},
		EndReason:        pgtype.Text{Valid: false},
		ConsultationFee:  pgtype.Numeric{Valid: false},
		FeeCurrency:      "USD",
		PaymentStatus:    "pending",
		PaymentReference: pgtype.Text{Valid: false},
		PatientRating:    pgtype.Int4{Valid: false},
		PatientFeedback:  pgtype.Text{Valid: false},
		RatedAt:          pgtype.Timestamp{Valid: false},
		FollowUpAppointmentID: pgtype.UUID{Valid: false},
		CreatedAt:        pgtype.Timestamp{Time: now, Valid: true},
		UpdatedAt:        pgtype.Timestamp{Time: now, Valid: true},
	}
}

func buildConsultation(id string, status telemedicine.ConsultationStatus) telemedicine.Consultation {
	now := nowTime()
	return telemedicine.Consultation{
		ID:             uuid.MustParse(id),
		SymptomSessionID: uuid.MustParse("123e4567-e89b-12d3-a456-426614174001"),
		PatientID:      uuid.MustParse("123e4567-e89b-12d3-a456-426614174002"),
		Channel:        telemedicine.ChannelChat,
		TriageLevelAtStart: stringPtr("low"),
		RequestedAt:    &now,
		Status:         status,
		FeeCurrency:    "USD",
		PaymentStatus:  telemedicine.PaymentStatusPending,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func TestConsultationRepository_CreateConsultation(t *testing.T) {
	ctx := context.Background()
	symptomSessionID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174001")
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174002")

	tests := []struct {
		name          string
		consultation  telemedicine.Consultation
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.Consultation
		expectedError error
	}{
		{
			name: "success",
			consultation: telemedicine.Consultation{
				SymptomSessionID:    symptomSessionID,
				PatientID:           patientID,
				Channel:             telemedicine.ChannelChat,
				TriageLevelAtStart: stringPtr("low"),
				ConsultationFee:     float64Ptr(50.00),
				FeeCurrency:         "USD",
			},
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildConsultationRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174002",
					"pending_acceptance",
				)
				row.ConsultationFee = pgtype.Numeric{Int: nil, Exp: 0, Valid: false}
				m.On("CreateConsultation", ctx, mock.Anything).Return(row, nil)
			},
			expected: buildConsultation("123e4567-e89b-12d3-a456-426614174000", telemedicine.ConsultationStatusPendingAcceptance),
			expectedError: nil,
		},
		{
			name: "database error",
			consultation: telemedicine.Consultation{
				SymptomSessionID:    symptomSessionID,
				PatientID:           patientID,
				Channel:             telemedicine.ChannelChat,
				TriageLevelAtStart: stringPtr("low"),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CreateConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, assert.AnError)
			},
			expected:      telemedicine.Consultation{},
			expectedError: assert.AnError,
		},
		{
			name: "foreign key violation",
			consultation: telemedicine.Consultation{
				SymptomSessionID:    symptomSessionID,
				PatientID:           patientID,
				Channel:             telemedicine.ChannelChat,
				TriageLevelAtStart: stringPtr("low"),
			},
			mockSetup: func(m *mocks.MockQuerier) {
				pgErr := &pgconn.PgError{Code: "23503"}
				m.On("CreateConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, pgErr)
			},
			expected:      telemedicine.Consultation{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationRepositoryWithQuerier(mockQuerier)

			got, err := repo.CreateConsultation(ctx, tt.consultation)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "create consultation")
				} else {
					var pgErr *pgconn.PgError
					if errors.As(err, &pgErr) {
						assert.Equal(t, "23503", pgErr.Code)
					} else {
						assert.Equal(t, tt.expectedError, err)
					}
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.SymptomSessionID, got.SymptomSessionID)
				assert.Equal(t, tt.expected.PatientID, got.PatientID)
				assert.Equal(t, tt.expected.Channel, got.Channel)
				assert.Equal(t, tt.expected.Status, got.Status)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationRepository_GetConsultationByID(t *testing.T) {
	ctx := context.Background()
	id := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		id            uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.Consultation
		expectedError error
	}{
		{
			name: "found",
			id:   id,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildConsultationRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174002",
					"in_progress",
				)
				m.On("GetConsultationByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(row, nil)
			},
			expected:      buildConsultation("123e4567-e89b-12d3-a456-426614174000", telemedicine.ConsultationStatusInProgress),
			expectedError: nil,
		},
		{
			name: "not found",
			id:   id,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetConsultationByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.Consultation{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.Consultation{},
			expectedError: domain.ErrNotFound,
		},
		{
			name: "database error",
			id:   id,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetConsultationByID", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.Consultation{}, assert.AnError)
			},
			expected:      telemedicine.Consultation{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationRepositoryWithQuerier(mockQuerier)

			got, err := repo.GetConsultationByID(ctx, tt.id)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get consultation by id")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.Status, got.Status)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationRepository_AcceptConsultation(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	providerStaffID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174003")
	clinicID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174004")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		providerStaffID uuid.UUID
		clinicID      uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.Consultation
		expectedError error
	}{
		{
			name:           "success",
			consultationID: consultationID,
			providerStaffID: providerStaffID,
			clinicID:       clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildConsultationRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174002",
					"accepted",
				)
				row.ProviderStaffID = uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174003")
				row.ClinicID = uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174004")
				m.On("AcceptConsultation", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildConsultation("123e4567-e89b-12d3-a456-426614174000", telemedicine.ConsultationStatusAccepted),
			expectedError: nil,
		},
		{
			name:           "not found",
			consultationID: consultationID,
			providerStaffID: providerStaffID,
			clinicID:       clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AcceptConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.Consultation{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			providerStaffID: providerStaffID,
			clinicID:       clinicID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("AcceptConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, assert.AnError)
			},
			expected:      telemedicine.Consultation{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationRepositoryWithQuerier(mockQuerier)

			got, err := repo.AcceptConsultation(ctx, tt.consultationID, tt.providerStaffID, tt.clinicID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "accept consultation")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.Status, got.Status)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationRepository_StartConsultation(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.Consultation
		expectedError error
	}{
		{
			name:           "success",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildConsultationRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174002",
					"in_progress",
				)
				m.On("StartConsultation", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(row, nil)
			},
			expected:      buildConsultation("123e4567-e89b-12d3-a456-426614174000", telemedicine.ConsultationStatusInProgress),
			expectedError: nil,
		},
		{
			name:           "not found",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("StartConsultation", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.Consultation{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.Consultation{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("StartConsultation", ctx, uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000")).Return(sqlc.Consultation{}, assert.AnError)
			},
			expected:      telemedicine.Consultation{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationRepositoryWithQuerier(mockQuerier)

			got, err := repo.StartConsultation(ctx, tt.consultationID)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "start consultation")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.Status, got.Status)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationRepository_CompleteConsultation(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	endedBy := uuid.MustParse("123e4567-e89b-12d3-a456-426614174005")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		endedBy       uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.Consultation
		expectedError error
	}{
		{
			name:           "success",
			consultationID: consultationID,
			endedBy:       endedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildConsultationRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174002",
					"completed",
				)
				row.EndedBy = uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174005")
				row.EndReason = pgtype.Text{String: "completed", Valid: true}
				row.DurationSeconds = pgtype.Int4{Int32: 1800, Valid: true}
				m.On("CompleteConsultation", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildConsultation("123e4567-e89b-12d3-a456-426614174000", telemedicine.ConsultationStatusCompleted),
			expectedError: nil,
		},
		{
			name:           "not found",
			consultationID: consultationID,
			endedBy:       endedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CompleteConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.Consultation{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			endedBy:       endedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CompleteConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, assert.AnError)
			},
			expected:      telemedicine.Consultation{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationRepositoryWithQuerier(mockQuerier)

			got, err := repo.CompleteConsultation(ctx, tt.consultationID, tt.endedBy)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "complete consultation")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.Status, got.Status)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationRepository_CancelConsultation(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	endedBy := uuid.MustParse("123e4567-e89b-12d3-a456-426614174005")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		endedBy       uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.Consultation
		expectedError error
	}{
		{
			name:           "success",
			consultationID: consultationID,
			endedBy:       endedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildConsultationRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174002",
					"cancelled",
				)
				row.EndedBy = uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174005")
				row.EndReason = pgtype.Text{String: "cancelled", Valid: true}
				m.On("CancelConsultation", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildConsultation("123e4567-e89b-12d3-a456-426614174000", telemedicine.ConsultationStatusCancelled),
			expectedError: nil,
		},
		{
			name:           "not found",
			consultationID: consultationID,
			endedBy:       endedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CancelConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.Consultation{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			endedBy:       endedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("CancelConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, assert.AnError)
			},
			expected:      telemedicine.Consultation{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationRepositoryWithQuerier(mockQuerier)

			got, err := repo.CancelConsultation(ctx, tt.consultationID, tt.endedBy)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "cancel consultation")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.Status, got.Status)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationRepository_EscalateConsultation(t *testing.T) {
	ctx := context.Background()
	consultationID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
	endedBy := uuid.MustParse("123e4567-e89b-12d3-a456-426614174005")

	tests := []struct {
		name          string
		consultationID uuid.UUID
		endedBy       uuid.UUID
		mockSetup     func(*mocks.MockQuerier)
		expected      telemedicine.Consultation
		expectedError error
	}{
		{
			name:           "success",
			consultationID: consultationID,
			endedBy:       endedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				row := buildConsultationRow(
					"123e4567-e89b-12d3-a456-426614174000",
					"123e4567-e89b-12d3-a456-426614174001",
					"123e4567-e89b-12d3-a456-426614174002",
					"escalated",
				)
				row.EndedBy = uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174005")
				row.EndReason = pgtype.Text{String: "escalated", Valid: true}
				m.On("EscalateConsultation", ctx, mock.Anything).Return(row, nil)
			},
			expected:      buildConsultation("123e4567-e89b-12d3-a456-426614174000", telemedicine.ConsultationStatusEscalated),
			expectedError: nil,
		},
		{
			name:           "not found",
			consultationID: consultationID,
			endedBy:       endedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("EscalateConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, pgx.ErrNoRows)
			},
			expected:      telemedicine.Consultation{},
			expectedError: domain.ErrNotFound,
		},
		{
			name:           "database error",
			consultationID: consultationID,
			endedBy:       endedBy,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("EscalateConsultation", ctx, mock.Anything).Return(sqlc.Consultation{}, assert.AnError)
			},
			expected:      telemedicine.Consultation{},
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationRepositoryWithQuerier(mockQuerier)

			got, err := repo.EscalateConsultation(ctx, tt.consultationID, tt.endedBy)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "escalate consultation")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected.ID, got.ID)
				assert.Equal(t, tt.expected.Status, got.Status)
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}

func TestConsultationRepository_GetPatientConsultations(t *testing.T) {
	ctx := context.Background()
	patientID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174002")

	tests := []struct {
		name          string
		patientID     uuid.UUID
		limit         int
		offset        int
		mockSetup     func(*mocks.MockQuerier)
		expected      []telemedicine.PatientConsultationSummary
		expectedError error
	}{
		{
			name:     "found",
			patientID: patientID,
			limit:    10,
			offset:   0,
			mockSetup: func(m *mocks.MockQuerier) {
				now := nowTime()
				rows := []sqlc.GetPatientConsultationsRow{
					{
						ID:                uuidPgtypeFromString("123e4567-e89b-12d3-a456-426614174000"),
						Status:            "completed",
						Channel:          "chat",
						TriageLevelAtStart: pgtype.Text{String: "low", Valid: true},
						RequestedAt:       pgtype.Timestamp{Time: now, Valid: true},
						StartedAt:         pgtype.Timestamp{Time: now, Valid: true},
						EndedAt:           pgtype.Timestamp{Time: now, Valid: true},
						DurationSeconds:   pgtype.Int4{Int32: 1800, Valid: true},
						ConsultationFee:   pgtype.Numeric{Valid: false},
						PaymentStatus:     "pending",
						PatientRating:     pgtype.Int4{Int32: 5, Valid: true},
						ChiefComplaint:    "Headache",
						ProviderFirstName: pgtype.Text{String: "Dr", Valid: true},
						ProviderLastName:  pgtype.Text{String: "Smith", Valid: true},
						ProviderSpecialization: pgtype.Text{String: "General", Valid: true},
					},
				}
				m.On("GetPatientConsultations", ctx, mock.Anything).Return(rows, nil)
			},
			expected: []telemedicine.PatientConsultationSummary{
				{
					ID:        uuid.MustParse("123e4567-e89b-12d3-a456-426614174000"),
					Status:    telemedicine.ConsultationStatusCompleted,
					Channel:   telemedicine.ChannelChat,
					ChiefComplaint: "Headache",
					ProviderFirstName: stringPtr("Dr"),
					ProviderLastName: stringPtr("Smith"),
				},
			},
			expectedError: nil,
		},
		{
			name:     "empty",
			patientID: patientID,
			limit:    10,
			offset:   0,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientConsultations", ctx, mock.Anything).Return([]sqlc.GetPatientConsultationsRow{}, nil)
			},
			expected:      []telemedicine.PatientConsultationSummary(nil),
			expectedError: nil,
		},
		{
			name:     "database error",
			patientID: patientID,
			limit:    10,
			offset:   0,
			mockSetup: func(m *mocks.MockQuerier) {
				m.On("GetPatientConsultations", ctx, mock.Anything).Return(nil, assert.AnError)
			},
			expected:      nil,
			expectedError: assert.AnError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockQuerier := mocks.NewMockQuerier(t)
			tt.mockSetup(mockQuerier)

			repo := NewConsultationRepositoryWithQuerier(mockQuerier)

			got, err := repo.GetPatientConsultations(ctx, tt.patientID, tt.limit, tt.offset)

			if tt.expectedError != nil {
				require.Error(t, err)
				if tt.expectedError == assert.AnError {
					assert.Contains(t, err.Error(), "get patient consultations")
				} else {
					assert.Equal(t, tt.expectedError, err)
				}
			} else {
				require.NoError(t, err)
				if tt.expected == nil {
					assert.Empty(t, got)
				} else {
					assert.Equal(t, len(tt.expected), len(got))
					if len(got) > 0 {
						assert.Equal(t, tt.expected[0].ID, got[0].ID)
						assert.Equal(t, tt.expected[0].Status, got[0].Status)
					}
				}
			}
			mockQuerier.AssertExpectations(t)
		})
	}
}