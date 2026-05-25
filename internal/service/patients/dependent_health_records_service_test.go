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

type mockDependentHealthRecordRepository struct {
	addDependentHealthRecordFunc  func(ctx context.Context, record domainpatients.DependentHealthRecord) (domainpatients.DependentHealthRecord, error)
	getDependentHealthRecordsFunc func(ctx context.Context, dependentID uuid.UUID) ([]domainpatients.DependentHealthRecord, error)
	getGrowthRecordsFunc          func(ctx context.Context, dependentID uuid.UUID) ([]domainpatients.DependentHealthRecord, error)
}

func (m *mockDependentHealthRecordRepository) AddDependentHealthRecord(ctx context.Context, record domainpatients.DependentHealthRecord) (domainpatients.DependentHealthRecord, error) {
	if m.addDependentHealthRecordFunc != nil {
		return m.addDependentHealthRecordFunc(ctx, record)
	}
	return record, nil
}

func (m *mockDependentHealthRecordRepository) UpdateDependentHealthRecord(ctx context.Context, record domainpatients.DependentHealthRecord) error {
	return nil
}

func (m *mockDependentHealthRecordRepository) DeleteDependentHealthRecord(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockDependentHealthRecordRepository) GetDependentHealthRecords(ctx context.Context, dependentID uuid.UUID) ([]domainpatients.DependentHealthRecord, error) {
	if m.getDependentHealthRecordsFunc != nil {
		return m.getDependentHealthRecordsFunc(ctx, dependentID)
	}
	return nil, nil
}

func (m *mockDependentHealthRecordRepository) GetGrowthRecords(ctx context.Context, dependentID uuid.UUID) ([]domainpatients.DependentHealthRecord, error) {
	if m.getGrowthRecordsFunc != nil {
		return m.getGrowthRecordsFunc(ctx, dependentID)
	}
	return nil, nil
}

var _ repository.DependentHealthRecordRepository = (*mockDependentHealthRecordRepository)(nil)

type mockPatientDependentRepositoryForHealthRecords struct {
	getPatientDependentsFunc func(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientDependent, error)
}

func (m *mockPatientDependentRepositoryForHealthRecords) AddPatientDependent(ctx context.Context, dependent domainpatients.PatientDependent) (domainpatients.PatientDependent, error) {
	return domainpatients.PatientDependent{}, nil
}

func (m *mockPatientDependentRepositoryForHealthRecords) UpdatePatientDependent(ctx context.Context, dependent domainpatients.PatientDependent) error {
	return nil
}

func (m *mockPatientDependentRepositoryForHealthRecords) DeletePatientDependent(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPatientDependentRepositoryForHealthRecords) GetPatientDependents(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientDependent, error) {
	if m.getPatientDependentsFunc != nil {
		return m.getPatientDependentsFunc(ctx, patientID)
	}
	return nil, nil
}

func (m *mockPatientDependentRepositoryForHealthRecords) GetDependentChildren(ctx context.Context, patientID uuid.UUID) ([]domainpatients.PatientDependent, error) {
	return nil, nil
}

var _ repository.PatientDependentRepository = (*mockPatientDependentRepositoryForHealthRecords)(nil)

func TestDependentHealthRecordServiceGetDependentHealthRecordsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	dependentID := uuid.New()
	expected := []domainpatients.DependentHealthRecord{
		{
			ID:         uuid.New(),
			DependentID: dependentID,
			RecordDate: time.Now().Add(-24 * time.Hour),
		},
	}

	svc := &dependentHealthRecordService{
		dependentHealthRepo: &mockDependentHealthRecordRepository{
			getDependentHealthRecordsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.DependentHealthRecord, error) {
				require.Equal(t, dependentID, got)
				return expected, nil
			},
		},
		dependentRepo: &mockPatientDependentRepositoryForHealthRecords{
			getPatientDependentsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientDependent, error) {
				require.Equal(t, dependentID, got)
				return []domainpatients.PatientDependent{{ID: dependentID}}, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetDependentHealthRecords(context.Background(), dependentID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestDependentHealthRecordServiceGetGrowthRecordsWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	dependentID := uuid.New()
	expected := []domainpatients.DependentHealthRecord{
		{
			ID:          uuid.New(),
			DependentID: dependentID,
			RecordDate:  time.Now().Add(-48 * time.Hour),
		},
	}

	svc := &dependentHealthRecordService{
		dependentHealthRepo: &mockDependentHealthRecordRepository{
			getGrowthRecordsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.DependentHealthRecord, error) {
				require.Equal(t, dependentID, got)
				return expected, nil
			},
		},
		dependentRepo: &mockPatientDependentRepositoryForHealthRecords{
			getPatientDependentsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientDependent, error) {
				require.Equal(t, dependentID, got)
				return []domainpatients.PatientDependent{{ID: dependentID}}, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.GetGrowthRecords(context.Background(), dependentID)
	require.NoError(t, err)
	require.Len(t, result, 1)
	require.Equal(t, expected[0].ID, result[0].ID)
}

func TestDependentHealthRecordServiceAddDependentHealthRecordWithoutCache(t *testing.T) {
	logger := zerolog.New(io.Discard)
	dependentID := uuid.New()
	weight := 12.5
	input := domainpatients.DependentHealthRecord{
		DependentID: dependentID,
		RecordDate:  time.Now().Add(-24 * time.Hour),
		WeightKg:    &weight,
	}

	svc := &dependentHealthRecordService{
		dependentHealthRepo: &mockDependentHealthRecordRepository{
			addDependentHealthRecordFunc: func(ctx context.Context, record domainpatients.DependentHealthRecord) (domainpatients.DependentHealthRecord, error) {
				require.Equal(t, dependentID, record.DependentID)
				require.NotEqual(t, uuid.Nil, record.ID)
				return record, nil
			},
		},
		dependentRepo: &mockPatientDependentRepositoryForHealthRecords{
			getPatientDependentsFunc: func(ctx context.Context, got uuid.UUID) ([]domainpatients.PatientDependent, error) {
				require.Equal(t, dependentID, got)
				return []domainpatients.PatientDependent{{ID: dependentID}}, nil
			},
		},
		cache:  nil,
		logger: &logger,
	}

	result, err := svc.AddDependentHealthRecord(context.Background(), input)
	require.NoError(t, err)
	require.Equal(t, dependentID, result.DependentID)
}
