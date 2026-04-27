package patients

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/cache"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/core"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/domain/patients"
	"github.com/nyashahama/healthcare-access-connector-backend/internal/repository"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockPatientProfileRepository struct {
	createFunc           func(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error)
	getByUserIDFunc     func(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error)
	getByIDFunc         func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error)
	getByNationalIDFunc func(ctx context.Context, nationalID string) (patients.PatientProfile, error)
	updateFunc          func(ctx context.Context, profile patients.PatientProfile) error
}

func (m *mockPatientProfileRepository) CreatePatientProfile(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, profile)
	}
	return profile, nil
}

func (m *mockPatientProfileRepository) GetPatientProfileByUserID(ctx context.Context, userID uuid.UUID) (patients.PatientProfile, error) {
	if m.getByUserIDFunc != nil {
		return m.getByUserIDFunc(ctx, userID)
	}
	return patients.PatientProfile{}, domain.ErrNotFound
}

func (m *mockPatientProfileRepository) GetPatientProfileByID(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
	if m.getByIDFunc != nil {
		return m.getByIDFunc(ctx, id)
	}
	return patients.PatientProfile{}, domain.ErrNotFound
}

func (m *mockPatientProfileRepository) GetPatientProfileByNationalID(ctx context.Context, nationalID string) (patients.PatientProfile, error) {
	if m.getByNationalIDFunc != nil {
		return m.getByNationalIDFunc(ctx, nationalID)
	}
	return patients.PatientProfile{}, domain.ErrNotFound
}

func (m *mockPatientProfileRepository) UpdatePatientProfile(ctx context.Context, profile patients.PatientProfile) error {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, profile)
	}
	return nil
}

func (m *mockPatientProfileRepository) DeletePatientProfile(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockPatientProfileRepository) DeletePatientProfileByUserID(ctx context.Context, userID uuid.UUID) error {
	return nil
}

func (m *mockPatientProfileRepository) ListPatientProfiles(ctx context.Context, limit, offset int) ([]patients.PatientProfile, error) {
	return nil, nil
}

func (m *mockPatientProfileRepository) SearchPatientProfiles(ctx context.Context, query string, limit, offset int) ([]patients.PatientProfile, error) {
	return nil, nil
}

func (m *mockPatientProfileRepository) ProfileExists(ctx context.Context, id uuid.UUID) (bool, error) {
	return false, nil
}

func (m *mockPatientProfileRepository) ProfileExistsByUserID(ctx context.Context, userID uuid.UUID) (bool, error) {
	return false, nil
}

func (m *mockPatientProfileRepository) NationalIDExists(ctx context.Context, nationalID string, excludeID *uuid.UUID) (bool, error) {
	return false, nil
}

func (m *mockPatientProfileRepository) DependentBelongsToPatient(ctx context.Context, patientID uuid.UUID, dependentID uuid.UUID) (bool, error) {
	return false, nil
}

type mockUserRepositoryForPatient struct {
	updateProfileCompletionFunc func(ctx context.Context, id uuid.UUID, percentage int) error
}

func (m *mockUserRepositoryForPatient) GetUserByID(ctx context.Context, id uuid.UUID) (core.User, error) {
	if m.updateProfileCompletionFunc != nil {
		return core.User{}, nil
	}
	return core.User{}, domain.ErrUserNotFound
}

func (m *mockUserRepositoryForPatient) UpdateUserStatus(ctx context.Context, id uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepositoryForPatient) UpdateUser(ctx context.Context, user core.User) error {
	return nil
}

func (m *mockUserRepositoryForPatient) DeactivateUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepositoryForPatient) DeleteUser(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockUserRepositoryForPatient) ListUsers(ctx context.Context, role string, limit, offset int) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepositoryForPatient) SearchUsers(ctx context.Context, query string, role string, status string) ([]core.User, error) {
	return nil, nil
}

func (m *mockUserRepositoryForPatient) CountUsers(ctx context.Context, role string) (int64, error) {
	return 0, nil
}

func (m *mockUserRepositoryForPatient) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
	return core.User{}, patients.PatientProfile{}, nil
}

func (m *mockUserRepositoryForPatient) UpdateUserEmail(ctx context.Context, id uuid.UUID, email string) error {
	return nil
}

func (m *mockUserRepositoryForPatient) UpdateUserPhone(ctx context.Context, id uuid.UUID, phone string) error {
	return nil
}

func (m *mockUserRepositoryForPatient) UpdateUserRole(ctx context.Context, id uuid.UUID, role string) error {
	return nil
}

func (m *mockUserRepositoryForPatient) UpdateUserProfileCompletion(ctx context.Context, id uuid.UUID, percentage int) error {
	if m.updateProfileCompletionFunc != nil {
		return m.updateProfileCompletionFunc(ctx, id, percentage)
	}
	return nil
}

func (m *mockUserRepositoryForPatient) UpdateUserConsents(ctx context.Context, id uuid.UUID, smsConsent, popiaConsent bool, consentDate time.Time) error {
	return nil
}

func (m *mockUserRepositoryForPatient) BulkUpdateStatus(ctx context.Context, ids []uuid.UUID, status string) error {
	return nil
}

func (m *mockUserRepositoryForPatient) GetUsersByIDs(ctx context.Context, ids []uuid.UUID) ([]core.User, error) {
	return nil, nil
}

type mockNotificationRepositoryForPatient struct{}

func (m *mockNotificationRepositoryForPatient) CreateNotificationPreferences(ctx context.Context, prefs core.NotificationPreferences) (core.NotificationPreferences, error) {
	return prefs, nil
}

func (m *mockNotificationRepositoryForPatient) GetNotificationPreferences(ctx context.Context, userID uuid.UUID) (core.NotificationPreferences, error) {
	return core.NotificationPreferences{}, nil
}

func (m *mockNotificationRepositoryForPatient) UpdateNotificationPreferences(ctx context.Context, prefs core.NotificationPreferences) error {
	return nil
}

func (m *mockNotificationRepositoryForPatient) DeleteNotificationPreferences(ctx context.Context, userID uuid.UUID) error {
	return nil
}

type mockCacheServiceForPatient struct{}

func (m *mockCacheServiceForPatient) Get(ctx context.Context, key string, dest interface{}) error {
	return cache.ErrCacheMiss
}

func (m *mockCacheServiceForPatient) Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
	return nil
}

func (m *mockCacheServiceForPatient) Delete(ctx context.Context, key string) error {
	return nil
}

func (m *mockCacheServiceForPatient) Exists(ctx context.Context, key string) (bool, error) {
	return false, nil
}

func (m *mockCacheServiceForPatient) Ping(ctx context.Context) error {
	return nil
}

func (m *mockCacheServiceForPatient) IsAvailable() bool {
	return true
}

func newPatientServiceForTest(t *testing.T) *patientService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &patientService{
		patientRepo:      &mockPatientProfileRepository{},
		userRepo:         &mockUserRepositoryForPatient{},
		notificationRepo: &mockNotificationRepositoryForPatient{},
		cache:            &mockCacheServiceForPatient{},
		logger:           &logger,
	}
}

func newPatientServiceWithMocks(t *testing.T) (*patientService, *mockPatientProfileRepository, *mockUserRepositoryForPatient) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockPatientRepo := &mockPatientProfileRepository{}
	mockUserRepo := &mockUserRepositoryForPatient{}

	return &patientService{
		patientRepo:      mockPatientRepo,
		userRepo:         mockUserRepo,
		notificationRepo: &mockNotificationRepositoryForPatient{},
		cache:            &mockCacheServiceForPatient{},
		logger:           &logger,
	}, mockPatientRepo, mockUserRepo
}

func TestPatientService_CreateProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockPatientRepo, mockUserRepo := newPatientServiceWithMocks(t)

		userID := uuid.New()
		dob := time.Date(1990, 1, 15, 0, 0, 0, 0, time.UTC)
		nationalID := "9001155000089"

		mockPatientRepo.createFunc = func(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error) {
			return patients.PatientProfile{
				ID:                uuid.New(),
				UserID:            profile.UserID,
				FirstName:         profile.FirstName,
				LastName:          profile.LastName,
				DateOfBirth:       profile.DateOfBirth,
				NationalIDNumber:  &nationalID,
				Country:          "South Africa",
				LanguagePreferences: []string{"en", "af", "zu"},
				PreferredCommunicationMethod: "sms",
				Timezone:          "Africa/Johannesburg",
			}, nil
		}

		mockUserRepo.updateProfileCompletionFunc = func(ctx context.Context, id uuid.UUID, percentage int) error {
			return nil
		}

		profile := patients.PatientProfile{
			UserID:           userID,
			FirstName:        "John",
			LastName:         "Doe",
			DateOfBirth:      &dob,
			NationalIDNumber: &nationalID,
		}

		result, err := svc.CreatePatientProfile(context.Background(), profile)
		require.NoError(t, err)
		assert.Equal(t, "John", result.FirstName)
		assert.Equal(t, "Doe", result.LastName)
		assert.NotNil(t, result.ID)
	})

	t.Run("validation error - missing user ID", func(t *testing.T) {
		svc := newPatientServiceForTest(t)

		profile := patients.PatientProfile{
			FirstName: "John",
			LastName:  "Doe",
		}

		_, err := svc.CreatePatientProfile(context.Background(), profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "user ID is required")
	})

	t.Run("validation error - missing first name", func(t *testing.T) {
		svc := newPatientServiceForTest(t)

		profile := patients.PatientProfile{
			UserID:  uuid.New(),
			LastName: "Doe",
		}

		_, err := svc.CreatePatientProfile(context.Background(), profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "first name is required")
	})

	t.Run("validation error - missing last name", func(t *testing.T) {
		svc := newPatientServiceForTest(t)

		profile := patients.PatientProfile{
			UserID:    uuid.New(),
			FirstName: "John",
		}

		_, err := svc.CreatePatientProfile(context.Background(), profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "last name is required")
	})

	t.Run("validation error - future date of birth", func(t *testing.T) {
		svc := newPatientServiceForTest(t)

		futureDate := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
		profile := patients.PatientProfile{
			UserID:       uuid.New(),
			FirstName:    "John",
			LastName:     "Doe",
			DateOfBirth: &futureDate,
		}

		_, err := svc.CreatePatientProfile(context.Background(), profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "date of birth cannot be in the future")
	})

	t.Run("validation error - invalid national ID length", func(t *testing.T) {
		svc := newPatientServiceForTest(t)

		shortNationalID := "12345"
		profile := patients.PatientProfile{
			UserID:           uuid.New(),
			FirstName:        "John",
			LastName:         "Doe",
			NationalIDNumber: &shortNationalID,
		}

		_, err := svc.CreatePatientProfile(context.Background(), profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "national ID must be at least 13 characters")
	})

	t.Run("duplicate national ID", func(t *testing.T) {
		svc, mockPatientRepo, _ := newPatientServiceWithMocks(t)

		nationalID := "9001155000089"

		mockPatientRepo.createFunc = func(ctx context.Context, profile patients.PatientProfile) (patients.PatientProfile, error) {
			return patients.PatientProfile{}, errors.New("national ID already registered")
		}

		profile := patients.PatientProfile{
			UserID:           uuid.New(),
			FirstName:         "John",
			LastName:          "Doe",
			NationalIDNumber: &nationalID,
		}

		_, err := svc.CreatePatientProfile(context.Background(), profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "National ID already registered")
	})
}

func TestPatientService_GetProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockPatientRepo, _ := newPatientServiceWithMocks(t)

		userID := uuid.New()
		expectedProfile := patients.PatientProfile{
			ID:        uuid.New(),
			UserID:    userID,
			FirstName: "John",
			LastName:  "Doe",
		}

		mockPatientRepo.getByUserIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return expectedProfile, nil
		}

		result, err := svc.GetPatientProfile(context.Background(), userID)
		require.NoError(t, err)
		assert.Equal(t, "John", result.FirstName)
		assert.Equal(t, "Doe", result.LastName)
	})

	t.Run("not found", func(t *testing.T) {
		svc, mockPatientRepo, _ := newPatientServiceWithMocks(t)

		userID := uuid.New()

		mockPatientRepo.getByUserIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{}, domain.ErrNotFound
		}

		_, err := svc.GetPatientProfile(context.Background(), userID)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Patient profile not found")
	})
}

func TestPatientService_UpdateProfile(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockPatientRepo, _ := newPatientServiceWithMocks(t)

		profileID := uuid.New()
		userID := uuid.New()

		mockPatientRepo.updateFunc = func(ctx context.Context, profile patients.PatientProfile) error {
			return nil
		}

		profile := patients.PatientProfile{
			ID:        profileID,
			UserID:    userID,
			FirstName: "John",
			LastName:  "Doe Updated",
		}

		err := svc.UpdatePatientProfile(context.Background(), profile)
		require.NoError(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		svc, mockPatientRepo, _ := newPatientServiceWithMocks(t)

		mockPatientRepo.updateFunc = func(ctx context.Context, profile patients.PatientProfile) error {
			return domain.ErrNotFound
		}

		profile := patients.PatientProfile{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			FirstName: "John",
			LastName:  "Doe",
		}

		err := svc.UpdatePatientProfile(context.Background(), profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Failed to update patient profile")
	})

	t.Run("validation error - missing first name", func(t *testing.T) {
		svc := newPatientServiceForTest(t)

		profile := patients.PatientProfile{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			FirstName: "",
			LastName:  "Doe",
		}

		err := svc.UpdatePatientProfile(context.Background(), profile)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "first name is required")
	})
}

type mockMedicationRepository struct {
	addFunc              func(ctx context.Context, medication patients.PatientMedication) (patients.PatientMedication, error)
	getByPatientIDFunc  func(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientMedication, error)
}

func (m *mockMedicationRepository) AddPatientMedication(ctx context.Context, medication patients.PatientMedication) (patients.PatientMedication, error) {
	if m.addFunc != nil {
		return m.addFunc(ctx, medication)
	}
	return medication, nil
}

func (m *mockMedicationRepository) UpdatePatientMedication(ctx context.Context, medication patients.PatientMedication) error {
	return nil
}

func (m *mockMedicationRepository) DeletePatientMedication(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockMedicationRepository) GetPatientMedications(ctx context.Context, patientID uuid.UUID, status *string) ([]patients.PatientMedication, error) {
	if m.getByPatientIDFunc != nil {
		return m.getByPatientIDFunc(ctx, patientID, status)
	}
	return nil, nil
}

func (m *mockMedicationRepository) GetActiveMedications(ctx context.Context, patientID uuid.UUID) ([]patients.PatientMedication, error) {
	return nil, nil
}

func newMedicationServiceForTest(t *testing.T) *medicationService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &medicationService{
		medicationRepo: &mockMedicationRepository{},
		patientRepo:  &mockPatientProfileRepository{},
		cache:       &mockCacheServiceForPatient{},
		logger:      &logger,
	}
}

func newMedicationServiceWithMocks(t *testing.T) (*medicationService, *mockMedicationRepository, *mockPatientProfileRepository) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockMedicationRepo := &mockMedicationRepository{}
	mockPatientRepo := &mockPatientProfileRepository{}

	return &medicationService{
		medicationRepo: mockMedicationRepo,
		patientRepo:  mockPatientRepo,
		cache:       &mockCacheServiceForPatient{},
		logger:      &logger,
	}, mockMedicationRepo, mockPatientRepo
}

func TestMedicationService_AddMedication(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockMedicationRepo, mockPatientRepo := newMedicationServiceWithMocks(t)

		patientID := uuid.New()
		medName := "Aspirin"

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: patientID}, nil
		}

		mockMedicationRepo.addFunc = func(ctx context.Context, medication patients.PatientMedication) (patients.PatientMedication, error) {
			return patients.PatientMedication{
				ID:             uuid.New(),
				PatientID:      patientID,
				MedicationName:  medName,
				Status:         "active",
			}, nil
		}

		medication := patients.PatientMedication{
			PatientID:     patientID,
			MedicationName: medName,
		}

		result, err := svc.AddPatientMedication(context.Background(), medication)
		require.NoError(t, err)
		assert.Equal(t, "Aspirin", result.MedicationName)
		assert.Equal(t, "active", result.Status)
	})

	t.Run("patient not found", func(t *testing.T) {
		svc, _, mockPatientRepo := newMedicationServiceWithMocks(t)

		patientID := uuid.New()

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{}, domain.ErrNotFound
		}

		medication := patients.PatientMedication{
			PatientID:     patientID,
			MedicationName: "Aspirin",
		}

		_, err := svc.AddPatientMedication(context.Background(), medication)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Patient not found")
	})

	t.Run("validation error - missing patient ID", func(t *testing.T) {
		svc := newMedicationServiceForTest(t)

		medication := patients.PatientMedication{
			MedicationName: "Aspirin",
		}

		_, err := svc.AddPatientMedication(context.Background(), medication)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "patient ID is required")
	})

	t.Run("validation error - missing medication name", func(t *testing.T) {
		svc, _, mockPatientRepo := newMedicationServiceWithMocks(t)

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: uuid.New()}, nil
		}

		medication := patients.PatientMedication{
			PatientID:     uuid.New(),
			MedicationName: "",
		}

		_, err := svc.AddPatientMedication(context.Background(), medication)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "medication name is required")
	})

	t.Run("validation error - future start date", func(t *testing.T) {
		svc, _, mockPatientRepo := newMedicationServiceWithMocks(t)

		futureDate := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: uuid.New()}, nil
		}

		medication := patients.PatientMedication{
			PatientID:     uuid.New(),
			MedicationName: "Aspirin",
			StartDate:    &futureDate,
		}

		_, err := svc.AddPatientMedication(context.Background(), medication)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "start date cannot be in the future")
	})
}

type mockAllergyRepository struct {
	addFunc func(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error)
}

func (m *mockAllergyRepository) AddPatientAllergy(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error) {
	if m.addFunc != nil {
		return m.addFunc(ctx, allergy)
	}
	return allergy, nil
}

func (m *mockAllergyRepository) UpdatePatientAllergy(ctx context.Context, allergy patients.PatientAllergy) error {
	return nil
}

func (m *mockAllergyRepository) DeletePatientAllergy(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockAllergyRepository) GetPatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error) {
	return nil, nil
}

func (m *mockAllergyRepository) GetActivePatientAllergies(ctx context.Context, patientID uuid.UUID) ([]patients.PatientAllergy, error) {
	return nil, nil
}

func newAllergyServiceForTest(t *testing.T) *allergyService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &allergyService{
		allergyRepo: &mockAllergyRepository{},
		patientRepo: &mockPatientProfileRepository{},
		cache:     &mockCacheServiceForPatient{},
		logger:    &logger,
	}
}

func newAllergyServiceWithMocks(t *testing.T) (*allergyService, *mockAllergyRepository, *mockPatientProfileRepository) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockAllergyRepo := &mockAllergyRepository{}
	mockPatientRepo := &mockPatientProfileRepository{}

	return &allergyService{
		allergyRepo: mockAllergyRepo,
		patientRepo: mockPatientRepo,
		cache:     &mockCacheServiceForPatient{},
		logger:    &logger,
	}, mockAllergyRepo, mockPatientRepo
}

func TestAllergyService_AddAllergy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockAllergyRepo, mockPatientRepo := newAllergyServiceWithMocks(t)

		patientID := uuid.New()
		allergyName := "Peanuts"

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: patientID}, nil
		}

		mockAllergyRepo.addFunc = func(ctx context.Context, allergy patients.PatientAllergy) (patients.PatientAllergy, error) {
			return patients.PatientAllergy{
				ID:         uuid.New(),
				PatientID:   patientID,
				AllergyName: allergyName,
				Severity:    "severe",
				Status:     "active",
			}, nil
		}

		allergy := patients.PatientAllergy{
			PatientID:   patientID,
			AllergyName: allergyName,
			Severity:    "severe",
		}

		result, err := svc.AddPatientAllergy(context.Background(), allergy)
		require.NoError(t, err)
		assert.Equal(t, "Peanuts", result.AllergyName)
		assert.Equal(t, "severe", result.Severity)
	})

	t.Run("patient not found", func(t *testing.T) {
		svc, _, mockPatientRepo := newAllergyServiceWithMocks(t)

		patientID := uuid.New()

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{}, domain.ErrNotFound
		}

		allergy := patients.PatientAllergy{
			PatientID:   patientID,
			AllergyName: "Peanuts",
			Severity:    "severe",
		}

		_, err := svc.AddPatientAllergy(context.Background(), allergy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Patient not found")
	})

	t.Run("validation error - missing patient ID", func(t *testing.T) {
		svc := newAllergyServiceForTest(t)

		allergy := patients.PatientAllergy{
			AllergyName: "Peanuts",
			Severity:    "severe",
		}

		_, err := svc.AddPatientAllergy(context.Background(), allergy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "patient ID is required")
	})

	t.Run("validation error - missing allergy name", func(t *testing.T) {
		svc, _, mockPatientRepo := newAllergyServiceWithMocks(t)

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: uuid.New()}, nil
		}

		allergy := patients.PatientAllergy{
			PatientID: uuid.New(),
			Severity:  "severe",
		}

		_, err := svc.AddPatientAllergy(context.Background(), allergy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "allergy name is required")
	})

	t.Run("validation error - missing severity", func(t *testing.T) {
		svc, _, mockPatientRepo := newAllergyServiceWithMocks(t)

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: uuid.New()}, nil
		}

		allergy := patients.PatientAllergy{
			PatientID:   uuid.New(),
			AllergyName: "Peanuts",
		}

		_, err := svc.AddPatientAllergy(context.Background(), allergy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "severity is required")
	})

	t.Run("validation error - invalid severity", func(t *testing.T) {
		svc, _, mockPatientRepo := newAllergyServiceWithMocks(t)

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: uuid.New()}, nil
		}

		allergy := patients.PatientAllergy{
			PatientID:   uuid.New(),
			AllergyName: "Peanuts",
			Severity:   "invalid-severity",
		}

		_, err := svc.AddPatientAllergy(context.Background(), allergy)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid severity")
	})
}

type mockDependentRepository struct {
	addFunc func(ctx context.Context, dependent patients.PatientDependent) (patients.PatientDependent, error)
}

func (m *mockDependentRepository) AddPatientDependent(ctx context.Context, dependent patients.PatientDependent) (patients.PatientDependent, error) {
	if m.addFunc != nil {
		return m.addFunc(ctx, dependent)
	}
	return dependent, nil
}

func (m *mockDependentRepository) UpdatePatientDependent(ctx context.Context, dependent patients.PatientDependent) error {
	return nil
}

func (m *mockDependentRepository) DeletePatientDependent(ctx context.Context, id uuid.UUID) error {
	return nil
}

func (m *mockDependentRepository) GetPatientDependents(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error) {
	return nil, nil
}

func (m *mockDependentRepository) GetDependentChildren(ctx context.Context, patientID uuid.UUID) ([]patients.PatientDependent, error) {
	return nil, nil
}

func newDependentServiceForTest(t *testing.T) *dependentService {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &dependentService{
		dependentRepo: &mockDependentRepository{},
		patientRepo:  &mockPatientProfileRepository{},
		cache:      &mockCacheServiceForPatient{},
		logger:     &logger,
	}
}

func newDependentServiceWithMocks(t *testing.T) (*dependentService, *mockDependentRepository, *mockPatientProfileRepository) {
	t.Helper()
	logger := zerolog.New(io.Discard)
	mockDependentRepo := &mockDependentRepository{}
	mockPatientRepo := &mockPatientProfileRepository{}

	return &dependentService{
		dependentRepo: mockDependentRepo,
		patientRepo:  mockPatientRepo,
		cache:      &mockCacheServiceForPatient{},
		logger:     &logger,
	}, mockDependentRepo, mockPatientRepo
}

func TestDependentService_AddDependent(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc, mockDependentRepo, mockPatientRepo := newDependentServiceWithMocks(t)

		patientID := uuid.New()
		dob := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: patientID}, nil
		}

		mockDependentRepo.addFunc = func(ctx context.Context, dependent patients.PatientDependent) (patients.PatientDependent, error) {
			return patients.PatientDependent{
				ID:           uuid.New(),
				PatientID:     patientID,
				FirstName:    "Jane",
				LastName:     "Doe",
				DateOfBirth: dob,
				Relationship: "child",
			}, nil
		}

		dependent := patients.PatientDependent{
			PatientID:     patientID,
			FirstName:     "Jane",
			LastName:     "Doe",
			DateOfBirth:  dob,
			Relationship: "child",
		}

		result, err := svc.AddPatientDependent(context.Background(), dependent)
		require.NoError(t, err)
		assert.Equal(t, "Jane", result.FirstName)
		assert.Equal(t, "child", result.Relationship)
	})

	t.Run("patient not found", func(t *testing.T) {
		svc, _, mockPatientRepo := newDependentServiceWithMocks(t)

		patientID := uuid.New()
		dob := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{}, domain.ErrNotFound
		}

		dependent := patients.PatientDependent{
			PatientID:     patientID,
			FirstName:     "Jane",
			LastName:     "Doe",
			DateOfBirth:  dob,
			Relationship: "child",
		}

		_, err := svc.AddPatientDependent(context.Background(), dependent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "Patient not found")
	})

	t.Run("validation error - missing patient ID", func(t *testing.T) {
		svc := newDependentServiceForTest(t)

		dob := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)

		dependent := patients.PatientDependent{
			FirstName:     "Jane",
			LastName:     "Doe",
			DateOfBirth:  dob,
			Relationship: "child",
		}

		_, err := svc.AddPatientDependent(context.Background(), dependent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "patient ID is required")
	})

	t.Run("validation error - missing first name", func(t *testing.T) {
		svc, _, mockPatientRepo := newDependentServiceWithMocks(t)

		dob := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: uuid.New()}, nil
		}

		dependent := patients.PatientDependent{
			PatientID:     uuid.New(),
			LastName:     "Doe",
			DateOfBirth:  dob,
			Relationship: "child",
		}

		_, err := svc.AddPatientDependent(context.Background(), dependent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "first name is required")
	})

	t.Run("validation error - dependent older than patient", func(t *testing.T) {
		svc, _, mockPatientRepo := newDependentServiceWithMocks(t)

		patientID := uuid.New()
		dependentDOB := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

		mockPatientRepo.getByIDFunc = func(ctx context.Context, id uuid.UUID) (patients.PatientProfile, error) {
			return patients.PatientProfile{ID: patientID}, nil
		}

		dependent := patients.PatientDependent{
			PatientID:     patientID,
			FirstName:     "Adult",
			LastName:     "Child",
			DateOfBirth: dependentDOB,
			Relationship: "child",
		}

		_, err := svc.AddPatientDependent(context.Background(), dependent)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "child dependents must be under 18 years old")
	})
}

var _ repository.PatientProfileRepository = (*mockPatientProfileRepository)(nil)
var _ repository.UserRepository = (*mockUserRepositoryForPatient)(nil)
var _ repository.NotificationRepository = (*mockNotificationRepositoryForPatient)(nil)
var _ cache.Service = (*mockCacheServiceForPatient)(nil)
var _ repository.PatientMedicationRepository = (*mockMedicationRepository)(nil)
var _ repository.PatientAllergyRepository = (*mockAllergyRepository)(nil)
var _ repository.PatientDependentRepository = (*mockDependentRepository)(nil)