# Test Coverage Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Expand test coverage across the entire codebase from 19 test files to ~60+ test files following existing table-driven + testify + mockery patterns, plus add testcontainers-based integration tests.

**Architecture:** Five-phase bottom-up approach: repository tests first (mocking sqlc Querier), then service tests (mocking repository interfaces), then handler tests (mocking service interfaces via httptest), then integration tests (testcontainers with real PostgreSQL/Redis/NATS), then infrastructure tests (email providers, cache, messaging, WebSocket, AI, validator).

**Tech Stack:** Go 1.24, testify v1.11.1 (assert/require/mock), mockery (MockQuerier), httptest, testcontainers-go v0.42.0, pgx/v5 pgtype, zerolog

---

## Task 0: Environment and Dependency Setup

**Files:**
- Modify: `.env.test`
- Modify: `go.mod`

- [ ] **Step 1: Fix duplicate entries in `.env.test`**

Read `.env.test` and remove the duplicate `DB_URL` on line 13 (keep line 1) and duplicate `REDIS_URL` on line 26 (keep line 4).

- [ ] **Step 2: Add testcontainers-go dependency**

```bash
go get github.com/testcontainers/testcontainers-go/modules/postgres@v0.42.0
go get github.com/testcontainers/testcontainers-go/modules/redis@v0.42.0
go get github.com/testcontainers/testcontainers-go@v0.42.0
go mod tidy
```

- [ ] **Step 3: Verify builds still pass**

```bash
go build ./...
```

Expected: clean build, no errors.

- [ ] **Step 4: Commit**

```bash
git add .env.test go.mod go.sum
git commit -m "chore: add testcontainers-go dependency, fix .env.test duplicates"
```

---

## Task 1: Providers Repository Tests — Clinic

**Files:**
- Create: `internal/repository/providers/clinic_repository_test.go`

**Pattern:** Follow `internal/repository/core/user_repository_test.go`. Package is `providers`. Use `mocks.NewMockQuerier(t)` from `internal/db/mocks`. Inject via `NewClinicRepositoryWithQuerier(mockQuerier)`.

**Test helpers** needed in this file:
```go
func stringPtr(s string) *string { return &s }
func uuidPtr(id uuid.UUID) *uuid.UUID { return &id }
func uuidToPgtype(id uuid.UUID) pgtype.UUID { return pgtype.UUID{Bytes: id, Valid: true} }
```

**Imports:**
```go
import (
    "context"
    "testing"
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
```

- [ ] **Step 1: Write `TestClinicRepository_CreateClinic`**

Table-driven with 3 cases: happy path, DB error, nil clinic returns error. Mock `CreateClinic` sqlc method.

```go
func TestClinicRepository_CreateClinic(t *testing.T) {
    ctx := context.Background()
    clinicID := uuid.New()
    ownerID := uuid.New()

    tests := []struct {
        name          string
        clinic        providers.Clinic
        mockSetup     func(*mocks.MockQuerier)
        expectedError error
    }{
        {
            name: "successful clinic creation",
            clinic: providers.Clinic{
                ID: clinicID, Name: "Test Clinic", Address: "123 Main St",
                OwnerUserID: ownerID, Status: "pending",
            },
            mockSetup: func(m *mocks.MockQuerier) {
                m.On("CreateClinic", ctx, mock.MatchedBy(func(params sqlc.CreateClinicParams) bool {
                    return params.Name == "Test Clinic"
                })).Return(sqlc.Clinic{
                    ID: uuidToPgtype(clinicID), Name: "Test Clinic", Status: "pending",
                }, nil)
                m.On("CreateUserClinic", ctx, mock.Anything).Return(nil)
            },
            expectedError: nil,
        },
        {
            name: "database error on insert",
            clinic: providers.Clinic{Name: "Test Clinic"},
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

            clinic, err := repo.CreateClinic(ctx, tt.clinic, clinicID, ownerID)

            if tt.expectedError != nil {
                assert.Error(t, err)
            } else {
                require.NoError(t, err)
                assert.Equal(t, "Test Clinic", clinic.Name)
            }
            mockQuerier.AssertExpectations(t)
        })
    }
}
```

- [ ] **Step 2: Write `TestClinicRepository_GetClinicByID`**

3 cases: found, not found (`pgx.ErrNoRows` → `domain.ErrNotFound`), DB error.

- [ ] **Step 3: Write `TestClinicRepository_UpdateClinic`**

3 cases: success, not found, DB error.

- [ ] **Step 4: Write `TestClinicRepository_SearchClinics`**

3 cases: results found, empty results, DB error.

- [ ] **Step 5: Write `TestClinicRepository_GetClinicByOwner`**

3 cases: found, not found, DB error.

- [ ] **Step 6: Run tests**

```bash
go test ./internal/repository/providers/ -v -run TestClinicRepository
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/repository/providers/clinic_repository_test.go
git commit -m "test: add clinic repository tests"
```

---

## Task 2: Providers Repository Tests — Staff and Credentials

**Files:**
- Create: `internal/repository/providers/staff_repository_test.go`
- Create: `internal/repository/providers/credential_repository_test.go`

- [ ] **Step 1: Write `TestStaffRepository_CreateStaffMember`**

Mock `InsertClinicStaff` sqlc method. 3 cases: success (returns staff with clinic info), DB error, FK violation (`pgconn.PgError{Code: "23503"}`).

- [ ] **Step 2: Write `TestStaffRepository_GetStaffByUserID`**

3 cases: found, not found, DB error.

- [ ] **Step 3: Write `TestStaffRepository_GetAllClinicStaff`**

3 cases: staff found, empty list, DB error.

- [ ] **Step 4: Write `TestStaffRepository_UpdateStaffMember`**

3 cases: success, not found, DB error.

- [ ] **Step 5: Write `TestStaffRepository_DeleteStaffMember`**

2 cases: success, DB error.

- [ ] **Step 6: Write `TestStaffRepository_CreateStaffInvitation`**

3 cases: success, DB error, duplicate email (`pgconn.PgError{Code: "23505"}`).

- [ ] **Step 7: Write `TestCredentialRepository_CreateCredential`**

3 cases: success, DB error, FK violation.

- [ ] **Step 8: Write `TestCredentialRepository_GetStaffCredentials`**

3 cases: found, empty list, DB error.

- [ ] **Step 9: Run tests**

```bash
go test ./internal/repository/providers/ -v -run "TestStaffRepository|TestCredentialRepository"
```

Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add internal/repository/providers/staff_repository_test.go internal/repository/providers/credential_repository_test.go
git commit -m "test: add staff and credential repository tests"
```

---

## Task 3: Providers Repository Tests — Services

**Files:**
- Create: `internal/repository/providers/service_repository_test.go`

- [ ] **Step 1: Write `TestServiceRepository_CreateClinicService`**

3 cases: success, DB error, FK violation.

- [ ] **Step 2: Write `TestServiceRepository_GetServiceByID`**

3 cases: found, not found, DB error.

- [ ] **Step 3: Write `TestServiceRepository_UpdateClinicService`**

3 cases: success, not found, DB error.

- [ ] **Step 4: Write `TestServiceRepository_GetClinicServices`**

3 cases: found, empty list, DB error.

- [ ] **Step 5: Write `TestServiceRepository_DeleteClinicService`**

2 cases: success, DB error.

- [ ] **Step 6: Write `TestServiceRepository_ServiceExists`**

3 cases: true, false, DB error.

- [ ] **Step 7: Run tests**

```bash
go test ./internal/repository/providers/ -v -run TestServiceRepository
```

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/repository/providers/service_repository_test.go
git commit -m "test: add clinic service repository tests"
```

---

## Task 4: Patients Repository Tests — Profile and Medical Records

**Files:**
- Create: `internal/repository/patients/patient_profile_repository_test.go`

- [ ] **Step 1: Write `TestPatientProfileRepository_CreatePatientProfile`**

Package is `patients`. Inject via `NewPatientProfileRepositoryWithQuerier(mock)`. Mock `CreatePatientProfile` sqlc method.

3 cases: success, DB error, duplicate national ID (`pgconn.PgError{Code: "23505", ConstraintName: "patient_profiles_national_id_key"}`).

- [ ] **Step 2: Write `TestPatientProfileRepository_GetPatientProfileByID`**

3 cases: found, not found, DB error.

- [ ] **Step 3: Write `TestPatientProfileRepository_GetPatientProfileByUserID`**

3 cases: found, not found, DB error.

- [ ] **Step 4: Write `TestPatientProfileRepository_UpdatePatientProfile`**

3 cases: success, not found, DB error.

- [ ] **Step 5: Write `TestPatientProfileRepository_NationalIDExists`**

3 cases: true, false, DB error.

- [ ] **Step 6: Run tests**

```bash
go test ./internal/repository/patients/ -v -run TestPatientProfileRepository
```

Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add internal/repository/patients/patient_profile_repository_test.go
git commit -m "test: add patient profile repository tests"
```

---

## Task 5: Patients Repository Tests — Medical History Sub-Resources

**Files:**
- Create: `internal/repository/patients/allergy_repository_test.go`
- Create: `internal/repository/patients/medication_repository_test.go`
- Create: `internal/repository/patients/condition_repository_test.go`
- Create: `internal/repository/patients/immunization_repository_test.go`
- Create: `internal/repository/patients/surgery_repository_test.go`
- Create: `internal/repository/patients/family_history_repository_test.go`
- Create: `internal/repository/patients/dependent_repository_test.go`
- Create: `internal/repository/patients/emergency_contact_repository_test.go`
- Create: `internal/repository/patients/medical_info_repository_test.go`

- [ ] **Step 1: Write allergy tests** — `AddPatientAllergy`, `GetPatientAllergies`, `UpdatePatientAllergy`, `DeletePatientAllergy`. 3 cases each.

- [ ] **Step 2: Write medication tests** — `AddPatientMedication`, `GetPatientMedications`, `UpdatePatientMedication`, `DeletePatientMedication`. 3 cases each.

- [ ] **Step 3: Write condition tests** — `AddPatientCondition`, `GetPatientConditions`, `UpdatePatientCondition`, `DeletePatientCondition`. 3 cases each.

- [ ] **Step 4: Write immunization tests** — `AddPatientImmunization`, `GetPatientImmunizations`, `UpdatePatientImmunization`, `DeletePatientImmunization`. 3 cases each.

- [ ] **Step 5: Write surgery tests** — `AddPatientSurgery`, `GetPatientSurgeries`, `UpdatePatientSurgery`, `DeletePatientSurgery`. 3 cases each.

- [ ] **Step 6: Write family history tests** — `AddFamilyHistory`, `GetPatientFamilyHistory`, `UpdateFamilyHistory`, `DeleteFamilyHistory`. 3 cases each.

- [ ] **Step 7: Write dependent tests** — `AddPatientDependent`, `GetPatientDependents`, `UpdatePatientDependent`, `DeletePatientDependent`. 3 cases each.

- [ ] **Step 8: Write emergency contact tests** — `AddEmergencyContact`, `GetPatientEmergencyContacts`, `GetPrimaryEmergencyContact`, `UpdateEmergencyContact`, `DeleteEmergencyContact`. 3 cases each.

- [ ] **Step 9: Write medical info tests** — `CreateMedicalInfo`, `GetMedicalInfoByPatientID`, `UpdateMedicalInfo`. 3 cases each.

- [ ] **Step 10: Run tests**

```bash
go test ./internal/repository/patients/ -v
```

Expected: PASS

- [ ] **Step 11: Commit**

```bash
git add internal/repository/patients/
git commit -m "test: add patient medical history repository tests"
```

---

## Task 6: Appointments Repository Tests

**Files:**
- Create: `internal/repository/appointments/appointments_repository_test.go`

Package is `appointments`. Inject via `NewAppointmentsRepositoryWithQuerier(mock)`. Follow the same table-driven + MockQuerier pattern.

- [ ] **Step 1: Write `TestAppointmentRepository_BookAppointment`**

3 cases: success, DB error, scheduling conflict (returns error from repo).

- [ ] **Step 2: Write `TestAppointmentRepository_GetAppointmentByID`**

3 cases: found, not found, DB error.

- [ ] **Step 3: Write `TestAppointmentRepository_GetAppointmentsByPatient`**

3 cases: found, empty, DB error.

- [ ] **Step 4: Write `TestAppointmentRepository_GetAppointmentsByClinic`**

3 cases: found, empty, DB error.

- [ ] **Step 5: Write `TestAppointmentRepository_RescheduleAppointment`**

3 cases: success, not found, DB error.

- [ ] **Step 6: Write `TestAppointmentRepository_ConfirmAppointment`**

3 cases: success, not found, DB error.

- [ ] **Step 7: Write `TestAppointmentRepository_CancelAppointment`**

3 cases: success, not found, DB error.

- [ ] **Step 8: Write `TestAppointmentRepository_CheckSchedulingConflict`**

3 cases: conflict found, no conflict, DB error.

- [ ] **Step 9: Write `TestAppointmentRepository_GetAppointmentCount`**

3 cases: returns count, zero, DB error.

- [ ] **Step 10: Run tests**

```bash
go test ./internal/repository/appointments/ -v
```

Expected: PASS

- [ ] **Step 11: Commit**

```bash
git add internal/repository/appointments/appointments_repository_test.go
git commit -m "test: add appointment repository tests"
```

---

## Task 7: Telemedicine Repository Tests — Consultations

**Files:**
- Create: `internal/repository/telemedicine/consultations_repository_test.go`

Package is `telemedicine`. Inject via `NewConsultationRepositoryWithQuerier(mock)`.

- [ ] **Step 1: Write `TestConsultationRepository_CreateConsultation`**

3 cases: success, DB error, FK violation.

- [ ] **Step 2: Write `TestConsultationRepository_GetConsultationByID`**

3 cases: found, not found, DB error.

- [ ] **Step 3: Write `TestConsultationRepository_AcceptConsultation`**

3 cases: success, not found, DB error.

- [ ] **Step 4: Write `TestConsultationRepository_StartConsultation`**

3 cases: success, not found, DB error.

- [ ] **Step 5: Write `TestConsultationRepository_CompleteConsultation`**

3 cases: success, not found, DB error.

- [ ] **Step 6: Write `TestConsultationRepository_CancelConsultation`**

3 cases: success, not found, DB error.

- [ ] **Step 7: Write `TestConsultationRepository_EscalateConsultation`**

3 cases: success, not found, DB error.

- [ ] **Step 8: Write `TestConsultationRepository_GetPatientConsultations`**

3 cases: found, empty, DB error.

- [ ] **Step 9: Run tests**

```bash
go test ./internal/repository/telemedicine/ -v -run TestConsultationRepository
```

Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add internal/repository/telemedicine/consultations_repository_test.go
git commit -m "test: add consultation repository tests"
```

---

## Task 8: Telemedicine Repository Tests — Messages, Notes, Availability, Symptom Checker

**Files:**
- Create: `internal/repository/telemedicine/consultation_messages_repository_test.go`
- Create: `internal/repository/telemedicine/consultation_notes_repository_test.go`
- Create: `internal/repository/telemedicine/provider_availability_repository_test.go`
- Create: `internal/repository/telemedicine/symptom_checker_repository_test.go`

- [ ] **Step 1: Write message tests** — `InsertMessage`, `GetConsultationMessages`, `MarkMessageRead`, `CountUnreadMessages`. 3 cases each.

- [ ] **Step 2: Write note tests** — `CreateNote`, `GetNoteByConsultationID`, `UpdateNote`, `FinaliseNote`, `IsNoteFinalised`. 3 cases each.

- [ ] **Step 3: Write availability tests** — `UpsertAvailability`, `GoOnline`, `GoOffline`, `SetAccepting`, `GetAvailableProviders`, `GetAvailabilityByStaffID`. 3 cases each.

- [ ] **Step 4: Write symptom checker tests** — `CreateSession`, `GetSessionByID`, `UpdateSessionStatus`, `GetPatientSessions`. 3 cases each.

- [ ] **Step 5: Run tests**

```bash
go test ./internal/repository/telemedicine/ -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/repository/telemedicine/
git commit -m "test: add telemedicine sub-resource repository tests"
```

---

## Task 9: Service Tests — Core Auth (Expand Existing)

**Files:**
- Modify: `internal/service/core/auth_service_test.go`

Existing file has 2 tests. Expand to ~15 tests. The existing `newAuthServiceForTest` factory needs to be expanded to accept all dependencies.

- [ ] **Step 1: Expand the test helper factory**

```go
func newAuthServiceForTest(t *testing.T, maxAttempts int, lockout time.Duration) *authService {
    t.Helper()
    return &authService{
        authRepo:         &mockAuthRepo{},
        userRepo:         &mockUserRepo{},
        otpRepo:          &mockOTPRepo{},
        patientRepo:      &mockPatientProfileRepo{},
        sessionSvc:       &mockSessionService{},
        consentRepo:      &mockConsentRepo{},
        staffService:     &mockStaffService{},
        cache:            &mockCache{},
        broker:           &mockBroker{},
        emailService:     &mockEmailService{},
        logger:           zerolog.New(io.Discard),
        jwtSecret:        "test-secret-key-for-testing-only-123456",
        jwtExpiry:        1 * time.Hour,
        smsEnabled:       false,
        bcryptCost:       bcrypt.MinCost,
        tokenPool:        sync.Pool{New: func() interface{} { return new(bytes.Buffer) }},
        loginAttempts:    make(map[string]loginAttempt),
        loginMaxAttempts: maxAttempts,
        loginLockout:     lockout,
    }
}
```

- [ ] **Step 2: Write `TestLoginSuccess`** — mock `authRepo.GetUserByEmail` returns user, mock bcrypt match, generate token, verify response has token, user, expires_at.

- [ ] **Step 3: Write `TestLoginInvalidPassword`** — mock user found, bcrypt mismatch, expect `domain.ErrInvalidCredentials`.

- [ ] **Step 4: Write `TestLoginUserNotFound`** — mock `GetUserByEmail` returns not found, expect `domain.ErrUserNotFound`.

- [ ] **Step 5: Write `TestLoginAccountLocked`** — mock user found, call `RecordFailedLogin` N times to exceed threshold, then login should fail with lockout error.

- [ ] **Step 6: Write `TestRefreshTokenSuccess`** — create valid session, call `RefreshToken`, verify new token returned.

- [ ] **Step 7: Write `TestRefreshTokenExpired`** — expired session, expect `domain.ErrExpiredToken`.

- [ ] **Step 8: Write `TestLogoutSuccess`** — valid session, call `Logout`, verify session deleted.

- [ ] **Step 9: Write `TestVerifyEmailSuccess`** — mock `GetUserByVerificationToken` returns user, verify updates user status.

- [ ] **Step 10: Write `TestVerifyEmailInvalidToken`** — mock returns not found, expect error.

- [ ] **Step 11: Write `TestRequestPasswordResetSuccess`** — mock user found, mock email send succeeds, expect no error.

- [ ] **Step 12: Write `TestRequestPasswordResetUserNotFound`** — mock not found, still returns nil (no user enumeration).

- [ ] **Step 13: Write `TestResetPasswordSuccess`** — mock `GetUserByPasswordResetToken` returns user, `UpdateUserPassword` succeeds.

- [ ] **Step 14: Write `TestResetPasswordInvalidToken`** — mock not found, expect error.

- [ ] **Step 15: Write `TestRegisterRejectsPrivilegedSelfSelection`** — already exists, keep.

- [ ] **Step 16: Run tests**

```bash
go test ./internal/service/core/ -v -run TestAuth
```

Expected: PASS

- [ ] **Step 17: Commit**

```bash
git add internal/service/core/auth_service_test.go
git commit -m "test: expand auth service tests to 15+ cases"
```

---

## Task 10: Service Tests — Providers

**Files:**
- Create: `internal/service/providers/clinic_service_test.go`
- Create: `internal/service/providers/staff_service_test.go`

**Mock pattern** — manual mock structs with func fields:

```go
type mockClinicRepo struct {
    CreateClinicFn func(ctx context.Context, clinic providers.Clinic, createdBy, ownerID uuid.UUID) (providers.Clinic, error)
    GetByIDFn      func(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
    VerifyClinicFn func(ctx context.Context, id, verifiedBy uuid.UUID, notes string) error
    // ... one func field per method on ClinicRepository interface
}
func (m *mockClinicRepo) CreateClinic(ctx context.Context, clinic providers.Clinic, createdBy, ownerID uuid.UUID) (providers.Clinic, error) {
    return m.CreateClinicFn(ctx, clinic, createdBy, ownerID)
}
```

- [ ] **Step 1: Write `TestClinicService_RegisterClinic`** — success (valid data, mock CreateClinic returns clinic, audit logged), validation error (empty name), duplicate clinic (owner already has clinic).

- [ ] **Step 2: Write `TestClinicService_GetClinicByID`** — found, not found, unauthorized (user doesn't own clinic).

- [ ] **Step 3: Write `TestClinicService_UpdateClinic`** — success, not found, validation error (empty name after update).

- [ ] **Step 4: Write `TestClinicService_VerifyClinic`** — success (admin verifies), unauthorized (non-admin tries to verify), not found.

- [ ] **Step 5: Write `TestStaffService_InviteStaff`** — success (clinic admin invites staff, email sent), unauthorized (non-admin tries), duplicate email (already invited).

- [ ] **Step 6: Write `TestStaffService_AcceptInvitation`** — success, invalid token, expired token.

- [ ] **Step 7: Write `TestStaffService_RemoveStaff`** — success, cannot remove last clinic admin, unauthorized (non-admin tries).

- [ ] **Step 8: Run tests**

```bash
go test ./internal/service/providers/ -v
```

Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/service/providers/clinic_service_test.go internal/service/providers/staff_service_test.go
git commit -m "test: add provider service tests"
```

---

## Task 11: Service Tests — Patients

**Files:**
- Create: `internal/service/patients/patient_service_test.go`

- [ ] **Step 1: Write `TestPatientService_CreateProfile`** — success (valid profile, consents given), validation error (missing required consents), duplicate (national ID already exists).

- [ ] **Step 2: Write `TestPatientService_GetProfile`** — success, not found.

- [ ] **Step 3: Write `TestPatientService_UpdateProfile`** — success, not found, validation error (invalid data).

- [ ] **Step 4: Write `TestMedicationService_AddMedication`** — success, patient not found (FK), validation error (missing name).

- [ ] **Step 5: Write `TestAllergyService_AddAllergy`** — success, patient not found, validation error.

- [ ] **Step 6: Write `TestDependentService_AddDependent`** — success, patient not found, validation error (dependent older than patient).

- [ ] **Step 7: Run tests**

```bash
go test ./internal/service/patients/ -v
```

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/service/patients/patient_service_test.go
git commit -m "test: add patient service tests"
```

---

## Task 12: Service Tests — Appointments

**Files:**
- Create: `internal/service/appointments/appointment_service_test.go`

- [ ] **Step 1: Write `TestAppointmentService_BookAppointment`** — success, scheduling conflict, max appointments per day exceeded.

- [ ] **Step 2: Write `TestAppointmentService_CancelAppointment`** — success (within window), error (outside cancellation window).

- [ ] **Step 3: Write `TestAppointmentService_ConfirmAppointment`** — success (clinic confirms), unauthorized (non-clinic user tries).

- [ ] **Step 4: Write `TestAppointmentService_Reschedule`** — success, conflict on new slot, not found.

- [ ] **Step 5: Run tests**

```bash
go test ./internal/service/appointments/ -v
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/service/appointments/appointment_service_test.go
git commit -m "test: add appointment service tests"
```

---

## Task 13: Service Tests — Telemedicine

**Files:**
- Create: `internal/service/telemedicine/consultation_service_test.go`

- [ ] **Step 1: Write `TestConsultationService_RequestConsultation`** — success (available provider matched), no provider available, patient already has active consultation.

- [ ] **Step 2: Write `TestConsultationService_AcceptConsultation`** — success, already accepted by another provider, not found.

- [ ] **Step 3: Write `TestConsultationService_StartConsultation`** — success, not in accepted state, timeout before start.

- [ ] **Step 4: Write `TestConsultationService_CompleteConsultation`** — success, notes not yet finalized, not found.

- [ ] **Step 5: Write `TestConsultationService_EscalateConsultation`** — success, not found.

- [ ] **Step 6: Write `TestProviderAvailabilityService_GoOnline`** — success, already online.

- [ ] **Step 7: Write `TestProviderAvailabilityService_GoOffline`** — success, has active consultations (should warn).

- [ ] **Step 8: Run tests**

```bash
go test ./internal/service/telemedicine/ -v
```

Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/service/telemedicine/consultation_service_test.go
git commit -m "test: add telemedicine service tests"
```

---

## Task 14: Handler Tests — Core Auth

**Files:**
- Create: `internal/handler/core/auth_handler_test.go`

**Pattern:** Mock `service.AuthService` interface using manual mock struct, inject into `AuthHandler`, use `httptest.NewRecorder` + `httptest.NewRequest`. Use `middleware.UserContextKey` to inject claims for auth-gated endpoints.

```go
type mockAuthService struct {
    RegisterFn    func(ctx context.Context, email, phone, password, role string) (core.User, error)
    LoginFn       func(ctx context.Context, identifier, password, ipAddress, userAgent string) (string, time.Time, core.User, error)
    RefreshTokenFn func(ctx context.Context, tokenString, ipAddress, userAgent string) (string, time.Time, core.User, error)
    LogoutFn      func(ctx context.Context, tokenString string, userID uuid.UUID) error
    ValidateTokenFn func(ctx context.Context, token string) (*service.TokenClaims, error)
    VerifyEmailFn func(ctx context.Context, token string) error
    // ... all AuthService interface methods
}
```

- [ ] **Step 1: Write `TestAuthHandler_Register`** — success (201, valid response body), validation error (400, missing password, wrong role), service error (409, duplicate email).

Send `POST /api/v1/auth/register` with `RegisterRequest` body:
```go
body := `{"email":"test@example.com","password":"password123","role":"patient"}`
req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", strings.NewReader(body))
req.Header.Set("Content-Type", "application/json")
```

Assert `recorder.Code` and decode response body.

- [ ] **Step 2: Write `TestAuthHandler_Login`** — success (200, token + user in response), invalid credentials (401), validation error (400, empty identifier).

- [ ] **Step 3: Write `TestAuthHandler_RefreshToken`** — success (200), expired token (401).

- [ ] **Step 4: Write `TestAuthHandler_Logout`** — success (204), missing token (401).

- [ ] **Step 5: Write `TestAuthHandler_VerifyEmail`** — success (200), invalid token (400), already verified (409).

- [ ] **Step 6: Write `TestAuthHandler_RequestPasswordReset`** — success (200, always returns 200 even if user not found), validation (400, empty identifier).

- [ ] **Step 7: Write `TestAuthHandler_ResetPassword`** — success (200), invalid token (400), weak password (400).

- [ ] **Step 8: Write `TestAuthHandler_ResendVerificationEmail`** — success (200), validation (400, empty email).

- [ ] **Step 9: Run tests**

```bash
go test ./internal/handler/core/ -v -run TestAuthHandler
```

Expected: PASS

- [ ] **Step 10: Commit**

```bash
git add internal/handler/core/auth_handler_test.go
git commit -m "test: add auth handler tests"
```

---

## Task 15: Handler Tests — Providers

**Files:**
- Create: `internal/handler/providers/clinic_handler_test.go`

- [ ] **Step 1: Write mock for `service.ClinicService` interface**

```go
type mockClinicService struct {
    RegisterClinicFn func(ctx context.Context, clinic providers.Clinic, createdBy, ownerID uuid.UUID) (providers.Clinic, error)
    GetClinicByIDFn  func(ctx context.Context, id uuid.UUID) (providers.Clinic, error)
    // ... all ClinicService interface methods
}
```

- [ ] **Step 2: Write `TestClinicHandler_CreateClinic`** — success (201), validation error (400, empty name), auth failure (401, no token), forbidden (403, wrong role).

- [ ] **Step 3: Write `TestClinicHandler_GetClinic`** — success (200), not found (404).

- [ ] **Step 4: Write `TestClinicHandler_GetMyClinic`** — success (200, auth context provides userID), not found (404), no clinic (200 with empty/null).

- [ ] **Step 5: Write `TestClinicHandler_UpdateClinic`** — success (200), not found (404), validation error (400).

- [ ] **Step 6: Write `TestClinicHandler_ListClinics`** — success (200, list), empty list (200, empty array).

- [ ] **Step 7: Write `TestClinicHandler_DeleteClinic`** — success (204), not found (404).

- [ ] **Step 8: Run tests**

```bash
go test ./internal/handler/providers/ -v -run TestClinicHandler
```

Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/handler/providers/clinic_handler_test.go
git commit -m "test: add clinic handler tests"
```

---

## Task 16: Handler Tests — Patients

**Files:**
- Create: `internal/handler/patients/patient_handler_test.go`

- [ ] **Step 1: Write mock for `service.PatientService` interface**

- [ ] **Step 2: Write `TestPatientHandler_CreatePatientProfile`** — success (201), validation error (400, missing required fields), auth failure (401), forbidden (403, not patient/caregiver role).

- [ ] **Step 3: Write `TestPatientHandler_GetPatientProfile`** — success (200), not found (404).

- [ ] **Step 4: Write `TestPatientHandler_UpdatePatientProfile`** — success (200), not found (404), validation error (400).

- [ ] **Step 5: Write `TestPatientHandler_SearchPatients`** — success (200, results), empty query (200, all), no results (200, empty).

- [ ] **Step 6: Write `TestPatientHandler_DeletePatientProfile`** — success (204), not found (404).

- [ ] **Step 7: Run tests**

```bash
go test ./internal/handler/patients/ -v -run TestPatientHandler
```

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/handler/patients/patient_handler_test.go
git commit -m "test: add patient handler tests"
```

---

## Task 17: Handler Tests — Appointments

**Files:**
- Create: `internal/handler/appointments/appointment_handler_test.go`

- [ ] **Step 1: Write mock for `service.AppointmentService` interface**

- [ ] **Step 2: Write `TestAppointmentHandler_CreateAppointment`** — success (201), conflict (409), validation error (400), auth failure (401).

- [ ] **Step 3: Write `TestAppointmentHandler_GetAppointmentByID`** — success (200), not found (404).

- [ ] **Step 4: Write `TestAppointmentHandler_GetAppointmentsByPatient`** — success (200, list), empty (200).

- [ ] **Step 5: Write `TestAppointmentHandler_CancelAppointment`** — success (200), outside cancellation window (409), not found (404).

- [ ] **Step 6: Write `TestAppointmentHandler_ConfirmAppointment`** — success (200), forbidden (403, patient tries to confirm).

- [ ] **Step 7: Run tests**

```bash
go test ./internal/handler/appointments/ -v -run TestAppointmentHandler
```

Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add internal/handler/appointments/appointment_handler_test.go
git commit -m "test: add appointment handler tests"
```

---

## Task 18: Handler Tests — Telemedicine

**Files:**
- Create: `internal/handler/telemedicine/consultation_handler_test.go`

- [ ] **Step 1: Write mock for `service.ConsultationService` interface**

- [ ] **Step 2: Write `TestConsultationHandler_RequestConsultation`** — success (201), no provider (503), already active (409), auth failure (401).

- [ ] **Step 3: Write `TestConsultationHandler_AcceptConsultation`** — success (200), already accepted (409), forbidden (403, patient tries).

- [ ] **Step 4: Write `TestConsultationHandler_StartConsultation`** — success (200), wrong state (409).

- [ ] **Step 5: Write `TestConsultationHandler_CompleteConsultation`** — success (200), notes not finalized (409).

- [ ] **Step 6: Write `TestConsultationHandler_GetPatientActiveConsultation`** — success (200, has active), success (200, no active).

- [ ] **Step 7: Write `TestConsultationHandler_GetWaitingRoom`** — success (200), empty (200).

- [ ] **Step 8: Run tests**

```bash
go test ./internal/handler/telemedicine/ -v -run TestConsultationHandler
```

Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add internal/handler/telemedicine/consultation_handler_test.go
git commit -m "test: add telemedicine handler tests"
```

---

## Task 19: Handler Tests — Admin

**Files:**
- Create: `internal/handler/admin/admin_handler_test.go`

- [ ] **Step 1: Write mock for `service.SystemAdminService` interface**

- [ ] **Step 2: Write `TestAdminHandler_CreateSystemAdmin`** — success (201), forbidden (403, non-admin role), duplicate (409), validation error (400).

For auth-gated admin routes, inject claims with role `system_admin`:
```go
claims := &service.TokenClaims{UserID: adminID, Role: "system_admin", Email: "admin@example.com"}
ctx := context.WithValue(r.Context(), middleware.UserContextKey, claims)
req = req.WithContext(ctx)
```

- [ ] **Step 3: Write `TestAdminHandler_GetSystemAdminByUserID`** — success (200), not found (404), forbidden (403).

- [ ] **Step 4: Run tests**

```bash
go test ./internal/handler/admin/ -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/handler/admin/admin_handler_test.go
git commit -m "test: add admin handler tests"
```

---

## Task 20: Integration Tests — Setup with Testcontainers

**Files:**
- Create: `tests/integration/setup_test.go`

- [ ] **Step 1: Create directory and go.mod for integration tests**

```bash
mkdir -p tests/integration
```

The `tests/integration` package uses build tag `//go:build integration` on every file.

- [ ] **Step 2: Write `setup_test.go` with TestMain**

```go
//go:build integration

package integration

import (
    "context"
    "log"
    "os"
    "testing"

    "github.com/golang-migrate/migrate/v4"
    _ "github.com/golang-migrate/migrate/v4/database/postgres"
    _ "github.com/golang-migrate/migrate/v4/source/file"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/modules/postgres"
    "github.com/testcontainers/testcontainers-go/modules/redis"
)

var (
    testDBURL    string
    testRedisURL string
    pgContainer  *postgres.PostgresContainer
    redisContainer *redis.RedisContainer
)

func TestMain(m *testing.M) {
    ctx := context.Background()

    // Start PostgreSQL
    var err error
    pgContainer, err = postgres.Run(ctx,
        "postgres:16-alpine",
        postgres.WithDatabase("healthcare_test"),
        postgres.WithUsername("testuser"),
        postgres.WithPassword("testpass"),
        postgres.WithInitScripts("../../database/init.sql"),
        postgres.BasicWaitStrategies(),
    )
    if err != nil {
        log.Fatalf("failed to start postgres: %s", err)
    }
    defer func() {
        if err := testcontainers.TerminateContainer(pgContainer); err != nil {
            log.Printf("failed to terminate postgres: %s", err)
        }
    }()

    testDBURL, err = pgContainer.ConnectionString(ctx, "sslmode=disable")
    if err != nil {
        log.Fatalf("failed to get postgres connection string: %s", err)
    }

    // Start Redis
    redisContainer, err = redis.Run(ctx,
        "redis:7-alpine",
    )
    if err != nil {
        log.Fatalf("failed to start redis: %s", err)
    }
    defer func() {
        if err := testcontainers.TerminateContainer(redisContainer); err != nil {
            log.Printf("failed to terminate redis: %s", err)
        }
    }()

    redisHost, err := redisContainer.Host(ctx)
    if err != nil {
        log.Fatalf("failed to get redis host: %s", err)
    }
    redisPort, err := redisContainer.MappedPort(ctx, "6379")
    if err != nil {
        log.Fatalf("failed to get redis port: %s", err)
    }
    testRedisURL = "redis://" + redisHost + ":" + redisPort.Port()

    // Set env vars for the application
    os.Setenv("DB_URL", testDBURL)
    os.Setenv("REDIS_URL", testRedisURL)
    os.Setenv("JWT_SECRET", "integration-test-secret-key-minimum-32-chars!")
    os.Setenv("ENVIRONMENT", "test")
    os.Setenv("LOG_LEVEL", "error")
    os.Setenv("METRICS_ENABLED", "false")
    os.Setenv("RATE_LIMIT_RPS", "1000")
    os.Setenv("BCRYPT_COST", "4")
    os.Setenv("CACHE_ENABLED", "false")

    // Run migrations
    runMigrations(testDBURL)

    // Run tests
    code := m.Run()

    os.Exit(code)
}

func runMigrations(dbURL string) {
    // Build the migration URL by stripping the database name and adding sslmode
    // The connection string from testcontainers includes database name already
    migrateURL := dbURL + "&x-migrations-table=schema_migrations"

    m, err := migrate.New(
        "file://../../database/migrations",
        migrateURL,
    )
    if err != nil {
        log.Fatalf("failed to create migrator: %s", err)
    }
    defer m.Close()

    if err := m.Up(); err != nil && err != migrate.ErrNoChange {
        log.Fatalf("failed to run migrations: %s", err)
    }
    log.Println("migrations applied successfully")
}
```

- [ ] **Step 3: Run the setup to verify containers start**

```bash
go test -v -tags=integration -run TestMain ./tests/integration/ -count=1
```

Expected: containers start, migrations run, no errors.

- [ ] **Step 4: Commit**

```bash
git add tests/integration/setup_test.go
git commit -m "test: add integration test setup with testcontainers"
```

---

## Task 21: Integration Tests — Auth Flow

**Files:**
- Create: `tests/integration/auth_flow_test.go`

- [ ] **Step 1: Write `TestAuthFlow`**

Boot the full app using `internal/app` with test config. Use `httptest.Server` for in-process HTTP. Run the flow:

1. **Register** patient — `POST /api/v1/auth/register` → 201, verify user response
2. **Verify email** — `POST /api/v1/auth/verify-email` with token from DB → 200
3. **Login** — `POST /api/v1/auth/login` → 200, extract token
4. **Refresh token** — `POST /api/v1/auth/refresh` with token → 200, extract new token
5. **Logout** — `POST /api/v1/auth/logout` with token → 204
6. **Login with expired session** — expect 401

```go
//go:build integration

package integration

import (
    "testing"
    "net/http/httptest"
    // ... app imports
)

func TestAuthFlow(t *testing.T) {
    // Create app with test config
    cfg, _ := config.Load()
    app := app.NewApp(cfg)
    
    // Create HTTP test server
    handler := app.Router()
    ts := httptest.NewServer(handler)
    defer ts.Close()

    // Step 1: Register
    resp := doPost(t, ts.URL + "/api/v1/auth/register", map[string]string{
        "email": "patient@test.com",
        "password": "TestPassword123!",
        "role": "patient",
    })
    assert.Equal(t, 201, resp.StatusCode)

    // Step 2: Login
    resp = doPost(t, ts.URL + "/api/v1/auth/login", map[string]string{
        "identifier": "patient@test.com",
        "password": "TestPassword123!",
    })
    assert.Equal(t, 200, resp.StatusCode)
    var loginResp LoginResponse
    json.NewDecoder(resp.Body).Decode(&loginResp)
    token := loginResp.Token

    // ... continue flow
}
```

- [ ] **Step 2: Run the integration test**

```bash
go test -v -tags=integration ./tests/integration/ -run TestAuthFlow
```

Expected: PASS (requires Docker running)

- [ ] **Step 3: Commit**

```bash
git add tests/integration/auth_flow_test.go
git commit -m "test: add auth integration test"
```

---

## Task 22: Integration Tests — Provider, Patient, Appointment, and Telemedicine Flows

**Files:**
- Create: `tests/integration/provider_flow_test.go`
- Create: `tests/integration/patient_flow_test.go`
- Create: `tests/integration/appointment_flow_test.go`
- Create: `tests/integration/telemedicine_flow_test.go`

- [ ] **Step 1: Write `TestProviderFlow`** — Register provider → login → create clinic → invite staff → accept invitation → manage credentials.

- [ ] **Step 2: Write `TestPatientFlow`** — Register patient → verify email → login → create profile → add medical history (allergy, medication) → update consents → add emergency contact.

- [ ] **Step 3: Write `TestAppointmentFlow`** — Register clinic → book appointment as patient → provider confirms → patient cancels → verify status.

- [ ] **Step 4: Write `TestTelemedicineFlow`** — Register both patient and provider → provider goes online → patient requests consultation → provider accepts → exchange messages → complete consultation.

- [ ] **Step 5: Run all integration tests**

```bash
go test -v -tags=integration ./tests/integration/...
```

Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add tests/integration/
git commit -m "test: add provider, patient, appointment, and telemedicine integration tests"
```

---

## Task 23: Infrastructure Tests — Email Providers

**Files:**
- Modify: `internal/email/providers/smtp/smtp_test.go` (currently empty stub)
- Modify: `internal/email/providers/resend/resend_test.go` (currently empty stub)
- Modify: `internal/email/providers/ses/ses_test.go` (currently empty stub)

- [ ] **Step 1: Write SMTP tests** — test config validation (missing host, missing port), connection failure handling (unreachable host), TLS negotiation error.

```go
func TestSMTPProvider_InvalidConfig(t *testing.T) {
    cfg := types.Config{SMTPHost: "", SMTPPort: 0}
    provider, err := NewSMTPProvider(cfg)
    assert.Error(t, err)
    assert.Nil(t, provider)
    assert.Contains(t, err.Error(), "SMTP host")
}

func TestSMTPProvider_ConnectionFailure(t *testing.T) {
    cfg := types.Config{SMTPHost: "invalid-host-that-does-not-exist.local", SMTPPort: 587}
    provider, err := NewSMTPProvider(cfg)
    require.NoError(t, err)
    err = provider.Send(context.Background(), email.Email{...})
    assert.Error(t, err)
}
```

- [ ] **Step 2: Write Resend tests** — test empty API key validation, mock HTTP transport for success/error.

For mocking HTTP in email providers, use `httptest.NewServer` to create a mock API endpoint:
```go
func TestResendProvider_SendSuccess(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        assert.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))
        w.WriteHeader(200)
        json.NewEncoder(w).Encode(map[string]string{"id": "msg_123"})
    }))
    defer server.Close()

    provider := NewResendProvider("test-api-key")
    provider.baseURL = server.URL
    err := provider.Send(context.Background(), email.Email{...})
    assert.NoError(t, err)
}
```

- [ ] **Step 3: Write SES tests** — test missing credentials, mock AWS client, test send failure.

- [ ] **Step 4: Run tests**

```bash
go test ./internal/email/providers/... -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/email/providers/smtp/smtp_test.go internal/email/providers/resend/resend_test.go internal/email/providers/ses/ses_test.go
git commit -m "test: fill email provider test stubs"
```

---

## Task 24: Infrastructure Tests — Cache and Messaging

**Files:**
- Create: `internal/cache/redis_test.go`
- Create: `internal/messaging/nats_test.go`

- [ ] **Step 1: Write Redis cache unit tests** — mock the `redis.Client` interface. Test `Get` (hit, miss, error), `Set`, `Delete`, `Exists`, `Increment`.

```go
type mockRedisClient struct {
    GetFn    func(ctx context.Context, key string) *redis.StringCmd
    SetFn    func(ctx context.Context, key string, value interface{}, ttl time.Duration) *redis.StatusCmd
    DelFn    func(ctx context.Context, keys ...string) *redis.IntCmd
    ExistsFn func(ctx context.Context, keys ...string) *redis.IntCmd
}
```

- [ ] **Step 2: Write NATS messaging unit tests** — mock `nats.Conn`. Test `Publish`, `Subscribe`, `Request`, connection failure.

```go
type mockNatsConn struct {
    PublishFn    func(subject string, data []byte) error
    SubscribeFn  func(subject string, handler nats.MsgHandler) (*nats.Subscription, error)
    CloseFn      func()
}
```

- [ ] **Step 3: Run tests**

```bash
go test ./internal/cache/ -v
go test ./internal/messaging/ -v
```

Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/cache/redis_test.go internal/messaging/nats_test.go
git commit -m "test: add cache and messaging unit tests"
```

---

## Task 25: Infrastructure Tests — WebSocket, AI, Validator

**Files:**
- Create: `internal/ws/hub_test.go`
- Create: `internal/ai/client_test.go`
- Create: `internal/validator/validator_test.go`

- [ ] **Step 1: Write WebSocket hub tests** — test subscribe/unsubscribe, broadcast to room, client disconnect cleanup.

```go
func TestHubSubscribe(t *testing.T) {
    hub := NewHub()
    client := &Client{ID: "client-1", Rooms: make(map[string]bool)}
    
    hub.Subscribe("room-1", client)
    assert.Len(t, hub.Rooms["room-1"], 1)
}

func TestHubUnsubscribe(t *testing.T) {
    hub := NewHub()
    client := &Client{ID: "client-1", Rooms: make(map[string]bool)}
    hub.Subscribe("room-1", client)
    hub.Unsubscribe("room-1", client)
    assert.Len(t, hub.Rooms["room-1"], 0)
}

func TestHubBroadcastSkipsSender(t *testing.T) {
    hub := NewHub()
    sender := &Client{ID: "sender", Send: make(chan []byte, 1), Rooms: make(map[string]bool)}
    receiver := &Client{ID: "receiver", Send: make(chan []byte, 1), Rooms: make(map[string]bool)}
    hub.Subscribe("room-1", sender)
    hub.Subscribe("room-1", receiver)
    
    hub.Broadcast("room-1", []byte("hello"), sender.ID)
    
    // Sender should NOT receive the message
    select {
    case <-sender.Send:
        t.Fatal("sender should not receive own broadcast")
    case <-time.After(50 * time.Millisecond):
    }
    
    // Receiver SHOULD receive
    select {
    case msg := <-receiver.Send:
        assert.Equal(t, []byte("hello"), msg)
    case <-time.After(50 * time.Millisecond):
        t.Fatal("receiver did not receive broadcast")
    }
}
```

- [ ] **Step 2: Write AI client tests** — mock HTTP transport. Test prompt building, success response, error response, timeout.

```go
func TestAIClient_SendSuccess(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(200)
        json.NewEncoder(w).Encode(map[string]interface{}{
            "choices": []map[string]interface{}{{"message": map[string]string{"content": "I'm a helpful assistant response"}}},
        })
    }))
    defer server.Close()

    client := NewClient(ClientConfig{BaseURL: server.URL, APIKey: "test-key"})
    resp, err := client.Send(context.Background(), "Hello")
    require.NoError(t, err)
    assert.Contains(t, resp, "helpful assistant")
}

func TestAIClient_Timeout(t *testing.T) {
    server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        time.Sleep(2 * time.Second) // longer than client timeout
    }))
    defer server.Close()

    client := NewClient(ClientConfig{BaseURL: server.URL, APIKey: "test-key", Timeout: 500 * time.Millisecond})
    _, err := client.Send(context.Background(), "Hello")
    assert.Error(t, err)
}
```

- [ ] **Step 3: Write validator tests** — every method × valid + invalid + boundary cases:

```go
func TestValidateEmail(t *testing.T) {
    v := Validator{} // or New()
    assert.True(t, v.ValidateEmail("test@example.com"))
    assert.False(t, v.ValidateEmail("invalid"))
    assert.False(t, v.ValidateEmail(""))
}
// Repeat for: ValidatePhone, ValidatePassword, ValidateRole, ValidateRequired,
// ValidateLength, ValidateMinLength, ValidateMaxLength, ValidateNumeric,
// ValidateOTP, ValidateEnum, ValidateUUID
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/ws/ -v
go test ./internal/ai/ -v
go test ./internal/validator/ -v
```

Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/ws/hub_test.go internal/ai/client_test.go internal/validator/validator_test.go
git commit -m "test: add WebSocket, AI, and validator tests"
```

---

## Task 26: CI and Makefile Updates

**Files:**
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yml`

- [ ] **Step 1: Add smoke test target to Makefile**

Add to `Makefile`:
```makefile
test-smoke:
	@echo "Running smoke tests..."
	./tests/smoke/smoke.sh
```

- [ ] **Step 2: Add integration test job to CI**

Add to `.github/workflows/ci.yml`:
```yaml
  integration-tests:
    runs-on: ubuntu-latest
    needs: [fast-checks]
    services:
      docker:
        image: docker:dind
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.24'
      - name: Run integration tests
        run: go test -v -tags=integration ./tests/integration/...
```

- [ ] **Step 3: Add smoke test job to CI**

Add to `.github/workflows/ci.yml`:
```yaml
  smoke-tests:
    runs-on: ubuntu-latest
    needs: [docker-build]
    steps:
      - uses: actions/checkout@v4
      - name: Build and run smoke tests
        run: |
          docker build -t healthcare-api:test .
          docker run -d --name api-test -p 8080:8080 \
            -e DB_URL=postgres://ignore:ignore@host.docker.internal:5432/test \
            -e JWT_SECRET=test-secret-key-for-testing-only-123456 \
            -e ENVIRONMENT=test \
            -e LOG_LEVEL=error \
            -e METRICS_ENABLED=true \
            healthcare-api:test
          sleep 5
          ./tests/smoke/smoke.sh
          docker stop api-test
```

- [ ] **Step 4: Add coverage upload to CI**

Add to `fast-checks` job:
```yaml
      - name: Upload coverage report
        uses: actions/upload-artifact@v4
        with:
          name: coverage-report
          path: coverage.out
```

- [ ] **Step 5: Run Makefile targets to verify**

```bash
make test-smoke
```

Expected: smoke tests run (may fail if no server running, that's OK for this step).

- [ ] **Step 6: Commit**

```bash
git add Makefile .github/workflows/ci.yml
git commit -m "ci: add integration, smoke, and coverage to CI pipeline"
```

---

## Task 27: Final Verification

**Files:** (none, verification only)

- [ ] **Step 1: Run all unit tests**

```bash
go test ./... -v -short -count=1
```

Expected: ALL PASS. No failures, no panics.

- [ ] **Step 2: Run with race detector**

```bash
go test ./... -race -short -count=1
```

Expected: ALL PASS. No race conditions detected.

- [ ] **Step 3: Run full test suite**

```bash
go test ./... -v -race -coverprofile=coverage.out -covermode=atomic
```

Expected: ALL PASS. Coverage report generated.

- [ ] **Step 4: Generate and review coverage report**

```bash
go tool cover -html=coverage.out -o coverage.html
```

Review `coverage.html` — verify coverage exists in all bounded contexts.

- [ ] **Step 5: Verify builds**

```bash
go build ./...
```

Expected: clean build.

- [ ] **Step 6: Verify generated code is clean**

```bash
sqlc generate
git diff --exit-code -- internal/db/
```

Expected: no drift.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: final verification - all tests pass"
```

---

## Summary

| Phase | Tasks | New Test Files | Estimated Test Cases |
|-------|-------|---------------|---------------------|
| 1. Repository | 1–8 | 19 | ~200 |
| 2. Service | 9–13 | 5 | ~50 |
| 3. Handler | 14–19 | 6 | ~70 |
| 4. Integration | 20–22 | 6 | ~15 (end-to-end) |
| 5. Infrastructure | 23–25 | 8 | ~40 |
| CI/Verification | 26–27 | 0 | N/A |
| **Total** | **28** | **44** | **~375** |
