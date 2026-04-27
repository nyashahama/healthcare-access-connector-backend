# Test Coverage Expansion Design

> **Status:** Approved  
> **Date:** 2026-04-27  
> **Related plan:** `docs/superpowers/plans/2026-04-22-production-readiness-master-plan.md` (Wave 5)

## Goal

Expand test coverage across the entire codebase using a bottom-up, confidence-driven approach. Every bounded context gets repository, service, and handler tests. Integration tests verify end-to-end flows against real infrastructure via testcontainers.

## Baseline

| Area | Existing tests |
|------|---------------|
| `repository/core/*` | 7 files, ~5,600 lines (users, auth, sessions, OTP, consent, notifications, audit) |
| `middleware/*` | 3 files (auth, cors, ratelimit) |
| `service/core/auth` | 1 file, 2 tests |
| `config/`, `app/`, `server/`, `version/` | 1 file each |
| `email/providers/*` | 3 empty stubs |
| `handler/*` | None |
| `service/{providers,patients,appointments,telemedicine}` | None |
| `repository/{providers,patients,appointments,telemedicine}` | None |
| `cache/`, `messaging/`, `ws/`, `ai/`, `validator/` | None |
| Integration tests | Directory does not exist |

## Key Decisions

1. **Bottom-up approach** — repositories first, then services, then handlers, then integration, then infrastructure
2. **Testcontainers** — `testcontainers-go` for integration tests against real PostgreSQL, Redis, and NATS
3. **Confidence-driven coverage** — no hard percentage targets. Cover every business rule, error path, and authorization boundary. Skip trivial getters/setters.
4. **Preserve existing patterns** — table-driven tests, testify assert/require/mock, mockery-generated `MockQuerier`, custom assert helpers per domain

---

## Phase 1: Repository Tests

Follow the exact pattern established by the 7 existing core repository tests. Each new repository test file uses:

- `mocks.NewMockQuerier(t)` from `internal/db/mocks` (covers all sqlc-generated queries)
- Table-driven tests: `[]struct{name, mockSetup, expectedResult, expectedError}`
- `mockQuerier.AssertExpectations(t)` at end of every test
- Per-file custom assert helpers: `assertClinicEqual`, `assertAppointmentEqual`, etc.
- Every query method tested for 3 paths: happy, not-found (`pgx.ErrNoRows`), DB error (`assert.AnError`)
- Constraint violations tested where applicable (`pgconn.PgError` codes: `23505` duplicate, `23503` FK, `23514` check)

### New test files

**Providers:**
- `internal/repository/providers/clinic_repository_test.go` — CreateClinic, GetClinicByID, GetClinicsByOwner, UpdateClinic, ListClinics, SearchClinics
- `internal/repository/providers/staff_repository_test.go` — CreateStaff, GetStaffByClinic, GetStaffByUserID, UpdateStaffRole, RemoveStaff
- `internal/repository/providers/credential_repository_test.go` — CreateCredential, GetCredentialsByProvider, VerifyCredential
- `internal/repository/providers/service_repository_test.go` — CreateService, GetServicesByClinic, UpdateService, DeleteService

**Patients:**
- `internal/repository/patients/profile_repository_test.go` — CreateProfile, GetProfile, GetProfileByUserID, UpdateProfile, ListDependents
- `internal/repository/patients/medical_repository_test.go` — Allergies, Medications, Conditions, Surgeries, Immunizations, FamilyHistory CRUD

**Appointments:**
- `internal/repository/appointments/appointment_repository_test.go` — Create, GetByID, GetByPatient, GetByProvider, Update, Cancel, List, ConflictCheck

**Telemedicine:**
- `internal/repository/telemedicine/consultation_repository_test.go` — Create, GetByID, List, UpdateStatus
- `internal/repository/telemedicine/message_repository_test.go` — Create, GetByConsultation, MarkRead
- `internal/repository/telemedicine/note_repository_test.go` — Create, GetByConsultation, Finalize
- `internal/repository/telemedicine/availability_repository_test.go` — Set, Get, Delete slots
- `internal/repository/telemedicine/symptom_checker_repository_test.go` — CreateSession, UpdateSession, GetSession

---

## Phase 2: Service Tests

Services depend on repositories, email, cache, and messaging. Dependencies are mocked via manual mock structs (one func field per method) consistent with the existing `mockAuthService` pattern. Logger silenced with `zerolog.New(io.Discard)`. bcrypt uses `bcrypt.MinCost` for test speed.

### New test files

**Core (expand existing):**
- `internal/service/core/auth_service_test.go` — expand from 2 tests to ~15: login success, password reset flow, refresh token rotation, OTP challenge/generation, session invalidation, account lockout escalation, email verification flow

**Providers:**
- `internal/service/providers/clinic_service_test.go` — Clinic registration validation, staff invitation authorization, credential verification state machine, service catalog management, clinic search
- `internal/service/providers/staff_service_test.go` — Role-based access within clinic, invitation accept/decline, removal constraints (can't remove last clinic_admin)

**Patients:**
- `internal/service/patients/profile_service_test.go` — Profile creation with consent gates, medical history CRUD authorization (patient vs caregiver vs dependent), dependent management authorization, emergency contact validation

**Appointments:**
- `internal/service/appointments/appointment_service_test.go` — Slot availability validation, conflict detection, cancellation window policy enforcement, reminder scheduling, max-per-day enforcement

**Telemedicine:**
- `internal/service/telemedicine/consultation_service_test.go` — Consultation lifecycle state machine (scheduled → in_progress → completed → cancelled), provider availability validation, patient-provider matching, message authorization, note finalization authorization

### Shared mock pattern

```go
type mockClinicRepo struct {
    GetByIDFn func(ctx context.Context, id uuid.UUID) (Clinic, error)
    CreateFn   func(ctx context.Context, params CreateParams) (Clinic, error)
    // ... one func field per repository method
}
```

---

## Phase 3: Handler Tests

HTTP handlers tested via `httptest.NewRecorder` + `httptest.NewRequest`. Service layer is mocked. Auth-dependent tests inject claims via context (`context.WithValue`) matching the middleware's claim key.

Each endpoint gets minimum 3 cases:
1. **Success** (200/201 with expected response body shape)
2. **Auth failure** (401 — missing token, invalid token, insufficient role)
3. **Input validation** (400 with field-level error messages)

Plus domain-specific error propagation: 403 forbidden, 404 not-found, 409 conflict, 429 rate-limited.

### New test files

- `internal/handler/core/auth_handler_test.go` — Register, login, refresh, logout, password-reset request/confirm, verify-email, resend-verification
- `internal/handler/providers/clinic_handler_test.go` — Clinic CRUD, staff invitation endpoints, credential management
- `internal/handler/patients/profile_handler_test.go` — Profile CRUD, medical history sub-resources, dependents, emergency contacts
- `internal/handler/appointments/appointment_handler_test.go` — CRUD endpoints, conflict response, availability check
- `internal/handler/telemedicine/consultation_handler_test.go` — Consultation lifecycle, messaging, notes, provider availability
- `internal/handler/admin/admin_handler_test.go` — Admin-only user management, system configuration, NGO partner operations

---

## Phase 4: Integration Tests

### Dependencies

Add `github.com/testcontainers/testcontainers-go` and its modules (`testcontainers-go/modules/postgres`, `testcontainers-go/modules/redis`, `testcontainers-go/modules/nats`) to `go.mod`.

### Directory

`tests/integration/` — new directory, matches the Makefile target `go test -v -tags=integration ./tests/integration/...`

### Setup

- `tests/integration/setup_test.go` — `TestMain` function that boots PostgreSQL 16, Redis 7, and NATS 2 containers, runs migrations via `golang-migrate`, exposes container host/port via env vars or a shared config struct
- Single container lifecycle shared across all integration tests in the package (not per-test)
- Uses build tag `//go:build integration` on all files

### End-to-end flow tests

- `tests/integration/auth_flow_test.go` — Register patient → verify email token → login → refresh token → password reset → logout → login with expired session
- `tests/integration/provider_flow_test.go` — Register provider → create clinic → invite staff → accept invitation → manage credentials → list services
- `tests/integration/patient_flow_test.go` — Create profile with consent → add medical history (allergies, medications, conditions) → update consents → add dependent → add emergency contact
- `tests/integration/appointment_flow_test.go` — Patient books slot → provider confirms → patient cancels within window → check availability reflects changes
- `tests/integration/telemedicine_flow_test.go` — Schedule consultation → provider starts session → exchange messages → add clinical notes → complete → verify final state

Each integration test boots the full application via `internal/app` with test configuration and makes real HTTP calls against it using `httptest.Server` (in-process) or a real listener.

---

## Phase 5: Infrastructure Tests

### Email providers

Fill the 3 empty stub files:
- `internal/email/providers/smtp/smtp_test.go` — Config validation, connection failure handling, TLS negotiation errors
- `internal/email/providers/resend/resend_test.go` — API key validation, request body construction, HTTP error response handling
- `internal/email/providers/ses/ses_test.go` — Credential validation, send failure, region configuration

### Cache

- `internal/cache/redis_test.go` — Unit tests with a mock redis client; integration via testcontainers Redis

### Messaging

- `internal/messaging/nats_test.go` — Unit tests with mock NATS connection; integration via testcontainers NATS

### WebSocket

- `internal/ws/hub_test.go` — Subscribe/unsubscribe, broadcast to room, client disconnect cleanup, per-message size limits

### AI Client

- `internal/ai/client_test.go` — Mock HTTP transport, prompt building, error responses, timeout handling, max token enforcement

### Validator

- `internal/validator/validator_test.go` — Every validation method × valid input + invalid input + boundary/empty input

---

## CI and Makefile Changes

### Makefile additions

- `make test-smoke` — runs `./tests/smoke/smoke.sh` against a running instance
- `make test-integration` — existing target, now backed by real tests
- Update `make check` to include integration tests when Docker is available

### CI changes (`.github/workflows/ci.yml`)

- Add `integration-tests` job: runs `make test-integration` with Docker service available
- Add `smoke-tests` job: builds image, starts container, runs smoke script
- Upload coverage report as CI artifact

### `.env.test` fixes

- Remove duplicate `DB_URL` and `REDIS_URL` entries
- Add `NATS_URL` and `REDIS_URL` entries matching testcontainers defaults if not present

---

## What We Don't Test

- Trivial getters and setters (single field accessors with no logic)
- Generated code (`internal/db/` sqlc output — tested indirectly through repository tests)
- Third-party library internals (pgx, chi, zerolog, testify)
- Private helper functions in isolation (tested through public API of their owning package)
- Code coverage percentage thresholds (confidence-driven, not metric-driven)

---

## Success Criteria

- Every bounded context (core, providers, patients, appointments, telemedicine, admin) has repository, service, and handler tests
- Every email provider has tests (empty stubs filled)
- Integration tests cover the 5 critical end-to-end flows
- Infrastructure packages (cache, messaging, ws, ai, validator) have tests
- All new tests follow the existing table-driven + testify + mockery pattern
- `make test-integration` passes reliably in CI
- No new dependencies beyond `testcontainers-go` and its modules
