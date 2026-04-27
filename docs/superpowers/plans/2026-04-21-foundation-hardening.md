# Foundation Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove stop-ship risks and restore truthful local and CI signals for the backend.

**Architecture:** This wave avoids broad rewrites. It fixes secret handling, config contract drift, runtime wiring, and the known failing test while preserving the existing `handler -> service -> repository -> sqlc` structure. Runtime settings should become config-driven, startup and shutdown should be deterministic, and the repo should expose one clear build-and-test path.

**Tech Stack:** Go 1.24, chi, pgx/sqlc, zerolog, Docker Compose, GitHub Actions

---

### Task 1: Replace Tracked Secrets With Safe Templates

**Files:**
- Create: `docs/operations/secrets-rotation.md`
- Modify: `.env.example`
- Modify: `.env.development`
- Modify: `.env.production`
- Modify: `.gitignore`
- Modify: `ENVIRONMENT.md`

- [ ] **Step 1: Write the failing guard test for secret-bearing env files**

```go
// internal/config/env_contract_test.go
func TestTrackedEnvFilesContainNoLiveSecrets(t *testing.T) {
    files := []string{".env.development", ".env.production"}
    bannedMarkers := []string{
        "postgresql://",
        "rediss://",
        "re_",
        "sk-",
        "hf_",
        "smtp_password",
    }

    for _, file := range files {
        data, err := os.ReadFile(file)
        require.NoError(t, err)
        lower := strings.ToLower(string(data))
        for _, marker := range bannedMarkers {
            assert.NotContains(t, lower, strings.ToLower(marker), file)
        }
    }
}
```

- [ ] **Step 2: Run the guard test to verify it fails against the current tracked files**

Run: `go test ./internal/config -run TestTrackedEnvFilesContainNoLiveSecrets -v`
Expected: FAIL because the current env files contain live-looking secrets.

- [ ] **Step 3: Replace tracked env files with placeholder templates and document the rotation process**

```dotenv
# .env.production
ENVIRONMENT=production
DB_URL=postgresql://user:password@host:6543/database?sslmode=require
REDIS_URL=rediss://default:password@host:6379
EMAIL_PROVIDER=resend
RESEND_API_KEY=replace-in-secret-manager
JWT_SECRET=replace-with-secret-manager-value
AI_ENABLED=false
```

```markdown
# docs/operations/secrets-rotation.md
1. Rotate Supabase or Postgres credentials.
2. Rotate Upstash Redis credentials.
3. Rotate Resend API credentials.
4. Rotate SMTP credentials if still used.
5. Rotate JWT signing secret.
6. Rotate AI-related tokens.
7. Revoke old tokens.
8. Remove secrets from git history using the team-approved process.
```

- [ ] **Step 4: Re-run the guard test**

Run: `go test ./internal/config -run TestTrackedEnvFilesContainNoLiveSecrets -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add .env.example .env.development .env.production .gitignore ENVIRONMENT.md docs/operations/secrets-rotation.md internal/config/env_contract_test.go
git commit -m "chore: remove tracked secrets and add env contract guard"
```

### Task 2: Normalize the Configuration Contract

**Files:**
- Create: `internal/config/config_test.go`
- Modify: `internal/config/config.go`
- Modify: `docker-compose.yml`
- Modify: `Makefile`
- Modify: `README.md`
- Modify: `QUICKSTART.md`
- Modify: `ENVIRONMENT.md`

- [ ] **Step 1: Write failing tests for canonical config loading**

```go
func TestLoadReadsCanonicalDatabaseURL(t *testing.T) {
    t.Setenv("DB_URL", "postgresql://postgres:admin@localhost:5432/healthcare_db?sslmode=disable")
    t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
    t.Setenv("ENVIRONMENT", "development")

    cfg, err := Load()
    require.NoError(t, err)
    assert.Equal(t, "postgresql://postgres:admin@localhost:5432/healthcare_db?sslmode=disable", cfg.DBURL)
}

func TestLoadRejectsProductionWildcardOrigins(t *testing.T) {
    t.Setenv("DB_URL", "postgresql://postgres:admin@localhost:5432/healthcare_db?sslmode=disable")
    t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
    t.Setenv("ENVIRONMENT", "production")
    t.Setenv("ALLOWED_ORIGINS", "*")

    _, err := Load()
    require.Error(t, err)
}
```

- [ ] **Step 2: Run targeted config tests**

Run: `go test ./internal/config -run 'TestLoadReadsCanonicalDatabaseURL|TestLoadRejectsProductionWildcardOrigins' -v`
Expected: FAIL until validation and docs are aligned.

- [ ] **Step 3: Make `DB_URL` the canonical contract and align Docker and docs with it**

```yaml
# docker-compose.yml
api:
  environment:
    DB_URL: postgresql://postgres:admin@postgres:5432/healthcare_db?sslmode=disable
    REDIS_URL: redis://redis:6379
    NATS_URL: nats://nats:4222
    SMTP_HOST: mailpit
    SMTP_PORT: 1025
```

```go
// internal/config/config.go
if c.IsProduction() && slices.Contains(c.AllowedOrigins, "*") {
    errors = append(errors, "ALLOWED_ORIGINS must not contain '*' in production")
}
```

- [ ] **Step 4: Re-run config tests and a full build**

Run: `go test ./internal/config -v && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go docker-compose.yml Makefile README.md QUICKSTART.md ENVIRONMENT.md
git commit -m "refactor: normalize runtime config contract"
```

### Task 3: Fix the Failing Repository Contract and Restore `go test`

**Files:**
- Modify: `internal/repository/core/user_repository.go`
- Modify: `internal/repository/core/user_repository_test.go`
- Test: `internal/repository/core/user_repository_test.go`

- [ ] **Step 1: Add a failing regression test for missing patient profile repository wiring**

```go
func TestUserRepository_GetUserProfile_WhenPatientRepoMissingDoesNotPanic(t *testing.T) {
    ctx := context.Background()
    userID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174000")
    mockQuerier := mocks.NewMockQuerier(t)

    mockQuerier.On("GetUserByID", ctx, uuidPgtypeFromString(userID.String())).Return(sqlc.GetUserByIDRow{
        ID: uuidPgtypeFromString(userID.String()),
        Email: "test@example.com",
        Role: "patient",
        CreatedAt: pgtype.Timestamp{Time: nowTime(), Valid: true},
        UpdatedAt: pgtype.Timestamp{Time: nowTime(), Valid: true},
    }, nil)

    repo := &userRepository{querier: mockQuerier}
    require.NotPanics(t, func() {
        _, _, _ = repo.GetUserProfile(ctx, userID)
    })
}
```

- [ ] **Step 2: Run the focused repository tests**

Run: `go test ./internal/repository/core -run TestUserRepository_GetUserProfile -v`
Expected: FAIL with the current nil-pointer panic.

- [ ] **Step 3: Make repository behavior explicit instead of panic-prone**

```go
func (r *userRepository) GetUserProfile(ctx context.Context, userID uuid.UUID) (core.User, patients.PatientProfile, error) {
    user, err := r.GetUserByID(ctx, userID)
    if err != nil {
        return core.User{}, patients.PatientProfile{}, err
    }

    if r.patientProfileRepo == nil {
        return user, patients.PatientProfile{}, nil
    }

    profile, err := r.patientProfileRepo.GetPatientProfileByUserID(ctx, userID)
    if errors.Is(err, domain.ErrNotFound) || errors.Is(err, domain.ErrPatientNotFound) {
        return user, patients.PatientProfile{}, nil
    }
    if err != nil {
        return core.User{}, patients.PatientProfile{}, fmt.Errorf("get patient profile: %w", err)
    }

    return user, profile, nil
}
```

- [ ] **Step 4: Re-run repository tests and full suite**

Run: `go test ./internal/repository/core -v && go test ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/repository/core/user_repository.go internal/repository/core/user_repository_test.go
git commit -m "test: fix user profile repository panic"
```

### Task 4: Wire Runtime Settings and Cleanup Correctly

**Files:**
- Create: `internal/app/app_test.go`
- Modify: `cmd/api/main.go`
- Modify: `internal/app/app.go`
- Modify: `internal/server/server.go`
- Test: `internal/app/app_test.go`

- [ ] **Step 1: Write failing tests for cleanup and timeout wiring**

```go
func TestBuildHTTPServerUsesConfiguredTimeouts(t *testing.T) {
    cfg := &config.Config{Port: ":8080", ReadTimeout: 11 * time.Second, WriteTimeout: 12 * time.Second, IdleTimeout: 13 * time.Second}
    srv := &Server{config: cfg}
    httpServer := srv.buildHTTPServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))

    require.Equal(t, 11*time.Second, httpServer.ReadTimeout)
    require.Equal(t, 12*time.Second, httpServer.WriteTimeout)
    require.Equal(t, 13*time.Second, httpServer.IdleTimeout)
}

func TestNewPoolConfigAppliesConfiguredLimits(t *testing.T) {
    cfg := &config.Config{
        DBMaxConns:        11,
        DBMinConns:        3,
        DBMaxConnLifetime: time.Hour,
        DBMaxConnIdleTime: 5 * time.Minute,
    }

    poolCfg, err := newPoolConfig("postgresql://postgres:admin@localhost:5432/healthcare_db?sslmode=disable", cfg)
    require.NoError(t, err)
    require.Equal(t, int32(11), poolCfg.MaxConns)
    require.Equal(t, int32(3), poolCfg.MinConns)
    require.Equal(t, time.Hour, poolCfg.MaxConnLifetime)
    require.Equal(t, 5*time.Minute, poolCfg.MaxConnIdleTime)
}
```

- [ ] **Step 2: Run targeted tests**

Run: `go test ./internal/app ./internal/server -run 'TestBuildHTTPServerUsesConfiguredTimeouts|TestNewPoolConfigAppliesConfiguredLimits' -v`
Expected: FAIL until lifecycle wiring is corrected.

- [ ] **Step 3: Apply runtime hardening**

```go
// cmd/api/main.go
application, err := app.New(cfg)
if err != nil {
    log.Fatal("Failed to initialize application:", err)
}
defer application.Cleanup()
```

```go
// internal/app/app.go
func newPoolConfig(dbURL string, cfg *config.Config) (*pgxpool.Config, error) {
    poolCfg, err := pgxpool.ParseConfig(dbURL)
    if err != nil {
        return nil, err
    }
    poolCfg.MaxConns = int32(cfg.DBMaxConns)
    poolCfg.MinConns = int32(cfg.DBMinConns)
    poolCfg.MaxConnLifetime = cfg.DBMaxConnLifetime
    poolCfg.MaxConnIdleTime = cfg.DBMaxConnIdleTime
    poolCfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
    return poolCfg, nil
}
```

```go
// internal/server/server.go
func (s *Server) buildHTTPServer(router http.Handler) *http.Server {
    return &http.Server{
        Addr:         s.config.Port,
        Handler:      router,
        ReadTimeout:  s.config.ReadTimeout,
        WriteTimeout: s.config.WriteTimeout,
        IdleTimeout:  s.config.IdleTimeout,
    }
}
```

- [ ] **Step 4: Re-run targeted tests and build**

Run: `go test ./internal/app ./internal/server -v && go build ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/api/main.go internal/app/app.go internal/app/app_test.go internal/server/server.go
git commit -m "refactor: wire runtime settings and cleanup"
```

### Task 5: Remove Hot-Path Debug Code and Harden Auth Policy

**Files:**
- Create: `internal/service/core/auth_service_test.go`
- Modify: `internal/app/app.go`
- Modify: `internal/handler/core/auth_handler.go`
- Modify: `internal/handler/appointments/appointments_handler.go`
- Modify: `internal/service/providers/staff_service.go`
- Modify: `internal/service/providers/clinic_service.go`
- Modify: `internal/service/core/consent_service.go`
- Modify: `internal/service/core/auth_service.go`
- Test: `internal/service/core/auth_service_test.go`

- [ ] **Step 1: Write failing tests for privileged role self-registration and configurable login throttling**

```go
func newAuthServiceForTest(t *testing.T, maxAttempts int, lockout time.Duration) *authService {
    t.Helper()
    logger := zerolog.New(io.Discard)
    return &authService{
        logger:           &logger,
        jwtSecret:        strings.Repeat("x", 32),
        jwtExpiry:        time.Hour,
        bcryptCost:       bcrypt.MinCost,
        loginAttempts:    make(map[string]loginAttempt),
        loginMaxAttempts: maxAttempts,
        loginLockout:     lockout,
    }
}

func TestRegisterRejectsPrivilegedSelfSelection(t *testing.T) {
    svc := newAuthServiceForTest(t, 5, 5*time.Minute)
    _, err := svc.Register(context.Background(), "admin@example.com", "", "StrongPass123!", "system_admin")
    require.Error(t, err)
}

func TestRecordFailedLoginUsesConfiguredThresholds(t *testing.T) {
    svc := newAuthServiceForTest(t, 3, 2*time.Minute)
    svc.recordFailedLogin("user@example.com")
    svc.recordFailedLogin("user@example.com")
    svc.recordFailedLogin("user@example.com")
    assert.True(t, svc.isLoginLocked("user@example.com"))
}
```

- [ ] **Step 2: Run targeted auth tests**

Run: `go test ./internal/service/core -run 'TestRegisterRejectsPrivilegedSelfSelection|TestRecordFailedLoginUsesConfiguredThresholds' -v`
Expected: FAIL until auth policy is explicit and configurable.

- [ ] **Step 3: Remove debug prints and implement policy-backed auth behavior**

```go
type authService struct {
    loginMaxAttempts int
    loginLockout     time.Duration
}

// internal/app/app.go
authService := servicecore.NewAuthService(
    authRepo,
    userRepo,
    otpRepo,
    patientRepo,
    sessionService,
    consentRepo,
    staffService,
    cacheService,
    broker,
    emailService,
    logger,
    cfg.JWTSecret,
    cfg.JWTExpiry,
    cfg.SMSEnabled,
    cfg.BcryptCost,
    cfg.LoginMaxAttempts,
    time.Duration(cfg.LoginLockoutMins)*time.Minute,
)
```

```go
// Replace fmt.Println calls with structured logs or delete them outright.
h.logger.Debug().Str("ip_address", ipAddress).Msg("login completed")
```

- [ ] **Step 3a: Apply configurable login policy**

```go
// internal/service/core/auth_service.go
validRoles := map[string]bool{
    "patient": true,
    "caregiver": true,
    "provider_staff": true,
    "clinic_admin": true,
}
if role == "system_admin" || role == "ngo_partner" {
    return core.User{}, domain.NewAppError(domain.ErrForbidden, "Privileged roles require invitation or admin action", 403)
}

if attempt.attempts >= s.loginMaxAttempts {
    lockedUntil := time.Now().Add(s.loginLockout)
    attempt.lockedUntil = &lockedUntil
}
```

- [ ] **Step 4: Re-run auth tests and full suite**

Run: `go test ./internal/service/core -v && go test ./...`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/app/app.go internal/handler/core/auth_handler.go internal/handler/appointments/appointments_handler.go internal/service/providers/staff_service.go internal/service/providers/clinic_service.go internal/service/core/consent_service.go internal/service/core/auth_service.go internal/service/core/auth_service_test.go
git commit -m "fix: remove debug code and harden auth policy"
```

### Task 6: Add CI and Documentation Gates

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `docs/operations/release-checklist.md`
- Modify: `Makefile`
- Modify: `README.md`
- Modify: `QUICKSTART.md`

- [ ] **Step 1: Add a failing CI dry-run target locally**

```bash
make check
```

Expected: FAIL until the repository passes build, vet, and tests consistently.

- [ ] **Step 2: Create the CI workflow**

```yaml
name: ci
on:
  pull_request:
  push:
    branches: [develop, main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod
      - run: go mod download
      - run: go build ./...
      - run: go vet ./...
      - run: go test ./...
```

- [ ] **Step 3: Add a release checklist and align docs with the real commands**

```markdown
# Release Checklist
1. Secret rotation status verified.
2. Build, vet, tests, and lint all green.
3. Migration plan reviewed.
4. Smoke environment validated.
5. Rollback steps prepared.
```

- [ ] **Step 4: Validate the repository with the documented command set**

Run: `go build ./... && go vet ./... && go test ./... && make check`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ci.yml docs/operations/release-checklist.md Makefile README.md QUICKSTART.md
git commit -m "chore: add ci and release gates"
```

## Self-Review

### Spec Coverage

- Secret containment: covered by Task 1.
- Config normalization and environment parity: covered by Task 2.
- Failing tests and stabilization: covered by Task 3.
- Runtime wiring and cleanup: covered by Task 4.
- Security and auth hot-path cleanup: covered by Task 5.
- Delivery governance: covered by Task 6.

### Placeholder Scan

No `TODO`, `TBD`, or deferred "implement later" instructions are used as plan steps. Each task identifies concrete files, commands, and expected outcomes.

### Type Consistency

The plan consistently treats `DB_URL` as the canonical database contract, keeps `Config` as the source of runtime settings, and limits the first wave to containment and stabilization rather than broad architectural rewrite.
