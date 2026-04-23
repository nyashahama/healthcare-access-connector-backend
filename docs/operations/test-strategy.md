# Test Strategy

This document defines the test pyramid and coverage expectations for the Healthcare Access Connector backend.

## Test Pyramid

```
        /
       /  \      E2E / Smoke tests (few)
      /    \
     /------\    Integration tests (some)
    /        \
   /----------\  Unit tests (many)
  /------------\
```

## Unit Tests

### Coverage Targets

| Package Category | Minimum Coverage | Notes |
|------------------|------------------|-------|
| `internal/config` | 90% | Config loading and validation |
| `internal/middleware` | 85% | Auth, CORS, rate limit, logging |
| `internal/service/core` | 80% | Auth, user, session, consent |
| `internal/handler/core` | 70% | Auth handlers |
| `internal/service/*` | 60% | Provider, appointment, telemedicine |
| `internal/repository/*` | 50% | Repository contracts (sqlc-generated) |

### Running Unit Tests

```bash
make test-unit
# or
go test -v -short ./...
```

## Integration Tests

Integration tests boot the application against real (but disposable) dependencies.

### Requirements

- PostgreSQL 16+
- Redis 7+
- NATS 2 (optional)

### Running Integration Tests

```bash
make test-integration
# or
go test -v -tags=integration ./tests/integration/...
```

### Integration Test Scope

- App startup with valid config
- Health/readiness endpoints against real database
- Auth flow: register -> login -> refresh -> logout
- Appointment lifecycle: create -> confirm -> complete

## Smoke Tests

Smoke tests verify the deployed binary or container through HTTP.

### Running Smoke Tests

```bash
# Start the app, then run:
./tests/smoke/smoke.sh 8080
```

### Smoke Test Scope

- `/health`, `/ready`, `/live` respond correctly
- `/metrics` is accessible (if enabled)
- Key endpoints return expected status codes
- 404 handler works

## CI Integration

All test levels run in CI:

1. **Fast checks** (every PR): build, vet, unit tests
2. **Generated code drift** (every PR): sqlc, mocks
3. **Docker build** (every PR): image builds successfully
4. **Migration validation** (every PR): migrations on fresh DB
5. **Smoke tests** (on `main` and tags): against staging

## Coverage Reporting

```bash
make test-coverage
```

This generates `coverage.html` with per-package coverage.

## Test Data

- Use fixtures for repository tests.
- Use random/generated data for handler tests to avoid brittle assertions.
- Never use production data in tests.

## Test Environment Variables

Integration tests read from `.env.test` or environment variables:

```bash
TEST_DB_URL=postgres://postgres:postgres@localhost:5433/test_db?sslmode=disable
TEST_REDIS_URL=redis://localhost:6380
```

## Adding Tests

1. Follow the existing test patterns in each package.
2. Use `testify/assert` and `testify/require`.
3. Mock external dependencies; test real database interactions in integration tests.
4. Name tests descriptively: `Test<Method><Scenario>`.

## Test Ownership

- **Unit tests:** Feature developer
- **Integration tests:** Application owner
- **Smoke tests:** Ops owner
- **CI configuration:** Platform owner
