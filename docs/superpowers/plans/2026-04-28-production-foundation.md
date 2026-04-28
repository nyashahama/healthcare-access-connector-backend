# Production Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the backend foundation so production startup, readiness, migrations, Docker health checks, and release verification are explicit, testable, and aligned with the target production system design.

**Architecture:** Keep the current Go modular monolith and improve only the production foundation layer. This plan touches configuration validation, health/readiness behavior, Docker/Compose health checks, migration validation, smoke checks, and operations docs without changing domain behavior.

**Tech Stack:** Go, chi, pgxpool, Redis, NATS, Docker, Docker Compose, golang-migrate, Bash, Make.

---

## Scope

This is plan 1 of the target production system design. It intentionally does not implement the later security/compliance, async outbox, telemedicine scaling, or observability plans.

This plan implements:

- Production configuration contract hardening.
- Correct optional dependency semantics for NATS, Redis, email, AI, and WebSocket checks.
- Readiness that gates traffic only on critical dependencies.
- Docker health checks that use `/ready`, not `/health`.
- Migration validation that catches missing and empty down migrations.
- A local foundation verification target.
- Smoke tests that can target a full URL or port.
- Operations documentation updates for the foundation release gate.

## File Structure

Modify:

- `internal/config/config.go`: enforce stricter production startup rules, support explicit optional dependency disabling, and validate email provider names.
- `internal/config/config_test.go`: add targeted tests for production foundation validation.
- `internal/handler/health_handler.go`: return structured health/readiness responses and separate critical from optional dependency checks.
- `internal/handler/health_handler_test.go`: create focused health/readiness tests with fakes.
- `Dockerfile`: change container health check to `/ready`.
- `docker-compose.yml`: change API health check to `/ready` and align local env defaults.
- `Makefile`: add `foundation-check` and migration validation targets.
- `scripts/ci/migration-check.sh`: fail on missing down migrations and empty down migrations unless explicitly allowlisted.
- `tests/smoke/smoke.sh`: accept a full base URL, verify health JSON, and preserve port-only compatibility.
- `docs/operations/config-contract.md`: document new optional dependency and production validation semantics.
- `docs/operations/deploy.md`: document the foundation release gate.
- `docs/operations/go-live-checklist.md`: add the foundation gate.

Create:

- `internal/handler/health_handler_test.go`: focused unit tests for health/readiness responses.
- `scripts/ci/empty-down-allowlist.txt`: temporary allowlist for already-existing empty down migrations.

Do not modify:

- Domain services or repositories.
- Existing database schema unless a later plan requires it.
- User `.env.*` values beyond documented example-value contract changes.

---

## Task 1: Harden Configuration Contract

**Files:**

- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `docs/operations/config-contract.md`

- [ ] **Step 1: Write failing config tests**

Add these tests to `internal/config/config_test.go`:

```go
func TestLoadAllowsExplicitNATSDisable(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("NATS_URL", "disabled")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Empty(t, cfg.NatsURL)
}

func TestLoadRejectsInvalidEmailProvider(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=disable")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("EMAIL_PROVIDER", "mailgun")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EMAIL_PROVIDER must be one of")
}

func TestLoadRejectsProductionWithoutEmailProvider(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@localhost:5432/healthcare_db?sslmode=require")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.com")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "EMAIL_PROVIDER is required in production")
}

func TestLoadRejectsProductionRedisWithoutTLSOrExplicitException(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@db.example.com:5432/healthcare_db?sslmode=require")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.com")
	t.Setenv("EMAIL_PROVIDER", "resend")
	t.Setenv("EMAIL_FROM_ADDRESS", "no-reply@example.com")
	t.Setenv("REDIS_URL", "redis://redis.example.com:6379")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "REDIS_URL must use rediss:// in production")
}

func TestLoadAllowsProductionRedisTLS(t *testing.T) {
	t.Setenv("DB_URL", "postgresql://postgres:replace_me@db.example.com:5432/healthcare_db?sslmode=require")
	t.Setenv("JWT_SECRET", strings.Repeat("x", 32))
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("ALLOWED_ORIGINS", "https://app.example.com")
	t.Setenv("EMAIL_PROVIDER", "resend")
	t.Setenv("EMAIL_FROM_ADDRESS", "no-reply@example.com")
	t.Setenv("REDIS_URL", "rediss://redis.example.com:6379")

	cfg, err := Load()
	require.NoError(t, err)
	assert.Equal(t, "rediss://redis.example.com:6379", cfg.RedisURL)
}
```

- [ ] **Step 2: Run config tests and verify failure**

Run:

```bash
go test ./internal/config -run 'TestLoadAllowsExplicitNATSDisable|TestLoadRejectsInvalidEmailProvider|TestLoadRejectsProductionWithoutEmailProvider|TestLoadRejectsProductionRedisWithoutTLSOrExplicitException|TestLoadAllowsProductionRedisTLS' -v
```

Expected:

- `TestLoadAllowsExplicitNATSDisable` fails because `NATS_URL=disabled` is not mapped to an empty runtime value.
- Invalid email provider and production email provider tests fail because validation is missing.
- Production Redis TLS validation fails because `redis://` is currently accepted.

- [ ] **Step 3: Implement config hardening**

In `internal/config/config.go`, add this helper near `getEnv`:

```go
func getOptionalServiceURL(key, defaultValue string) string {
	value, ok := os.LookupEnv(key)
	if !ok {
		return defaultValue
	}

	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.EqualFold(trimmed, "disabled") || strings.EqualFold(trimmed, "none") {
		return ""
	}

	return trimmed
}
```

Change `NatsURL` loading inside `Load()` from:

```go
NatsURL:        getEnv("NATS_URL", "nats://localhost:4222"),
```

to:

```go
NatsURL:        getOptionalServiceURL("NATS_URL", "nats://localhost:4222"),
```

In `Validate()`, add email provider validation after the rate limit checks:

```go
validEmailProviders := map[string]bool{
	"":       true,
	"smtp":   true,
	"resend": true,
	"ses":    true,
	"mock":   true,
}
if !validEmailProviders[c.EmailProvider] {
	errors = append(errors, "EMAIL_PROVIDER must be one of: smtp, resend, ses, mock")
}
```

Replace the existing production hardening block with:

```go
if c.IsProduction() {
	if strings.Contains(c.DBURL, "sslmode=disable") || !strings.Contains(c.DBURL, "sslmode=require") {
		errors = append(errors, "DB_URL must use sslmode=require in production")
	}

	if slices.Contains(c.AllowedOrigins, "*") {
		errors = append(errors, "ALLOWED_ORIGINS must not contain '*' in production")
	}

	if c.EmailProvider == "" {
		errors = append(errors, "EMAIL_PROVIDER is required in production")
	}

	if c.EmailProvider == "smtp" {
		if c.SMTPHost == "" {
			errors = append(errors, "SMTP_HOST is required when EMAIL_PROVIDER=smtp in production")
		}
		if c.EmailFromAddress == "" {
			errors = append(errors, "EMAIL_FROM_ADDRESS is required when EMAIL_PROVIDER=smtp in production")
		}
	}

	if c.EmailProvider == "resend" || c.EmailProvider == "ses" {
		if c.EmailFromAddress == "" {
			errors = append(errors, fmt.Sprintf("EMAIL_FROM_ADDRESS is required when EMAIL_PROVIDER=%s in production", c.EmailProvider))
		}
	}

	if c.RedisURL != "" && strings.HasPrefix(c.RedisURL, "redis://") && os.Getenv("ALLOW_INSECURE_REDIS_IN_PRODUCTION") != "true" {
		errors = append(errors, "REDIS_URL must use rediss:// in production unless ALLOW_INSECURE_REDIS_IN_PRODUCTION=true")
	}
}
```

Keep the existing `Load()` production wildcard validation if desired, but avoid duplicate error messages by moving the check into `Validate()` or leaving one place only.

- [ ] **Step 4: Update config contract docs**

In `docs/operations/config-contract.md`, update the NATS row to:

```markdown
| `NATS_URL` | `nats://localhost:4222` | NATS connection URL. Set to `disabled`, `none`, or an empty value to disable async messaging explicitly. |
```

Add this Redis production rule under Redis variables:

```markdown
Production rule: `REDIS_URL` must use `rediss://` unless `ALLOW_INSECURE_REDIS_IN_PRODUCTION=true` is set for a documented private-network exception.
```

Update production startup rules to:

```markdown
1. `DB_URL` must contain `sslmode=require`.
2. `ALLOWED_ORIGINS` must not contain `*`.
3. `EMAIL_PROVIDER` must be set to `smtp`, `resend`, `ses`, or `mock`.
4. If `EMAIL_PROVIDER=smtp`, `SMTP_HOST` and `EMAIL_FROM_ADDRESS` must be set.
5. If `EMAIL_PROVIDER=resend` or `EMAIL_PROVIDER=ses`, `EMAIL_FROM_ADDRESS` must be set.
6. `REDIS_URL` must use `rediss://` unless `ALLOW_INSECURE_REDIS_IN_PRODUCTION=true` is explicitly set.
```

- [ ] **Step 5: Run config tests**

Run:

```bash
go test ./internal/config -v
```

Expected:

- All tests pass.

- [ ] **Step 6: Commit**

Run:

```bash
git add internal/config/config.go internal/config/config_test.go docs/operations/config-contract.md
git commit -m "feat: harden production configuration contract"
```

---

## Task 2: Structure Health and Readiness Responses

**Files:**

- Modify: `internal/handler/health_handler.go`
- Create: `internal/handler/health_handler_test.go`

- [ ] **Step 1: Write failing health handler tests**

Create `internal/handler/health_handler_test.go` with:

```go
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakePinger struct {
	err error
}

func (f fakePinger) Ping(context.Context) error {
	return f.err
}

func TestReadinessReturnsJSONReadyWhenCriticalDependenciesPass(t *testing.T) {
	h := &HealthHandler{
		db: fakePinger{},
	}

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	h.Readiness(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body HealthResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "ready", body.Status)
	require.Equal(t, "healthy", body.Services["database"])
}

func TestReadinessReturnsJSONNotReadyWhenDatabaseFails(t *testing.T) {
	h := &HealthHandler{
		db: fakePinger{err: errors.New("db down")},
	}

	req := httptest.NewRequest(http.MethodGet, "/ready", nil)
	rec := httptest.NewRecorder()

	h.Readiness(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var body HealthResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "not_ready", body.Status)
	require.Contains(t, body.Services["database"], "unhealthy")
}

func TestHealthTreatsOptionalDependencyFailureAsDegraded(t *testing.T) {
	h := &HealthHandler{
		db:    fakePinger{},
		cache: fakeCache{err: errors.New("redis down")},
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.Health(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)

	var body HealthResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "degraded", body.Status)
	require.Equal(t, "degraded", body.Services["cache"])
	require.Equal(t, "healthy", body.Services["database"])
}

func TestHealthReturnsUnhealthyWhenDatabaseFails(t *testing.T) {
	h := &HealthHandler{
		db: fakePinger{err: errors.New("db down")},
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	h.Health(rec, req)

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)

	var body HealthResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "unhealthy", body.Status)
	require.Contains(t, body.Services["database"], "unhealthy")
}
```

If `fakeCache` does not already exist in the package, add this test fake to the same file and adjust method signatures to match `cache.Service`:

```go
type fakeCache struct {
	err error
}

func (f fakeCache) Get(context.Context, string) (string, error) {
	return "", errors.New("not implemented in test")
}

func (f fakeCache) Set(context.Context, string, interface{}, time.Duration) error {
	return errors.New("not implemented in test")
}

func (f fakeCache) Delete(context.Context, string) error {
	return errors.New("not implemented in test")
}

func (f fakeCache) Exists(context.Context, string) (bool, error) {
	return false, errors.New("not implemented in test")
}

func (f fakeCache) Ping(context.Context) error {
	return f.err
}
```

Add `time` to imports if `fakeCache` requires it.

- [ ] **Step 2: Run health tests and verify failure**

Run:

```bash
go test ./internal/handler -run 'TestReadiness|TestHealth' -v
```

Expected:

- Tests fail because `HealthHandler` currently stores `pool *pgxpool.Pool`, readiness has no JSON response, and optional dependency degradation is not reflected as top-level `degraded`.

- [ ] **Step 3: Introduce pinger abstraction and structured status**

In `internal/handler/health_handler.go`, add:

```go
type dependencyPinger interface {
	Ping(context.Context) error
}
```

Change the `HealthHandler` struct from:

```go
pool         *pgxpool.Pool
```

to:

```go
db           dependencyPinger
```

Keep `pgxpool` import because the constructor still accepts `*pgxpool.Pool`.

Change `NewHealthHandler` assignment from:

```go
pool: pool,
```

to:

```go
db: pool,
```

Change all references from `h.pool.Ping(ctx)` to `h.db.Ping(ctx)`.

Add this helper at the bottom of the file:

```go
func writeHealthJSON(w http.ResponseWriter, statusCode int, response HealthResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(response)
}
```

- [ ] **Step 4: Update `Health` status behavior**

Replace the status selection in `Health` with:

```go
status := "healthy"
statusCode := http.StatusOK
if !allHealthy {
	status = "unhealthy"
	statusCode = http.StatusServiceUnavailable
} else {
	for _, serviceStatus := range services {
		if serviceStatus == "degraded" || serviceStatus == "disabled" || serviceStatus == "unavailable" {
			status = "degraded"
			break
		}
	}
}
```

Replace the direct JSON write block with:

```go
writeHealthJSON(w, statusCode, response)
```

- [ ] **Step 5: Update `Readiness` to return JSON**

Replace `Readiness` with:

```go
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	services := map[string]string{}
	status := "ready"
	statusCode := http.StatusOK

	if err := h.db.Ping(ctx); err != nil {
		services["database"] = "unhealthy: " + err.Error()
		status = "not_ready"
		statusCode = http.StatusServiceUnavailable
	} else {
		services["database"] = "healthy"
	}

	response := HealthResponse{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Services:  services,
		Version:   version.Version + " (" + version.Commit + ")",
	}

	writeHealthJSON(w, statusCode, response)
}
```

- [ ] **Step 6: Run health tests**

Run:

```bash
go test ./internal/handler -run 'TestReadiness|TestHealth' -v
```

Expected:

- All health/readiness tests pass.

- [ ] **Step 7: Run broader handler tests**

Run:

```bash
go test ./internal/handler/... -v
```

Expected:

- All handler package tests pass.

- [ ] **Step 8: Commit**

Run:

```bash
git add internal/handler/health_handler.go internal/handler/health_handler_test.go
git commit -m "feat: structure health and readiness probes"
```

---

## Task 3: Use Readiness for Container Health Checks

**Files:**

- Modify: `Dockerfile`
- Modify: `docker-compose.yml`

- [ ] **Step 1: Change Dockerfile health check**

In `Dockerfile`, replace:

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1
```

with:

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ready || exit 1
```

- [ ] **Step 2: Change Compose API health check**

In `docker-compose.yml`, replace the API healthcheck URL:

```yaml
test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
```

with:

```yaml
test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/ready"]
```

- [ ] **Step 3: Validate Dockerfile syntax**

Run:

```bash
docker build --target builder -t hac-api-foundation-builder .
```

Expected:

- Docker build reaches the builder target successfully.

- [ ] **Step 4: Validate Compose syntax**

Run:

```bash
docker compose config
```

Expected:

- Compose renders valid configuration.
- API health check points to `/ready`.

- [ ] **Step 5: Commit**

Run:

```bash
git add Dockerfile docker-compose.yml
git commit -m "chore: use readiness probe for container health"
```

---

## Task 4: Harden Migration Validation

**Files:**

- Modify: `scripts/ci/migration-check.sh`
- Create: `scripts/ci/empty-down-allowlist.txt`
- Modify: `docs/operations/migrations.md`

- [ ] **Step 1: Add the existing empty-down allowlist**

Create `scripts/ci/empty-down-allowlist.txt` with one migration path per line for existing empty down migrations only. Generate the initial list with:

```bash
find database/migrations -name '*.down.sql' -size 0 -print | sort > scripts/ci/empty-down-allowlist.txt
```

Expected:

- The file contains only existing empty down migrations.
- New empty down migrations will fail unless explicitly added to the allowlist in review.

- [ ] **Step 2: Add migration structure checks**

In `scripts/ci/migration-check.sh`, after `MIGRATIONS_DIR="database/migrations"`, add:

```bash
ALLOWLIST_FILE="scripts/ci/empty-down-allowlist.txt"
```

After the migration count check, add:

```bash
echo ""
echo "1b. Validate up/down migration pairs"
missing_down=0
while IFS= read -r up_file; do
	down_file="${up_file%.up.sql}.down.sql"
	if [ ! -f "${down_file}" ]; then
		echo "Error: Missing down migration for ${up_file}"
		missing_down=1
	fi
done < <(find "${MIGRATIONS_DIR}" -name '*.up.sql' | sort -V)

if [ "${missing_down}" -ne 0 ]; then
	exit 1
fi
echo "  [PASS] Every up migration has a down migration"

echo ""
echo "1c. Validate empty down migrations are allowlisted"
empty_down_error=0
while IFS= read -r down_file; do
	if [ ! -s "${down_file}" ]; then
		if [ ! -f "${ALLOWLIST_FILE}" ] || ! grep -Fxq "${down_file}" "${ALLOWLIST_FILE}"; then
			echo "Error: Empty down migration is not allowlisted: ${down_file}"
			empty_down_error=1
		fi
	fi
done < <(find "${MIGRATIONS_DIR}" -name '*.down.sql' | sort -V)

if [ "${empty_down_error}" -ne 0 ]; then
	exit 1
fi
echo "  [PASS] Empty down migrations are explicitly allowlisted"
```

- [ ] **Step 3: Update down-roundtrip skip logic**

Replace:

```bash
if [ ! -s "${latest_down}" ]; then
	echo "  [SKIP] Latest down migration (${latest_down}) is empty — skipping down/up round-trip test"
else
```

with:

```bash
if [ ! -s "${latest_down}" ]; then
	if [ -f "${ALLOWLIST_FILE}" ] && grep -Fxq "${latest_down}" "${ALLOWLIST_FILE}"; then
		echo "  [SKIP] Latest down migration (${latest_down}) is empty and allowlisted"
	else
		echo "Error: Latest down migration (${latest_down}) is empty and not allowlisted"
		exit 1
	fi
else
```

- [ ] **Step 4: Update migration docs**

In `docs/operations/migrations.md`, add this section under "Migration Rules":

```markdown
### Empty Down Migration Policy

Existing empty down migrations are tracked in `scripts/ci/empty-down-allowlist.txt`.
New migrations must include a real down migration unless the data owner approves an explicit irreversible migration.
If a migration is irreversible, the down file must contain a SQL comment explaining why and the migration must be added to the allowlist in the same review.
```

- [ ] **Step 5: Run shell syntax check**

Run:

```bash
bash -n scripts/ci/migration-check.sh
```

Expected:

- No syntax errors.

- [ ] **Step 6: Run migration pair check without DB**

Run:

```bash
./scripts/ci/migration-check.sh
```

Expected:

- Fails fast with `Error: DB_URL is required`.
- This confirms the script still validates invocation before DB work.

- [ ] **Step 7: Run full migration check with a test DB**

Start a disposable database:

```bash
docker run -d --name hac-migration-check -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16-alpine
```

Run:

```bash
DB_URL="postgres://postgres:postgres@localhost:5433/postgres?sslmode=disable"
./scripts/ci/migration-check.sh "$DB_URL"
```

Expected:

- Migration structure checks pass.
- Fresh migration check passes.
- Down/up round-trip either passes or skips only when the latest empty down migration is allowlisted.

Cleanup:

```bash
docker stop hac-migration-check
docker rm hac-migration-check
```

- [ ] **Step 8: Commit**

Run:

```bash
git add scripts/ci/migration-check.sh scripts/ci/empty-down-allowlist.txt docs/operations/migrations.md
git commit -m "chore: harden migration validation"
```

---

## Task 5: Add Foundation Verification Make Target

**Files:**

- Modify: `Makefile`
- Modify: `docs/operations/deploy.md`

- [ ] **Step 1: Add Make targets**

In `Makefile`, add `foundation-check` to `.PHONY`:

```make
.PHONY: help dev prod docker-up docker-down docker-logs db-migrate db-seed test test-smoke clean build run sqlc mocks generate foundation-check migration-check
```

After the existing `check` target, add:

```make
foundation-check: build vet
	@echo "${GREEN}Running production foundation checks...${RESET}"
	go test ./internal/config ./internal/handler ./internal/server -v
	bash -n scripts/ci/migration-check.sh
	@echo "${GREEN}✓ Production foundation checks passed!${RESET}"

migration-check:
	@if [ -z "$(DB_URL)" ]; then \
		echo "${YELLOW}Error: DB_URL is required. Usage: make migration-check DB_URL=\"postgres://...\"${RESET}"; \
		exit 1; \
	fi
	./scripts/ci/migration-check.sh "$(DB_URL)"
```

- [ ] **Step 2: Update help output**

In the "Testing" section of `help`, add:

```make
	@echo "  make foundation-check - Run production foundation checks"
	@echo "  make migration-check  - Validate migrations with DB_URL"
```

- [ ] **Step 3: Update deploy docs**

In `docs/operations/deploy.md`, under prerequisites, add:

```markdown
- [ ] `make foundation-check` passes locally or in CI.
```

Under "Prepare the Release", add:

```bash
make foundation-check
```

- [ ] **Step 4: Run Make target**

Run:

```bash
make foundation-check
```

Expected:

- Build succeeds.
- `go vet` succeeds.
- Config, handler, and server tests pass.
- `bash -n scripts/ci/migration-check.sh` succeeds.

- [ ] **Step 5: Commit**

Run:

```bash
git add Makefile docs/operations/deploy.md
git commit -m "chore: add production foundation check"
```

---

## Task 6: Improve Smoke Test Targeting

**Files:**

- Modify: `tests/smoke/smoke.sh`
- Modify: `docs/operations/deploy.md`

- [ ] **Step 1: Update smoke script target parsing**

In `tests/smoke/smoke.sh`, replace:

```bash
PORT="${1:-8080}"
BASE_URL="http://localhost:${PORT}"
TIMEOUT=30
```

with:

```bash
TARGET="${1:-8080}"
TIMEOUT=30

if [[ "${TARGET}" =~ ^https?:// ]]; then
	BASE_URL="${TARGET%/}"
else
	BASE_URL="http://localhost:${TARGET}"
fi
```

- [ ] **Step 2: Add JSON health assertion**

After the `http_get` helper, add:

```bash
assert_health_json() {
	local url="$1"
	local body
	body=$(curl -s --max-time "${TIMEOUT}" "${url}" || true)

	if command -v jq >/dev/null 2>&1; then
		local status
		status=$(printf '%s' "${body}" | jq -r '.status // empty')
		if [ "${status}" != "healthy" ] && [ "${status}" != "degraded" ]; then
			echo "  [FAIL] /health JSON status expected healthy or degraded, got '${status}'"
			return 1
		fi
		echo "  [PASS] /health JSON status is ${status}"
	else
		if [[ "${body}" != *'"status"'* ]]; then
			echo "  [FAIL] /health response did not include status field"
			return 1
		fi
		echo "  [PASS] /health JSON includes status field"
	fi
}
```

After:

```bash
http_get "${BASE_URL}/health" "200" "GET /health"
```

add:

```bash
assert_health_json "${BASE_URL}/health"
```

- [ ] **Step 3: Update usage comment**

Replace:

```bash
# Usage: ./tests/smoke/smoke.sh [PORT]
```

with:

```bash
# Usage: ./tests/smoke/smoke.sh [PORT_OR_BASE_URL]
# Examples:
#   ./tests/smoke/smoke.sh 8080
#   ./tests/smoke/smoke.sh https://api.example.com
```

- [ ] **Step 4: Update deploy docs**

In `docs/operations/deploy.md`, replace:

```bash
./tests/smoke/smoke.sh 8080
```

with:

```bash
./tests/smoke/smoke.sh https://api.example.com
```

Add:

```markdown
For local verification, use `./tests/smoke/smoke.sh 8080`.
```

- [ ] **Step 5: Run shell syntax check**

Run:

```bash
bash -n tests/smoke/smoke.sh
```

Expected:

- No syntax errors.

- [ ] **Step 6: Run smoke script against a non-running port**

Run:

```bash
./tests/smoke/smoke.sh 65535
```

Expected:

- Fails at `/health` with an HTTP status of `000`.
- This confirms the script still fails closed when the service is unavailable.

- [ ] **Step 7: Commit**

Run:

```bash
git add tests/smoke/smoke.sh docs/operations/deploy.md
git commit -m "chore: improve smoke test targeting"
```

---

## Task 7: Update Go-Live Foundation Gate

**Files:**

- Modify: `docs/operations/go-live-checklist.md`
- Modify: `docs/operations/deploy.md`

- [ ] **Step 1: Update go-live checklist**

In `docs/operations/go-live-checklist.md`, under "Pre-Launch (T-7 Days)", add:

```markdown
- [ ] Production foundation gate passes: `make foundation-check`.
- [ ] Container health check uses `/ready`, not `/health`.
- [ ] `/health` may report `degraded` for optional dependencies without removing the instance from service.
- [ ] `/ready` returns `200` only when critical dependencies required for serving traffic are available.
```

- [ ] **Step 2: Add deploy verification note**

In `docs/operations/deploy.md`, under "Post-Deploy Verification", add:

```markdown
`/ready` is the traffic gate. `/health` is the diagnostic endpoint and may return `degraded` while optional services recover.
```

- [ ] **Step 3: Run markdown grep sanity check**

Run:

```bash
rg -n "/ready|foundation-check|degraded" docs/operations/go-live-checklist.md docs/operations/deploy.md
```

Expected:

- Output includes the new foundation gate references in both files.

- [ ] **Step 4: Commit**

Run:

```bash
git add docs/operations/go-live-checklist.md docs/operations/deploy.md
git commit -m "docs: add production foundation gate"
```

---

## Task 8: Final Verification

**Files:**

- Verify all files changed in Tasks 1-7.

- [ ] **Step 1: Run formatting**

Run:

```bash
gofmt -w internal/config/config.go internal/config/config_test.go internal/handler/health_handler.go internal/handler/health_handler_test.go
```

Expected:

- Files are formatted.

- [ ] **Step 2: Run targeted tests**

Run:

```bash
go test ./internal/config ./internal/handler ./internal/server -v
```

Expected:

- All targeted foundation tests pass.

- [ ] **Step 3: Run foundation check**

Run:

```bash
make foundation-check
```

Expected:

- Build, vet, targeted tests, and shell syntax checks pass.

- [ ] **Step 4: Run full unit suite if time permits**

Run:

```bash
go test ./...
```

Expected:

- All tests pass.
- If integration tests require unavailable external services, record the exact failing package and rerun the targeted foundation checks before handoff.

- [ ] **Step 5: Review worktree**

Run:

```bash
git status --short
```

Expected:

- Only intentional files from this plan are modified.
- Existing unrelated dirty files from before the plan remain untouched unless they were explicitly part of a task.

- [ ] **Step 6: Final commit if needed**

If formatting or final verification changed files after prior commits, run:

```bash
git add internal/config/config.go internal/config/config_test.go internal/handler/health_handler.go internal/handler/health_handler_test.go Dockerfile docker-compose.yml Makefile scripts/ci/migration-check.sh scripts/ci/empty-down-allowlist.txt tests/smoke/smoke.sh docs/operations/config-contract.md docs/operations/migrations.md docs/operations/deploy.md docs/operations/go-live-checklist.md
git commit -m "chore: finalize production foundation hardening"
```

Expected:

- Commit is created only if there are remaining staged changes.

---

## Self-Review Notes

Spec coverage:

- Requirements and scope: covered through production foundation gate and deploy docs.
- Non-functional requirements: covered for startup validation, readiness, migration validation, health checks, and verification.
- Infrastructure: covered through Dockerfile, Compose, Make, deploy docs, and go-live checklist.
- Observability/security foundations: covered only at the foundation level through health/readiness and production config validation.

Intentional gaps for later plans:

- Security and Compliance Plan: detailed RBAC, PHI redaction, consent/export/deletion workflows.
- Async Reliability Plan: outbox, event contracts, retry and dead-letter handling.
- Telemedicine Production Plan: WebSocket backplane, signed attachments, polling fallback.
- Observability Plan: OpenTelemetry, dashboards, alert rules, SLO instrumentation.

Red-flag wording scan:

- This plan has no unresolved marker steps.
- Later subsystem work is explicitly separated into named future plans, not left as ambiguous work inside this plan.

Type consistency:

- The health handler plan introduces a `dependencyPinger` interface and uses `db` consistently.
- Test fake names match the planned struct field names.
- Config helper `getOptionalServiceURL` is defined before use.
