# Production Readiness Master Plan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the Healthcare Access Connector backend into a production-ready system with truthful build signals, safe runtime behavior, secure operations, repeatable delivery, and documented ownership across application, data, infrastructure, and support workflows.

**Architecture:** Keep the existing Go `handler -> service -> repository -> sqlc` structure, but harden the operating model before doing broad refactors. The system already builds, vets, and tests on April 22, 2026, so the program should focus on closing the production gap between "code compiles" and "service can be safely deployed, operated, audited, and recovered".

**Tech Stack:** Go 1.24, chi, pgx/sqlc, PostgreSQL 16, Redis 7, NATS 2, Docker Compose, GitHub Actions, Prometheus, zerolog, WebSockets, SMTP/Resend/SES adapters

---

## Current Audit Baseline

### Verified on April 22, 2026

- `go build ./...` passes.
- `go vet ./...` passes.
- `go test ./...` passes.
- CI exists at `.github/workflows/ci.yml`, but it only runs build, vet, and test.
- Only 15 test files exist.
- There are no tests under `internal/handler`, `internal/middleware`, `internal/service/providers`, `internal/service/patients`, `internal/service/appointments`, `internal/service/telemedicine`, `internal/repository/providers`, `internal/repository/patients`, or `internal/repository/appointments`.
- Integration test directory `tests/integration` does not exist.
- Ops docs exist only for release checklist and secret rotation.

### Production Gaps Confirmed During Audit

1. Env and runtime contracts are still split.
   - App config reads `DB_URL`, `EMAIL_HOST`, `EMAIL_PORT` in `internal/config/config.go`.
   - Email adapter reads `EMAIL_FROM_ADDRESS`, `SMTP_HOST`, `SMTP_PORT` in `internal/email/config.go`.
   - `docker-compose.yml` injects `SMTP_HOST` and `SMTP_PORT`, not the `internal/config` names.

2. Request metrics are unsafe for scale.
   - `internal/server/server.go` labels Prometheus metrics with raw `r.URL.Path`, which creates unbounded cardinality for parameterized routes.

3. `/metrics` exposure is unconditional.
   - `internal/server/server.go` mounts `/metrics` regardless of `METRICS_ENABLED`.

4. CORS behavior is unsafe and semantically wrong for credentialed requests.
   - `internal/middleware/cors.go` can emit `Access-Control-Allow-Origin: *` together with `Access-Control-Allow-Credentials: true`.

5. Rate limiting is process-local and keyed by `RemoteAddr` rather than a trusted client IP policy.
   - `internal/middleware/ratelimit.go` uses an in-memory map and never shares limits across replicas.

6. Health semantics are incomplete.
   - `internal/handler/health_handler.go` treats database failure as fatal but other dependencies as degraded/unavailable without a documented policy.
   - Version is hard-coded to `1.0.0`.

7. Security hardening is incomplete.
   - `internal/service/core/auth_service.go` still carries TODO history around privileged role registration.
   - Authorization coverage around admin, provider, patient, and telemedicine paths is thin.

8. Operational readiness is incomplete.
   - No rollback runbook.
   - No deploy runbook.
   - No smoke test suite.
   - No migration validation in CI.
   - No backup/restore drill documentation.
   - No alerting, SLO, paging, or incident-response runbook.

9. README and environment docs still overstate readiness.
   - They describe the system as production-ready even though the operational contract is not complete.

---

## Production-Ready Definition

The backend is production ready only when all of the following are true:

- Secrets are not tracked in git and rotation ownership is documented.
- One canonical runtime config contract is used by local dev, CI, Docker, and deployed environments.
- Startup, health, readiness, metrics, logging, and shutdown behavior are deterministic.
- Auth, authorization, rate limiting, and session behavior are explicitly tested.
- Database migrations are validated on clean and upgrade paths.
- CI gates cover build, vet, test, generated-code drift, migrations, and smoke tests.
- Deployment, rollback, secret rotation, and incident response are documented and rehearsed.
- Monitoring, dashboards, alerts, backups, restore drills, and on-call ownership exist.
- Release criteria are defined and enforced.

---

## Delivery Rules

These rules apply for the rest of the project:

- Do not ship new product features until Waves 0 through 4 are complete.
- Every production-affecting change must include tests, docs updates, and a rollback note.
- Every new dependency must declare whether it is critical, optional, or best-effort.
- Every public HTTP route must have auth/authorization expectations documented and tested.
- Every release candidate must pass the release gates at the end of this plan.

---

## Wave 0: Stop-Ship Containment

### Objective

Remove any remaining ambiguity around secrets, environment ownership, and deploy safety.

### Files

- Modify: `.env.example`
- Modify: `.env.development`
- Modify: `.env.production`
- Modify: `.gitignore`
- Modify: `README.md`
- Modify: `ENVIRONMENT.md`
- Modify: `docs/operations/secrets-rotation.md`
- Create: `docs/operations/secret-ownership.md`
- Create: `docs/operations/repository-history-cleanup.md`

### Steps

- [ ] Replace secret-like placeholder patterns in `.env.example` with obviously fake values that cannot be mistaken for live credentials.
- [ ] Confirm `.env.development` and `.env.production` remain placeholder-only and match the canonical config contract.
- [ ] Document secret owners for database, Redis, email provider, JWT signing, AI providers, and any deployment platform credentials.
- [ ] Document the exact repository history cleanup procedure if historical live secrets were ever committed.
- [ ] Remove any claim in docs that the backend is already production-ready.
- [ ] Verify with `go test ./internal/config -run TestTrackedEnvFilesContainNoLiveSecrets -v`.

### Exit Criteria

- No tracked env file contains live or live-looking credentials.
- Secret rotation and history-cleanup responsibilities are assigned.
- Public docs no longer overclaim readiness.

---

## Wave 1: Canonical Runtime Contract

### Objective

Make configuration truthful, singular, and enforceable.

### Files

- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`
- Modify: `internal/email/config.go`
- Modify: `internal/app/app.go`
- Modify: `cmd/api/main.go`
- Modify: `docker-compose.yml`
- Modify: `Makefile`
- Modify: `.env.example`
- Modify: `.env.development`
- Modify: `.env.production`
- Modify: `README.md`
- Modify: `QUICKSTART.md`
- Modify: `ENVIRONMENT.md`
- Create: `docs/operations/config-contract.md`

### Steps

- [ ] Decide and document the canonical variable names for database, email, SMTP, metrics, profiling, AI, WebSocket, and optional integrations.
- [ ] Remove split naming between `EMAIL_FROM` vs `EMAIL_FROM_ADDRESS` and `EMAIL_HOST`/`EMAIL_PORT` vs `SMTP_HOST`/`SMTP_PORT`.
- [ ] Make `internal/config/config.go` the single validation point for runtime configuration.
- [ ] Fail startup on contradictory or partial production configuration.
- [ ] Ensure Docker Compose, Makefile targets, and docs use the same variable names the app actually reads.
- [ ] Add tests for invalid production config, missing required variables, and optional dependency disablement.
- [ ] Verify with `go test ./internal/config -v && go build ./...`.

### Exit Criteria

- There is exactly one config contract.
- Every documented variable is actually consumed by runtime code.
- Production startup rejects invalid or partial config.

---

## Wave 2: Truthful Runtime Lifecycle

### Objective

Make startup, shutdown, and dependency behavior deterministic.

### Files

- Modify: `internal/app/app.go`
- Modify: `internal/app/app_test.go`
- Modify: `internal/server/server.go`
- Modify: `internal/server/server_test.go`
- Modify: `cmd/api/main.go`
- Modify: `internal/handler/health_handler.go`
- Create: `docs/operations/dependency-policy.md`

### Steps

- [ ] Define dependency criticality: database required; Redis policy explicit; NATS explicit; email explicit; AI disabled by default unless enabled.
- [ ] Ensure all config-driven server and pool settings are actually wired into runtime construction paths.
- [ ] Ensure cleanup closes database pools, brokers, workers, and hubs in a consistent order.
- [ ] Replace hard-coded health version output with build-time version/commit metadata.
- [ ] Make readiness reflect only the dependencies required to serve traffic for the chosen deployment mode.
- [ ] Add tests for server timeout wiring, shutdown behavior, and degraded optional integrations.
- [ ] Verify with `go test ./internal/app ./internal/server -v`.

### Exit Criteria

- Runtime behavior is deterministic.
- Health/readiness semantics match documented dependency policy.
- Version/build metadata is emitted by the service.

---

## Wave 3: Observability and Diagnostics Hardening

### Objective

Make logs, metrics, and diagnostics safe for production use.

### Files

- Modify: `internal/server/server.go`
- Modify: `internal/middleware/logger.go`
- Modify: `internal/handler/health_handler.go`
- Modify: `prometheus.yml`
- Create: `docs/operations/observability.md`
- Create: `docs/operations/alerting.md`
- Create: `docs/operations/sli-slo.md`

### Steps

- [ ] Replace raw-path Prometheus labels with chi route patterns or a bounded fallback label set.
- [ ] Gate `/metrics` behind `METRICS_ENABLED` and define whether metrics live on the main port or a separate listener.
- [ ] Decide whether pprof is supported; if yes, gate it behind explicit config and network restrictions; if no, remove the config knobs.
- [ ] Standardize structured log fields for request ID, authenticated user ID, role, clinic ID, consultation ID, and outcome.
- [ ] Add redaction rules so logs never leak passwords, tokens, OTPs, or protected health data.
- [ ] Define dashboards and alerts for error rate, latency, DB connectivity, Redis availability, queue health, and auth anomalies.
- [ ] Verify with focused handler/middleware tests and a manual Prometheus scrape test.

### Exit Criteria

- Metrics are cardinality-safe.
- Observability endpoints are intentionally exposed.
- Alerting, dashboards, and SLOs are documented.

---

## Wave 4: Security and Access Control Hardening

### Objective

Close the highest-risk security and authorization gaps.

### Files

- Modify: `internal/service/core/auth_service.go`
- Modify: `internal/service/core/auth_service_test.go`
- Modify: `internal/middleware/auth.go`
- Modify: `internal/middleware/ratelimit.go`
- Modify: `internal/middleware/cors.go`
- Modify: `internal/handler/core/auth_handler.go`
- Modify: `internal/handler/admin/admin_handler.go`
- Modify: `internal/handler/providers/*.go`
- Modify: `internal/handler/patients/*.go`
- Modify: `internal/handler/telemedicine/*.go`
- Create: `internal/middleware/auth_test.go`
- Create: `internal/middleware/cors_test.go`
- Create: `internal/middleware/ratelimit_test.go`
- Create: `docs/operations/security-posture.md`

### Steps

- [ ] Reconfirm that privileged roles cannot be self-selected during registration and remove stale TODOs that imply otherwise.
- [ ] Add explicit authorization tests for patient-only, clinic-only, provider-only, and admin-only routes.
- [ ] Fix CORS so it never returns `*` with credentials enabled.
- [ ] Replace naive `RemoteAddr` limiting with trusted client IP extraction and document proxy expectations.
- [ ] Decide whether rate limiting must be distributed for multi-instance production; if yes, implement Redis-backed limits or an edge-proxy policy.
- [ ] Add audit coverage for privileged changes such as role updates, clinic verification, consent changes, and telemedicine note finalization.
- [ ] Review session invalidation, refresh-token flow, and OTP behavior for brute-force and replay controls.
- [ ] Verify with targeted middleware, service, and handler tests.

### Exit Criteria

- Critical auth and authorization paths are test-backed.
- CORS and rate limiting are valid for the intended deployment topology.
- Privileged operations are auditable.

---

## Wave 5: Test Pyramid Expansion

### Objective

Raise confidence beyond repository-level happy paths.

### Files

- Create: `tests/integration/...`
- Create: `tests/smoke/...`
- Create: `internal/handler/.../*_test.go`
- Create: `internal/service/providers/*_test.go`
- Create: `internal/service/patients/*_test.go`
- Create: `internal/service/appointments/*_test.go`
- Create: `internal/service/telemedicine/*_test.go`
- Create: `internal/repository/providers/*_test.go`
- Create: `internal/repository/patients/*_test.go`
- Create: `internal/repository/appointments/*_test.go`
- Create: `docs/operations/test-strategy.md`

### Minimum Required Coverage

- Core auth flow: register, login, refresh, logout, password reset, OTP.
- User profile and consent flow.
- Provider clinic creation, staff invitation, and credential management.
- Appointment create/read/update/cancel lifecycle.
- Telemedicine consultation, messaging, and notes authorization.
- Middleware behavior: auth, rate limit, CORS, recovery, logging.
- Health/readiness behavior for missing dependencies.
- Generated SQL repository contracts for providers, patients, and appointments.

### Steps

- [ ] Create unit tests for all middleware.
- [ ] Add handler tests for at least one success path and one authorization failure path per bounded context.
- [ ] Add service tests for policy-heavy provider, appointment, and telemedicine flows.
- [ ] Add repository tests for providers, patients, and appointments.
- [ ] Create integration tests that boot the app against disposable dependencies.
- [ ] Create smoke tests that hit the built binary or container through HTTP.
- [ ] Add a coverage-report target and define minimum thresholds by package category.
- [ ] Verify with `go test ./...` plus dedicated integration/smoke targets.

### Exit Criteria

- Test coverage extends beyond core repositories and auth service.
- Integration and smoke suites exist and run in CI.
- Release-critical user journeys are covered.

---

## Wave 6: Delivery Pipeline and Release Governance

### Objective

Make releases repeatable and block unsafe changes.

### Files

- Modify: `.github/workflows/ci.yml`
- Create: `.github/workflows/release.yml`
- Modify: `Makefile`
- Modify: `Dockerfile`
- Modify: `docker-compose.yml`
- Create: `scripts/ci/*.sh`
- Create: `docs/operations/deploy.md`
- Create: `docs/operations/rollback.md`
- Modify: `docs/operations/release-checklist.md`

### Steps

- [ ] Split CI into fast checks and environment-backed checks.
- [ ] Add jobs for `go build`, `go vet`, `go test`, generated-code drift, migration validation, and smoke tests.
- [ ] Fail CI if `sqlc generate` or mock generation produces drift.
- [ ] Add Docker build validation and image metadata labels.
- [ ] Add a release workflow that records artifact version, git SHA, migration version, and changelog.
- [ ] Document deployment steps, rollback procedure, migration rollback policy, and release sign-off roles.
- [ ] Define branch protection requirements for `main` and `develop`.

### Exit Criteria

- Merges are protected by CI.
- Releases have a documented and rehearsed path forward and backward.
- Generated artifacts cannot silently drift.

---

## Wave 7: Database Operations and Data Safety

### Objective

Make the database safe to evolve and recover.

### Files

- Modify: `database/migrations/*`
- Modify: `database/init.sql`
- Modify: `sqlc.yaml`
- Create: `scripts/ci/migration-check.sh`
- Create: `docs/operations/migrations.md`
- Create: `docs/operations/backups.md`
- Create: `docs/operations/restore-drill.md`

### Steps

- [ ] Validate every migration against a fresh database and an upgrade-path database in CI.
- [ ] Review migration naming consistency and obvious spelling mistakes so future operators are not confused.
- [ ] Define backup frequency, retention, encryption, and restore ownership for production data.
- [ ] Run and document a restore drill against a non-production environment.
- [ ] Define retention and deletion policy for sessions, audit logs, OTPs, messages, and clinical data.
- [ ] Confirm indexes match the highest-risk read paths and slow-query expectations.

### Exit Criteria

- Migrations are validated before release.
- Backup and restore procedures are documented and tested.
- Data retention policy is explicit.

---

## Wave 8: Infrastructure and Deployment Topology

### Objective

Define the real production topology rather than relying on dev-compose assumptions.

### Files

- Create: `deploy/` or `infra/` manifests if infrastructure is managed in-repo
- Create: `docs/operations/topology.md`
- Create: `docs/operations/networking.md`
- Create: `docs/operations/capacity-planning.md`
- Modify: `Dockerfile`
- Modify: `README.md`

### Decisions Required

- Deployment platform: Render, Fly.io, ECS, Kubernetes, or another target.
- TLS termination location.
- Reverse proxy/load balancer behavior.
- Trusted proxy/IP forwarding behavior for rate limiting and audit logs.
- Instance count and autoscaling policy.
- Whether Redis and NATS are mandatory in production.
- Whether WebSocket traffic needs sticky sessions or shared backplane behavior.

### Steps

- [ ] Choose and document the production hosting topology.
- [ ] Define service-to-service network policy and allowed ingress.
- [ ] Define CPU, memory, connection-pool, and replica sizing assumptions.
- [ ] Define deployment health checks, readiness delays, and rolling deploy strategy.
- [ ] Define how static config, secrets, and build metadata enter the runtime.
- [ ] Validate the final topology with a staging deployment.

### Exit Criteria

- The team can describe exactly how production traffic reaches the service.
- Deployment behavior is no longer inferred from Docker Compose.
- Capacity assumptions are documented.

---

## Wave 9: Compliance, Privacy, and Support Operations

### Objective

Close the gap between software readiness and operating a healthcare-adjacent system responsibly.

### Files

- Create: `docs/operations/privacy-and-retention.md`
- Create: `docs/operations/access-review.md`
- Create: `docs/operations/incident-response.md`
- Create: `docs/operations/on-call.md`
- Create: `docs/operations/support-escalation.md`
- Modify: `docs/operations/security-posture.md`

### Steps

- [ ] Define access review cadence for admin users, clinic admins, support users, and infrastructure maintainers.
- [ ] Define incident severity levels, paging expectations, and communication channels.
- [ ] Define procedures for suspected account compromise, data-access disputes, and service outages.
- [ ] Define retention and deletion policies for patient-facing support artifacts, audit trails, and consultation data.
- [ ] Define privacy review and sign-off requirements before launch.

### Exit Criteria

- There is an operator-facing response model for outages and security events.
- Access review and privacy controls are documented.

---

## Wave 10: Staging Validation and Production Cutover

### Objective

Prove the system is ready in an environment that behaves like production, then cut over with discipline.

### Files

- Modify: `docs/operations/release-checklist.md`
- Modify: `docs/operations/deploy.md`
- Modify: `docs/operations/rollback.md`
- Create: `docs/operations/go-live-checklist.md`
- Create: `docs/operations/post-launch-verification.md`

### Steps

- [ ] Deploy the candidate to staging with production-like configuration.
- [ ] Run migrations, smoke tests, and synthetic checks in staging.
- [ ] Verify auth, provider, appointment, telemedicine, email, and degraded-dependency behavior.
- [ ] Verify dashboards, alerts, logs, and on-call routing.
- [ ] Execute a rollback rehearsal.
- [ ] Define production cutover window, owners, and abort criteria.
- [ ] Verify post-launch metrics, error budget, and support channel readiness.

### Exit Criteria

- Staging behaves like production and passes the full checklist.
- Rollback is proven, not theoretical.
- Cutover ownership and abort criteria are explicit.

---

## Release Gates

Every release candidate must satisfy all gates below.

### Code and Build Gates

- [ ] `go build ./...`
- [ ] `go vet ./...`
- [ ] `go test ./...`
- [ ] Generated code and mocks are clean with no drift.
- [ ] Docker image builds successfully.

### Runtime Gates

- [ ] Health/readiness semantics match documented dependency policy.
- [ ] Metrics are cardinality-safe.
- [ ] Logging redaction is verified.
- [ ] Build version and commit SHA are exposed.

### Security Gates

- [ ] No secrets in git.
- [ ] Auth and authorization tests pass.
- [ ] CORS and rate limiting are valid for production topology.
- [ ] Session and OTP controls are verified.

### Data Gates

- [ ] Migrations validate on fresh and upgrade-path databases.
- [ ] Backup and restore procedure exists and has been rehearsed.
- [ ] Retention and deletion policy is documented.

### Delivery Gates

- [ ] CI is green on all required jobs.
- [ ] Deploy and rollback runbooks exist.
- [ ] Smoke tests pass in staging.
- [ ] Alerts, dashboards, and on-call routing are active.

---

## Recommended Execution Order

1. Wave 0: Stop-Ship Containment
2. Wave 1: Canonical Runtime Contract
3. Wave 2: Truthful Runtime Lifecycle
4. Wave 3: Observability and Diagnostics Hardening
5. Wave 4: Security and Access Control Hardening
6. Wave 5: Test Pyramid Expansion
7. Wave 6: Delivery Pipeline and Release Governance
8. Wave 7: Database Operations and Data Safety
9. Wave 8: Infrastructure and Deployment Topology
10. Wave 9: Compliance, Privacy, and Support Operations
11. Wave 10: Staging Validation and Production Cutover

This order matters. Do not start broad architecture refactors or new feature work before the first six waves are materially complete.

---

## Ownership Model

Assign a clear owner for each workstream.

- Application owner: runtime contract, handlers, services, middleware.
- Data owner: migrations, backup/restore, retention, sqlc drift.
- Platform owner: CI/CD, deployment topology, secrets, DNS, TLS, scaling.
- Ops owner: monitoring, alerting, on-call, incident response, release execution.
- Security owner: auth policy, role boundaries, access reviews, secret governance.

If this remains a single-person project, treat these as hats and schedule explicit review checkpoints per hat.

---

## What Not To Do

- Do not declare production readiness because build/vet/test pass.
- Do not rely on Docker Compose as the production topology.
- Do not add new major features until the release gates exist.
- Do not keep split config contracts across packages.
- Do not expose metrics, profiling, or admin behavior by accident.
- Do not launch without a backup/restore drill and rollback rehearsal.

---

## Success Condition

The backend is production ready when the repository, runtime, deployment topology, and operational docs all tell the same truth, and that truth has been tested in staging before launch.
