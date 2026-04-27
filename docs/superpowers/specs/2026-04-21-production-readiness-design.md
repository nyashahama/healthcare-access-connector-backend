# Healthcare Access Connector Backend Production Readiness Design

## Executive Summary

The backend is feature-rich but not production ready. It has a broad domain model, a working HTTP surface, sqlc-backed repositories, health endpoints, and optional adapters for Redis, NATS, email, WebSocket chat, and AI-assisted symptom summarization. The problem is not lack of features. The problem is that security, configuration, testability, delivery discipline, and runtime behavior are inconsistent enough that the team cannot reliably answer a simple question: what is actually safe to deploy and support.

This design recommends a phased hardening program instead of a rewrite. We should preserve the existing Go, chi, pgx/sqlc, and domain structure, but impose a much stricter operating model:

1. Contain the secret exposure and normalize configuration.
2. Stabilize build and test signals so the repository tells the truth.
3. Decompose oversized bootstrap, routing, and service hot spots.
4. Add delivery gates, smoke tests, and operational runbooks.
5. Harden security and observability so runtime behavior is measurable and predictable.

## Current-State Evidence

### What appears healthy

- Working tree is clean on `develop`.
- `go build ./...` completes successfully on April 21, 2026.
- `go vet ./...` completes without reported findings on April 21, 2026.
- The codebase has consistent package layering at a coarse level: `handler -> service -> repository -> sqlc`.
- sqlc-generated repositories and domain types provide a good base for incremental hardening.

### Stop-Ship Findings

1. Secrets are committed to the repository.
   - [`.env.production`](/home/nyasha-hama/projects/healthcare-access-connector-backend/.env.production#L5) contains production-looking database credentials, Redis credentials, Resend API credentials, and a JWT secret.
   - [`.env.development`](/home/nyasha-hama/projects/healthcare-access-connector-backend/.env.development#L45) contains live-looking email, SMTP, AI, and API credentials, including additional tokens later in the file at [`.env.development`](/home/nyasha-hama/projects/healthcare-access-connector-backend/.env.development#L158).
   - This requires immediate rotation and history cleanup before any normal product work.

2. The production env file is internally contradictory.
   - [`.env.production`](/home/nyasha-hama/projects/healthcare-access-connector-backend/.env.production#L5) sets `ENVIRONMENT=development`.
   - That undermines logging behavior, bcrypt defaults, and any future production-only safety checks.

3. The repository's core test signal is currently failing.
   - `go test ./...` fails in `internal/repository/core` with a nil-pointer panic in `GetUserProfile`.
   - Faulting code path: [`internal/repository/core/user_repository.go:221`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/repository/core/user_repository.go#L221).
   - Reproduced by test setup at [`internal/repository/core/user_repository_test.go:751`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/repository/core/user_repository_test.go#L751).

4. Runtime configuration is not wired consistently.
   - The app only loads `DB_URL` in [`internal/config/config.go:105`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/config/config.go#L105), but the Docker API service tries to override runtime connectivity via `DB_HOST` and `DB_PORT` in [`docker-compose.yml:97`](/home/nyasha-hama/projects/healthcare-access-connector-backend/docker-compose.yml#L97).
   - That means local containerized runtime parity is unreliable.

5. Production runtime knobs exist in config but are not actually enforced in key runtime paths.
   - Server timeout values are loaded in [`internal/config/config.go:145`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/config/config.go#L145) but hard-coded in [`internal/server/server.go:193`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/server/server.go#L193).
   - Database pool tuning values are loaded in [`internal/config/config.go:134`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/config/config.go#L134) but ignored in [`internal/app/app.go:493`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/app/app.go#L493).

6. Observability behavior is unsafe for production scale.
   - Metrics use raw request paths as labels in [`internal/server/server.go:497`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/server/server.go#L497), which will create unbounded cardinality for route params.
   - `/metrics` is always exposed from the main server in [`internal/server/server.go:274`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/server/server.go#L274) even though config exposes metrics toggles.

7. Request-path debug code is still present.
   - Example: [`internal/handler/core/auth_handler.go:181`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/handler/core/auth_handler.go#L181).
   - Example: [`internal/service/providers/staff_service.go:182`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/service/providers/staff_service.go#L182).
   - This is a direct symptom of missing release gates.

8. Delivery governance is missing.
   - There is no `.github` workflow directory in the repository root.
   - Documentation references `DEVELOPMENT.md`, but that file does not exist.
   - Only 10 test files exist, concentrated in repositories and email providers.

### Structural Hot Spots

- [`internal/app/app.go`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/app/app.go) is the composition root for nearly the entire system and has become a high-risk edit surface.
- [`internal/server/server.go`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/server/server.go) owns global middleware, metrics, health endpoints, auth wiring, and route registration for every bounded context.
- [`internal/service/core/auth_service.go`](/home/nyasha-hama/projects/healthcare-access-connector-backend/internal/service/core/auth_service.go) is large enough that auth, onboarding, invitations, sessions, email, and login throttling are hard to reason about together.
- Provider and appointment service/handler files are similarly oversized.

## Production Readiness Goals

1. A clean secret model: no credentials in git, explicit templates only, documented rotation, deployment-secret ownership outside the repo.
2. A single authoritative configuration contract with startup validation and environment parity between local, CI, and deployed runtimes.
3. Deterministic runtime behavior: startup, shutdown, health, readiness, metrics, caching, and optional integrations must behave consistently.
4. Truthful engineering signals: build, vet, lint, unit tests, integration tests, smoke tests, and migration checks must be runnable in CI.
5. Better bounded contexts: smaller bootstrap and route modules, less cross-package wiring, clearer ownership.
6. Explicit security posture: role restrictions, session controls, rate limiting, feature gating, and auditable failure modes.
7. Release readiness: docs, runbooks, CI, and rollback/migration discipline.

## Non-Goals

- Rewriting the backend in a new language or framework.
- Replacing chi, pgx, sqlc, or zerolog.
- Re-modeling the domain layer from scratch.
- Shipping new product features before the foundation is stabilized.

## Options Considered

### Option A: Patch Critical Bugs Only

Pros:
- Fastest short-term path.
- Lowest immediate code churn.

Cons:
- Leaves architecture drift and delivery risk intact.
- Does not solve the "what is actually working?" problem.
- High chance of repeated regressions.

### Option B: Phased Production-Readiness Program

Pros:
- Preserves working code while fixing the truthfulness of the system.
- Allows a strict order: contain, stabilize, harden, then optimize.
- Produces measurable release gates.

Cons:
- Requires discipline across several workstreams.
- Some refactors are unavoidable.

### Option C: Large-Scale Rewrite of Runtime Shell and Modules

Pros:
- Maximum design freedom.
- Can yield very clean boundaries.

Cons:
- Highest schedule and regression risk.
- Unnecessary given the existing repository, domain, and sqlc investment.

### Recommendation

Choose Option B.

The repository already has enough valuable structure to justify hardening instead of replacement. The correct move is to keep the stack, fix the operational truth gap, and refactor only where the current shape directly blocks reliability.

## Target Operating Model

### 1. Configuration Contract

Adopt one canonical configuration schema for the application.

Required principles:
- `DB_URL`, `REDIS_URL`, `NATS_URL`, provider-specific email variables, and feature flags are the only runtime contract.
- `.env.example` and optional `*.example` variants contain placeholders only.
- Environment-specific real secrets live in deployment platforms or local untracked files.
- Startup validation must reject contradictory or partial configuration.
- Optional dependencies must be explicitly disabled, not silently half-enabled.

### 2. Runtime Lifecycle

The process should have a single lifecycle manager that:
- Initializes infrastructure with explicit policy per environment.
- Starts optional subsystems only when enabled and valid.
- Uses config-driven HTTP and pool settings.
- Cleans up pools, brokers, workers, and hubs on shutdown.
- Exposes health and readiness based on declared dependency criticality.

### 3. Bounded HTTP Modules

Keep the current bounded contexts, but move route registration into focused router modules:
- `core`
- `patients`
- `providers`
- `appointments`
- `telemedicine`
- `admin`
- `infrastructure`

The top-level server should compose routers and middleware, not own the details of every route tree.

### 4. Infrastructure Adapters With Explicit Policy

Each infrastructure adapter needs a production policy:
- Database: fail fast if unavailable.
- Redis: fail fast in production unless explicitly disabled; no silent in-memory fallback in multi-instance production mode.
- NATS: allowed to degrade if the feature is optional and health reports it clearly.
- Email: allowed to degrade only if product behavior is defined for that state.
- AI: disabled by default unless configured and intentionally enabled.

### 5. Test Pyramid and Release Gates

Minimum required test surface:
- Unit tests for config, middleware, service policy, and edge-case behavior.
- Repository tests for SQL mapping and contract behavior.
- HTTP handler tests for auth, validation, and error translation.
- Integration tests for startup, migrations, auth flow, and one path per bounded context.
- Smoke tests run in CI against dockerized dependencies.

### 6. Security and Access Controls

Immediate hardening targets:
- Remove committed secrets and rotate them.
- Prevent self-selection of privileged roles during registration.
- Make login throttling use config instead of hard-coded values.
- Standardize audit logging on privileged operations.
- Ensure admin-only and clinic-only flows have explicit authorization checks backed by tests.

## Workstreams

### Workstream 0: Incident Containment

Deliverables:
- Secret rotation checklist.
- Secret purge from tracked env files.
- History rewrite or repository secret-removal process.
- Replacement env templates.

### Workstream 1: Foundation Stabilization

Deliverables:
- Passing `go test ./...`.
- Removal of debug prints and request-path leftovers.
- Config/runtime parity between local, Docker, and deployed environments.
- Startup/shutdown cleanup fixes.

### Workstream 2: Runtime and Architecture Hardening

Deliverables:
- Smaller composition root.
- Smaller server/router modules.
- Config-driven HTTP server and DB pool settings.
- Better health/readiness policy.
- Safe metrics labeling.

### Workstream 3: Delivery Pipeline and Operations

Deliverables:
- CI workflow.
- Release checklist.
- Migration validation step.
- Smoke environment docs.
- Updated README and environment docs that match reality.

### Workstream 4: Domain and Security Hardening

Deliverables:
- Auth policy cleanup.
- Test coverage on role management, invitations, session lifecycle, and telemedicine authorization.
- Feature-flag policy for optional integrations.

## Sequencing

This program must run in the following order:

1. Contain secrets.
2. Restore truthful tests and config.
3. Wire runtime settings correctly.
4. Refactor only after build, test, and deployment signals are trustworthy.
5. Expand coverage and CI before broader feature work resumes.

## Release Gates

A release candidate is acceptable only when all of the following are true:

- No real secrets are tracked in git.
- `go build ./...`, `go vet ./...`, and `go test ./...` pass in CI.
- Lint passes in CI.
- Migrations validate against a fresh database and an upgrade path database.
- Smoke tests cover auth, user profile, provider management, appointments, and telemedicine basics.
- Health/readiness semantics match dependency policy.
- Metrics and logs are safe for production cardinality and privacy.
- Ops docs exist for deploy, rollback, secret rotation, and incident triage.

## Recommended Decomposition

This repository is too broad for a single implementation pass.

Recommended decomposition:
- Program-level roadmap for the whole backend.
- Detailed execution plan for the first wave only: containment and stabilization.
- Subsequent per-workstream plans after the foundation wave is complete.

## Decision

Proceed with a production-readiness program anchored on containment and stabilization first. Do not add product features until the foundation wave is complete.
