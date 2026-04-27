# Production Readiness Roadmap

## Purpose

This roadmap turns the design doc into an execution sequence. It is not the detailed task-by-task implementation plan. It defines the order of work, ownership boundaries, and exit criteria for each wave.

## Guiding Principle

The backend does not need more breadth right now. It needs a truthful operating model. Each wave below exists to make the next wave safer and more deterministic.

## Wave 0: Containment

### Objective

Stop ongoing security exposure and remove ambiguity about which configuration is authoritative.

### Scope

- Rotate all credentials currently tracked in `*.env` files.
- Remove tracked secrets from repository files.
- Replace tracked env files with placeholder templates only.
- Document secret ownership and rotation procedure.
- Freeze deploys until rotation is complete.

### Primary Files

- `.env.development`
- `.env.production`
- `.env.example`
- `.gitignore`
- `ENVIRONMENT.md`
- `README.md`
- `docs/operations/secrets-rotation.md`

### Exit Criteria

- No live credentials remain in tracked files.
- Deployment secrets are sourced from environment or secret managers only.
- Team can recreate local dev env from placeholders and docs.

## Wave 1: Stabilization

### Objective

Make the repository's local and CI signals trustworthy.

### Scope

- Fix failing repository tests.
- Remove request-path debug prints.
- Normalize config names and runtime expectations.
- Ensure Docker and dev instructions match actual app behavior.
- Wire cleanup and runtime settings that already exist in config.

### Primary Files

- `internal/repository/core/user_repository.go`
- `internal/repository/core/user_repository_test.go`
- `internal/config/config.go`
- `internal/app/app.go`
- `internal/server/server.go`
- `cmd/api/main.go`
- `docker-compose.yml`
- `Makefile`
- `README.md`
- `QUICKSTART.md`
- `ENVIRONMENT.md`

### Exit Criteria

- `go build ./...`, `go vet ./...`, and `go test ./...` pass locally and in CI.
- Startup and shutdown are deterministic.
- Containerized and local dev startup use the same effective config contract.
- No `fmt.Println` or similar debug leftovers remain in runtime code.

## Wave 2: Runtime Hardening

### Objective

Make the server safe to run and observe in production.

### Scope

- Replace hard-coded server settings with config-driven values.
- Normalize health and readiness semantics.
- Gate metrics and profiling correctly.
- Fix metrics cardinality by using route patterns instead of raw paths.
- Define infrastructure degradation policy per dependency.

### Primary Files

- `internal/server/server.go`
- `internal/handler/health_handler.go`
- `internal/cache/redis_cache.go`
- `internal/messaging/nats_broker.go`
- `internal/email/*`
- `internal/config/config.go`

### Exit Criteria

- Observability endpoints behave according to config.
- Metrics are safe for production label cardinality.
- Optional dependencies are either cleanly disabled or cleanly reported as degraded.

## Wave 3: Architecture Hardening

### Objective

Reduce concentration risk in the current composition root and route tree.

### Scope

- Split route registration by bounded context.
- Split bootstrap modules by subsystem.
- Reduce the size of auth, clinic, staff, and appointment hot spots.
- Introduce clearer dependency seams for testing.

### Primary Files

- `internal/app/app.go`
- `internal/server/server.go`
- `internal/service/core/auth_service.go`
- `internal/service/providers/clinic_service.go`
- `internal/service/providers/staff_service.go`
- `internal/service/appointments/appointments_service.go`
- `internal/handler/providers/*`
- `internal/handler/appointments/*`

### Exit Criteria

- Composition root and server modules are materially smaller and easier to review.
- Route ownership is obvious per bounded context.
- Critical services gain focused tests around policies and edge cases.

## Wave 4: Delivery and Governance

### Objective

Make releases repeatable and auditable.

### Scope

- Add CI workflows.
- Add smoke and migration validation jobs.
- Add release and rollback checklists.
- Ensure generated code and migrations are checked in a repeatable way.

### Primary Files

- `.github/workflows/ci.yml`
- `Makefile`
- `sqlc.yaml`
- `Dockerfile`
- `docker-compose.yml`
- `docs/operations/release-checklist.md`
- `docs/operations/rollback.md`

### Exit Criteria

- CI blocks merges on broken build, test, lint, or migration state.
- Release steps are documented and reproducible.

## Wave 5: Security and Compliance Hardening

### Objective

Close remaining privilege, audit, and data-governance gaps.

### Scope

- Restrict privileged role self-registration.
- Make login throttling config-driven.
- Add tests for authorization-sensitive paths.
- Review audit trails, consent flows, and operational data retention.

### Primary Files

- `internal/service/core/auth_service.go`
- `internal/handler/core/auth_handler.go`
- `internal/middleware/auth.go`
- `internal/service/providers/*`
- `internal/service/core/*`
- `internal/handler/admin/*`

### Exit Criteria

- Privileged flows are test-backed.
- Security-sensitive behavior is explicit, documented, and observable.

## Recommended Delivery Order

1. Wave 0
2. Wave 1
3. Wave 2
4. Wave 4
5. Wave 3
6. Wave 5

Wave 4 is placed ahead of full architecture hardening because the repository needs CI protection before larger refactors begin.

## Risks

- Secret rotation may require external coordination and may break undeclared environments.
- Config normalization may reveal undocumented deploy assumptions.
- Router and service decomposition will create merge pressure if done before CI gates exist.
- Optional integrations may currently be relied on in hidden ways despite being treated as degraded in code.

## Success Definition

The project is production ready when the repository, runtime, and deployment process all tell the same truth.
