# Release Checklist

Every release candidate must satisfy all gates below before deployment.

## Code and Build Gates

- [ ] `go build ./...` passes.
- [ ] `go vet ./...` passes.
- [ ] `go test ./...` passes.
- [ ] Generated code and mocks are clean with no drift.
- [ ] Docker image builds successfully.
- [ ] Version metadata is injected (Version, Commit, BuildDate).

## Runtime Gates

- [ ] Health/readiness semantics match documented dependency policy.
- [ ] Metrics are cardinality-safe (chi route patterns, not raw paths).
- [ ] Logging redaction is verified (passwords, tokens, OTPs redacted).
- [ ] Build version and commit SHA are exposed via `/health`.
- [ ] `/metrics` is gated behind `METRICS_ENABLED`.

## Security Gates

- [ ] No secrets in git (`go test ./internal/config -run TestTrackedEnvFilesContainNoLiveSecrets -v`).
- [ ] Auth and authorization tests pass.
- [ ] CORS never returns `*` with credentials enabled.
- [ ] Rate limiting uses trusted client IP extraction.
- [ ] Session and OTP controls are verified.

## Data Gates

- [ ] Migrations validate on fresh and upgrade-path databases.
- [ ] Backup and restore procedure exists and has been rehearsed.
- [ ] Retention and deletion policy is documented.

## Delivery Gates

- [ ] CI is green on all required jobs (fast checks, drift, Docker, migrations).
- [ ] Deploy and rollback runbooks exist and are up to date.
- [ ] Smoke tests pass in staging.
- [ ] Alerts, dashboards, and on-call routing are active.

## Pre-Deploy Checks

- [ ] Secret rotation status verified.
- [ ] Build, vet, tests, and lint all green.
- [ ] Migration plan reviewed and validated.
- [ ] Smoke environment validated.
- [ ] Rollback steps prepared and rehearsed.
- [ ] On-call engineer notified.
- [ ] Status page updated (if maintenance window).

## Sign-Off

| Role | Name | Date |
|------|------|------|
| Application owner | | |
| Data owner | | |
| Platform owner | | |
| Security owner | | |
| Ops owner | | |
