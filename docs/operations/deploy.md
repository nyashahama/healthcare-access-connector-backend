# Deployment Guide

This document describes how to deploy the Healthcare Access Connector backend to production.

## Prerequisites

Before deploying, confirm:

- [ ] Release candidate passes all release gates (see `docs/operations/release-checklist.md`).
- [ ] Database migrations have been validated in CI.
- [ ] Smoke tests pass against the built container.
- [ ] Secrets are rotated if necessary.
- [ ] On-call rotation is active.

## Deployment Platform

The default deployment target is **Render** (or your chosen platform). See `docs/operations/topology.md` for the full production topology.

## Deployment Steps

### 1. Prepare the Release

```bash
# Tag the release
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin v1.2.3

# The release workflow will build the binary and Docker image
```

### 2. Database Migrations (Pre-Deploy)

Run migrations **before** deploying the new code if the release includes schema changes.

```bash
# Using the migrate CLI
migrate -path database/migrations -database "$DB_URL" up

# Verify migration version
migrate -path database/migrations -database "$DB_URL" version
```

**Never** run migrations from the application startup. Migrations must be explicit and reversible.

### 3. Deploy Application

#### Option A: Render.com

1. Push the tag to GitHub.
2. Render auto-deploys from the `main` branch (or tag).
3. Monitor the deploy logs for errors.
4. Verify `/health` and `/ready` return 200.

#### Option B: Docker

```bash
# Pull the release image
docker pull healthcare-access-connector:v1.2.3

# Run with production env
docker run -d \
  --name hac-api \
  --env-file .env.production \
  -p 8080:8080 \
  healthcare-access-connector:v1.2.3
```

### 4. Post-Deploy Verification

Run the smoke tests against the deployed instance:

```bash
./tests/smoke/smoke.sh 8080
```

Verify:
- [ ] `/health` returns 200
- [ ] `/ready` returns 200
- [ ] Key user journeys work (register, login, book appointment)
- [ ] Metrics are accessible (if enabled)
- [ ] Error rate is near zero
- [ ] Latency p99 is within SLO

### 5. Monitor and Rollback if Needed

Watch dashboards for 30 minutes after deploy. If error rate spikes or latency degrades:

1. **Stop** — do not panic.
2. **Assess** — check logs, metrics, and recent changes.
3. **Decide** — if the issue is clearly caused by the new release, initiate rollback.
4. **Execute** — follow the rollback procedure in `docs/operations/rollback.md`.

## Deployment Windows

- **Preferred:** Low-traffic hours (e.g., 02:00-04:00 local time).
- **Avoid:** Peak usage hours, weekends if telemedicine is active.
- **Emergency:** Any time, with explicit communication to users.

## Branch Protection

- `main`: Requires PR review + passing CI (build, vet, test, drift, migrations, Docker).
- `develop`: Requires PR review + passing fast checks.

## Rollback Criteria

Roll back immediately if any of the following occur within 15 minutes of deploy:

- Error rate exceeds 1% for 2 consecutive minutes.
- `/ready` probe fails for 2 consecutive minutes.
- p99 latency exceeds 2x the pre-deploy baseline.
- Any critical alert fires.

See `docs/operations/rollback.md` for the rollback procedure.

## Sign-Off Roles

| Step | Owner | Sign-Off Required |
|------|-------|-------------------|
| Release candidate validation | Application owner | Yes |
| Migration execution | Data owner | Yes |
| Deploy execution | Platform owner | Yes |
| Post-deploy verification | Ops owner | Yes |
| Rollback decision | Ops owner + Application owner | If needed |
