# Rollback Guide

This document describes how to roll back a deployment safely.

## Principle

Rollback is a rehearsed procedure, not an improvisation. Every release must have a known-good previous version that can be restored quickly.

## Rollback Scenarios

1. **Code rollback** — deploy the previous Docker image or binary.
2. **Database rollback** — reverse the last migration (if safe).
3. **Config rollback** — revert environment variables to the previous state.

## Code Rollback Procedure

### Step 1: Stop Traffic (if needed)

If the service is actively failing requests, take it out of the load balancer or scale to zero:

```bash
# Render: suspend service
# Kubernetes: kubectl scale deployment hac-api --replicas=0
# Docker: docker stop hac-api
```

### Step 2: Identify the Previous Good Version

```bash
# List recent tags
git tag --sort=-creatordate | head -5

# The previous good version is the tag before the current one
```

### Step 3: Deploy the Previous Version

```bash
# Docker
docker pull healthcare-access-connector:v1.2.2
docker stop hac-api
docker run -d --name hac-api --env-file .env.production -p 8080:8080 healthcare-access-connector:v1.2.2

# Render: trigger manual deploy of previous commit
```

### Step 4: Verify Rollback

```bash
./tests/smoke/smoke.sh 8080
```

Confirm:
- [ ] `/health` returns 200
- [ ] `/ready` returns 200
- [ ] Error rate returns to baseline
- [ ] Latency returns to baseline

### Step 5: Restore Traffic

Re-enable the service in the load balancer or scale back up.

## Database Rollback Policy

**Warning:** Database rollbacks are dangerous and can cause data loss. Only reverse migrations if:

1. The migration was applied within the last 5 minutes.
2. No new data was written that depends on the new schema.
3. The down migration has been tested in staging.

```bash
# Reverse the last migration
migrate -path database/migrations -database "$DB_URL" down 1

# Verify version
migrate -path database/migrations -database "$DB_URL" version
```

If the migration cannot be safely reversed, do **not** roll back the database. Instead:

1. Roll back the code.
2. Apply a forward-fix migration in the next release.
3. Document the schema discrepancy.

## Config Rollback

If the issue is caused by environment variable changes:

1. Revert the variables in your deployment platform or secret manager.
2. Restart the service.
3. Verify behavior.

## Communication

During a rollback:

1. **Notify** the team in the incident channel.
2. **Update** status page if one exists.
3. **Document** the rollback reason and timeline.
4. **Schedule** a post-mortem within 24 hours.

## Rollback Rehearsal

Execute a rollback rehearsal in staging **before every production deploy**:

1. Deploy the candidate to staging.
2. Run smoke tests.
3. Roll back to the previous version.
4. Run smoke tests again.
5. Confirm data integrity.

## Rollback Checklist

- [ ] Previous good version is identified and available.
- [ ] Database migration reversal plan is documented (or forward-fix is prepared).
- [ ] Secrets are unchanged from the previous deployment.
- [ ] Smoke tests pass after rollback.
- [ ] Team is notified.
- [ ] Post-mortem is scheduled.
