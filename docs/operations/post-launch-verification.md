# Post-Launch Verification

This document describes the verification steps to perform after launching to production.

## Immediate Verification (0-1 Hour)

### Health Checks

- [ ] `/health` returns 200 with all services healthy.
- [ ] `/ready` returns 200.
- [ ] `/live` returns 200.

### Metrics

- [ ] Prometheus scrape succeeds.
- [ ] Request rate matches expected traffic.
- [ ] Error rate is < 0.1%.
- [ ] p50 latency is < 100ms.
- [ ] p99 latency is < 500ms.

### Critical User Journeys

- [ ] Patient registration succeeds.
- [ ] Patient login succeeds.
- [ ] Provider login succeeds.
- [ ] Appointment booking succeeds.
- [ ] Telemedicine consultation can be initiated.
- [ ] Email notifications are delivered.

## Short-Term Verification (1-24 Hours)

### Error Logs

- [ ] No unexpected panics or 500 errors.
- [ ] No database connection pool exhaustion.
- [ ] No Redis connection errors.

### Resource Utilization

- [ ] CPU usage is < 50% average.
- [ ] Memory usage is < 70% average.
- [ ] Database connections are < 80% of max.
- [ ] Disk usage is < 70%.

### Security

- [ ] No anomalous login attempts.
- [ ] Rate limiting is blocking abusive IPs.
- [ ] No unauthorized admin actions in audit logs.

## Medium-Term Verification (1-7 Days)

### User Metrics

- [ ] Daily active users are within expected range.
- [ ] Registration conversion rate is healthy.
- [ ] Appointment booking rate is healthy.
- [ ] Support ticket volume is manageable.

### Infrastructure

- [ ] Autoscaling has not triggered unexpectedly.
- [ ] Backups are completing successfully.
- [ ] TLS certificate is valid.
- [ ] No failed deployments or rollbacks.

### Financial

- [ ] Infrastructure costs are within budget.
- [ ] Email provider costs are within budget.
- [ ] No unexpected charges from cloud provider.

## Long-Term Verification (1-30 Days)

### SLO Attainment

- [ ] Availability SLO (99.9%) is met.
- [ ] Latency SLO (p99 < 500ms) is met.
- [ ] Error budget is not exhausted.

### Operational Maturity

- [ ] All post-incident reviews from launch period are complete.
- [ ] Runbooks have been updated based on real incidents.
- [ ] On-call engineers are comfortable with the system.
- [ ] Capacity plan is validated against actual usage.

## Issue Tracking

Any issue found during post-launch verification must be:

1. **Logged** in the issue tracker.
2. **Prioritized** as P0 (fix within 24h), P1 (fix within 1 week), or P2 (fix within 1 month).
3. **Assigned** to the appropriate owner.
4. **Verified** as resolved before closing.
