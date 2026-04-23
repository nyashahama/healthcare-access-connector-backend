# Go-Live Checklist

This checklist must be completed before the Healthcare Access Connector backend is declared production-ready.

## Pre-Launch (T-7 Days)

- [ ] All Waves 0-4 are materially complete.
- [ ] All release gates pass on the release candidate.
- [ ] Staging deployment is active and stable.
- [ ] Smoke tests pass in staging.
- [ ] Migrations are validated on a copy of production data.
- [ ] Secrets are rotated and stored in the production secret manager.
- [ ] On-call rotation is active and confirmed.
- [ ] Status page is configured.

## Pre-Launch (T-3 Days)

- [ ] Load tests pass at 2x expected peak traffic.
- [ ] Security scan (dependency + static analysis) is clean.
- [ ] Privacy review is signed off.
- [ ] Backup and restore drill is completed successfully.
- [ ] Rollback rehearsal is completed successfully.
- [ ] All operators have read the deploy and rollback runbooks.

## Pre-Launch (T-1 Day)

- [ ] Production environment variables are set.
- [ ] DNS is pointed to the production load balancer.
- [ ] TLS certificate is valid and auto-renewal is confirmed.
- [ ] Monitoring dashboards are live.
- [ ] Alerts are configured and tested.
- [ ] Support channels are staffed.

## Launch Day (T-0)

- [ ] Deploy to production during the agreed window.
- [ ] Run smoke tests immediately after deploy.
- [ ] Monitor error rate, latency, and health checks for 1 hour.
- [ ] Verify critical user journeys: register, login, book appointment.
- [ ] Confirm email delivery is working.
- [ ] Post launch announcement to stakeholders.

## Launch Day + 1 Hour

- [ ] Error rate is < 0.1%.
- [ ] p99 latency is within SLO.
- [ ] No critical or warning alerts are firing.
- [ ] Support queue is manageable.

## Launch Day + 24 Hours

- [ ] Daily active users are within expected range.
- [ ] No incidents occurred.
- [ ] Backup from launch day is verified.
- [ ] Post-launch review is scheduled.

## Abort Criteria

Abort the launch and roll back if:

- [ ] Error rate exceeds 1% within 15 minutes of deploy.
- [ ] `/ready` probe fails for 2 consecutive minutes.
- [ ] Any critical alert fires.
- [ ] Support queue exceeds 10 unresolved tickets within 1 hour.
- [ ] Data integrity issue is detected.

## Sign-Off

| Role | Name | Signature | Date |
|------|------|-----------|------|
| Application owner | | | |
| Data owner | | | |
| Platform owner | | | |
| Security owner | | | |
| Ops owner | | | |
