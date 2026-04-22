# Incident Response Guide

This document defines how to respond to outages, security events, and data-access disputes.

## Incident Severity Levels

| Level | Description | Examples | Response Time | Paging |
|-------|-------------|----------|---------------|--------|
| **SEV-1** | Service down or severe data breach | Database unreachable, mass PHI leak | 5 minutes | Yes |
| **SEV-2** | Major degradation or security event | Elevated 500s, suspected account compromise | 15 minutes | Yes |
| **SEV-3** | Minor degradation or policy violation | Slow queries, CORS misconfiguration | 1 hour | No |
| **SEV-4** | Low impact, no user impact | Certificate expiry in 30 days, log disk full | Next business day | No |

## Incident Response Process

### 1. Detect

- Monitoring alerts (Prometheus, PagerDuty).
- User reports (support channel).
- Automated anomaly detection.

### 2. Triage

- Assign severity level.
- Identify affected systems and users.
- Create an incident channel / war room.

### 3. Respond

- **SEV-1:** Page on-call engineer immediately. Escalate to security owner if breach suspected.
- **SEV-2:** Page on-call engineer. Notify security owner.
- **SEV-3:** Assign to application owner. Monitor.
- **SEV-4:** Create ticket for next sprint.

### 4. Mitigate

- Apply short-term fix to stop the bleeding.
- Preserve evidence (logs, snapshots) before fixing if security-related.
- Communicate status to stakeholders.

### 5. Resolve

- Confirm service is healthy.
- Run smoke tests.
- Update status page.
- Close the incident channel.

### 6. Post-Incident Review

Within 24 hours for SEV-1/2, within 1 week for SEV-3:

- Timeline of events.
- Root cause analysis (5 Whys).
- Action items to prevent recurrence.
- Publish findings (internal).

## Specific Scenarios

### Suspected Account Compromise

1. **Lock** the affected account.
2. **Revoke** all active sessions.
3. **Force** password reset.
4. **Review** audit logs for unauthorized access.
5. **Notify** the user and security owner.
6. **Document** the incident.

### Data Access Dispute

1. **Preserve** audit logs related to the disputed access.
2. **Verify** the access was authorized per consent records.
3. **Notify** the privacy officer.
4. **Document** findings.
5. **Remediate** if unauthorized access is confirmed.

### Service Outage

1. **Assess** scope (partial or total).
2. **Check** dependency health (DB, Redis, NATS).
3. **Roll back** if correlated with a recent deploy.
4. **Scale** if load-related.
5. **Communicate** to users via status page.

## Communication Channels

| Severity | Internal Channel | External Channel |
|----------|-----------------|------------------|
| SEV-1 | #incidents-war-room | Status page + user email |
| SEV-2 | #incidents | Status page |
| SEV-3 | #alerts-app | None |
| SEV-4 | Ticket system | None |

## On-Call Rotation

See `docs/operations/on-call.md` for the on-call schedule and escalation policy.
