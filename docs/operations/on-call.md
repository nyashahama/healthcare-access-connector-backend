# On-Call Guide

This document defines the on-call rotation, responsibilities, and escalation policy.

## Rotation

- **Primary on-call:** Application owner or designated engineer.
- **Secondary on-call:** Platform owner or senior engineer.
- **Escalation:** Security owner for security incidents, Data owner for database issues.

## Schedule

- **Weekdays:** Business hours coverage by the team.
- **Nights / Weekends:** Rotating primary + secondary pager.
- **Handoff:** Every Monday at 09:00 local time.

## Responsibilities

### Primary On-Call

- Respond to pages within 5 minutes for SEV-1, 15 minutes for SEV-2.
- Triage alerts and initiate incident response.
- Communicate status to stakeholders.
- Escalate to secondary if unable to resolve within 30 minutes.

### Secondary On-Call

- Back up primary for complex issues.
- Handle escalations from primary.
- Coordinate with external vendors if needed.

## Alert Routing

| Alert Type | Primary | Secondary |
|------------|---------|-----------|
| Service down | App owner | Platform owner |
| Database issues | Data owner | Platform owner |
| Security alerts | Security owner | App owner |
| Email failures | Ops owner | App owner |

## Escalation Path

1. **Primary on-call** (5 min response)
2. **Secondary on-call** (if primary doesn't respond in 10 min)
3. **Team lead / manager** (if secondary doesn't respond in 15 min)
4. **Executive sponsor** (for SEV-1 only, if no response in 30 min)

## On-Call Readiness Checklist

Before going on-call:

- [ ] PagerDuty / phone notifications are enabled.
- [ ] Laptop and internet access are available.
- [ ] VPN / SSH keys work.
- [ ] Access to production logs and metrics.
- [ ] Runbook URLs are bookmarked.
- [ ] Know the rollback procedure.

## Post-On-Call Handoff

- Document any incidents or near-misses.
- Update runbooks if gaps were found.
- Notify the next on-call engineer of any ongoing issues.
