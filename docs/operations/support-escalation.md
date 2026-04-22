# Support Escalation Guide

This document defines how customer-facing support issues are escalated to engineering and operations.

## Support Tiers

| Tier | Team | Scope | Response Time |
|------|------|-------|---------------|
| **L1** | Customer support | Account issues, password resets, basic how-to | 4 hours |
| **L2** | Application owner | Bugs, feature requests, data corrections | 1 business day |
| **L3** | Platform / Data owner | Infrastructure issues, database problems | 2 business days |
| **L4** | Security owner | Security incidents, data breaches, compliance | 4 hours |

## Escalation Criteria

Escalate to L2 when:
- L1 cannot resolve the issue with existing documentation.
- The issue involves application behavior or data integrity.

Escalate to L3 when:
- The issue involves service availability or performance.
- Database access or migration is required.

Escalate to L4 when:
- A security incident is suspected.
- PHI may have been accessed inappropriately.
- Legal or compliance questions arise.

## Escalation Process

1. **Create a ticket** with all relevant details (user ID, timestamps, screenshots, logs).
2. **Assign** to the appropriate tier.
3. **Notify** the owner via Slack or email.
4. **Track** progress and communicate with the user.
5. **Close** the ticket with a summary and any follow-up actions.

## Communication Templates

### User-Facing Incident

```
Subject: Service Disruption — [Brief Description]

We are currently investigating a service disruption affecting [feature].
Our team is working to resolve this as quickly as possible.

Status page: [link]
Estimated resolution: [time or "under investigation"]

We apologize for the inconvenience.
```

### Data Access Dispute

```
Subject: Re: Data Access Inquiry

Thank you for reaching out. We take data privacy seriously.
We are reviewing your inquiry and will respond within 48 hours.

If you believe there has been unauthorized access, please contact
our security team at security@example.com.
```

## Metrics

Track support metrics monthly:

- Average time to resolution by tier.
- Escalation rate (how many L1 tickets escalate to L2).
- User satisfaction score.
