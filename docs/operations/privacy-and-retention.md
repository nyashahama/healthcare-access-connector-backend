# Privacy and Data Retention Policy

This document defines how long different categories of data are retained and when they are deleted.

## Data Categories

| Category | Retention Period | Deletion Trigger | Owner |
|----------|-----------------|------------------|-------|
| Patient profiles | 7 years after last activity | Legal requirement / user request | Data owner |
| Provider profiles | 7 years after last activity | Legal requirement / user request | Data owner |
| Appointments | 7 years | Legal requirement | Data owner |
| Consultation messages | 7 years | Legal requirement | Data owner |
| Clinical notes | 10 years | Legal requirement | Data owner |
| Audit logs | 2 years | Automatic purge | Security owner |
| Session tokens | 30 days | Expiry / logout | Security owner |
| OTP codes | 15 minutes | Expiry / use | Security owner |
| Password reset tokens | 1 hour | Expiry / use | Security owner |
| Email verification tokens | 24 hours | Expiry / use | Security owner |
| Failed login attempts | 30 minutes | Automatic cleanup | Security owner |
| WebSocket presence events | 24 hours | Automatic purge | Ops owner |
| Support tickets | 3 years | Case closure + grace period | Ops owner |

## Deletion Procedures

### User-Initiated Deletion

When a user requests account deletion:

1. **Soft delete** the user record (mark as deleted, anonymize PII).
2. **Schedule** hard deletion after the retention grace period (30 days).
3. **Invalidate** all sessions and tokens.
4. **Log** the deletion in the audit trail.

### Automatic Purge

Scheduled jobs clean up expired data:

```sql
-- Example: purge expired sessions
DELETE FROM user_sessions WHERE expires_at < NOW() - INTERVAL '30 days';

-- Example: purge old audit logs
DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '2 years';
```

## Anonymization

Before hard deletion, anonymize records that must be retained for legal or statistical reasons:

- Replace name with hash.
- Replace email/phone with null.
- Retain demographic data (age range, gender) for analytics if consented.

## Legal Holds

If a legal hold is issued:

1. Suspend all deletion for the affected users.
2. Document the hold and scope.
3. Notify the legal team.

## Privacy Review Sign-Off

Before every major release:

- [ ] No new PII fields are added without review.
- [ ] Data retention periods are documented.
- [ ] Deletion procedures are tested.
- [ ] Privacy policy is updated if needed.

## Compliance

This policy supports compliance with:
- POPIA (South Africa)
- GDPR (EU users, if applicable)
- HIPAA (if handling US PHI)
