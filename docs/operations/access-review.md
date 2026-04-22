# Access Review Guide

This document defines the cadence and process for reviewing user and infrastructure access.

## Access Review Cadence

| Role / System | Frequency | Reviewer |
|---------------|-----------|----------|
| System admins | Quarterly | Security owner |
| Clinic admins | Quarterly | Security owner |
| Support users | Quarterly | Ops owner |
| Infrastructure maintainers | Quarterly | Platform owner |
| Database access | Quarterly | Data owner |
| CI/CD pipeline access | Quarterly | Platform owner |
| Third-party integrations | Annually | Security owner |

## Review Process

1. **Generate access report:** Export all users by role from the database.
2. **Verify necessity:** Confirm each user still requires their access level.
3. **Remove stale access:** Deactivate or downgrade users who no longer need access.
4. **Document changes:** Log all removals in the audit trail.
5. **Sign-off:** Security owner approves the review.

## Admin User Review Checklist

For each admin user:

- [ ] Still employed by the organization.
- [ ] Still requires admin privileges for their role.
- [ ] MFA is enabled.
- [ ] Last login was within the last 90 days.
- [ ] No suspicious activity in audit logs.

## Infrastructure Access Review

For each infrastructure maintainer:

- [ ] Still requires SSH / VPN / cloud console access.
- [ ] Access keys are rotated within the last 90 days.
- [ ] No unused IAM permissions.
- [ ] Least-privilege principle is enforced.

## Post-Review Actions

1. Update access control documentation.
2. Revoke unnecessary permissions.
3. Schedule the next review.
4. Report findings to leadership if significant risks are identified.
