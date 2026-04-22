# Secret Ownership

This document assigns clear owners for every class of secret used by the Healthcare Access Connector backend.

## Principle

Every secret has exactly one owner. The owner is responsible for generation, storage, rotation, and incident response for that secret. If this project is maintained by a single person, that person wears all of these hats and must schedule explicit review checkpoints.

## Secret Registry

| Secret Category | Variables | Owner | Storage | Rotation Cadence | Rotation Trigger |
|-----------------|-----------|-------|---------|------------------|------------------|
| Database | `DB_URL` (contains password) | Data Owner | Deployment platform env vars or secret manager | Every 90 days or on personnel change | Compromise suspicion, team member departure, quarterly review |
| Redis | `REDIS_URL` (contains auth) | Platform Owner | Deployment platform env vars or secret manager | Every 90 days or on personnel change | Compromise suspicion, team member departure |
| JWT Signing | `JWT_SECRET` | Security Owner | Deployment platform env vars or secret manager | Every 90 days | Compromise suspicion, token leak, quarterly review |
| Email Provider (Resend) | `RESEND_API_KEY` | Ops Owner | Secret manager (e.g., 1Password, AWS Secrets Manager) | Every 90 days | Key leak, provider breach notification, quarterly review |
| Email Provider (SMTP) | `SMTP_PASSWORD` | Ops Owner | Secret manager | Every 90 days | Compromise suspicion, quarterly review |
| Email Provider (AWS SES) | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Platform Owner | AWS IAM + secret manager | Every 90 days or per AWS policy | Key leak, IAM policy change, quarterly review |
| AI Providers | `AI_API_KEY` (if enabled) | Security Owner | Secret manager | Every 90 days | Provider breach, key leak, quarterly review |
| Deployment Platform | Render/Fly.io/ECS API tokens | Platform Owner | Platform-native secret management | Per platform policy | Token leak, platform security advisory |
| TLS / Certificates | Load balancer or reverse proxy certs | Platform Owner | Certificate manager (e.g., Let's Encrypt, AWS ACM) | Before expiry (typically 90 days for Let's Encrypt) | Expiry alert, revocation event |

## Owner Responsibilities

### Data Owner
- Validates backup encryption keys.
- Owns database credential rotation.
- Approves restore drills.

### Platform Owner
- Owns infrastructure secrets (Redis, NATS, TLS, deployment platform tokens).
- Manages network and host-level access.
- Executes infrastructure changes.

### Security Owner
- Owns JWT signing secrets and AI provider keys.
- Defines auth policy and reviews access logs.
- Leads incident response for auth anomalies.

### Ops Owner
- Owns email provider credentials and monitoring integrations.
- Manages alerting channels and on-call routing.
- Executes secret rotations for owned credentials.

## Rotation Workflow

1. **Generate new secret** in the appropriate secret manager or provider console.
2. **Update deployment platform** environment variables or secret references.
3. **Restart / redeploy** affected services (rolling restart if possible).
4. **Verify health** checks and smoke tests pass.
5. **Revoke old secret** at the provider after confirming new secret is active.
6. **Document rotation** in the deployment log or incident tracker.

## Emergency Rotation

If a secret is suspected to be compromised:

1. Rotate immediately (do not wait for scheduled window).
2. Force logout all sessions if the secret is `JWT_SECRET`.
3. Review access logs for the affected service.
4. Document the event and findings.

See also:
- [Secret Rotation Guide](secrets-rotation.md)
- [Repository History Cleanup](repository-history-cleanup.md)
