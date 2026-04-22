# Security Posture

This document summarizes the security controls and posture of the Healthcare Access Connector backend.

## Authentication

- **JWT tokens** with HS256 signing and configurable expiry.
- **bcrypt** password hashing with environment-aware cost.
- **Multi-factor authentication** via OTP (optional, configurable).
- **Session management** with device tracking and revocation.

## Authorization

- **Role-based access control:** patient, provider_staff, clinic_admin, system_admin.
- **Privileged roles** (system_admin, ngo_partner) cannot be self-selected during registration.
- **Admin-only routes** protected by `RequireRole` middleware.
- **Clinic-scoped access** verified at the service layer.

## Rate Limiting

- **IP-based rate limiting** with trusted client IP extraction (X-Forwarded-For, X-Real-Ip).
- **Login attempt locking** after configurable failures.
- **Per-endpoint burst limits** configurable via environment variables.

## CORS

- **Never emits `*`** when credentials are enabled.
- **Echoes the actual origin** for credentialed requests.
- **Vary: Origin** header is included.
- **Production rejects wildcard origins** at config validation time.

## Input Validation

- **Centralized validator** package for email, phone, password, role, UUID.
- **SQL injection protection** via sqlc-generated parameterized queries.
- **XSS protection** via JSON responses and content-type headers.

## Secrets Management

- **No secrets tracked in git.** Verified by `TestTrackedEnvFilesContainNoLiveSecrets`.
- **Secret ownership** documented per category.
- **Rotation cadence:** 90 days for all credentials.
- **Repository history cleanup** procedure documented for accidental commits.

## Audit Logging

- **User activities** logged to the database (login, logout, profile updates).
- **Data access** logged for sensitive operations.
- **Structured logs** with request IDs for traceability.
- **Log redaction** for passwords, tokens, OTPs, and API keys.

## Transport Security

- **TLS 1.2+** required for production database connections (`sslmode=require`).
- **TLS termination** at the load balancer / CDN.
- **HSTS** enabled.

## Dependency Security

- **Go modules** verified in CI (`go mod verify`).
- **Vulnerability scanning** recommended (e.g., `govulncheck`).
- **Dependency updates** reviewed before merge.

## Incident Response

- **Severity levels** defined (SEV-1 to SEV-4).
- **Escalation path** documented.
- **On-call rotation** active.
- **Post-incident reviews** required for SEV-1 and SEV-2.

## Compliance Notes

- **POPIA-ready:** Consent tracking, data retention policies, user deletion.
- **HIPAA-ready architecture:** Encryption in transit, audit logging, access controls.
- **Not yet certified:** Formal HIPAA BAA, SOC 2, or ISO 27001 certification requires additional third-party audit.

## Security Review Cadence

- **Monthly:** Dependency vulnerability scan.
- **Quarterly:** Access review, penetration test (if budget allows).
- **Annually:** Full security posture review and policy updates.
