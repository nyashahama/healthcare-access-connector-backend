# Alerting Guide

This document defines alerts for the Healthcare Access Connector backend.

## Alert Philosophy

- **Page on symptoms, not causes.** Alert when user-impacting symptoms occur.
- **Every alert must have a runbook.** If there's no runbook, there's no alert.
- **Severity drives response time.**

## Alert Severity Levels

| Severity | Response Time | Channel | Example |
|----------|--------------|---------|---------|
| **critical** | 5 minutes | Pager / SMS | Database down, 500 spike |
| **warning** | 30 minutes | Slack / Email | Elevated error rate, latency p99 high |
| **info** | Next business day | Dashboard / Email | Certificate expiry in 30 days |

## Alert Definitions

### Critical Alerts

#### DatabaseUnhealthy

- **Condition:** `health{service="database"} == 0` for 2 minutes
- **Impact:** Service cannot serve traffic
- **Runbook:** `docs/operations/dependency-policy.md`
- **Escalation:** Platform owner -> Data owner

#### RedisUnavailable

- **Condition:** `health{service="cache"} == "degraded"` for 3 minutes
- **Impact:** Auth and session cache miss storm, elevated DB load
- **Runbook:** Check Redis connection pool, failover to standby
- **Escalation:** Platform owner

#### HighErrorRate

- **Condition:** `rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) > 0.1` for 3 minutes
- **Impact:** 10% of requests failing
- **Runbook:** Check logs for panic or dependency failure
- **Escalation:** Application owner

#### HealthEndpointDown

- **Condition:** `up{job="healthcare-access-connector"} == 0` for 2 minutes
- **Impact:** Service completely unavailable
- **Runbook:** Check deployment status, pod events, resource limits
- **Escalation:** Platform owner

### Warning Alerts

#### ElevatedLatency

- **Condition:** `histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[5m])) > 2` for 5 minutes
- **Impact:** Slow user experience
- **Runbook:** Check database slow queries, Redis latency, external API timeouts
- **Escalation:** Application owner

#### AuthAnomalies

- **Condition:** `rate(http_requests_total{path="/api/v1/auth/login",status="401"}[5m]) > 10` for 5 minutes
- **Impact:** Possible brute-force attack
- **Runbook:** Review rate limiter behavior, check source IPs, enable WAF
- **Escalation:** Security owner

#### EmailServiceDegraded

- **Condition:** `health{service="email"} == "degraded"` for 10 minutes
- **Impact:** Users not receiving transactional emails
- **Runbook:** Check email provider status, verify SMTP/SES/Resend credentials
- **Escalation:** Ops owner

### Info Alerts

#### CertificateExpiry

- **Condition:** TLS certificate expires in < 30 days
- **Impact:** Service will become unreachable
- **Runbook:** Renew certificate via Let's Encrypt or ACM
- **Escalation:** Platform owner

#### LowTestCoverage

- **Condition:** CI coverage report drops below threshold
- **Impact:** Reduced confidence in releases
- **Runbook:** Add tests for uncovered code paths
- **Escalation:** Application owner

## Alert Routing

| Owner | Primary Channel | Secondary Channel |
|-------|----------------|-------------------|
| Platform | `#alerts-platform` | PagerDuty |
| Application | `#alerts-app` | Email |
| Security | `#alerts-security` | Email |
| Ops | `#alerts-ops` | Email |
| Data | `#alerts-data` | Email |

## Dashboards

### Required Dashboards

1. **API Overview** — RPS, latency p50/p99, error rate by endpoint
2. **Dependency Health** — DB, Redis, NATS, Email health over time
3. **Auth Security** — Login attempts, 401/403 rates, session counts
4. **Infrastructure** — CPU, memory, goroutines, GC pressure
5. **Business Metrics** — Registrations, appointments, consultations

## Adding New Alerts

1. Define the PromQL expression.
2. Document the impact and runbook steps.
3. Assign severity and owner.
4. Add to CI validation (if using Prometheus rule files).
5. Test the alert in staging before production.
