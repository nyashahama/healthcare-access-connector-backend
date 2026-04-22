# Service Level Indicators (SLIs) and Service Level Objectives (SLOs)

This document defines the SLIs and SLOs for the Healthcare Access Connector backend.

## SLIs

### Availability

- **Definition:** The proportion of valid requests that result in a successful response (2xx/3xx).
- **Measurement:** `1 - (rate(http_requests_total{status=~"5.."}[window]) / rate(http_requests_total[window]))`

### Latency

- **Definition:** The proportion of requests that complete within a threshold.
- **Measurement:** `histogram_quantile(0.99, rate(http_request_duration_seconds_bucket[window]))`

### Error Rate

- **Definition:** The proportion of requests that result in a 5xx error.
- **Measurement:** `rate(http_requests_total{status=~"5.."}[window]) / rate(http_requests_total[window])`

### Throughput

- **Definition:** Requests per second the system handles.
- **Measurement:** `rate(http_requests_total[1m])`

## SLOs

### API Availability

- **Objective:** 99.9% of valid requests return a successful response over a 30-day window.
- **Error Budget:** 0.1% of requests may fail. For 1M requests/month, that's 1,000 failed requests.
- **Alert:** Warn at 50% error budget consumed; page at 80%.

### API Latency

- **Objective:** 99% of requests complete in < 500ms over a 30-day window.
- **Measurement:** p99 latency
- **Alert:** Warn when p99 > 500ms for 5 minutes.

### Auth Endpoint Latency

- **Objective:** 99% of login and token refresh requests complete in < 200ms.
- **Measurement:** p99 latency for `/api/v1/auth/login` and `/api/v1/auth/refresh`
- **Alert:** Warn when p99 > 200ms for 5 minutes.

### Database Query Performance

- **Objective:** 99% of database queries complete in < 100ms.
- **Measurement:** p99 query duration (if instrumented)
- **Alert:** Warn when p99 > 100ms for 5 minutes.

### Health Check Reliability

- **Objective:** `/health` and `/ready` respond within 2 seconds 99.9% of the time.
- **Alert:** Page when `/health` or `/ready` fails for 2 minutes.

## Error Budget Policy

### Error Budget Calculation

```
Error Budget = 1 - SLO
Monthly Budget = Error Budget * Total Requests
```

### Burn Rate Alerts

| Burn Rate | Lookback | Alert Action |
|-----------|----------|--------------|
| 1x | 30 days | Dashboard review |
| 2x | 15 days | Warning |
| 6x | 5 days | Page |
| 10x | 3 days | Page + war room |

### Error Budget Exhaustion Response

1. **50% consumed:** Review recent deployments and roll back if correlated.
2. **80% consumed:** Halt non-critical releases. Focus on reliability work.
3. **100% consumed:** Freeze feature work. All engineering effort goes to reliability until SLO is met.

## SLO Review Cadence

- **Monthly:** Review SLO attainment and error budget consumption.
- **Quarterly:** Adjust SLOs based on user feedback and operational data.
- **Annually:** Re-evaluate whether SLOs still match business needs.

## SLIs by Endpoint Category

### Public Endpoints (registration, login, health)

| SLI | Target |
|-----|--------|
| Availability | 99.9% |
| Latency p99 | < 500ms |
| Error rate | < 0.1% |

### Protected Endpoints (appointments, profiles)

| SLI | Target |
|-----|--------|
| Availability | 99.5% |
| Latency p99 | < 1s |
| Error rate | < 0.5% |

### Admin Endpoints

| SLI | Target |
|-----|--------|
| Availability | 99.0% |
| Latency p99 | < 2s |
| Error rate | < 1.0% |

## Dependencies

- [Observability Guide](observability.md)
- [Alerting Guide](alerting.md)
- [Dependency Policy](dependency-policy.md)
