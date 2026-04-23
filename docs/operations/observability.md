# Observability Guide

This document describes the logging, metrics, and diagnostics exposed by the Healthcare Access Connector backend.

## Logging

### Structured Log Fields

Every HTTP request log entry includes the following fields:

| Field | Description | Example |
|-------|-------------|---------|
| `request_id` | Unique request identifier from chi middleware | `abc123` |
| `method` | HTTP method | `GET`, `POST` |
| `path` | Request path with sensitive query params redacted | `/api/v1/users/123?password=[REDACTED]` |
| `client_ip` | Client IP from X-Forwarded-For, X-Real-Ip, or RemoteAddr | `203.0.113.1` |
| `user_agent` | User-Agent header (truncated if extremely long) | `Mozilla/5.0...` |
| `authorization` | Authorization header with bearer token redacted | `Bearer [REDACTED]` |
| `status` | HTTP response status code | `200`, `500` |
| `bytes` | Response body size in bytes | `1024` |
| `duration` | Request processing time | `15ms` |
| `level` | Log level based on status code | `info`, `warn`, `error` |

### Redaction Rules

The logger middleware automatically redacts:

- Query parameters named: `password`, `token`, `otp`, `api_key`, `secret`, `jwt`
- Bearer tokens in the `Authorization` header
- PHI (Protected Health Information) should never be logged in plain text

### Log Levels

| Status Code | Log Level |
|-------------|-----------|
| 1xx-2xx | `info` |
| 3xx | `info` |
| 4xx | `warn` |
| 5xx | `error` |

## Metrics

### Prometheus Endpoints

`/metrics` is exposed **only when `METRICS_ENABLED=true`**.

### Metric Definitions

| Metric Name | Type | Labels | Description |
|-------------|------|--------|-------------|
| `http_requests_total` | Counter | `path`, `method`, `status` | Total HTTP requests |
| `http_request_duration_seconds` | Histogram | `path`, `method` | Request latency |

### Cardinality Safety

- `path` labels use **chi route patterns**, not raw URLs.
- Example: `/api/v1/users/{id}` instead of `/api/v1/users/abc-123`.
- If no route pattern is matched (e.g., 404), the label is `unknown`.

### Metric Port Policy

Metrics currently live on the **main HTTP port** (`:8080`) under `/metrics`.
For high-security environments, consider moving metrics to a separate internal-only port.

## Diagnostics

### Health Endpoints

| Endpoint | Purpose | Status Codes |
|----------|---------|--------------|
| `/health` | Comprehensive dependency health | 200 healthy, 503 unhealthy |
| `/ready` | Readiness for traffic | 200 ready, 503 not ready |
| `/live` | Liveness probe | 200 alive |

### pprof / Profiling

pprof endpoints are **disabled by default** (`PROFILING_ENABLED=false`).
When enabled, they are exposed on `PROFILING_PORT` (default `6060`).

**Security note:** Never expose pprof to the public internet. Use network restrictions or an internal-only listener.

## Log Verification

Verify redaction is working:

```bash
# Start the app and make a request with a sensitive query param
curl "http://localhost:8080/api/v1/users?password=secret123"

# Check logs — password should appear as [REDACTED]
```

## Metrics Verification

```bash
# Scrape metrics
curl http://localhost:8080/metrics

# Verify path labels use route patterns, not raw IDs
grep 'http_requests_total' | grep -v 'unknown'
```
