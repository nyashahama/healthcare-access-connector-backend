# Dependency Criticality Policy

This document defines the criticality of each external dependency and how the service behaves when a dependency is missing or degraded.

## Dependency Matrix

| Dependency | Criticality | Required for Traffic | Failure Behavior | Recovery |
|------------|-------------|----------------------|------------------|----------|
| PostgreSQL | **Critical** | Yes | Startup fails fast. Health returns 503. Readiness fails. | Automatic on next pool ping. |
| Redis | **Critical** | Yes | Startup fails fast. Health returns 503. Readiness fails. | Automatic on next pool ping. |
| NATS | **Optional** | No | Log warning. Async operations disabled. Health shows "unavailable". | Automatic when NATS reconnects. |
| Email | **Optional** | No | Log warning. Email queue accumulates or drops. Health shows "degraded". | Automatic when provider recovers. |
| AI (HuggingFace) | **Best-effort** | No | Disabled if no API key. Health shows "disabled". | Automatic when API key valid and reachable. |
| WebSocket Hub | **Critical** | Yes (for telemedicine) | Startup fails if config invalid. Hub stops on context cancel. | Requires process restart. |

## Definitions

- **Critical:** The service cannot start or serve traffic without this dependency. Failure is fatal.
- **Optional:** The service starts and serves traffic, but specific features are disabled. Failure is logged and surfaced in health checks.
- **Best-effort:** The service ignores failures. The feature is silently disabled or falls back to a no-op.

## Startup Behavior

1. **Config validation** runs first. If invalid, the process exits with code 1 before any connections are opened.
2. **Database pool** is initialized next. If the pool cannot be created or the initial ping fails, the process exits.
3. **Redis cache** is initialized. If the cache cannot connect, the process exits.
4. **NATS broker** is initialized. If NATS is unavailable, a warning is logged and `broker` is set to `nil`. Async messaging is disabled.
5. **AI client** is initialized. If the config is invalid or no API key is present, the client is created but marked unavailable.
6. **WebSocket hub** is initialized. If the config is invalid, startup fails. The hub runs in a background goroutine.
7. **Email service** is initialized. If the provider is unavailable, `emailService` is set to `nil`. Emails are not sent.

## Readiness Semantics

`/ready` returns **200** only when:

- PostgreSQL responds to `Ping()` within 2 seconds.
- Redis responds to `Ping()` within 2 seconds.

`/ready` returns **503** when either critical dependency is unreachable.

## Health Semantics

`/health` returns a comprehensive status for all dependencies:

- **database:** `healthy` or `unhealthy` (fatal)
- **cache:** `healthy` or `degraded`
- **messaging:** `healthy`, `unavailable`, or omitted if nil
- **email:** `healthy`, `degraded`, or omitted if nil
- **ai:** `healthy`, `disabled`, or omitted if nil
- **websocket:** `healthy` or `unavailable`

The HTTP status is:
- **200** if all critical dependencies are healthy.
- **503** if any critical dependency is unhealthy.

## Shutdown Order

Cleanup is performed in reverse initialization order:

1. **Email service** — flush any queued messages and close connections.
2. **WebSocket hub** — cancel the hub context, which stops the event loop and unregisters all clients.
3. **Message broker** — close the NATS connection.
4. **Database pool** — close all connections and release the pool.

## Deployment Modes

### Minimal Mode (no optional deps)

Suitable for local development and some integration tests:

- `NATS_URL=` (empty)
- `EMAIL_PROVIDER=` (empty)
- `AI_ENABLED=false`

### Full Mode (all deps)

Suitable for production and staging:

- All critical and optional dependencies configured and reachable.

### Degraded Mode (one optional dep down)

Suitable for resilience testing:

- Redis available, NATS down, Email down.
- The service should still serve HTTP traffic and return 200 for readiness.

## Verification

Run the health and readiness tests:

```bash
go test ./internal/app ./internal/server -v
```

Simulate a degraded dependency in local development:

```bash
# Start without NATS
NATS_URL= go run ./cmd/api/main.go
```
