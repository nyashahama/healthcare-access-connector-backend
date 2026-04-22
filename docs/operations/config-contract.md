# Runtime Configuration Contract

This document defines the single, canonical runtime configuration contract for the Healthcare Access Connector backend. All environments — local development, Docker Compose, CI, staging, and production — must use these exact variable names.

## Principle

There is exactly one config contract. No package reads environment variables that the main `config.Load()` does not validate. If a variable is documented here, it is consumed by runtime code. If it is not documented here, it is either internal to a sub-package or not yet part of the contract.

## Required Variables

These variables must be set in every environment. `config.Load()` returns an error if any are missing or invalid.

| Variable | Type | Description | Validation |
|----------|------|-------------|------------|
| `DB_URL` | string | PostgreSQL connection URL | Required, non-empty. In production must contain `sslmode=require`. |
| `JWT_SECRET` | string | JWT signing secret | Required, minimum 32 characters. |
| `ENVIRONMENT` | string | Runtime environment | One of: `development`, `staging`, `production`. |

## Server Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP server port |
| `LOG_LEVEL` | `info` | zerolog level (`debug`, `info`, `warn`, `error`) |
| `TIMEOUT_SECONDS` | `30s` | General request timeout |
| `READ_TIMEOUT` | `10s` | HTTP read timeout |
| `WRITE_TIMEOUT` | `10s` | HTTP write timeout |
| `IDLE_TIMEOUT` | `60s` | HTTP idle timeout |

## Security Variables

| Variable | Default | Description | Validation |
|----------|---------|-------------|------------|
| `ALLOWED_ORIGINS` | `*` | Comma-separated CORS origins | `*` is rejected in production. |
| `RATE_LIMIT_RPS` | `10` | Rate limit requests per second | Must be >= 1. |
| `RATE_LIMIT_BURST` | `20` | Rate limit burst capacity | Must be >= `RATE_LIMIT_RPS`. |
| `BCRYPT_COST` | `10` (dev: `4`) | bcrypt work factor | Between 4 and 31. |
| `JWT_EXPIRY_HOURS` | `24` | JWT token lifetime | Minimum 1 minute. |
| `LOGIN_MAX_ATTEMPTS` | `5` | Failed login threshold | >= 1. |
| `LOGIN_LOCKOUT_MINS` | `5` | Lockout duration | >= 1 minute. |

## Database Pool Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_MAX_CONNS` | `25` | Max open connections |
| `DB_MIN_CONNS` | `5` | Min idle connections |
| `DB_MAX_CONN_LIFETIME` | `1h` | Max connection lifetime |
| `DB_MAX_CONN_IDLE_TIME` | `5m` | Max connection idle time |

## Redis Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379` | Redis connection URL |
| `REDIS_MAX_CONNS` | `10` | Max Redis connections |
| `REDIS_MIN_IDLE_CONNS` | `3` | Min idle Redis connections |
| `REDIS_POOL_TIMEOUT` | `1s` | Redis pool timeout |

## Email Variables (Canonical Names)

> **Note:** These names are shared between `internal/config` and `internal/email`. There is no split naming.

| Variable | Default | Description |
|----------|---------|-------------|
| `EMAIL_PROVIDER` | *(empty)* | Provider: `smtp`, `resend`, or `ses` |
| `EMAIL_FROM_ADDRESS` | *(empty)* | From address for transactional email |
| `EMAIL_FROM_NAME` | `Healthcare Access Connector` | Display name for From address |
| `SMTP_HOST` | *(empty)* | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USERNAME` | *(empty)* | SMTP authentication username |
| `SMTP_PASSWORD` | *(empty)* | SMTP authentication password |

**Email-specific variables** (read directly by `internal/email`):

| Variable | Default | Description |
|----------|---------|-------------|
| `RESEND_API_KEY` | *(empty)* | Resend API key |
| `AWS_REGION` | `us-east-1` | AWS region for SES |
| `AWS_ACCESS_KEY_ID` | *(empty)* | AWS access key |
| `AWS_SECRET_ACCESS_KEY` | *(empty)* | AWS secret key |

## NATS Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NATS_URL` | `nats://localhost:4222` | NATS connection URL. Empty disables async messaging. |

## Cache Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CACHE_ENABLED` | `true` | Enable Redis caching |
| `CACHE_DEFAULT_TTL` | `5m` | Default cache TTL |
| `CACHE_USER_TTL` | `10m` | User data cache TTL |
| `CACHE_SESSION_TTL` | `1m` | Session cache TTL |
| `CACHE_TOKEN_TTL` | `1m` | Token cache TTL |

## Observability Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `METRICS_ENABLED` | `true` | Enable Prometheus metrics endpoint |
| `METRICS_PORT` | `9090` | Metrics listener port (if separate) |
| `PROFILING_ENABLED` | `false` | Enable pprof endpoints |
| `PROFILING_PORT` | `6060` | pprof listener port |

## WebSocket Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WS_PING_INTERVAL` | `30s` | WebSocket ping interval |
| `WS_PONG_WAIT` | `60s` | WebSocket pong timeout |
| `WS_WRITE_WAIT` | `10s` | WebSocket write timeout |
| `WS_MAX_MESSAGE_BYTES` | `8192` | Max WebSocket message size |
| `WS_SEND_CHANNEL_BUFFER` | `256` | WebSocket send buffer size |

## AI Variables (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `AI_ENABLED` | `false` | Enable AI integrations |
| `AI_MODEL` | *(empty)* | Model identifier |
| `AI_REQUEST_TIMEOUT` | `30s` | AI API timeout |
| `AI_MAX_TOKENS` | `512` | Max tokens per request |

## Frontend Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FRONTEND_URL` | *(empty)* | Base URL of the frontend application |

## HTTP Client Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HTTP_CLIENT_TIMEOUT` | `30s` | External HTTP request timeout |
| `HTTP_MAX_IDLE_CONNS` | `100` | Max idle connections |
| `HTTP_MAX_CONNS_PER_HOST` | `10` | Max connections per host |
| `HTTP_IDLE_CONN_TIMEOUT` | `90s` | Idle connection timeout |

## Healthcare Domain Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APPOINTMENT_REMINDER_HOURS` | `24` | Hours before appointment to send reminder |
| `MAX_APPOINTMENTS_PER_DAY` | `10` | Max appointments per provider per day |
| `PROVIDER_SEARCH_RADIUS_KM` | `50` | Search radius for nearby providers |

## Production Startup Rules

`config.Load()` enforces the following in `ENVIRONMENT=production`:

1. `DB_URL` must contain `sslmode=require`.
2. `ALLOWED_ORIGINS` must not contain `*`.
3. If `EMAIL_PROVIDER=smtp`, `SMTP_HOST` and `EMAIL_FROM_ADDRESS` must be set.
4. If `EMAIL_PROVIDER=ses`, `EMAIL_FROM_ADDRESS` must be set.

## Change Process

1. Any new environment variable must be added to this document **before** it is used in code.
2. Any rename must update `internal/config/config.go`, all `.env.*` files, `docker-compose.yml`, `Makefile`, and this document in the same commit.
3. All changes must include tests in `internal/config/config_test.go` or `env_contract_test.go`.

## Verification

Run the config validation tests after any change:

```bash
go test ./internal/config -v
```

Run the env-file guard test before every commit:

```bash
go test ./internal/config -run TestTrackedEnvFilesContainNoLiveSecrets -v
```
