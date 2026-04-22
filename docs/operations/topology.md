# Production Topology

This document defines the production hosting topology for the Healthcare Access Connector backend.

## Deployment Platform

**Primary:** Render.com (Web Service)
**Alternative:** Fly.io, AWS ECS, or Google Cloud Run

## Architecture Overview

```
Internet
    |
    v
[Cloudflare / CDN]  (DNS, DDoS protection)
    |
    v
[Load Balancer]     (TLS termination, rate limiting)
    |
    v
[Healthcare Access Connector API]  (Go backend, 2+ replicas)
    |                    |
    v                    v
[PostgreSQL]        [Redis]
(Supabase / RDS)    (Upstash / ElastiCache)
    |
    v
[NATS]              [Email Provider]
(NATS Cloud)        (Resend / SES)
```

## Components

### API Service

- **Runtime:** Docker container on Render
- **Instances:** Minimum 2, maximum 10 (autoscaling based on CPU/memory)
- **Health checks:** `/ready` every 30 seconds
- **Rolling deploy:** 1 instance at a time, wait for healthy

### Database

- **Provider:** Managed PostgreSQL (Supabase or AWS RDS)
- **Version:** PostgreSQL 16
- **High availability:** Enabled (multi-AZ if using RDS)
- **Backups:** Daily automated + PITR

### Cache

- **Provider:** Managed Redis (Upstash or ElastiCache)
- **Version:** Redis 7
- **Persistence:** AOF enabled

### Message Broker

- **Provider:** NATS Cloud or self-hosted NATS
- **JetStream:** Enabled for persistence

### Email

- **Primary:** Resend
- **Fallback:** AWS SES
- **Local dev:** Mailpit

## TLS Termination

TLS terminates at the **load balancer / CDN**.
- Traffic between LB and API is **HTTPS**.
- Internal service communication uses **TLS** where supported.

## Reverse Proxy Behavior

- The load balancer sets `X-Forwarded-For` and `X-Real-Ip` headers.
- The API uses these headers for client IP extraction (see rate limiting config).
- WebSocket connections are forwarded with `Upgrade` and `Connection` headers.

## Instance Sizing

| Component | CPU | Memory | Replicas |
|-----------|-----|--------|----------|
| API | 1 vCPU | 2 GB | 2-10 |
| PostgreSQL | 2 vCPU | 4 GB | 1 (HA pair) |
| Redis | 1 vCPU | 1 GB | 1 (HA pair) |

## Autoscaling Policy

- **Scale up:** CPU > 70% for 2 minutes, or request queue > 100.
- **Scale down:** CPU < 30% for 5 minutes.
- **Cooldown:** 3 minutes between scaling events.

## WebSocket Considerations

- WebSocket connections are **stateful**.
- Sticky sessions are **not required** if all instances share the same Redis backplane.
- For multi-instance deployments, ensure the load balancer supports WebSocket forwarding.

## Environment Isolation

| Environment | Purpose | Data |
|-------------|---------|------|
| Production | Live user traffic | Real data |
| Staging | Pre-release validation | Anonymized snapshot |
| Development | Local development | Synthetic data |

## Validation

Before declaring the topology ready:

- [ ] Deploy to staging with the target topology.
- [ ] Run load tests (e.g., 1000 concurrent users).
- [ ] Verify autoscaling triggers correctly.
- [ ] Test failover by restarting one API instance.
- [ ] Verify WebSocket connections survive instance restarts.
