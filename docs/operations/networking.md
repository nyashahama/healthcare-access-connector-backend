# Networking Guide

This document defines service-to-service network policies and allowed ingress.

## Ingress Rules

### Public Ingress

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 443 | TCP | Internet | HTTPS traffic |
| 443 | TCP | Internet | WebSocket traffic |

### Internal Ingress

| Port | Protocol | Source | Purpose |
|------|----------|--------|---------|
| 8080 | TCP | Load balancer | Health checks |
| 9090 | TCP | Internal monitoring | Prometheus metrics |
| 6060 | TCP | Internal diagnostics | pprof (if enabled) |

## Egress Rules

| Destination | Port | Purpose |
|-------------|------|---------|
| PostgreSQL | 5432 | Database |
| Redis | 6379 | Cache |
| NATS | 4222 | Messaging |
| Resend API | 443 | Email |
| HuggingFace Router | 443 | AI summarization |

## Network Policy

### API Service

- Allow ingress from load balancer on 8080.
- Allow egress to PostgreSQL, Redis, NATS.
- Allow egress to external APIs (Resend, HuggingFace).
- Deny all other ingress/egress by default.

### Database

- Allow ingress from API service only.
- Deny all egress.
- No public internet access.

### Redis

- Allow ingress from API service only.
- Deny all egress.
- No public internet access.

## Trusted Proxy Configuration

The API trusts these proxy IP ranges for `X-Forwarded-For`:

- Render load balancer IPs (if using Render)
- Cloudflare IP ranges (if using Cloudflare)
- Internal VPC CIDR (if using AWS/GCP)

Update `internal/middleware/ratelimit.go` if the trusted proxy list changes.

## DNS

| Record | Type | Target |
|--------|------|--------|
| api.example.com | A / CNAME | Load balancer |
| status.example.com | CNAME | Status page provider |

## TLS

- **Termination:** Load balancer / CDN.
- **Certificate:** Let's Encrypt (auto-renewed) or provider-managed.
- **Minimum TLS version:** 1.2.
- **HSTS:** Enabled.

## Firewall Rules

If using a cloud provider firewall:

1. Default deny all.
2. Allow 443 from anywhere.
3. Allow 8080 from load balancer security group only.
4. Allow 5432 from API security group only.
5. Allow 6379 from API security group only.
