# Capacity Planning

This document defines CPU, memory, connection-pool, and replica sizing assumptions.

## Baseline Assumptions

| Metric | Baseline | Peak |
|--------|----------|------|
| Concurrent users | 500 | 5,000 |
| Requests per second | 100 | 1,000 |
| Database connections | 25 | 100 |
| WebSocket connections | 50 | 500 |
| Average request latency | 50ms | 200ms |

## API Service Sizing

### Per Instance

| Resource | Minimum | Recommended | Maximum |
|----------|---------|-------------|---------|
| CPU | 0.5 vCPU | 1 vCPU | 2 vCPU |
| Memory | 512 MB | 2 GB | 4 GB |
| Goroutines | ~100 | ~500 | ~2,000 |

### Connection Pools (Per Instance)

| Pool | Size | Notes |
|------|------|-------|
| Database (pgx) | 25 max, 5 min | Shared across handlers |
| Redis | 10 max, 3 min | Shared across cache operations |
| HTTP client | 100 max idle | For external API calls |

## Database Sizing

| Metric | Initial | 12-month projection |
|--------|---------|---------------------|
| Storage | 10 GB | 100 GB |
| IOPS | 500 | 2,000 |
| Connections | 100 max | 500 max |

## Redis Sizing

| Metric | Initial | 12-month projection |
|--------|---------|---------------------|
| Memory | 256 MB | 1 GB |
| Connections | 100 max | 500 max |

## Scaling Triggers

### Scale Up

- CPU > 70% for 2 minutes.
- Memory > 80% for 2 minutes.
- Request latency p99 > 500ms for 5 minutes.
- Error rate > 1% for 2 minutes.
- Active connections > 80% of pool capacity.

### Scale Down

- CPU < 30% for 10 minutes.
- Memory < 40% for 10 minutes.
- Request latency p99 < 200ms for 10 minutes.

## Load Testing

Run load tests quarterly:

```bash
# Example using k6
k6 run --vus 1000 --duration 5m load-test.js
```

Verify:
- [ ] No 5xx errors.
- [ ] p99 latency < 500ms.
- [ ] Database connection pool does not exhaust.
- [ ] Autoscaling triggers correctly.

## Cost Projections

| Component | Monthly Cost (Initial) | Monthly Cost (12 months) |
|-----------|------------------------|--------------------------|
| API (2 instances) | $50 | $200 |
| PostgreSQL | $50 | $150 |
| Redis | $20 | $50 |
| NATS | $10 | $30 |
| Email | $10 | $50 |
| Monitoring | $0 | $30 |
| **Total** | **$140** | **$510** |

## Review Cadence

- **Monthly:** Review resource utilization dashboards.
- **Quarterly:** Run load tests and adjust sizing.
- **Annually:** Re-evaluate cost projections and provider options.
