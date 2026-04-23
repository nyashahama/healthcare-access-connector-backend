# Backup and Restore Guide

This document defines backup frequency, retention, encryption, and restore procedures for production data.

## Backup Scope

| Data | Included | Frequency | Retention |
|------|----------|-----------|-----------|
| PostgreSQL database | Yes | Daily + continuous WAL | 30 days |
| Redis cache | No | Ephemeral — rebuilds from DB | N/A |
| NATS streams | Yes (if used for persistence) | Daily | 7 days |
| Environment config | Yes | Every change | Indefinite (git) |

## PostgreSQL Backups

### Managed PostgreSQL (Recommended)

If using a managed provider (e.g., Supabase, AWS RDS, Google Cloud SQL):

- Enable **automated daily backups**.
- Enable **Point-in-Time Recovery (PITR)** with WAL archiving.
- Verify backup integrity monthly.

### Self-Managed PostgreSQL

If running your own PostgreSQL:

```bash
# Daily logical backup (pg_dump)
pg_dump "$DB_URL" | gzip > "backup-$(date +%Y%m%d-%H%M%S).sql.gz"

# Upload to encrypted object storage (S3, GCS, etc.)
aws s3 cp backup-*.sql.gz s3://hac-backups/postgres/ --sse AES256

# WAL archiving for PITR (configure in postgresql.conf)
# archive_command = 'aws s3 cp %p s3://hac-backups/wal/%f'
```

### Backup Verification

Backups are worthless if they cannot be restored. Verify monthly:

```bash
# Restore to a temporary database
createdb test_restore
zcat backup-20260422-020000.sql.gz | psql test_restore

# Run a quick sanity check
psql test_restore -c "SELECT COUNT(*) FROM users;"

# Drop test database
dropdb test_restore
```

## Backup Encryption

All backups must be encrypted:

- **At rest:** Use provider-managed encryption (SSE-S3, SSE-KMS) or GPG.
- **In transit:** Use TLS for all backup uploads and downloads.

## Restore Procedures

### Full Database Restore

Use only in disaster recovery scenarios.

```bash
# 1. Stop application (prevent writes)
# 2. Drop and recreate database
dropdb app_db
createdb app_db

# 3. Restore from backup
gunzip -c backup-20260422-020000.sql.gz | psql app_db

# 4. Verify schema and data
psql app_db -c "\\dt"

# 5. Re-run any migrations applied after the backup
migrate -path database/migrations -database "$DB_URL" up

# 6. Start application
# 7. Run smoke tests
```

### Point-in-Time Recovery

If WAL archiving is enabled:

```bash
# Restore base backup, then replay WAL to a specific timestamp
pg_basebackup -D /var/lib/postgresql/restore -Fp -Xs -P -v
# Configure recovery.conf or postgresql.auto.conf for PITR
```

## Restore Drill

Execute a restore drill in a non-production environment **quarterly**:

1. Restore the latest backup to a fresh database.
2. Run migrations to catch up.
3. Boot the application against the restored database.
4. Run smoke tests.
5. Document the time taken and any issues.

## Retention and Deletion

| Backup Type | Retention | Deletion Method |
|-------------|-----------|-----------------|
| Daily full | 30 days | Automated lifecycle policy |
| Weekly full | 90 days | Automated lifecycle policy |
| Monthly full | 1 year | Manual review |
| WAL archives | 7 days | Automated lifecycle policy |

## Ownership

- **Backup configuration:** Platform owner
- **Backup verification:** Data owner
- **Restore execution:** Data owner + Platform owner
- **Restore drill scheduling:** Ops owner

## Escalation

If a restore is needed in production:

1. **Data owner** approves the restore.
2. **Platform owner** executes the restore.
3. **Ops owner** verifies service recovery.
4. **Security owner** reviews if data loss involved PHI.
