# Migration Guide

This document describes how to create, validate, and roll back database migrations.

## Creating Migrations

```bash
make migrate-create name=add_user_sessions_table
```

This creates:
- `database/migrations/NNNNNNNN_add_user_sessions_table.up.sql`
- `database/migrations/NNNNNNNN_add_user_sessions_table.down.sql`

### Migration Rules

1. **One change per migration.** Do not combine unrelated schema changes.
2. **Down migrations must reverse the up migration.** Every `up.sql` must have a corresponding `down.sql`.
3. **Migrations must be idempotent.** Use `IF EXISTS` / `IF NOT EXISTS` where possible.
4. **Never modify an existing migration file after it has been merged to `main`.** Create a new migration instead.
5. **Avoid destructive changes without a deprecation period.** If dropping a column, first make it nullable or ignored.

## Naming Convention

Use `migrate create -ext sql -dir database/migrations -seq <name>` which produces sequential numbers.

Examples:
- `000001_create_users_table.up.sql`
- `000002_add_email_index.up.sql`

## Validation

Migrations are validated in CI on every PR:

1. **Fresh database test:** Migrations run on a clean database.
2. **Upgrade-path test:** Migrations run on a database that is one version behind.
3. **Down migration test:** The last migration is reversed and re-applied.

Run locally:

```bash
# Start a test database
docker run -d --name test-postgres -e POSTGRES_PASSWORD=postgres -p 5433:5432 postgres:16-alpine

# Validate
DB_URL="postgres://postgres:postgres@localhost:5433/postgres?sslmode=disable" ./scripts/ci/migration-check.sh "$DB_URL"

# Cleanup
docker stop test-postgres && docker rm test-postgres
```

## Migration Rollback Policy

### When to Roll Back

Only roll back a migration if:
- It was applied within the last 5 minutes.
- No application code has written data using the new schema.
- The down migration is safe and tested.

### How to Roll Back

```bash
migrate -path database/migrations -database "$DB_URL" down 1
```

### When NOT to Roll Back

If data has been written using the new schema, do **not** roll back. Instead:
1. Deploy a forward-fix migration.
2. Update application code to handle both old and new schema during the transition.

## Deployment Order

1. **Before deploy:** Run migrations in a maintenance window or during low traffic.
2. **Verify:** Confirm migration version matches the release candidate.
3. **Deploy:** Deploy the application code that depends on the new schema.
4. **Monitor:** Watch for schema-related errors in logs.

## Migration Ownership

- **Migration creation:** Application owner (with Data owner review for breaking changes).
- **Migration validation:** Data owner.
- **Migration execution:** Platform owner or automated CI/CD.
- **Migration rollback:** Data owner approval required.

## Common Mistakes

- **Modifying an already-applied migration file.** This breaks environments that already ran it.
- **Forgetting the down migration.** Always provide a reversible path.
- **Destructive changes without a transition period.** Drop columns in a follow-up release, not the same one that introduces the replacement.
- **Large data migrations in a transaction.** For big tables, use batching or run data migrations as a separate job.
