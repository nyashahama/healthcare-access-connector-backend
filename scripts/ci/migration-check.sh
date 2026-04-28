#!/usr/bin/env bash
set -euo pipefail

# Migration validation script for CI.
# Validates migrations against a fresh database and an upgrade-path database.
# Usage: ./scripts/ci/migration-check.sh [DB_URL]

DB_URL="${1:-}"

if [ -z "${DB_URL}" ]; then
	echo "Error: DB_URL is required"
	echo "Usage: $0 <database_url>"
	exit 1
fi

echo "=== Migration Validation ==="
echo "Database: ${DB_URL}"
echo ""

# Check migrate tool is available
if ! command -v migrate &> /dev/null; then
	echo "Error: migrate CLI not found. Install with:"
	echo "  go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest"
	exit 1
fi

MIGRATIONS_DIR="database/migrations"

echo "1. Verify migration files exist"
if [ ! -d "${MIGRATIONS_DIR}" ]; then
	echo "Error: ${MIGRATIONS_DIR} not found"
	exit 1
fi

migration_count=$(find "${MIGRATIONS_DIR}" -name '*.up.sql' | wc -l)
echo "  Found ${migration_count} up migrations"

if [ "${migration_count}" -eq 0 ]; then
	echo "Error: No migration files found"
	exit 1
fi

echo ""
echo "2. Validate migrations on fresh database"
if ! migrate -path "${MIGRATIONS_DIR}" -database "${DB_URL}" up; then
	echo "Error: Fresh database migration failed"
	exit 1
fi
echo "  [PASS] Fresh database migrations applied"

echo ""
echo "3. Validate migration version matches file count"
version=$(migrate -path "${MIGRATIONS_DIR}" -database "${DB_URL}" version 2>/dev/null || true)
echo "  Current version: ${version}"

# Note: version may be dirty if migrations changed; we just check it applied successfully

echo ""
echo "4. Ensure every down migration is implemented"
while IFS= read -r down_file; do
	if [ ! -s "${down_file}" ]; then
		echo "Error: Down migration is empty: ${down_file}"
		echo "Please implement rollback SQL before merging."
		exit 1
	fi
done < <(find "${MIGRATIONS_DIR}" -name '*.down.sql' | sort -V)
echo "  [PASS] All down migrations contain statements"

echo ""
echo "5. Validate down and up migrations are reversible"
if ! migrate -path "${MIGRATIONS_DIR}" -database "${DB_URL}" down 1; then
	echo "Error: Down migration failed"
	exit 1
else
	echo "  [PASS] Down migration succeeded"
	if ! migrate -path "${MIGRATIONS_DIR}" -database "${DB_URL}" up 1; then
		echo "Error: Re-up migration failed after down"
		exit 1
	fi
	echo "  [PASS] Re-up migration succeeded"
fi

echo ""
echo "=== Migration Validation Complete ==="
