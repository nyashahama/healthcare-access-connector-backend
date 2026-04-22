#!/usr/bin/env bash
set -euo pipefail

# Smoke test for the Healthcare Access Connector backend.
# Usage: ./tests/smoke/smoke.sh [PORT]
# Requires: curl, jq (optional)

PORT="${1:-8080}"
BASE_URL="http://localhost:${PORT}"
TIMEOUT=30

echo "=== Smoke Test ==="
echo "Target: ${BASE_URL}"
echo ""

# Helper: HTTP GET with status code extraction
http_get() {
	local url="$1"
	local expected="$2"
	local label="$3"

	local status
	status=$(curl -s -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT}" "${url}" || true)

	if [ "${status}" == "${expected}" ]; then
		echo "  [PASS] ${label} (HTTP ${status})"
	else
		echo "  [FAIL] ${label} expected HTTP ${expected}, got ${status}"
		return 1
	fi
}

# Helper: HTTP POST with JSON body
http_post_json() {
	local url="$1"
	local body="$2"
	local expected="$3"
	local label="$4"

	local status
	status=$(curl -s -o /dev/null -w "%{http_code}" \
		--max-time "${TIMEOUT}" \
		-H "Content-Type: application/json" \
		-d "${body}" \
		"${url}" || true)

	if [ "${status}" == "${expected}" ]; then
		echo "  [PASS] ${label} (HTTP ${status})"
	else
		echo "  [FAIL] ${label} expected HTTP ${expected}, got ${status}"
		return 1
	fi
}

echo "1. Health endpoint"
http_get "${BASE_URL}/health" "200" "GET /health"

echo ""
echo "2. Readiness endpoint"
http_get "${BASE_URL}/ready" "200" "GET /ready"

echo ""
echo "3. Liveness endpoint"
http_get "${BASE_URL}/live" "200" "GET /live"

echo ""
echo "4. Metrics endpoint (if enabled)"
metrics_status=$(curl -s -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT}" "${BASE_URL}/metrics" || true)
if [ "${metrics_status}" == "200" ]; then
	echo "  [PASS] GET /metrics (HTTP 200)"
elif [ "${metrics_status}" == "404" ]; then
	echo "  [INFO] GET /metrics returned 404 (metrics may be disabled)"
else
	echo "  [FAIL] GET /metrics unexpected status ${metrics_status}"
	exit 1
fi

echo ""
echo "5. 404 handler"
http_get "${BASE_URL}/nonexistent" "404" "GET /nonexistent"

echo ""
echo "6. Auth register (validation failure)"
http_post_json "${BASE_URL}/api/v1/auth/register" \
	'{"email":"bad-email","password":"short"}' \
	"400" \
	"POST /api/v1/auth/register (bad input)"

echo ""
echo "7. Auth login (unknown user)"
http_post_json "${BASE_URL}/api/v1/auth/login" \
	'{"email":"notfound@example.com","password":"SecurePass123!"}' \
	"401" \
	"POST /api/v1/auth/login (unknown user)"

echo ""
echo "=== Smoke Test Complete ==="
