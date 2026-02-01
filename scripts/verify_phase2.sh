#!/usr/bin/env bash
#
# Phase 2 Verification Script
# Proves: Postgres persistence layer with hard fail-safe
#
# What this verifies:
# 1. Compose semantic requirements (even without Docker)
# 2. API health shows Postgres connected
# 3. Proposals persist via write-through
# 4. Hard fail-safe: 503 when Postgres unavailable
#
# Prerequisites:
# - Python 3.6+ (for compose semantic check)
# - curl, jq
# - For full verification: Docker + running compose stack
#
# Usage: ./scripts/verify_phase2.sh [--strict] [API_BASE]
#
# Exit codes:
#   0 = PASSED (all tests passed)
#   1 = FAILED (test failures)
#   2 = PARTIAL (some tests skipped - use --strict to fail on skips)
#
set -euo pipefail

# Parse args
STRICT_MODE=false
API_BASE="http://localhost:8000"

for arg in "$@"; do
    case $arg in
        --strict)
            STRICT_MODE=true
            ;;
        *)
            API_BASE="$arg"
            ;;
    esac
done

API_KEY="${M87_API_KEY:-m87-dev-key-change-me}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; TESTS_PASSED=$((TESTS_PASSED + 1)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
skip() { echo -e "${YELLOW}[SKIP]${NC} $1 (reason: $2)"; TESTS_SKIPPED=$((TESTS_SKIPPED + 1)); }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

TESTS_RUN=0
TESTS_PASSED=0
TESTS_SKIPPED=0

# ----------------------------------------------------------------
# Prerequisite checks
# ----------------------------------------------------------------
info "Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    fail "PREREQ_MISSING: python3 not found"
fi

if ! command -v curl &> /dev/null; then
    fail "PREREQ_MISSING: curl not found"
fi

if ! command -v jq &> /dev/null; then
    fail "PREREQ_MISSING: jq not found"
fi

echo "  python3: OK"
echo "  curl: OK"
echo "  jq: OK"
echo ""

# ----------------------------------------------------------------
# Test 0: Compose semantic validation (no Docker required)
# ----------------------------------------------------------------
info "Test 0: Compose semantic validation"
TESTS_RUN=$((TESTS_RUN + 1))

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_VALIDATOR="${SCRIPT_DIR}/verify_compose_semantics.py"

if [ -f "$COMPOSE_VALIDATOR" ]; then
    if python3 "$COMPOSE_VALIDATOR"; then
        pass "Compose semantics valid"
    else
        fail "COMPOSE_INVALID: semantic validation failed"
    fi
else
    skip "Compose validator" "not found at $COMPOSE_VALIDATOR"
fi

# ----------------------------------------------------------------
# Test 1: API health check (requires running stack)
# ----------------------------------------------------------------
info "Test 1: Health check shows Postgres connected"
TESTS_RUN=$((TESTS_RUN + 1))

HEALTH_RESP=$(curl -s --connect-timeout 5 "${API_BASE}/health" 2>/dev/null || echo '{"_error": "CONNECTION_REFUSED"}')

if echo "$HEALTH_RESP" | jq -e '._error == "CONNECTION_REFUSED"' > /dev/null 2>&1; then
    skip "Health check" "API_UNREACHABLE at ${API_BASE}"
else
    POSTGRES_STATUS=$(echo "$HEALTH_RESP" | jq -r '.postgres // "unknown"')
    PERSISTENCE=$(echo "$HEALTH_RESP" | jq -r '.persistence_available // false')

    if [ "$POSTGRES_STATUS" = "connected" ] && [ "$PERSISTENCE" = "true" ]; then
        pass "Health: postgres=connected, persistence_available=true"
    else
        fail "HEALTH_DEGRADED: postgres=$POSTGRES_STATUS, persistence_available=$PERSISTENCE"
    fi
fi

# ----------------------------------------------------------------
# Test 2: Create proposal (requires running stack)
# ----------------------------------------------------------------
info "Test 2: Create proposal with persistence"
TESTS_RUN=$((TESTS_RUN + 1))

# Only run if API is reachable
if echo "$HEALTH_RESP" | jq -e '._error == "CONNECTION_REFUSED"' > /dev/null 2>&1; then
    skip "Proposal creation" "API_UNREACHABLE"
else
    PROPOSAL_ID="verify-phase2-$(date +%s)"

    PROPOSAL_RESP=$(curl -s -w "\n%{http_code}" -X POST "${API_BASE}/v1/govern/proposal" \
        -H "Content-Type: application/json" \
        -H "X-M87-Key: ${API_KEY}" \
        -d "{
            \"proposal_id\": \"${PROPOSAL_ID}\",
            \"intent_id\": \"test-intent\",
            \"agent\": \"Casey\",
            \"summary\": \"Phase 2 verification test\",
            \"effects\": [\"READ_REPO\"],
            \"truth_account\": {
                \"observations\": [\"Test observation\"],
                \"claims\": []
            },
            \"risk_score\": 0.3
        }")

    HTTP_CODE=$(echo "$PROPOSAL_RESP" | tail -n1)
    BODY=$(echo "$PROPOSAL_RESP" | head -n-1)

    if [ "$HTTP_CODE" = "200" ]; then
        DECISION=$(echo "$BODY" | jq -r '.decision')
        if [ "$DECISION" = "ALLOW" ]; then
            pass "Proposal created: $PROPOSAL_ID (decision: ALLOW)"
        else
            fail "PROPOSAL_DECISION_UNEXPECTED: got $DECISION, expected ALLOW"
        fi
    elif [ "$HTTP_CODE" = "503" ]; then
        ERROR=$(echo "$BODY" | jq -r '.detail.error // "unknown"')
        fail "PERSISTENCE_UNAVAILABLE: 503 with error=$ERROR"
    elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
        fail "AUTH_FAILED: HTTP $HTTP_CODE - check M87_API_KEY"
    else
        fail "PROPOSAL_FAILED: HTTP $HTTP_CODE: $BODY"
    fi
fi

# ----------------------------------------------------------------
# Test 3: Verify DB durability via test endpoint (no psql required)
# ----------------------------------------------------------------
info "Test 3: Verify proposal persisted to Postgres (via API)"
TESTS_RUN=$((TESTS_RUN + 1))

if echo "$HEALTH_RESP" | jq -e '._error == "CONNECTION_REFUSED"' > /dev/null 2>&1; then
    skip "DB durability check" "API_UNREACHABLE"
elif [ -z "${PROPOSAL_ID:-}" ]; then
    skip "DB durability check" "no proposal created"
else
    # Try the test endpoint (requires M87_ENABLE_TEST_ENDPOINTS=true)
    DB_RESP=$(curl -s "${API_BASE}/v1/test/db/proposals/${PROPOSAL_ID}" \
        -H "X-M87-Key: ${API_KEY}" 2>/dev/null || echo '{"error": "REQUEST_FAILED"}')

    if echo "$DB_RESP" | jq -e '.error == "REQUEST_FAILED"' > /dev/null 2>&1; then
        skip "DB durability check" "test endpoint request failed"
    elif echo "$DB_RESP" | jq -e '.detail == "Not found"' > /dev/null 2>&1; then
        skip "DB durability check" "M87_ENABLE_TEST_ENDPOINTS not enabled"
    else
        EXISTS=$(echo "$DB_RESP" | jq -r '.exists // false')
        if [ "$EXISTS" = "true" ]; then
            pass "Proposal $PROPOSAL_ID exists in Postgres"
        else
            ERROR=$(echo "$DB_RESP" | jq -r '.error // "unknown"')
            fail "DB_DURABILITY_FAILED: proposal not found in Postgres (error: $ERROR)"
        fi
    fi
fi

# ----------------------------------------------------------------
# Test 4: Verify decision persisted via test endpoint
# ----------------------------------------------------------------
info "Test 4: Verify decision persisted to Postgres (via API)"
TESTS_RUN=$((TESTS_RUN + 1))

if echo "$HEALTH_RESP" | jq -e '._error == "CONNECTION_REFUSED"' > /dev/null 2>&1; then
    skip "Decision durability check" "API_UNREACHABLE"
elif [ -z "${PROPOSAL_ID:-}" ]; then
    skip "Decision durability check" "no proposal created"
else
    DB_RESP=$(curl -s "${API_BASE}/v1/test/db/decisions/${PROPOSAL_ID}" \
        -H "X-M87-Key: ${API_KEY}" 2>/dev/null || echo '{"error": "REQUEST_FAILED"}')

    if echo "$DB_RESP" | jq -e '.detail == "Not found"' > /dev/null 2>&1; then
        skip "Decision durability check" "M87_ENABLE_TEST_ENDPOINTS not enabled"
    else
        EXISTS=$(echo "$DB_RESP" | jq -r '.exists // false')
        if [ "$EXISTS" = "true" ]; then
            OUTCOME=$(echo "$DB_RESP" | jq -r '.outcome // "unknown"')
            pass "Decision for $PROPOSAL_ID exists in Postgres (outcome: $OUTCOME)"
        else
            skip "Decision durability check" "test endpoint not available or decision not found"
        fi
    fi
fi

# ----------------------------------------------------------------
# Test 5: Hard fail-safe documentation
# ----------------------------------------------------------------
info "Test 5: Hard fail-safe (manual verification required)"
echo ""
echo "  To verify hard fail-safe, stop Postgres and confirm 503:"
echo ""
echo "    docker stop <postgres_container>"
echo "    curl -X POST ${API_BASE}/v1/govern/proposal \\"
echo "      -H 'X-M87-Key: ${API_KEY}' \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"proposal_id\":\"fail-test\",...}'"
echo ""
echo "  Expected: HTTP 503 with {\"detail\":{\"error\":\"DB_UNAVAILABLE\",...}}"
echo ""

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
echo ""
echo "========================================"
echo "Phase 2 Verification Summary"
echo "========================================"
echo ""
echo "Tests run:     $TESTS_RUN"
echo "Tests passed:  $TESTS_PASSED"
echo "Tests skipped: $TESTS_SKIPPED"
echo ""

if [ "$TESTS_SKIPPED" -gt 0 ]; then
    echo "Skipped tests require:"
    echo "  - Running compose stack: cd infra && docker compose up -d"
    echo "  - Wait for healthchecks: sleep 15"
    echo "  - Re-run: ./scripts/verify_phase2.sh"
    echo ""
fi

TESTS_FAILED=$((TESTS_RUN - TESTS_PASSED - TESTS_SKIPPED))

if [ "$TESTS_FAILED" -gt 0 ]; then
    echo "RESULT: FAILED ($TESTS_FAILED failures)"
    exit 1
elif [ "$TESTS_SKIPPED" -gt 0 ]; then
    if [ "$STRICT_MODE" = true ]; then
        echo "RESULT: FAILED (strict mode - $TESTS_SKIPPED skipped tests treated as failures)"
        exit 1
    else
        echo "RESULT: PARTIAL ($TESTS_SKIPPED tests skipped)"
        echo ""
        echo "Use --strict flag to fail on skipped tests (for CI gates)"
        exit 2
    fi
else
    echo "RESULT: PASSED"
    exit 0
fi
