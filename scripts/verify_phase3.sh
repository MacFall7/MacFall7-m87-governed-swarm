#!/usr/bin/env bash
#
# Phase 3 Verification Script
# Proves: Invariant test suite protects system guarantees
#
# What this verifies:
# 1. Test dependencies installed
# 2. Auth invariant tests pass
# 3. Governance invariant tests pass
# 4. All tests pass (CI gate)
#
# Prerequisites:
# - Python 3.9+
# - pytest installed (pip install -r apps/api/requirements-test.txt)
#
# Usage: ./scripts/verify_phase3.sh [--ci]
#
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

CI_MODE=false
for arg in "$@"; do
    case $arg in
        --ci)
            CI_MODE=true
            ;;
    esac
done

# ----------------------------------------------------------------
# Check prerequisites
# ----------------------------------------------------------------
info "Checking prerequisites..."

if ! command -v python3 &> /dev/null; then
    fail "PREREQ_MISSING: python3 not found"
fi

# Check if pytest is available
if ! python3 -c "import pytest" 2>/dev/null; then
    info "pytest not installed, attempting to install test dependencies..."
    pip install -q -r apps/api/requirements-test.txt || fail "Failed to install test dependencies"
fi

echo "  python3: OK"
echo "  pytest: OK"
echo ""

# ----------------------------------------------------------------
# Run auth invariant tests
# ----------------------------------------------------------------
info "Running auth invariant tests..."

cd apps/api

if python3 -m pytest tests/test_auth_invariants.py -v --tb=short; then
    pass "Auth invariant tests passed"
else
    fail "AUTH_INVARIANTS_FAILED: auth tests failed"
fi

# ----------------------------------------------------------------
# Run governance invariant tests
# ----------------------------------------------------------------
info "Running governance invariant tests..."

if python3 -m pytest tests/test_governance_invariants.py -v --tb=short; then
    pass "Governance invariant tests passed"
else
    fail "GOVERNANCE_INVARIANTS_FAILED: governance tests failed"
fi

# ----------------------------------------------------------------
# Run all tests (CI gate)
# ----------------------------------------------------------------
info "Running full test suite..."

if python3 -m pytest tests/ -v --tb=short; then
    pass "Full test suite passed"
else
    fail "TEST_SUITE_FAILED: some tests failed"
fi

cd ../..

# ----------------------------------------------------------------
# Summary
# ----------------------------------------------------------------
echo ""
echo "========================================"
echo "Phase 3 Verification Summary"
echo "========================================"
echo ""
echo "All invariant tests passed:"
echo "  [x] Auth invariants (missing key, invalid key, scopes, risk)"
echo "  [x] Governance invariants (READ_SECRETS, agent scopes, DEPLOY)"
echo "  [x] Fail-safe invariants (DB unavailable)"
echo ""
echo "RESULT: PASSED"
echo ""

if [ "$CI_MODE" = true ]; then
    echo "CI mode: All tests must pass for merge."
fi
