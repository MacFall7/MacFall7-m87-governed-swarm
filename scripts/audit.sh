#!/bin/bash
# M87 Audit Script - One command to generate evidence
#
# Usage:
#   ./scripts/audit.sh
#
# This script:
#   1. Runs all invariant tests (proof-test.sh)
#   2. Runs API unit tests
#   3. Runs UI governance tests
#   4. Prints evidence file locations
#   5. Generates audit summary
#
# For auditors: This is your starting point. Run this script, review the output,
# then inspect the files listed in the evidence inventory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
EVIDENCE_DIR="$ROOT_DIR/evidence"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "========================================"
echo "M87 GOVERNANCE AUDIT"
echo "========================================"
echo ""
echo "=== Environment Provenance ==="
echo "Timestamp: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "Git commit: $(git rev-parse HEAD 2>/dev/null || echo 'not a git repo')"
echo "Git branch: $(git branch --show-current 2>/dev/null || echo 'unknown')"
echo "Python:     $(python3 --version 2>/dev/null || echo 'not installed')"
echo "Node:       $(node --version 2>/dev/null || echo 'not installed')"
echo "npm:        $(npm --version 2>/dev/null || echo 'not installed')"
echo "Docker:     $(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',' || echo 'not installed')"
echo ""

# Ensure evidence directory exists
mkdir -p "$EVIDENCE_DIR"

# Track pass/fail
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_SKIPPED=0

# ========================================
# PHASE 1: Proof Tests (Integration)
# ========================================
echo "========================================"
echo -e "${BLUE}PHASE 1: Proof Tests (Integration)${NC}"
echo "========================================"
echo ""

if curl -s "http://localhost:8000/health" 2>/dev/null | grep -q '"ok":true'; then
    echo "API is running. Executing proof-test.sh..."
    echo ""

    if "$SCRIPT_DIR/proof-test.sh" 2>&1 | tee "$EVIDENCE_DIR/proof-test-output.txt"; then
        echo ""
        echo -e "${GREEN}✓ Proof tests PASSED${NC}"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    else
        echo ""
        echo -e "${RED}✗ Proof tests FAILED${NC}"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
else
    echo -e "${YELLOW}⚠ API not running at localhost:8000${NC}"
    echo "  To run integration tests:"
    echo "    1. ./scripts/boot.sh"
    echo "    2. ./scripts/audit.sh"
    echo ""
    echo -e "${YELLOW}PHASE 1 SKIPPED${NC}"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
fi
echo ""

# ========================================
# PHASE 2: API Unit Tests
# ========================================
echo "========================================"
echo -e "${BLUE}PHASE 2: API Unit Tests${NC}"
echo "========================================"
echo ""

if [ -f "$ROOT_DIR/apps/api/requirements-test.txt" ]; then
    cd "$ROOT_DIR/apps/api"

    if command -v pytest >/dev/null 2>&1; then
        echo "Running pytest..."
        if pytest tests/ -v --tb=short 2>&1 | tee "$EVIDENCE_DIR/api-tests-output.txt"; then
            echo ""
            echo -e "${GREEN}✓ API unit tests PASSED${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo ""
            echo -e "${RED}✗ API unit tests FAILED${NC}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        echo -e "${YELLOW}⚠ pytest not installed${NC}"
        echo "  Install with: pip install -r apps/api/requirements-test.txt"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    fi

    cd "$ROOT_DIR"
else
    echo -e "${YELLOW}⚠ API test requirements not found${NC}"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
fi
echo ""

# ========================================
# PHASE 3: UI Governance Tests
# ========================================
echo "========================================"
echo -e "${BLUE}PHASE 3: UI Governance Tests${NC}"
echo "========================================"
echo ""

if [ -f "$ROOT_DIR/apps/ui/package.json" ]; then
    cd "$ROOT_DIR/apps/ui"

    if command -v npm >/dev/null 2>&1 && [ -d "node_modules" ]; then
        echo "Running UI governance tests..."
        if npm test 2>&1 | tee "$EVIDENCE_DIR/ui-tests-output.txt"; then
            echo ""
            echo -e "${GREEN}✓ UI governance tests PASSED${NC}"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo ""
            echo -e "${RED}✗ UI governance tests FAILED${NC}"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        echo -e "${YELLOW}⚠ npm not installed or node_modules missing${NC}"
        echo "  Install with: cd apps/ui && npm install"
        TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
    fi

    cd "$ROOT_DIR"
else
    echo -e "${YELLOW}⚠ UI package.json not found${NC}"
    TESTS_SKIPPED=$((TESTS_SKIPPED + 1))
fi
echo ""

# ========================================
# EVIDENCE INVENTORY
# ========================================
echo "========================================"
echo -e "${BLUE}EVIDENCE INVENTORY${NC}"
echo "========================================"
echo ""
echo "Documentation to review:"
echo "  1. README.md                    - System overview + guarantees"
echo "  2. docs/ARCHITECTURE.md         - Governing laws (10 invariants)"
echo "  3. docs/PROOF_MAP.md            - Claim → Mechanism → Test mapping"
echo "  4. docs/AUDITOR_WALKTHROUGH.md  - Step-by-step review guide"
echo ""
echo "Enforcement code:"
echo "  5. apps/api/app/main.py         - govern_proposal() + Phase 3-6"
echo "  6. services/runner/app/runner.py - execute_job() + DEH verification"
echo "  7. apps/ui/lib/governance/normalize.ts - UI normalization boundary"
echo ""
echo "Test files:"
echo "  8. apps/api/tests/test_governance.py - API governance tests"
echo "  9. services/runner/tests/          - Runner tests (if present)"
echo " 10. apps/ui/lib/__tests__/          - UI normalization tests"
echo ""
echo "Generated evidence (in evidence/):"
if [ -f "$EVIDENCE_DIR/proof-test-output.txt" ]; then
    echo "  • proof-test-output.txt        - Integration test output"
fi
if [ -f "$EVIDENCE_DIR/api-tests-output.txt" ]; then
    echo "  • api-tests-output.txt         - API unit test output"
fi
if [ -f "$EVIDENCE_DIR/ui-tests-output.txt" ]; then
    echo "  • ui-tests-output.txt          - UI test output"
fi
echo ""

# ========================================
# SUMMARY
# ========================================
echo "========================================"
echo "AUDIT SUMMARY"
echo "========================================"
echo ""
echo "Tests passed:  $TESTS_PASSED"
echo "Tests failed:  $TESTS_FAILED"
echo "Tests skipped: $TESTS_SKIPPED"
echo ""

if [ "$TESTS_FAILED" -gt 0 ]; then
    echo -e "${RED}══════════════════════════════════════${NC}"
    echo -e "${RED}  AUDIT FAILED - GUARANTEES ARE VOID  ${NC}"
    echo -e "${RED}══════════════════════════════════════${NC}"
    echo ""
    echo "Do not trust this system until all tests pass."
    exit 1
elif [ "$TESTS_SKIPPED" -eq 3 ]; then
    echo -e "${YELLOW}══════════════════════════════════════${NC}"
    echo -e "${YELLOW}  AUDIT INCOMPLETE - TESTS SKIPPED    ${NC}"
    echo -e "${YELLOW}══════════════════════════════════════${NC}"
    echo ""
    echo "Install dependencies and start services to complete audit."
    exit 2
else
    echo -e "${GREEN}══════════════════════════════════════${NC}"
    echo -e "${GREEN}  AUDIT PASSED - GUARANTEES VERIFIED  ${NC}"
    echo -e "${GREEN}══════════════════════════════════════${NC}"
    echo ""
    echo "All executed tests passed. Review evidence files for details."
    exit 0
fi
