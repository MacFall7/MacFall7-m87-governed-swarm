#!/bin/bash
# Phase 1 Verification: Scoped API Keys
# Proves the RBAC-lite system enforces all auth checks

set -e

API="${API_BASE:-http://localhost:8000}"
ADMIN_KEY="${M87_API_KEY:-m87-dev-key-change-me}"

echo "========================================"
echo "Phase 1 Verification: Scoped API Keys"
echo "========================================"
echo "API: $API"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}✓ PASS${NC}: $1"; }
fail() { echo -e "${RED}✗ FAIL${NC}: $1"; exit 1; }
info() { echo -e "${YELLOW}→${NC} $1"; }

# ---- Test 1: No key → 401
echo ""
echo "Test 1: Proposal without key → 401"
info "Submitting proposal without X-M87-Key header..."

HTTP_CODE=$(curl -s -o /tmp/phase1_test1.json -w "%{http_code}" \
  -X POST "$API/v1/govern/proposal" \
  -H "Content-Type: application/json" \
  -d '{
    "proposal_id": "p-test-nokey",
    "intent_id": "i-test",
    "agent": "Casey",
    "summary": "Test without key",
    "effects": ["READ_REPO"],
    "truth_account": {"observations": ["test"], "claims": []}
  }')

if [ "$HTTP_CODE" = "401" ]; then
  pass "Got 401 Unauthorized (no key)"
  cat /tmp/phase1_test1.json | jq -r '.detail' 2>/dev/null || true
else
  fail "Expected 401, got $HTTP_CODE"
fi

# ---- Test 2: Invalid key → 401
echo ""
echo "Test 2: Invalid key → 401"
info "Submitting proposal with wrong key..."

HTTP_CODE=$(curl -s -o /tmp/phase1_test2.json -w "%{http_code}" \
  -X POST "$API/v1/govern/proposal" \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: totally-wrong-key" \
  -d '{
    "proposal_id": "p-test-wrongkey",
    "intent_id": "i-test",
    "agent": "Casey",
    "summary": "Test with wrong key",
    "effects": ["READ_REPO"],
    "truth_account": {"observations": ["test"], "claims": []}
  }')

if [ "$HTTP_CODE" = "401" ]; then
  pass "Got 401 Unauthorized (invalid key)"
  cat /tmp/phase1_test2.json | jq -r '.detail' 2>/dev/null || true
else
  fail "Expected 401, got $HTTP_CODE"
fi

# ---- Test 3: Create restricted key for scope tests
echo ""
echo "Test 3: Create restricted key (endpoint scope: runner:result only)"
info "Creating key with limited endpoint scope..."

RESTRICTED_KEY_RESP=$(curl -s -X POST "$API/v1/admin/keys" \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: $ADMIN_KEY" \
  -d '{
    "principal_type": "service",
    "principal_id": "test-restricted",
    "endpoint_scopes": ["runner:result"],
    "effect_scopes": [],
    "max_risk": 0.5,
    "description": "Phase 1 test: restricted endpoint scope"
  }')

RESTRICTED_KEY=$(echo "$RESTRICTED_KEY_RESP" | jq -r '.key')
RESTRICTED_KEY_ID=$(echo "$RESTRICTED_KEY_RESP" | jq -r '.key_id')

if [ "$RESTRICTED_KEY" = "null" ] || [ -z "$RESTRICTED_KEY" ]; then
  fail "Failed to create restricted key: $RESTRICTED_KEY_RESP"
fi

pass "Created restricted key: $RESTRICTED_KEY_ID"

# ---- Test 4: Wrong endpoint scope → 403
echo ""
echo "Test 4: Wrong endpoint scope → 403 ENDPOINT_SCOPE_DENIED"
info "Using runner:result key to call proposal:create..."

HTTP_CODE=$(curl -s -o /tmp/phase1_test4.json -w "%{http_code}" \
  -X POST "$API/v1/govern/proposal" \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: $RESTRICTED_KEY" \
  -d '{
    "proposal_id": "p-test-scopedenied",
    "intent_id": "i-test",
    "agent": "Casey",
    "summary": "Test endpoint scope denial",
    "effects": ["READ_REPO"],
    "truth_account": {"observations": ["test"], "claims": []}
  }')

if [ "$HTTP_CODE" = "403" ]; then
  pass "Got 403 Forbidden (endpoint scope denied)"
  cat /tmp/phase1_test4.json | jq -r '.detail' 2>/dev/null || true
else
  fail "Expected 403, got $HTTP_CODE"
fi

# ---- Test 5: Create key with limited effect scope
echo ""
echo "Test 5: Create key with limited effect scope (READ_REPO only)"
info "Creating key that can only propose READ_REPO..."

EFFECT_KEY_RESP=$(curl -s -X POST "$API/v1/admin/keys" \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: $ADMIN_KEY" \
  -d '{
    "principal_type": "adapter",
    "principal_id": "test-effect-limited",
    "endpoint_scopes": ["proposal:create"],
    "effect_scopes": ["READ_REPO"],
    "max_risk": 1.0,
    "description": "Phase 1 test: limited effect scope"
  }')

EFFECT_KEY=$(echo "$EFFECT_KEY_RESP" | jq -r '.key')
EFFECT_KEY_ID=$(echo "$EFFECT_KEY_RESP" | jq -r '.key_id')

if [ "$EFFECT_KEY" = "null" ] || [ -z "$EFFECT_KEY" ]; then
  fail "Failed to create effect-limited key: $EFFECT_KEY_RESP"
fi

pass "Created effect-limited key: $EFFECT_KEY_ID"

# ---- Test 6: Effect scope violation → 403
echo ""
echo "Test 6: Effect scope violation → 403 EFFECT_SCOPE_DENIED"
info "Trying to propose WRITE_PATCH with READ_REPO-only key..."

HTTP_CODE=$(curl -s -o /tmp/phase1_test6.json -w "%{http_code}" \
  -X POST "$API/v1/govern/proposal" \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: $EFFECT_KEY" \
  -d '{
    "proposal_id": "p-test-effectdenied",
    "intent_id": "i-test",
    "agent": "Casey",
    "summary": "Test effect scope denial",
    "effects": ["READ_REPO", "WRITE_PATCH"],
    "truth_account": {"observations": ["test"], "claims": []}
  }')

if [ "$HTTP_CODE" = "403" ]; then
  pass "Got 403 Forbidden (effect scope denied)"
  cat /tmp/phase1_test6.json | jq -r '.detail' 2>/dev/null || true
else
  fail "Expected 403, got $HTTP_CODE"
fi

# ---- Test 7: Create key with low risk cap
echo ""
echo "Test 7: Create key with low risk cap (0.2)"
info "Creating key with max_risk=0.2..."

RISK_KEY_RESP=$(curl -s -X POST "$API/v1/admin/keys" \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: $ADMIN_KEY" \
  -d '{
    "principal_type": "adapter",
    "principal_id": "test-risk-limited",
    "endpoint_scopes": ["proposal:create"],
    "effect_scopes": ["READ_REPO", "WRITE_PATCH", "RUN_TESTS"],
    "max_risk": 0.2,
    "description": "Phase 1 test: low risk cap"
  }')

RISK_KEY=$(echo "$RISK_KEY_RESP" | jq -r '.key')
RISK_KEY_ID=$(echo "$RISK_KEY_RESP" | jq -r '.key_id')

if [ "$RISK_KEY" = "null" ] || [ -z "$RISK_KEY" ]; then
  fail "Failed to create risk-limited key: $RISK_KEY_RESP"
fi

pass "Created risk-limited key: $RISK_KEY_ID"

# ---- Test 8: Risk cap exceeded → 403
echo ""
echo "Test 8: Risk cap exceeded → 403 RISK_CAP_EXCEEDED"
info "Trying to propose with risk_score=0.5 using key with max_risk=0.2..."

HTTP_CODE=$(curl -s -o /tmp/phase1_test8.json -w "%{http_code}" \
  -X POST "$API/v1/govern/proposal" \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: $RISK_KEY" \
  -d '{
    "proposal_id": "p-test-riskdenied",
    "intent_id": "i-test",
    "agent": "Casey",
    "summary": "Test risk cap exceeded",
    "effects": ["READ_REPO"],
    "truth_account": {"observations": ["test"], "claims": []},
    "risk_score": 0.5
  }')

if [ "$HTTP_CODE" = "403" ]; then
  pass "Got 403 Forbidden (risk cap exceeded)"
  cat /tmp/phase1_test8.json | jq -r '.detail' 2>/dev/null || true
else
  fail "Expected 403, got $HTTP_CODE"
fi

# ---- Test 9: Valid key with valid scope → success
echo ""
echo "Test 9: Valid key + valid scope → 200 with decision"
info "Submitting valid proposal with admin key..."

HTTP_CODE=$(curl -s -o /tmp/phase1_test9.json -w "%{http_code}" \
  -X POST "$API/v1/govern/proposal" \
  -H "Content-Type: application/json" \
  -H "X-M87-Key: $ADMIN_KEY" \
  -d '{
    "proposal_id": "p-test-valid",
    "intent_id": "i-test",
    "agent": "Casey",
    "summary": "Valid Phase 1 test proposal",
    "effects": ["READ_REPO"],
    "truth_account": {"observations": ["test"], "claims": []},
    "risk_score": 0.1
  }')

if [ "$HTTP_CODE" = "200" ]; then
  DECISION=$(cat /tmp/phase1_test9.json | jq -r '.decision')
  pass "Got 200 OK with decision: $DECISION"
else
  fail "Expected 200, got $HTTP_CODE"
fi

# ---- Cleanup: Delete test keys
echo ""
echo "Cleanup: Deleting test keys..."

curl -s -X DELETE "$API/v1/admin/keys/$RESTRICTED_KEY_ID" \
  -H "X-M87-Key: $ADMIN_KEY" > /dev/null
curl -s -X DELETE "$API/v1/admin/keys/$EFFECT_KEY_ID" \
  -H "X-M87-Key: $ADMIN_KEY" > /dev/null
curl -s -X DELETE "$API/v1/admin/keys/$RISK_KEY_ID" \
  -H "X-M87-Key: $ADMIN_KEY" > /dev/null

info "Test keys deleted"

# ---- Summary
echo ""
echo "========================================"
echo "Phase 1 Verification Complete"
echo "========================================"
echo ""
echo "All auth checks verified:"
echo "  ✓ 401: Missing key"
echo "  ✓ 401: Invalid key"
echo "  ✓ 403: Endpoint scope denied"
echo "  ✓ 403: Effect scope denied"
echo "  ✓ 403: Risk cap exceeded"
echo "  ✓ 200: Valid key + valid scope"
echo ""
echo "Scoped keys (RBAC-lite) working correctly."
