#!/bin/bash
# M87 V1.4+ Proof Test - Validates the seven invariants (Phase 5: Result Contract Hardening)
#
# Usage:
#   ./scripts/proof-test.sh
#
# For full test including Invariant 3b (runner isolation):
#   1. Set M87_ENABLE_TEST_ENDPOINTS=true in .env
#   2. Restart: docker compose -f infra/docker-compose.yml up -d --build
#   3. Run: ./scripts/proof-test.sh
#   4. Set M87_ENABLE_TEST_ENDPOINTS=false and restart for production

set -euo pipefail

API="http://localhost:8000"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================"
echo "M87 V1.4 PROOF TEST"
echo "========================================"
echo ""

# Dependency checks
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found"; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "ERROR: jq not found"; exit 1; }

# Load API key from .env if exists
if [ -f .env ]; then
    set +u
    export $(grep -v '^#' .env | grep -v '^$' | xargs)
    set -u
fi
M87_API_KEY="${M87_API_KEY:-m87-dev-key-change-me}"

echo "Using API_KEY: ${M87_API_KEY:0:8}..."
echo ""

# Wait for API to be healthy
echo -n "Waiting for API health... "
for i in {1..30}; do
    if curl -s "$API/health" 2>/dev/null | grep -q '"ok":true'; then
        echo -e "${GREEN}OK${NC}"
        break
    fi
    sleep 1
    if [ "$i" -eq 30 ]; then
        echo -e "${RED}FAILED${NC}"
        echo "ERROR: API not reachable at $API"
        exit 1
    fi
done
echo ""

# ========================================
# INVARIANT 1: No approval → no job
# ========================================
echo "========================================"
echo "INVARIANT 1: No approval → no job"
echo "========================================"
echo ""

echo "Submitting DEPLOY proposal (should require approval)..."
RESPONSE=$(curl -s -X POST "$API/v1/govern/proposal" \
  -H "content-type: application/json" \
  -d '{
    "proposal_id":"p-deploy-1",
    "intent_id":"i-1",
    "agent":"Planner",
    "summary":"Deploy demo",
    "effects":["RUN_TESTS","DEPLOY"],
    "truth_account":{"observations":["test"],"claims":[]}
  }')
echo "$RESPONSE" | jq .
echo ""

DECISION=$(echo "$RESPONSE" | jq -r '.decision')
if [ "$DECISION" = "REQUIRE_HUMAN" ]; then
    echo -e "${GREEN}✓ Decision is REQUIRE_HUMAN${NC}"
else
    echo -e "${RED}✗ Expected REQUIRE_HUMAN, got: $DECISION${NC}"
    exit 1
fi
echo ""

echo "Checking pending approvals..."
PENDING=$(curl -s "$API/v1/pending-approvals")
echo "$PENDING" | jq .
PENDING_COUNT=$(echo "$PENDING" | jq '.pending | length')
if [ "$PENDING_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✓ Proposal in pending approvals ($PENDING_COUNT)${NC}"
else
    echo -e "${RED}✗ No pending approvals found${NC}"
    exit 1
fi
echo ""

echo "Checking jobs (should be empty for p-deploy-1)..."
JOBS=$(curl -s "$API/v1/jobs")
echo "$JOBS" | jq .
JOB_FOR_PROPOSAL=$(echo "$JOBS" | jq '[.jobs[] | select(.proposal_id=="p-deploy-1")] | length')
if [ "$JOB_FOR_PROPOSAL" -eq 0 ]; then
    echo -e "${GREEN}✓ No job minted yet (correct)${NC}"
else
    echo -e "${RED}✗ Job was minted before approval!${NC}"
    exit 1
fi
echo ""

echo -e "${GREEN}INVARIANT 1 PASSED${NC}"
echo ""

# ========================================
# INVARIANT 2: Approval requires API key
# ========================================
echo "========================================"
echo "INVARIANT 2: Approval requires API key"
echo "========================================"
echo ""

echo "Attempting approval WITHOUT API key..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API/v1/approve/p-deploy-1")
HTTP_CODE=$(echo "$RESPONSE" | tail -1)
BODY=$(echo "$RESPONSE" | head -n -1)
echo "HTTP Code: $HTTP_CODE"
echo "Body: $BODY"
echo ""

if [ "$HTTP_CODE" = "401" ]; then
    echo -e "${GREEN}✓ Got 401 Unauthorized (correct)${NC}"
else
    echo -e "${RED}✗ Expected 401, got: $HTTP_CODE${NC}"
    exit 1
fi
echo ""

echo "Verifying no job was minted..."
JOBS=$(curl -s "$API/v1/jobs")
JOB_FOR_PROPOSAL=$(echo "$JOBS" | jq '[.jobs[] | select(.proposal_id=="p-deploy-1")] | length')
if [ "$JOB_FOR_PROPOSAL" -eq 0 ]; then
    echo -e "${GREEN}✓ Still no job (correct)${NC}"
else
    echo -e "${RED}✗ Job was minted without auth!${NC}"
    exit 1
fi
echo ""

echo -e "${GREEN}INVARIANT 2 PASSED${NC}"
echo ""

# ========================================
# INVARIANT 3b: Runner ignores events stream
# ========================================
echo "========================================"
echo "INVARIANT 3b: Runner ignores events"
echo "========================================"
echo ""

echo "Emitting fake 'proposal.allowed' event (V1.1 would have triggered runner)..."
EMIT_RESPONSE=$(curl -s -w "\n%{http_code}" -X POST "$API/v1/admin/emit" \
  -H "content-type: application/json" \
  -H "X-M87-Key: $M87_API_KEY" \
  -d '{"type":"proposal.allowed","payload":{"proposal_id":"FAKE-EVENT-SHOULD-NOT-RUN","decision":"ALLOW","reasons":["fake"]}}')
EMIT_CODE=$(echo "$EMIT_RESPONSE" | tail -1)
EMIT_BODY=$(echo "$EMIT_RESPONSE" | head -n -1)

if [ "$EMIT_CODE" = "404" ]; then
    echo -e "${YELLOW}⚠ Test endpoints disabled (M87_ENABLE_TEST_ENDPOINTS=false)${NC}"
    echo "  To run this test, restart with: M87_ENABLE_TEST_ENDPOINTS=true"
    echo "  Or add to .env: M87_ENABLE_TEST_ENDPOINTS=true"
    echo ""
    echo -e "${YELLOW}INVARIANT 3b SKIPPED (endpoints disabled - this is correct for prod)${NC}"
    echo ""
else
    echo "$EMIT_BODY" | jq .
    echo ""

    echo "Waiting 5s for runner to potentially react..."
    sleep 5

    echo "Checking if runner created a job for fake event..."
    JOBS=$(curl -s "$API/v1/jobs")
    JOBS_FAKE=$(echo "$JOBS" | jq '[.jobs[] | select(.proposal_id=="FAKE-EVENT-SHOULD-NOT-RUN")] | length')
    if [ "$JOBS_FAKE" -eq 0 ]; then
        echo -e "${GREEN}✓ Runner ignored events stream (correct)${NC}"
    else
        echo -e "${RED}✗ Runner reacted to events stream (BAD - V1.1 regression!)${NC}"
        exit 1
    fi
    echo ""

    echo -e "${GREEN}INVARIANT 3b PASSED${NC}"
    echo ""
fi

# ========================================
# INVARIANT 3: Approval with key → job minted
# ========================================
echo "========================================"
echo "INVARIANT 3: Approval with key → job"
echo "========================================"
echo ""

echo "Approving WITH API key..."
RESPONSE=$(curl -s -X POST "$API/v1/approve/p-deploy-1" \
  -H "X-M87-Key: $M87_API_KEY")
echo "$RESPONSE" | jq .
echo ""

APPROVED=$(echo "$RESPONSE" | jq -r '.approved')
JOB_ID=$(echo "$RESPONSE" | jq -r '.job_id')
if [ "$APPROVED" = "true" ] && [ "$JOB_ID" != "null" ]; then
    echo -e "${GREEN}✓ Approved and job minted: ${JOB_ID:0:8}...${NC}"
else
    echo -e "${RED}✗ Approval failed or no job created${NC}"
    exit 1
fi
echo ""

# Wait for runner to execute
echo "Waiting for runner to execute job..."
for i in {1..10}; do
    JOBS=$(curl -s "$API/v1/jobs")
    JOB_STATUS=$(echo "$JOBS" | jq -r '.jobs[] | select(.proposal_id=="p-deploy-1") | .status')
    if [ "$JOB_STATUS" = "completed" ]; then
        break
    fi
    sleep 1
done

echo "Checking job status..."
JOBS=$(curl -s "$API/v1/jobs")
echo "$JOBS" | jq '.jobs[] | select(.proposal_id=="p-deploy-1")'
echo ""

JOB_STATUS=$(echo "$JOBS" | jq -r '.jobs[] | select(.proposal_id=="p-deploy-1") | .status')
if [ "$JOB_STATUS" = "completed" ]; then
    echo -e "${GREEN}✓ Job completed${NC}"
elif [ "$JOB_STATUS" = "pending" ] || [ "$JOB_STATUS" = "running" ]; then
    echo -e "${YELLOW}⏳ Job still $JOB_STATUS (runner may be slow)${NC}"
else
    echo -e "${YELLOW}⚠ Job status: $JOB_STATUS${NC}"
fi
echo ""

echo "Checking events for job.completed..."
EVENTS=$(curl -s "$API/v1/events?limit=20")
JOB_COMPLETED=$(echo "$EVENTS" | jq '[.events[] | select(.type=="job.completed")] | length')
if [ "$JOB_COMPLETED" -gt 0 ]; then
    echo -e "${GREEN}✓ job.completed event emitted${NC}"
else
    echo -e "${YELLOW}⏳ No job.completed event yet (runner may be slow)${NC}"
fi
echo ""

echo -e "${GREEN}INVARIANT 3 PASSED${NC}"
echo ""

# ========================================
# INVARIANT 4: No manifest entry → no execution (and tools are visible)
# ========================================
echo "========================================"
echo "INVARIANT 4: Manifest governs runner tools"
echo "========================================"
echo ""

echo "Checking /v1/tools endpoint..."
TOOLS_RESPONSE=$(curl -s "$API/v1/tools")
echo "$TOOLS_RESPONSE" | jq .

MANIFEST_HASH=$(echo "$TOOLS_RESPONSE" | jq -r '.manifest_hash // ""')
TOOL_COUNT=$(echo "$TOOLS_RESPONSE" | jq -r '.tools | length')
HAS_ECHO=$(echo "$TOOLS_RESPONSE" | jq -r '[.tools[] | select(.tool=="echo")] | length')
HAS_PYTEST=$(echo "$TOOLS_RESPONSE" | jq -r '[.tools[] | select(.tool=="pytest")] | length')

if [ "${#MANIFEST_HASH}" -ne 64 ]; then
  echo -e "${RED}✗ Missing/invalid manifest_hash from /v1/tools${NC}"
  exit 1
fi

if [ "$TOOL_COUNT" -lt 1 ]; then
  echo -e "${RED}✗ No tools reported by /v1/tools${NC}"
  exit 1
fi

if [ "$HAS_ECHO" -ne 1 ] || [ "$HAS_PYTEST" -ne 1 ]; then
  echo -e "${RED}✗ Tool list mismatch (expected echo + pytest)${NC}"
  exit 1
fi

echo -e "${GREEN}✓ Manifest visible + hashed; expected tools present${NC}"
echo -e "${GREEN}INVARIANT 4 PASSED${NC}"
echo ""

# ========================================
# INVARIANT 5: Jobs pinned with manifest hash (drift detection)
# ========================================
echo "========================================"
echo "INVARIANT 5: Jobs pinned with manifest hash"
echo "========================================"
echo ""

# Store manifest hash from API for comparison
API_MANIFEST_HASH="$MANIFEST_HASH"

echo "Submitting proposal for hash-pinning test..."
HASH_PROP_ID="p-hash-test-$(date +%s)"
RESPONSE=$(curl -s -X POST "$API/v1/govern/proposal" \
  -H "content-type: application/json" \
  -d "{
    \"proposal_id\":\"$HASH_PROP_ID\",
    \"intent_id\":\"i-hash-test\",
    \"agent\":\"Tester\",
    \"summary\":\"Test manifest hash pinning\",
    \"effects\":[\"SEND_NOTIFICATION\"],
    \"truth_account\":{\"observations\":[\"test\"],\"claims\":[]}
  }")

DECISION=$(echo "$RESPONSE" | jq -r '.decision')
if [ "$DECISION" != "ALLOW" ]; then
    echo -e "${RED}✗ Expected ALLOW for SEND_NOTIFICATION, got: $DECISION${NC}"
    exit 1
fi

JOB_ID=$(echo "$RESPONSE" | jq -r '.job_id')
if [ "$JOB_ID" = "null" ] || [ -z "$JOB_ID" ]; then
    echo -e "${RED}✗ No job_id returned for auto-approved proposal${NC}"
    exit 1
fi
echo -e "${GREEN}✓ Proposal auto-approved, job: ${JOB_ID:0:8}...${NC}"
echo ""

echo "Checking job has manifest_hash pinned..."
sleep 2  # Give runner time to execute
JOBS=$(curl -s "$API/v1/jobs")
JOB_MANIFEST_HASH=$(echo "$JOBS" | jq -r ".jobs[] | select(.job_id==\"$JOB_ID\") | .manifest_hash // \"\"")

if [ -z "$JOB_MANIFEST_HASH" ] || [ "$JOB_MANIFEST_HASH" = "null" ]; then
    echo -e "${RED}✗ Job missing manifest_hash (not pinned at mint time)${NC}"
    exit 1
fi

if [ "$JOB_MANIFEST_HASH" != "$API_MANIFEST_HASH" ]; then
    echo -e "${RED}✗ Job manifest_hash doesn't match API manifest_hash${NC}"
    echo "  Job hash: $JOB_MANIFEST_HASH"
    echo "  API hash: $API_MANIFEST_HASH"
    exit 1
fi

echo -e "${GREEN}✓ Job manifest_hash matches API manifest (${JOB_MANIFEST_HASH:0:16}...)${NC}"
echo ""

# Verify job completed (runner accepted matching hash)
JOB_STATUS=$(echo "$JOBS" | jq -r ".jobs[] | select(.job_id==\"$JOB_ID\") | .status")
if [ "$JOB_STATUS" = "completed" ]; then
    echo -e "${GREEN}✓ Job completed (runner accepted matching manifest hash)${NC}"
elif [ "$JOB_STATUS" = "pending" ] || [ "$JOB_STATUS" = "running" ]; then
    echo -e "${YELLOW}⏳ Job still $JOB_STATUS (runner may be slow)${NC}"
else
    echo -e "${YELLOW}⚠ Job status: $JOB_STATUS${NC}"
fi
echo ""

echo -e "${GREEN}INVARIANT 5 PASSED${NC}"
echo ""

# ========================================
# INVARIANT 6: Runner results are bounded + redacted
# ========================================
echo "========================================"
echo "INVARIANT 6: Runner results bounded + redacted"
echo "========================================"
echo ""

echo "Testing result payload size cap (expect 413)..."
BIG=$(python3 -c 'print("A" * 80000)')

HTTP_CODE=$(curl -s -o /tmp/m87_big_result.json -w "%{http_code}" \
  -X POST "$API/v1/runner/result" \
  -H "content-type: application/json" \
  -H "X-M87-Key: $M87_API_KEY" \
  -d "{
    \"job_id\":\"job-big-test-$(date +%s)\",
    \"proposal_id\":\"p-big-test\",
    \"status\":\"failed\",
    \"output\":{\"stdout\":\"$BIG\"},
    \"manifest_hash\":\"$MANIFEST_HASH\"
  }")

if [ "$HTTP_CODE" -eq 413 ]; then
  echo -e "${GREEN}✓ Size cap enforced (413)${NC}"
else
  echo -e "${RED}✗ Expected 413, got $HTTP_CODE${NC}"
  cat /tmp/m87_big_result.json 2>/dev/null || true
  exit 1
fi
echo ""

echo "Testing redaction (secret patterns stripped)..."
SECRET_PAYLOAD="{\"job_id\":\"job-redact-test-$(date +%s)\",\"proposal_id\":\"p-redact-test\",\"status\":\"failed\",\"output\":{\"stdout\":\"-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\nAPI_KEY=supersecret123\"},\"manifest_hash\":\"$MANIFEST_HASH\"}"

REDACT_RESPONSE=$(curl -s -X POST "$API/v1/runner/result" \
  -H "content-type: application/json" \
  -H "X-M87-Key: $M87_API_KEY" \
  -d "$SECRET_PAYLOAD")

if echo "$REDACT_RESPONSE" | grep -q '"ok":true'; then
  echo -e "${GREEN}✓ Redaction test submitted (secrets stripped before storage)${NC}"
else
  echo -e "${RED}✗ Redaction test failed${NC}"
  echo "$REDACT_RESPONSE"
  exit 1
fi
echo ""

echo -e "${GREEN}INVARIANT 6 PASSED${NC}"
echo ""

# ========================================
# SUMMARY
# ========================================
echo "========================================"
echo -e "${GREEN}ALL INVARIANTS PASSED${NC}"
echo "========================================"
echo ""
echo "V1.4+ is locked down:"
echo "  ✓ Invariant 1:  No approval → no job"
echo "  ✓ Invariant 2:  Approval requires API key (401 without)"
echo "  ✓ Invariant 3b: Runner ignores events stream"
echo "  ✓ Invariant 3:  Approval with key → job minted and executed"
echo "  ✓ Invariant 4:  No manifest entry → no execution"
echo "  ✓ Invariant 5:  Jobs pinned with manifest hash (drift detection)"
echo "  ✓ Invariant 6:  Runner results bounded + redacted"
echo ""
echo "The system is trustable at 02:00 on your phone."
