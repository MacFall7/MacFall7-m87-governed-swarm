#!/bin/bash
# M87 Operator Status Report
# Run this at 02:00 when something's weird

set -euo pipefail

cd "$(dirname "$0")/.."

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found"; exit 1; }

API="http://localhost:8000"

echo "========================================"
echo "M87 OPERATOR STATUS REPORT"
echo "$(date)"
echo "========================================"
echo ""

echo "=== CONTAINER STATUS ==="
docker compose -f infra/docker-compose.yml ps
echo ""

echo "=== API HEALTH ==="
curl -fsS "$API/health" 2>/dev/null && echo "" || echo "API unreachable"
echo ""

echo "=== PENDING APPROVALS ==="
PENDING=$(curl -fsS "$API/v1/pending-approvals" 2>/dev/null || echo '{"pending":[]}')
COUNT=$(echo "$PENDING" | grep -o '"proposal_id"' | wc -l || echo "0")
echo "Count: $COUNT"
if [ "$COUNT" -gt 0 ]; then
    echo "$PENDING" | sed 's/},{/},\n{/g'
fi
echo ""

echo "=== RECENT JOBS (last 10) ==="
curl -fsS "$API/v1/jobs?limit=10" 2>/dev/null | sed 's/},{/},\n{/g' || echo "Could not fetch jobs"
echo ""

echo "=== RECENT EVENTS (last 20) ==="
curl -fsS "$API/v1/events?limit=20" 2>/dev/null | sed 's/},{/},\n{/g' || echo "Could not fetch events"
echo ""

echo "=== NOTIFIER LOGS (last 30 lines) ==="
docker compose -f infra/docker-compose.yml logs --tail=30 notifier 2>/dev/null || echo "Could not fetch notifier logs"
echo ""

echo "=== RUNNER LOGS (last 30 lines) ==="
docker compose -f infra/docker-compose.yml logs --tail=30 runner 2>/dev/null || echo "Could not fetch runner logs"
echo ""

echo "========================================"
echo "END OF STATUS REPORT"
echo "========================================"
