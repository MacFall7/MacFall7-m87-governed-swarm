#!/bin/bash
# M87 Governed Swarm - Single Command Demo
#
# Usage: ./demo.sh
#
# This script brings up the entire M87 governance stack and runs proof tests.
# For airgap-hardened deployment, see infra/docker-compose.secure.yml (requires job_dispatcher).

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

COMPOSE_FILE="infra/docker-compose.yml"
API_URL="http://localhost:8000"
UI_URL="http://localhost:3000"

echo ""
echo -e "${BOLD}========================================${NC}"
echo -e "${BOLD}   M87 GOVERNED SWARM - DEMO BOOT${NC}"
echo -e "${BOLD}========================================${NC}"
echo ""

# -----------------------------------------------------------------------------
# Pre-flight checks
# -----------------------------------------------------------------------------
echo -e "${BLUE}[1/5]${NC} Pre-flight checks..."

if ! command -v docker &> /dev/null; then
    echo -e "${RED}ERROR: docker not found. Please install Docker.${NC}"
    exit 1
fi

if ! command -v docker compose &> /dev/null; then
    # Fallback to docker-compose
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}ERROR: docker compose not found. Please install Docker Compose.${NC}"
        exit 1
    fi
    DOCKER_COMPOSE="docker-compose"
else
    DOCKER_COMPOSE="docker compose"
fi

if ! command -v curl &> /dev/null; then
    echo -e "${RED}ERROR: curl not found. Please install curl.${NC}"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}WARNING: jq not found. Proof tests may have limited output.${NC}"
fi

echo -e "${GREEN}  Docker, curl ready${NC}"

# -----------------------------------------------------------------------------
# Environment setup
# -----------------------------------------------------------------------------
echo -e "${BLUE}[2/5]${NC} Environment setup..."

if [ ! -f .env ]; then
    echo "  Creating default .env file..."
    cat > .env << 'EOF'
# M87 Demo Environment
M87_API_KEY=m87-demo-key-change-in-prod
M87_ENABLE_TEST_ENDPOINTS=true
POSTGRES_PASSWORD=m87-demo-password
M87_CHALLENGE_SECRET=demo-challenge-secret
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
EOF
    echo -e "${GREEN}  Created .env with demo defaults${NC}"
else
    echo -e "${GREEN}  Using existing .env${NC}"
fi

# -----------------------------------------------------------------------------
# Build and start services
# -----------------------------------------------------------------------------
echo -e "${BLUE}[3/5]${NC} Building and starting services..."
echo "  This may take 1-2 minutes on first run..."
echo ""

$DOCKER_COMPOSE -f "$COMPOSE_FILE" up -d --build

echo ""
echo -e "${GREEN}  Services started${NC}"

# -----------------------------------------------------------------------------
# Wait for API health
# -----------------------------------------------------------------------------
echo -e "${BLUE}[4/5]${NC} Waiting for API health..."

for i in {1..60}; do
    if curl -s "$API_URL/health" 2>/dev/null | grep -q '"ok":true'; then
        echo -e "${GREEN}  API is healthy${NC}"
        break
    fi

    if [ "$i" -eq 60 ]; then
        echo -e "${RED}ERROR: API failed to start within 60 seconds${NC}"
        echo ""
        echo "Logs from services:"
        $DOCKER_COMPOSE -f "$COMPOSE_FILE" logs --tail=50 api
        exit 1
    fi

    echo -n "."
    sleep 1
done

echo ""

# -----------------------------------------------------------------------------
# Run proof tests
# -----------------------------------------------------------------------------
echo -e "${BLUE}[5/5]${NC} Running governance proof tests..."
echo ""

if [ -x ./scripts/proof-test.sh ]; then
    ./scripts/proof-test.sh
    PROOF_EXIT=$?
else
    echo -e "${YELLOW}WARNING: proof-test.sh not found or not executable${NC}"
    PROOF_EXIT=1
fi

echo ""

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo -e "${BOLD}========================================${NC}"
if [ "${PROOF_EXIT:-1}" -eq 0 ]; then
    echo -e "${GREEN}${BOLD}   DEMO READY - ALL TESTS PASSED${NC}"
else
    echo -e "${YELLOW}${BOLD}   DEMO READY - CHECK TEST OUTPUT${NC}"
fi
echo -e "${BOLD}========================================${NC}"
echo ""
echo -e "${BOLD}Endpoints:${NC}"
echo -e "  API:            ${BLUE}$API_URL${NC}"
echo -e "  Fire Control:   ${BLUE}$UI_URL${NC}"
echo -e "  Health:         ${BLUE}$API_URL/health${NC}"
echo -e "  Governance:     ${BLUE}$API_URL/v2/govern/proposal${NC}"
echo ""
echo -e "${BOLD}Useful commands:${NC}"
echo "  View logs:      docker compose -f $COMPOSE_FILE logs -f"
echo "  Stop:           docker compose -f $COMPOSE_FILE down"
echo "  Clean reset:    docker compose -f $COMPOSE_FILE down -v"
echo ""

# Optional: Open browser on macOS/Linux
if [ "${OPEN_BROWSER:-}" = "true" ]; then
    if command -v open &> /dev/null; then
        open "$UI_URL"
    elif command -v xdg-open &> /dev/null; then
        xdg-open "$UI_URL"
    fi
fi

exit ${PROOF_EXIT:-0}
