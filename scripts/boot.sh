#!/bin/bash
# M87 Governed Swarm - Boot Script
# Usage: ./scripts/boot.sh [fresh]
#   fresh - tears down volumes and rebuilds from scratch

set -euo pipefail

cd "$(dirname "$0")/.."

# Dependency checks
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose not available"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "ERROR: curl not found"; exit 1; }

# Check .env exists
if [ ! -f .env ]; then
    echo "WARNING: .env not found. Using defaults."
    echo "         Run: cp .env.example .env && nano .env"
fi

if [ "$#" -ge 1 ] && [ "$1" = "fresh" ]; then
    echo "Tearing down with volumes..."
    docker compose -f infra/docker-compose.yml down -v
fi

echo "Building and starting services..."
docker compose -f infra/docker-compose.yml up --build -d

echo ""
echo "Waiting for services to become healthy..."
for i in {1..60}; do
    # api health
    if curl -fsS http://localhost:8000/health >/dev/null 2>&1; then
        echo "API healthy."
        break
    fi
    echo -n "."
    sleep 2
    if [ "$i" -eq 60 ]; then
        echo ""
        echo "ERROR: API did not become healthy within 120s"
        docker compose -f infra/docker-compose.yml ps
        docker compose -f infra/docker-compose.yml logs api --tail=50
        exit 1
    fi
done

echo ""
echo "Services running:"
docker compose -f infra/docker-compose.yml ps

echo ""
echo "=========================================="
echo "Dashboard: http://localhost:3000"
echo "API:       http://localhost:8000"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  Run proof test:  ./scripts/proof-test.sh"
echo "  View logs:       docker compose -f infra/docker-compose.yml logs -f"
echo "  Stop:            docker compose -f infra/docker-compose.yml down"
