#!/bin/bash
# M87 Governed Swarm - Boot Script
# Usage: ./scripts/boot.sh [fresh]
#   fresh - tears down volumes and rebuilds from scratch

set -e

cd "$(dirname "$0")/.."

if [ "$1" = "fresh" ]; then
    echo "Tearing down with volumes..."
    docker compose -f infra/docker-compose.yml down -v
fi

echo "Building and starting services..."
docker compose -f infra/docker-compose.yml up --build -d

echo ""
echo "Waiting for services to be healthy..."
sleep 5

echo ""
echo "Service status:"
docker compose -f infra/docker-compose.yml ps

echo ""
echo "Dashboard: http://localhost:3000"
echo "API:       http://localhost:8000"
echo ""
echo "To run proof test: ./scripts/proof-test.sh"
echo "To view logs:      docker compose -f infra/docker-compose.yml logs -f"
