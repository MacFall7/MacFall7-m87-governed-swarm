#!/bin/bash
# M87 API Key Rotation
# Usage: ./scripts/rotate-key.sh
#
# Generates a new API key, updates .env, and restarts services.
# Use when: key leaked, periodic rotation, onboarding new operator.

set -euo pipefail

cd "$(dirname "$0")/.."

command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }

ENV_FILE=".env"

echo "========================================"
echo "M87 API KEY ROTATION"
echo "========================================"
echo ""

# Generate new key
NEW_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')

echo "Generated new key: ${NEW_KEY:0:12}...${NEW_KEY: -4}"
echo ""

# Check if .env exists
if [ ! -f "$ENV_FILE" ]; then
    echo "Creating $ENV_FILE from .env.example..."
    if [ -f ".env.example" ]; then
        cp .env.example "$ENV_FILE"
    else
        echo "M87_API_KEY=" > "$ENV_FILE"
    fi
fi

# Backup current .env
cp "$ENV_FILE" "${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
echo "Backed up current .env"

# Update the key in .env
if grep -q "^M87_API_KEY=" "$ENV_FILE"; then
    # Key exists, replace it
    sed -i "s|^M87_API_KEY=.*|M87_API_KEY=$NEW_KEY|" "$ENV_FILE"
else
    # Key doesn't exist, add it
    echo "M87_API_KEY=$NEW_KEY" >> "$ENV_FILE"
fi

echo "Updated $ENV_FILE with new key"
echo ""

# Ask to restart
read -p "Restart services now? [y/N] " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Restarting services..."
    docker compose -f infra/docker-compose.yml up -d --build
    echo ""
    echo "Services restarted with new key."
else
    echo "Services NOT restarted."
    echo "Run manually: docker compose -f infra/docker-compose.yml up -d --build"
fi

echo ""
echo "========================================"
echo "KEY ROTATION COMPLETE"
echo "========================================"
echo ""
echo "New key (save this somewhere safe):"
echo "$NEW_KEY"
echo ""
echo "Update your dashboard settings with the new key."
echo "Old key backups: ls -la .env.backup.*"
