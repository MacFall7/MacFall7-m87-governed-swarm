#!/usr/bin/env bash
# lock-manifest.sh — Mints the canonical manifest.lock.json
# Rule: No one edits manifest.lock.json by hand.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MANIFEST_PATH="$REPO_ROOT/services/runner/app/tool_manifest.json"
LOCK_PATH="$REPO_ROOT/manifest.lock.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
    echo "Usage: $0 [--force]"
    echo ""
    echo "Computes SHA-256 of tool_manifest.json and writes manifest.lock.json"
    echo ""
    echo "Options:"
    echo "  --force    Overwrite existing lock file"
    echo ""
    exit 1
}

FORCE=false
while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            ;;
    esac
done

# Check manifest exists
if [ ! -f "$MANIFEST_PATH" ]; then
    echo -e "${RED}ERROR: Manifest not found at $MANIFEST_PATH${NC}"
    exit 1
fi

# Check if lock exists and --force not specified
if [ -f "$LOCK_PATH" ] && [ "$FORCE" = false ]; then
    echo -e "${YELLOW}Lock file already exists: $LOCK_PATH${NC}"
    echo ""
    echo "Current lock contents:"
    cat "$LOCK_PATH"
    echo ""
    echo -e "${YELLOW}Use --force to overwrite${NC}"
    exit 1
fi

# Compute hash
SHA256=$(python3 -c "
import hashlib
from pathlib import Path
raw = Path('$MANIFEST_PATH').read_bytes()
print(hashlib.sha256(raw).hexdigest())
")

# Get manifest version
VERSION=$(python3 -c "
import json
from pathlib import Path
data = json.loads(Path('$MANIFEST_PATH').read_text())
print(data.get('version', 'unknown'))
")

# Get current commit (short)
COMMIT=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Get timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Write lock file
cat > "$LOCK_PATH" << EOF
{
  "manifest_version": "$VERSION",
  "manifest_path": "services/runner/app/tool_manifest.json",
  "sha256": "$SHA256",
  "generated_at": "$TIMESTAMP",
  "source_commit": "$COMMIT"
}
EOF

echo -e "${GREEN}Manifest lock created:${NC}"
echo ""
cat "$LOCK_PATH"
echo ""
echo -e "${GREEN}SHA-256: $SHA256${NC}"
echo -e "${GREEN}Commit:  $COMMIT${NC}"
