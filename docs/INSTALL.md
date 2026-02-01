# Installation Guide

Complete step-by-step guide to get M87 Governed Swarm running on your machine.

## Prerequisites

Before you begin, make sure you have:

| Requirement | Minimum Version | Check Command |
|-------------|-----------------|---------------|
| Docker | 20.10+ | `docker --version` |
| Docker Compose | 2.0+ | `docker compose version` |
| Git | 2.0+ | `git --version` |
| curl | any | `curl --version` |
| jq (optional) | any | `jq --version` |

### Installing Prerequisites

**macOS (using Homebrew):**
```bash
brew install git docker docker-compose curl jq
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y git docker.io docker-compose curl jq
sudo systemctl start docker
sudo usermod -aG docker $USER
# Log out and back in for group change to take effect
```

**Windows:**
1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop)
2. Install [Git for Windows](https://gitforwindows.org/)
3. Use PowerShell or Git Bash for commands

## Step 1: Clone the Repository

```bash
git clone https://github.com/MacFall7/MacFall7-m87-governed-swarm.git
cd MacFall7-m87-governed-swarm
```

## Step 2: Configure Environment

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and set your API key:

```bash
# Using your favorite editor
nano .env
# or
vim .env
# or
code .env
```

**Required changes in `.env`:**

```env
# CHANGE THIS to a secure random string
M87_API_KEY=your-secure-api-key-here

# Optional: Add your domain for CORS
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

**Generating a secure API key:**

```bash
# Option 1: Using openssl
openssl rand -hex 32

# Option 2: Using /dev/urandom
cat /dev/urandom | head -c 32 | base64

# Option 3: Using Python
python3 -c "import secrets; print(secrets.token_hex(32))"
```

## Step 3: Boot the System

**First-time boot (builds all containers):**

```bash
./scripts/boot.sh fresh
```

This will:
1. Build all Docker images
2. Start Redis
3. Start the Governance API
4. Start the Runner
5. Start the Notifier
6. Start the Adapters (Casey, Jordan, Riley)
7. Start the Dashboard UI

**Subsequent boots:**

```bash
./scripts/boot.sh
```

## Step 4: Verify Installation

Run these commands to verify everything is working:

### 4.1 Check API Health

```bash
curl -s http://localhost:8000/health | jq
```

**Expected output:**
```json
{
  "ok": true,
  "version": "0.1.3",
  "redis": "connected"
}
```

### 4.2 Check Agents Are Registered

```bash
curl -s http://localhost:8000/v1/agents | jq
```

**Expected output:**
```json
{
  "agents": [
    {
      "name": "Casey",
      "allowed_effects": ["READ_REPO", "RUN_TESTS", "WRITE_PATCH"],
      "max_risk": 0.6,
      "description": "Code changes and testing"
    },
    {
      "name": "Jordan",
      "allowed_effects": ["BUILD_ARTIFACT", "CREATE_PR", "READ_REPO", "SEND_NOTIFICATION"],
      "max_risk": 0.5,
      "description": "Artifacts, notifications, PRs"
    },
    {
      "name": "Riley",
      "allowed_effects": ["BUILD_ARTIFACT", "READ_REPO", "SEND_NOTIFICATION"],
      "max_risk": 0.4,
      "description": "Analysis and reporting"
    },
    {
      "name": "Human",
      "allowed_effects": ["BUILD_ARTIFACT", "CREATE_PR", "DEPLOY", "MERGE", "NETWORK_CALL", "READ_REPO", "RUN_TESTS", "SEND_NOTIFICATION", "WRITE_PATCH"],
      "max_risk": 1.0,
      "description": "Manual human proposals"
    }
  ]
}
```

### 4.3 Verify Auth Gate

This should return 401 (Unauthorized):

```bash
curl -i -X POST http://localhost:8000/v1/govern/proposal \
  -H "content-type: application/json" \
  -d '{"proposal_id":"test","intent_id":"i1","agent":"Casey","summary":"test","effects":["READ_REPO"],"truth_account":{"observations":[],"claims":[]}}'
```

**Expected:** `HTTP/1.1 401 Unauthorized`

### 4.4 Check Adapter Logs

```bash
docker compose -f infra/docker-compose.yml logs --tail=20 casey-adapter
```

**Expected:** Adapter startup logs with no 401 errors.

### 4.5 Open Dashboard

Open your browser to:

```
http://localhost:3000
```

You should see the M87 Governed Swarm dashboard with:
- Approvals tab (pending human approvals)
- Jobs tab (executed jobs)
- Agents tab (registered agents)
- Timeline tab (event stream)
- Settings tab (API configuration)

## Step 5: Configure Dashboard API Key

In the dashboard:

1. Click the **Settings** tab (gear icon)
2. Enter your API key from `.env`
3. Click **Save**

This allows the dashboard to approve/deny proposals.

## Stopping the System

```bash
docker compose -f infra/docker-compose.yml down
```

To stop and remove all data:

```bash
docker compose -f infra/docker-compose.yml down -v
```

## Updating

```bash
git pull origin main
./scripts/boot.sh fresh
```

## Common Issues

### "Cannot connect to Docker daemon"

```bash
# Start Docker
sudo systemctl start docker

# Or on macOS, start Docker Desktop
```

### "Permission denied" on scripts

```bash
chmod +x scripts/*.sh
```

### "Port already in use"

```bash
# Find what's using port 8000
lsof -i :8000

# Or port 3000
lsof -i :3000

# Kill the process or change ports in docker-compose.yml
```

### "Adapters showing 401 errors"

Check that `M87_API_KEY` in `.env` matches what's configured in the adapters' environment in `docker-compose.yml`.

### "Redis connection refused"

```bash
# Check if Redis is running
docker compose -f infra/docker-compose.yml ps redis

# Restart Redis
docker compose -f infra/docker-compose.yml restart redis
```

## Next Steps

- Read the [Architecture Guide](ARCHITECTURE.md) to understand the system
- Read the [Developer Guide](DEVELOPER.md) to extend the system
- Read the [API Reference](API.md) for endpoint details
- Read the [Troubleshooting Guide](TROUBLESHOOTING.md) for more help

## Verification Checklist

Before considering the installation complete, verify:

- [ ] `curl http://localhost:8000/health` returns `{"ok": true}`
- [ ] `curl http://localhost:8000/v1/agents` shows 4 agents
- [ ] Proposal without API key returns 401
- [ ] Dashboard loads at http://localhost:3000
- [ ] Agents tab shows Casey, Jordan, Riley
- [ ] Adapter logs show no 401 errors

If all checks pass, your installation is complete.
