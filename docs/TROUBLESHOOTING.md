# Troubleshooting Guide

Solutions for common issues with M87 Governed Swarm.

## Quick Diagnostics

Run this first to see overall system status:

```bash
./scripts/status.sh
```

## Common Issues

---

### Docker Issues

#### "Cannot connect to the Docker daemon"

**Symptoms:**
```
Cannot connect to the Docker daemon at unix:///var/run/docker.sock
```

**Solution:**

```bash
# Start Docker (Linux)
sudo systemctl start docker

# On macOS, start Docker Desktop from Applications

# Verify Docker is running
docker ps
```

#### "Permission denied" when running Docker

**Solution:**

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Log out and back in, then verify
docker ps
```

#### "Port already in use"

**Symptoms:**
```
Error starting userland proxy: listen tcp 0.0.0.0:8000: bind: address already in use
```

**Solution:**

```bash
# Find what's using the port
lsof -i :8000

# Kill the process
kill <PID>

# Or change the port in docker-compose.yml
ports:
  - "8001:8000"  # Use 8001 instead
```

---

### API Issues

#### API returns 401 Unauthorized

**Symptoms:**
```json
{"detail": "Invalid or missing API key"}
```

**Causes:**
1. Missing `X-M87-Key` header
2. Wrong API key value
3. Key mismatch between .env and request

**Solution:**

```bash
# Check your .env file
cat .env | grep M87_API_KEY

# Use the correct key in requests
curl -X POST http://localhost:8000/v1/govern/proposal \
  -H "X-M87-Key: $(grep M87_API_KEY .env | cut -d= -f2)" \
  -H "Content-Type: application/json" \
  -d '...'
```

#### API returns 503 Service Unavailable

**Symptoms:**
```json
{"detail": "Redis connection failed"}
```

**Solution:**

```bash
# Check if Redis is running
docker compose -f infra/docker-compose.yml ps redis

# Restart Redis
docker compose -f infra/docker-compose.yml restart redis

# Check Redis logs
docker compose -f infra/docker-compose.yml logs redis
```

#### API health check fails

**Symptoms:**
```bash
curl http://localhost:8000/health
# Connection refused
```

**Solution:**

```bash
# Check if API container is running
docker compose -f infra/docker-compose.yml ps api

# Check API logs
docker compose -f infra/docker-compose.yml logs api

# Restart API
docker compose -f infra/docker-compose.yml restart api
```

---

### Adapter Issues

#### Adapters showing 401 errors in logs

**Symptoms:**
```
Failed to submit proposal: 401 Client Error: Unauthorized
```

**Cause:** Adapters don't have the correct API key.

**Solution:**

1. Check docker-compose.yml has M87_API_KEY for adapters:

```yaml
casey-adapter:
  environment:
    - M87_API_KEY=${M87_API_KEY:-m87-dev-key-change-me}
```

2. Check .env has the key:

```bash
grep M87_API_KEY .env
```

3. Rebuild and restart:

```bash
docker compose -f infra/docker-compose.yml down
docker compose -f infra/docker-compose.yml up -d --build
```

#### Adapters not submitting proposals

**Symptoms:** Adapters are running but no proposals appear.

**Diagnosis:**

```bash
# Check adapter logs
docker compose -f infra/docker-compose.yml logs --tail=50 casey-adapter

# Check if adapters are connected to API
docker compose -f infra/docker-compose.yml logs casey-adapter | grep "API is healthy"
```

**Common causes:**
1. No intents to react to (adapters wait for events)
2. Intent mode doesn't match adapter triggers
3. Network connectivity issues

**Solution:**

```bash
# Create a test intent
curl -X POST http://localhost:8000/v1/intent \
  -H "Content-Type: application/json" \
  -d '{"intent_id":"i-test","from":"user","mode":"fix","goal":"test"}'

# Watch for proposals
curl -s http://localhost:8000/v1/events?limit=10 | jq
```

#### Adapter scope violations (DENY decisions)

**Symptoms:**
```
Decision: DENY
Reasons: Agent 'Casey' cannot propose effect 'DEPLOY'
```

**Cause:** Adapter is proposing effects outside its scope.

**Solution:** Check agent profiles in `apps/api/app/main.py`:

```python
AGENT_PROFILES = {
    "Casey": {
        "allowed_effects": {"READ_REPO", "WRITE_PATCH", "RUN_TESTS"},
        # Casey cannot propose DEPLOY
    },
}
```

Either:
- Change the adapter to only propose allowed effects
- Add the effect to the agent's allowed_effects

---

### Runner Issues

#### Jobs not being executed

**Symptoms:** Jobs appear in /v1/jobs but stay "pending".

**Diagnosis:**

```bash
# Check runner is running
docker compose -f infra/docker-compose.yml ps runner

# Check runner logs
docker compose -f infra/docker-compose.yml logs runner

# Check if runner can connect to Redis
docker compose -f infra/docker-compose.yml logs runner | grep "consumer group"
```

**Solution:**

```bash
# Restart runner
docker compose -f infra/docker-compose.yml restart runner
```

#### Jobs failing with "tool not in allowlist"

**Symptoms:**
```
Job failed: Tool 'npm' not in allowlist
```

**Cause:** The requested tool isn't in the runner's TOOL_ALLOWLIST.

**Solution:** Add the tool to `services/runner/app/runner.py`:

```python
TOOL_ALLOWLIST = {"echo", "pytest", "git", "build", "npm"}
```

Then rebuild:

```bash
docker compose -f infra/docker-compose.yml build runner
docker compose -f infra/docker-compose.yml up -d runner
```

---

### Redis Issues

#### Redis data loss

**Symptoms:** Events and jobs disappear after restart.

**Cause:** Redis persistence not configured or volume not mounted.

**Solution:** Check docker-compose.yml:

```yaml
redis:
  volumes:
    - redis_data:/data
  command:
    - redis-server
    - --appendonly
    - "yes"

volumes:
  redis_data:
```

#### Redis connection timeout

**Symptoms:**
```
Redis connection timed out
```

**Solution:**

```bash
# Check Redis is running
docker compose -f infra/docker-compose.yml ps redis

# Check Redis health
docker compose -f infra/docker-compose.yml exec redis redis-cli ping
# Should return: PONG

# Check Redis memory
docker compose -f infra/docker-compose.yml exec redis redis-cli info memory
```

---

### Dashboard Issues

#### Dashboard won't load

**Symptoms:** http://localhost:3000 shows error or blank page.

**Solution:**

```bash
# Check UI container
docker compose -f infra/docker-compose.yml ps ui

# Check UI logs
docker compose -f infra/docker-compose.yml logs ui

# Restart UI
docker compose -f infra/docker-compose.yml restart ui
```

#### Dashboard shows "Disconnected"

**Symptoms:** Dashboard header shows red pulse and "Disconnected".

**Causes:**
1. API not running
2. CORS blocking requests
3. Wrong API URL in settings

**Solution:**

1. Check API is running:
```bash
curl http://localhost:8000/health
```

2. Check CORS settings in .env:
```
ALLOWED_ORIGINS=http://localhost:3000,http://127.0.0.1:3000
```

3. In dashboard Settings tab, verify API URL is correct.

#### Approve/Deny buttons don't work

**Symptoms:** Clicking Approve or Deny shows error.

**Cause:** API key not configured in dashboard.

**Solution:**

1. Click Settings tab in dashboard
2. Enter your M87_API_KEY
3. Click Save
4. Refresh and try again

---

### Build Issues

#### Docker build fails

**Symptoms:**
```
ERROR: failed to solve: failed to compute cache key
```

**Solution:**

```bash
# Clear Docker cache
docker builder prune -f

# Rebuild
./scripts/boot.sh fresh
```

#### Python import errors

**Symptoms:**
```
ModuleNotFoundError: No module named 'adapter_sdk'
```

**Solution:**

```bash
# Install adapter SDK
pip install -e packages/adapter-sdk

# Or in Docker, check Dockerfile installs it:
RUN pip install --no-cache-dir -e /app/packages/adapter-sdk
```

---

## Diagnostic Commands

### Check all service status

```bash
docker compose -f infra/docker-compose.yml ps
```

### View all logs

```bash
docker compose -f infra/docker-compose.yml logs -f
```

### Check Redis streams

```bash
# Connect to Redis
docker compose -f infra/docker-compose.yml exec redis redis-cli

# View events
XRANGE m87:events - + COUNT 10

# View jobs
XRANGE m87:jobs - + COUNT 10

# Check consumer groups
XINFO GROUPS m87:jobs
XINFO GROUPS m87:events
```

### Test API endpoints

```bash
# Health
curl -s http://localhost:8000/health | jq

# Agents
curl -s http://localhost:8000/v1/agents | jq

# Events
curl -s http://localhost:8000/v1/events?limit=10 | jq

# Jobs
curl -s http://localhost:8000/v1/jobs | jq

# Pending approvals
curl -s http://localhost:8000/v1/pending-approvals | jq
```

### Verify invariants

```bash
./scripts/proof-test.sh
```

---

## Reset Everything

If all else fails, start fresh:

```bash
# Stop everything and remove volumes
docker compose -f infra/docker-compose.yml down -v

# Remove all images
docker compose -f infra/docker-compose.yml down --rmi all

# Clean boot
./scripts/boot.sh fresh
```

---

## Getting Help

1. Check the logs first - they usually tell you exactly what's wrong
2. Run `./scripts/status.sh` for quick diagnostics
3. Check this guide for your specific error
4. If still stuck, open an issue with:
   - Error message
   - Relevant logs
   - Steps to reproduce

## Failure Mode Quick Reference

| Symptom | Likely Cause | First Step |
|---------|--------------|------------|
| Boot crash | Compose/env issue | Check docker-compose logs |
| /health fails | API init | Check API logs |
| 401 errors | Missing/wrong API key | Verify .env and headers |
| 503 errors | Redis down | Check Redis status |
| Jobs stuck pending | Runner issue | Check runner logs |
| Adapters quiet | No events | Create test intent |
| Dashboard disconnected | CORS or API down | Check API health |
