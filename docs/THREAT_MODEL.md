# M87 Governed Swarm - Threat Model

## Overview

M87 is a policy-gated autonomous execution platform. This threat model documents trust boundaries, attack surfaces, mitigations, and residual risks.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                    UNTRUSTED ZONE                               │
│  (Internet, external APIs, user input)                          │
└──────────────────────────┬──────────────────────────────────────┘
                           │ HTTPS (reverse proxy)
┌──────────────────────────▼──────────────────────────────────────┐
│                    API BOUNDARY                                 │
│  - Input validation (Pydantic)                                  │
│  - API key authentication                                       │
│  - Rate limiting (recommended)                                  │
├─────────────────────────────────────────────────────────────────┤
│                    GOVERNANCE LAYER                             │
│  - Phase 3-6 enforcement lane                                   │
│  - Session risk tracking (Redis)                                │
│  - Toxic topology detection                                     │
│  - Challenge-response for escalations                           │
├─────────────────────────────────────────────────────────────────┤
│                    PERSISTENCE LAYER                            │
│  - PostgreSQL (proposals, decisions, jobs)                      │
│  - Redis (events, session state)                                │
└──────────────────────────┬──────────────────────────────────────┘
                           │ Internal network only
┌──────────────────────────▼──────────────────────────────────────┐
│                    RUNNER BOUNDARY (AIRGAPPED)                  │
│  - network_mode: none (Docker)                                  │
│  - Tool manifest enforcement                                    │
│  - Autonomy budget limits                                       │
│  - Result size caps + secret redaction                          │
└─────────────────────────────────────────────────────────────────┘
```

## Attack Surfaces

### 1. API Endpoint Abuse

**Threat**: Attacker bypasses governance by finding unprotected endpoints.

**Mitigations**:
- All execution flows through `/v1/govern/proposal` or `/v2/govern/proposal`
- Both endpoints delegate to `evaluate_governance_proposal()` (no bypass)
- `enqueue_job()` is only called after governance approval
- Test: `test_v1_delegates_to_phase_3_6_helpers_importable`

### 2. Salami Slicing (Incremental Exfiltration)

**Threat**: Attacker makes small, innocent-looking requests that combine to exfiltrate data.

Example:
1. `READ_REPO` (allowed)
2. `NETWORK_CALL` (would be allowed individually)
3. Combined → data exfiltration

**Mitigations**:
- SessionRiskTracker maintains sliding window of effects per principal
- Toxic topologies detected: `repo_read_then_network`, `secrets_then_network`, etc.
- Test: `test_salami_slicing_repo_read_then_network_escalates`

### 3. Replay/Bait-and-Switch Attacks

**Threat**: Attacker gets approval for benign proposal, then substitutes malicious payload.

**Mitigations**:
- Challenge-response binds approval to proposal hash (HMAC)
- `verify_challenge()` checks `challenge_id` matches `proposal_hash`
- Different proposals get different challenges
- Test: `test_tampered_binding_fails`, `test_different_proposals_different_challenges`

### 4. Runner Escape

**Threat**: Malicious code in runner escapes to make network calls or access secrets.

**Mitigations**:
- Runner runs with `network_mode: none` (Docker airgap)
- No network interface available - cannot make outbound connections
- Tool manifest restricts available tools
- Autonomy budget limits execution scope
- Test: Integration test via `proof-test.sh`

### 5. Confused Deputy (Agent Impersonation)

**Threat**: Attacker tricks system into executing actions under another principal's authority.

**Mitigations**:
- All proposals include `principal_id` and `agent_name`
- Session tracking is per-principal, per-agent
- Effect scopes tied to authenticated API key
- Test: `test_agent_effect_scope_violation_denied`

### 6. Redis Blindness

**Threat**: If Redis is unavailable, system can't see session history and may miss attacks.

**Mitigations**:
- Fail-closed: If history unavailable AND proposal includes exfil-adjacent effects → escalate
- Read-only operations allowed when blind (low risk)
- Test: `test_redis_blind_escalates_exfil_adjacent`, `test_redis_blind_allows_readonly`

### 7. Secret Exfiltration via Results

**Threat**: Runner output contains secrets that leak to logs/responses.

**Mitigations**:
- Result payload size capped (default 64KB)
- Secret patterns redacted (PEM keys, API_KEY=, etc.)
- Test: Integration test in `proof-test.sh`

### 8. Supply Chain Attack

**Threat**: Malicious dependency injected into build.

**Mitigations**:
- Dependency audit via `pip-audit` (documented in `DEPENDENCY_AUDIT.md`)
- SBOM generated and versioned (`sbom.json`)
- Pin exact versions in requirements.txt
- Manifest lock system for tool definitions

## Residual Risks

### Accepted Risks

1. **Redis single point of failure**: If Redis is down, governance still works but with degraded accuracy. Mitigation: Monitor Redis health, fail-closed for dangerous operations.

2. **Starlette CVEs not patched**: Currently running older version. Mitigation: API not exposed to untrusted networks; upgrade scheduled.

3. **Time-of-check/time-of-use (TOCTOU)**: Between governance check and execution, state could change. Mitigation: Short execution window, manifest hash pinning.

### Out of Scope

1. **Physical security**: Assumes secure datacenter/cloud environment.
2. **Insider threats with admin access**: Admin API keys have full access by design.
3. **Side-channel attacks**: Not a cryptographic system; timing attacks not considered.

## Recommendations

1. **Deploy reverse proxy** (nginx/traefik) with rate limiting in front of API
2. **Enable TLS** for all internal communication
3. **Regular dependency audits** (monthly via `pip-audit`)
4. **Monitor Redis health** with alerting
5. **Rotate API keys** periodically (use `scripts/rotate-key.sh`)

## Verification Commands

```bash
# Verify runner is airgapped
docker inspect runner | grep NetworkMode
# Expected: "NetworkMode": "none"

# Verify all tests pass
pytest apps/api/tests/ -v

# Run integration proof
./scripts/proof-test.sh

# Audit dependencies
pip-audit -r apps/api/requirements.txt
```
