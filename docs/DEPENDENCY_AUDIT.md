# Dependency Audit

**Date**: 2026-02-04
**Tool**: pip-audit

## Summary

| Component | Vulnerabilities | Status |
|-----------|-----------------|--------|
| API (`apps/api`) | 2 | Mitigated |
| Runner (`services/runner`) | 1 | Mitigated |
| UI | N/A | No npm dependencies |

## Findings

### API Dependencies (`apps/api/requirements.txt`)

| Package | Version | CVE | Fix Version | Threat Model Analysis |
|---------|---------|-----|-------------|----------------------|
| starlette | 0.41.3 | CVE-2025-54121 | 0.47.2 | **Non-exploitable**: API is internal-only, not exposed to untrusted input at the transport layer. |
| starlette | 0.41.3 | CVE-2025-62727 | 0.49.1 | **Non-exploitable**: Same rationale - no external exposure. |

### Runner Dependencies (`services/runner/requirements.txt`)

| Package | Version | CVE | Fix Version | Threat Model Analysis |
|---------|---------|-----|-------------|----------------------|
| requests | 2.32.3 | CVE-2024-47081 | 2.32.4 | **Non-exploitable**: Runner is airgapped (`network_mode: none`). No outbound network calls possible. |

## Mitigation Strategy

1. **Starlette CVEs**: Upgrade to 0.49.1+ in next maintenance window. Currently not exploitable due to:
   - API only accepts requests from trusted internal networks
   - All external ingress is via reverse proxy with validation

2. **Requests CVE**: Low priority. Runner cannot make network calls due to Docker network isolation.

## Recommended Actions

```bash
# Update API dependencies
pip install "starlette>=0.49.1"

# Update runner dependencies
pip install "requests>=2.32.4"
```

## Audit Commands

```bash
# API audit
pip-audit -r apps/api/requirements.txt

# Runner audit
pip-audit -r services/runner/requirements.txt

# Full audit (all components)
find . -name "requirements*.txt" -exec pip-audit -r {} \;
```

## Next Audit

Schedule: Monthly or before each release.
