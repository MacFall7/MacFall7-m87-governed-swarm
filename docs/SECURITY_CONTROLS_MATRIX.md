# Security Controls Matrix

This matrix maps security controls to their code locations, tests, and invariants.

| Control | Code Location | Test | Invariant |
|---------|---------------|------|-----------|
| Toxic topology detection | `app/session_risk.py:33-50` | `test_salami_slicing_repo_read_then_network_escalates` | READ_REPO → NETWORK_CALL escalates to REQUIRE_HUMAN |
| Secrets exfiltration block | `app/session_risk.py:37-38` | `test_secrets_then_network_is_hard_deny` | READ_SECRETS → NETWORK_CALL is DENY (not escalate) |
| Challenge-response binding | `app/governance/adversarial_review.py:90-120` | `test_tampered_binding_fails` | Replay/bait-switch rejected via HMAC binding |
| Runner airgap | `infra/docker-compose.secure.yml:84` | `proof-test.sh` (integration) | `network_mode: none` prevents all egress |
| Tripwire code scan | `app/governance/resource_limits.py:43-90` | `test_detects_socket_import`, `test_detects_subprocess` | Exfil primitives (socket, subprocess, eval) flagged |
| Autonomy Budget enforcement | `services/runner/app/runner.py:governed_request()` | `test_governance_invariants.py` | max_external_io checked preemptively |
| Fail-closed on Redis blind | `app/session_risk.py:76-89` | `test_redis_blind_escalates_exfil_adjacent` | Can't see history + exfil effect → escalate |
| READ_SECRETS absolute deny | `app/main.py:1030-1040` | `test_read_secrets_always_denied` | No agent can propose READ_SECRETS |
| DEPLOY requires human | `app/main.py:1050-1060` | `test_deploy_requires_human_approval` | DEPLOY effect always escalates |
| Unknown effect suspicion | `app/governance/effects.py:60-72` | `test_parse_unknown_maps_to_other` | Unknown effects map to OTHER (treated as suspicious) |
| V1/V2 bypass prevention | `app/main.py:1091-1156` | `test_v1_delegates_to_phase_3_6_helpers_importable` | Both endpoints use same Phase 3-6 helpers |
| Result size cap | `app/main.py:890-910` | `test_result_payload_size_cap` (proof-test.sh) | 413 on oversized payloads |
| Secret redaction | `app/main.py:860-885` | `test_redaction` (proof-test.sh) | PEM keys, API_KEY patterns stripped |

## Test Coverage by Control

| Control Category | Coverage |
|-----------------|----------|
| Session Risk Tracking | 92% |
| Adversarial Review | 89% |
| Effect Taxonomy | 94% |
| Resource Limits | 81% |

## Invariant Test Commands

```bash
# Run all governance invariant tests
pytest apps/api/tests/test_governance_invariants.py -v

# Run red team invariant tests (Phase 3-6)
pytest apps/api/tests/test_governance_redteam_invariants.py -v

# Run integration proof tests (requires Docker)
./scripts/proof-test.sh
```

## Control Verification Checklist

- [ ] All unit tests pass (`pytest apps/api/tests/ -v`)
- [ ] Integration tests pass (`./scripts/proof-test.sh`)
- [ ] Runner airgap verified (`docker inspect runner | grep NetworkMode`)
- [ ] No bypass lanes exist (grep for `enqueue_job` outside governance path)
