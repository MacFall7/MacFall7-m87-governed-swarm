# Layer 0 Proof Artifact

**Layer:** 0 -- Unauthorized Execution
**Question:** Can an untrusted agent execute without governance approval?
**Verdict:** SOLVED

---

## What Layer 0 Proves

Layer 0 guarantees that no agent proposal can reach the runner without
governance approval, and that the runner's filesystem view matches what
governance approved. This includes resistance to time-of-check/time-of-use
(TOCTOU) attacks where the filesystem changes between approval and execution.

## Enforcement Paths

### Path A: Governance denies virtual FS targets

Proposals targeting `/dev/shm`, `/sys`, `/run`, `/dev/pts`, `/dev/mqueue`,
or non-allowlisted `/proc` paths are denied before any governance evaluation.

```
Input:   proposal with artifact path = /dev/shm/exploit_payload
Output:  DENY (VIRTUAL_FS_DENIED)
Code:    apps/api/app/main.py:1297-1328 (govern_proposal)
Module:  apps/api/app/governance/virtual_fs_deny.py
```

### Path B: Runner rejects pathset divergence

The runner canonicalizes all input paths via `os.path.realpath()` and checks
`resolved_paths <= approved_paths`. Extra paths (injected files, overlay
changes) trigger `RUNNER_PATHSET_MISMATCH`. Glob re-expansion detects
`GLOB_DIVERGENCE_DETECTED`.

```
Input:   governance approves {a.txt, b.txt}; attacker injects c.txt
Output:  RUNNER_PATHSET_MISMATCH (extra_paths: [c.txt])
Code:    services/runner/app/runner.py (_runner_revalidate_paths)
Module:  apps/api/app/governance/glob_validation.py (runner_revalidate_glob)
```

### Path C: Runner fails closed at boot

Runner verifies its own isolation at startup:
- **Network namespace:** checks `/sys/class/net/` for non-loopback interfaces.
  If `eth0` exists, `RuntimeError: RUNNER_NAMESPACE_VIOLATION`.
- **Capabilities:** reads `/proc/self/status` CapEff. If `CAP_SYS_ADMIN`,
  `CAP_NET_RAW`, `CAP_NET_ADMIN`, or `CAP_SYS_PTRACE` present,
  `RuntimeError: RUNNER_CAPABILITY_VIOLATION`.

```
Input:   runner started with network_mode: bridge (eth0 visible)
Output:  RuntimeError("RUNNER_NAMESPACE_VIOLATION: ...")
Code:    services/runner/app/runner.py (_verify_network_namespace)
```

### Path D: TOCTOU symlink swap detection

Governance approves a symlink target. Attacker swaps the symlink between
approval and execution. Runner's `realpath()` resolves the new target,
detects it outside `base_dir`, and aborts.

```
Input:   governance approves /workspace/data.txt -> safe_file.txt
         attacker swaps: /workspace/data.txt -> /etc/passwd
Output:  pathset_valid=False, symlink_escapes=["/workspace/data.txt"]
Code:    services/runner/app/runner.py (_runner_revalidate_paths)
```

## How to Verify

### One-shot proof rail

```bash
# Run from repo root:
python -m pytest apps/api/tests/test_layer0_toctou_probes.py -v
python scripts/layer0_demo.py --json > proof.json
python -c "import json; d=json.load(open('proof.json')); print(d['verdict'], d['provenance']['repo_commit'][:12])"
```

Expected output:
```
LAYER_0_ENFORCED <commit-sha>
```

### CI enforcement

The `layer0-proof-rail` job in `.github/workflows/ci.yml` runs both checks
on every push and PR. It uploads `layer0_proof.json` as a build artifact.

### Sample JSON excerpt

```json
{
  "verdict": "LAYER_0_ENFORCED",
  "provenance": {
    "repo_commit": "bdd0b34725b8...",
    "branch": "claude/consolidate-hardening-package-KtZOW",
    "python_version": "3.11.14",
    "platform": "Linux-4.4.0-x86_64-with-glibc2.39",
    "runner_build_id": "local"
  },
  "total_checks": 16,
  "passed": 16,
  "failed": 0
}
```

## Test Coverage

| Category | Tests | File |
|----------|-------|------|
| Layer 0 closure | 27 | `tests/test_layer0_closure.py` |
| TOCTOU red-team probes | 20 | `tests/test_layer0_toctou_probes.py` |
| **Total Layer 0** | **47** | |

### TOCTOU Probes Summary

| Probe | Attack | Defense |
|-------|--------|---------|
| 1 | Symlink swap after approval | `_runner_revalidate_paths` detects escape |
| 2 | File injection between approval and execution | `RUNNER_PATHSET_MISMATCH` |
| 3 | Glob expansion divergence (file added) | `GLOB_DIVERGENCE_DETECTED` |
| 4 | Directory symlink swap escaping base_dir | `realpath` resolves outside workspace |
| 5 | Symlink-to-virtual-FS pivot | Both path revalidation + VFS deny fire |
| 6 | Double-fetch race (overlay divergence) | Mocked `realpath` divergence detected |
| 7 | Path traversal bypass (`../`, `//`, `/.`) | Normalized and denied |

## Defense-in-Depth

Each enforcement point operates independently:

```
Proposal → [Governance VFS deny] → [Phase 3-6] → [Reversibility Gate] → Job
Job → [Runner path revalidation] → [Runner VFS deny] → Execute
Boot → [Namespace check] → [Capability check] → Accept jobs
```

If governance misses a virtual FS path, the runner catches it.
If the runner's `realpath` is somehow bypassed, the VFS prefix check catches it.
If both are bypassed, the namespace/capability checks prevent execution in
a misconfigured container.

## Boundary: What Layer 0 Does NOT Cover

- **Content integrity** (Layer 2): A file at the same path can be overwritten
  with different content. Path revalidation passes because the *path* is
  unchanged. Content hashing is a Layer 2 concern.
- **Compositional threats** (Layer 2): Multiple safe operations composing
  into a dangerous state.
- **Observability poisoning** (Layer 3): Attacker manipulating what operators
  see in telemetry/dashboards.
