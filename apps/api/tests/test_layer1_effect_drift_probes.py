"""
M87 Layer 1 — Effect Drift Probes

These tests enforce Layer 1 (Effect Integrity): every side-effect the runner
can cause MUST be classified, versioned, and isolated.  If any probe fails,
governance is approving effects it doesn't understand.

PROBE 1: Effect taxonomy alignment
    The EffectTag enum in effects.py, the Literal in main.py, and every
    agent profile MUST reference only canonical effects.  Drift between
    these sources means governance can approve effects the runner ignores
    (or vice versa).

PROBE 2: ALLOWED_TOOLS ≡ manifest
    Every tool in ALLOWED_TOOLS must exist in tool_manifest.json and
    vice versa.  A phantom tool in ALLOWED_TOOLS but not in the manifest
    means governance can approve jobs the runner will always reject.

PROBE 3: Subprocess environment isolation
    Tool implementations (tool_echo, tool_pytest) must call subprocess.run()
    with an explicit `env` kwarg that excludes M87_API_KEY, REDIS_URL, and
    other governance secrets.  Without this, a malicious test can read
    os.environ and exfiltrate infrastructure credentials.

PROBE 4: Effect schema versioning
    Governance stamps effect_schema_version into every job spec.
    The runner rejects jobs whose version doesn't match its own.
    This prevents silent taxonomy drift between deployments.

PROBE 5: Manifest ↔ tool implementation parity
    Every tool in the manifest must have a corresponding implementation
    in the runner's execute_job dispatch table.  Orphaned manifest entries
    mean the runner will raise RuntimeError("Unhandled tool") at runtime.

PROBE 6: Exfil-adjacent effect classification
    Every effect in EXFIL_ADJACENT_EFFECTS must be a valid EffectTag.
    Every exfil-adjacent effect that appears in an agent profile must be
    explicitly allowed — not accidentally included via set union.

PROBE 7: Unknown effect → OTHER mapping (invariant)
    parse_effects() must map any unknown string to OTHER.  This is the
    fail-closed guarantee: unknown effects are inherently suspicious.

PROBE 8: Effect schema version agreement
    API's EFFECT_SCHEMA_VERSION must equal runner's RUNNER_EFFECT_SCHEMA_VERSION.
    If they diverge, the runner will reject every job.

PROBE 9: Scrubbed env completeness
    _scrubbed_env() must remove all M87_, REDIS_, POSTGRES_, DATABASE_,
    AWS_, GCP_, AZURE_, SECRET_, TOKEN_ prefixed vars.  Missing a prefix
    means a tool subprocess can read that secret.

These probes are structural regression tests — they verify invariants about
the codebase itself, not runtime behavior.
"""
from __future__ import annotations

import ast
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Set
from unittest.mock import patch

import pytest

# Resolve project root: tests/ → apps/api/ → apps/ → project root
TEST_DIR = Path(__file__).parent.resolve()
API_DIR = TEST_DIR.parent
PROJECT_ROOT = API_DIR.parent.parent  # apps/ → project root
sys.path.insert(0, str(API_DIR))
sys.path.insert(0, str(PROJECT_ROOT))

from app.governance.effects import (
    EFFECT_SCHEMA_VERSION,
    EXFIL_ADJACENT_EFFECTS,
    EffectTag,
    READ_ONLY_EFFECTS,
    parse_effects,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_manifest() -> dict:
    """Load tool_manifest.json from the runner service."""
    manifest_path = PROJECT_ROOT / "services" / "runner" / "app" / "tool_manifest.json"
    return json.loads(manifest_path.read_text())


def _get_main_literal_effects() -> Set[str]:
    """Extract effect strings from the EffectTag Literal in main.py."""
    main_path = API_DIR / "app" / "main.py"
    tree = ast.parse(main_path.read_text())
    for node in ast.walk(tree):
        # Look for: EffectTag = Literal[...]
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "EffectTag":
                    if isinstance(node.value, ast.Subscript):
                        # Literal[...] → extract string constants
                        slice_node = node.value.slice
                        if isinstance(slice_node, ast.Tuple):
                            return {
                                elt.value
                                for elt in slice_node.elts
                                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                            }
    raise RuntimeError("Could not find EffectTag Literal in main.py")


def _get_main_allowed_tools() -> Set[str]:
    """Extract tool names from ALLOWED_TOOLS in main.py."""
    main_path = API_DIR / "app" / "main.py"
    tree = ast.parse(main_path.read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "ALLOWED_TOOLS":
                    if isinstance(node.value, ast.Set):
                        return {
                            elt.value
                            for elt in node.value.elts
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
                        }
    raise RuntimeError("Could not find ALLOWED_TOOLS in main.py")


def _get_runner_tool_names() -> Set[str]:
    """Extract tool names from the runner's execute_job dispatch table."""
    runner_path = PROJECT_ROOT / "services" / "runner" / "app" / "runner.py"
    source = runner_path.read_text()
    tree = ast.parse(source)
    # Find: if tool == "echo": / elif tool == "pytest":
    tools = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare):
            if (
                isinstance(node.left, ast.Name)
                and node.left.id == "tool"
                and len(node.ops) == 1
                and isinstance(node.ops[0], ast.Eq)
                and len(node.comparators) == 1
                and isinstance(node.comparators[0], ast.Constant)
                and isinstance(node.comparators[0].value, str)
            ):
                tools.add(node.comparators[0].value)
    return tools


def _get_agent_profile_effects() -> Set[str]:
    """Collect all effect strings used in AGENT_PROFILES."""
    from app.main import AGENT_PROFILES
    all_effects: Set[str] = set()
    for profile in AGENT_PROFILES.values():
        all_effects |= profile["allowed_effects"]
    return all_effects


# ---------------------------------------------------------------------------
# PROBE 1: Effect taxonomy alignment
# ---------------------------------------------------------------------------

class TestEffectTaxonomyAlignment:
    """Every source of effect names must agree on the canonical set."""

    def test_literal_matches_enum(self):
        """EffectTag Literal in main.py must list exactly the same effects as the enum."""
        enum_effects = {e.value for e in EffectTag}
        literal_effects = _get_main_literal_effects()
        assert enum_effects == literal_effects, (
            f"Drift detected.\n"
            f"  In enum but not Literal: {enum_effects - literal_effects}\n"
            f"  In Literal but not enum: {literal_effects - enum_effects}"
        )

    def test_agent_profiles_use_canonical_effects(self):
        """All effects in agent profiles must be valid EffectTag values."""
        canonical = {e.value for e in EffectTag}
        profile_effects = _get_agent_profile_effects()
        unknown = profile_effects - canonical
        assert not unknown, f"Agent profiles reference non-canonical effects: {unknown}"

    def test_exfil_adjacent_are_valid(self):
        """EXFIL_ADJACENT_EFFECTS must only contain valid EffectTags."""
        canonical = {e for e in EffectTag}
        invalid = EXFIL_ADJACENT_EFFECTS - canonical
        assert not invalid, f"EXFIL_ADJACENT_EFFECTS contains invalid tags: {invalid}"

    def test_read_only_are_valid(self):
        """READ_ONLY_EFFECTS must only contain valid EffectTags."""
        canonical = {e for e in EffectTag}
        invalid = READ_ONLY_EFFECTS - canonical
        assert not invalid, f"READ_ONLY_EFFECTS contains invalid tags: {invalid}"

    def test_read_only_not_exfil_adjacent(self):
        """No effect should be both read-only and exfil-adjacent."""
        overlap = READ_ONLY_EFFECTS & EXFIL_ADJACENT_EFFECTS
        assert not overlap, f"Effects are both read-only AND exfil-adjacent: {overlap}"


# ---------------------------------------------------------------------------
# PROBE 2: ALLOWED_TOOLS ≡ manifest
# ---------------------------------------------------------------------------

class TestToolManifestAlignment:
    """ALLOWED_TOOLS, manifest, and runner dispatch must agree exactly."""

    def test_allowed_tools_match_manifest(self):
        """Every tool in ALLOWED_TOOLS must exist in tool_manifest.json."""
        allowed = _get_main_allowed_tools()
        manifest = _load_manifest()
        manifest_tools = set(manifest.get("tools", {}).keys())
        phantom = allowed - manifest_tools
        assert not phantom, (
            f"Phantom tools in ALLOWED_TOOLS (not in manifest): {phantom}"
        )

    def test_manifest_tools_in_allowed(self):
        """Every manifest tool must be in ALLOWED_TOOLS."""
        allowed = _get_main_allowed_tools()
        manifest = _load_manifest()
        manifest_tools = set(manifest.get("tools", {}).keys())
        missing = manifest_tools - allowed
        assert not missing, (
            f"Manifest tools not in ALLOWED_TOOLS: {missing}"
        )

    def test_manifest_tools_have_effects(self):
        """Every manifest tool must declare at least one effect."""
        manifest = _load_manifest()
        for tool_name, spec in manifest.get("tools", {}).items():
            effects = spec.get("effects", [])
            assert len(effects) > 0, f"Tool '{tool_name}' has no declared effects"

    def test_manifest_effects_are_canonical(self):
        """All effects declared in manifest must be valid EffectTags."""
        canonical = {e.value for e in EffectTag}
        manifest = _load_manifest()
        for tool_name, spec in manifest.get("tools", {}).items():
            for effect in spec.get("effects", []):
                assert effect in canonical, (
                    f"Tool '{tool_name}' declares non-canonical effect: {effect}"
                )


# ---------------------------------------------------------------------------
# PROBE 3: Subprocess environment isolation
# ---------------------------------------------------------------------------

class TestSubprocessEnvironmentIsolation:
    """Tool subprocesses must not inherit governance secrets."""

    def test_scrubbed_env_removes_m87_vars(self):
        """_scrubbed_env() must strip all M87_ prefixed variables."""
        from services.runner.app.runner import _scrubbed_env
        with patch.dict(os.environ, {
            "M87_API_KEY": "secret-key",
            "M87_RUNNER_KEY": "runner-key",
            "M87_BOOTSTRAP_KEY": "bootstrap-key",
            "HOME": "/home/test",
            "PATH": "/usr/bin",
        }):
            env = _scrubbed_env()
            assert "M87_API_KEY" not in env
            assert "M87_RUNNER_KEY" not in env
            assert "M87_BOOTSTRAP_KEY" not in env
            assert env.get("HOME") == "/home/test"
            assert "PATH" in env

    def test_scrubbed_env_removes_redis_vars(self):
        """_scrubbed_env() must strip REDIS_ prefixed variables."""
        from services.runner.app.runner import _scrubbed_env
        with patch.dict(os.environ, {
            "REDIS_URL": "redis://secret:6379",
            "REDIS_PASSWORD": "hunter2",
            "LANG": "en_US.UTF-8",
        }):
            env = _scrubbed_env()
            assert "REDIS_URL" not in env
            assert "REDIS_PASSWORD" not in env
            assert env.get("LANG") == "en_US.UTF-8"

    def test_scrubbed_env_removes_database_vars(self):
        """_scrubbed_env() must strip DATABASE_ and POSTGRES_ prefixed variables."""
        from services.runner.app.runner import _scrubbed_env
        with patch.dict(os.environ, {
            "DATABASE_URL": "postgres://user:pass@host/db",
            "POSTGRES_PASSWORD": "secret",
            "USER": "testuser",
        }):
            env = _scrubbed_env()
            assert "DATABASE_URL" not in env
            assert "POSTGRES_PASSWORD" not in env
            assert env.get("USER") == "testuser"

    def test_scrubbed_env_removes_cloud_vars(self):
        """_scrubbed_env() must strip AWS_, GCP_, AZURE_ prefixed variables."""
        from services.runner.app.runner import _scrubbed_env
        with patch.dict(os.environ, {
            "AWS_ACCESS_KEY_ID": "AKIA...",
            "AWS_SECRET_ACCESS_KEY": "secret",
            "GCP_SERVICE_ACCOUNT": "sa@project.iam",
            "AZURE_CLIENT_SECRET": "secret",
            "TERM": "xterm",
        }):
            env = _scrubbed_env()
            assert "AWS_ACCESS_KEY_ID" not in env
            assert "AWS_SECRET_ACCESS_KEY" not in env
            assert "GCP_SERVICE_ACCOUNT" not in env
            assert "AZURE_CLIENT_SECRET" not in env
            assert env.get("TERM") == "xterm"

    def test_scrubbed_env_removes_secret_token_vars(self):
        """_scrubbed_env() must strip SECRET_ and TOKEN_ prefixed variables."""
        from services.runner.app.runner import _scrubbed_env
        with patch.dict(os.environ, {
            "SECRET_KEY": "supersecret",
            "TOKEN_AUTH": "bearer-token",
            "SHELL": "/bin/bash",
        }):
            env = _scrubbed_env()
            assert "SECRET_KEY" not in env
            assert "TOKEN_AUTH" not in env
            assert env.get("SHELL") == "/bin/bash"

    def test_tool_echo_uses_scrubbed_env(self):
        """tool_echo must pass env= to subprocess.run (structural check)."""
        runner_path = PROJECT_ROOT / "services" / "runner" / "app" / "runner.py"
        source = runner_path.read_text()
        # Find the tool_echo function and verify it contains env=_scrubbed_env()
        in_echo = False
        found_scrubbed = False
        for line in source.split("\n"):
            if "def tool_echo(" in line:
                in_echo = True
            elif in_echo and line.strip().startswith("def "):
                break
            elif in_echo and "_scrubbed_env()" in line:
                found_scrubbed = True
                break
        assert found_scrubbed, "tool_echo does not call _scrubbed_env()"

    def test_tool_pytest_uses_scrubbed_env(self):
        """tool_pytest must pass env= to subprocess.run (structural check)."""
        runner_path = PROJECT_ROOT / "services" / "runner" / "app" / "runner.py"
        source = runner_path.read_text()
        in_pytest = False
        found_scrubbed = False
        for line in source.split("\n"):
            if "def tool_pytest(" in line:
                in_pytest = True
            elif in_pytest and line.strip().startswith("def "):
                break
            elif in_pytest and "_scrubbed_env()" in line:
                found_scrubbed = True
                break
        assert found_scrubbed, "tool_pytest does not call _scrubbed_env()"


# ---------------------------------------------------------------------------
# PROBE 4: Effect schema versioning
# ---------------------------------------------------------------------------

class TestEffectSchemaVersioning:
    """Effect schema version must be consistent and enforced."""

    def test_api_and_runner_versions_match(self):
        """API EFFECT_SCHEMA_VERSION must equal runner RUNNER_EFFECT_SCHEMA_VERSION."""
        from services.runner.app.runner import RUNNER_EFFECT_SCHEMA_VERSION
        assert EFFECT_SCHEMA_VERSION == RUNNER_EFFECT_SCHEMA_VERSION, (
            f"Version mismatch: API={EFFECT_SCHEMA_VERSION}, "
            f"runner={RUNNER_EFFECT_SCHEMA_VERSION}"
        )

    def test_version_is_semver(self):
        """EFFECT_SCHEMA_VERSION must be a valid semver string."""
        parts = EFFECT_SCHEMA_VERSION.split(".")
        assert len(parts) == 3, f"Not semver: {EFFECT_SCHEMA_VERSION}"
        for p in parts:
            assert p.isdigit(), f"Non-numeric semver component: {p}"

    def test_runner_rejects_mismatched_version(self):
        """Runner's execute_job must reject a job with wrong effect_schema_version."""
        from services.runner.app.runner import execute_job, load_manifest

        manifest_path = PROJECT_ROOT / "services" / "runner" / "app" / "tool_manifest.json"
        manifest = load_manifest(str(manifest_path))

        from app.main import compute_deployment_envelope_hash, DEFAULT_ENVELOPE
        envelope = DEFAULT_ENVELOPE.model_dump(mode="json", exclude_none=True)
        envelope_hash = compute_deployment_envelope_hash(DEFAULT_ENVELOPE)

        job = {
            "job_id": "test-esv-mismatch",
            "proposal_id": "test-proposal",
            "tool": "echo",
            "inputs": {"message": "hello"},
            "manifest_hash": manifest["_manifest_hash"],
            "envelope_hash": envelope_hash,
            "deployment_envelope": envelope,
            "effect_schema_version": "99.0.0",  # Deliberately wrong
        }

        result = execute_job(job, manifest)
        assert result.get("error") == "effect_schema_version_mismatch"

    def test_runner_accepts_matching_version(self):
        """Runner's execute_job must accept a job with correct effect_schema_version."""
        from services.runner.app.runner import execute_job, load_manifest, RUNNER_EFFECT_SCHEMA_VERSION

        manifest_path = PROJECT_ROOT / "services" / "runner" / "app" / "tool_manifest.json"
        manifest = load_manifest(str(manifest_path))

        from app.main import compute_deployment_envelope_hash, DEFAULT_ENVELOPE
        envelope = DEFAULT_ENVELOPE.model_dump(mode="json", exclude_none=True)
        envelope_hash = compute_deployment_envelope_hash(DEFAULT_ENVELOPE)

        job = {
            "job_id": "test-esv-match",
            "proposal_id": "test-proposal",
            "tool": "echo",
            "inputs": {"message": "hello"},
            "manifest_hash": manifest["_manifest_hash"],
            "envelope_hash": envelope_hash,
            "deployment_envelope": envelope,
            "effect_schema_version": RUNNER_EFFECT_SCHEMA_VERSION,
        }

        result = execute_job(job, manifest)
        # Should NOT be rejected for ESV mismatch — may succeed or fail for other reasons
        assert result.get("error") != "effect_schema_version_mismatch"


# ---------------------------------------------------------------------------
# PROBE 5: Manifest ↔ runner dispatch parity
# ---------------------------------------------------------------------------

class TestManifestDispatchParity:
    """Every manifest tool must have a runner implementation."""

    def test_manifest_tools_have_dispatch(self):
        """Every tool in manifest must be handled in execute_job's dispatch."""
        manifest = _load_manifest()
        manifest_tools = set(manifest.get("tools", {}).keys())
        dispatch_tools = _get_runner_tool_names()
        unhandled = manifest_tools - dispatch_tools
        assert not unhandled, (
            f"Manifest tools without runner dispatch: {unhandled}. "
            f"Runner will raise RuntimeError('Unhandled tool') for these."
        )

    def test_dispatch_tools_in_manifest(self):
        """Runner dispatch should not handle tools not in the manifest."""
        manifest = _load_manifest()
        manifest_tools = set(manifest.get("tools", {}).keys())
        dispatch_tools = _get_runner_tool_names()
        orphaned = dispatch_tools - manifest_tools
        assert not orphaned, (
            f"Runner dispatches tools not in manifest: {orphaned}. "
            f"These will always fail manifest validation."
        )


# ---------------------------------------------------------------------------
# PROBE 6: Unknown effect → OTHER mapping
# ---------------------------------------------------------------------------

class TestUnknownEffectMapping:
    """parse_effects() must map unknown effects to OTHER (fail-closed)."""

    def test_unknown_effect_maps_to_other(self):
        """An unknown effect string must be mapped to EffectTag.OTHER."""
        effects = parse_effects(["MADE_UP_EFFECT"])
        assert EffectTag.OTHER in effects

    def test_multiple_unknowns_collapse_to_one_other(self):
        """Multiple unknown effects should all produce a single OTHER."""
        effects = parse_effects(["FAKE1", "FAKE2", "FAKE3"])
        assert effects == {EffectTag.OTHER}

    def test_mix_known_and_unknown(self):
        """Known effects are preserved; unknown effects become OTHER."""
        effects = parse_effects(["READ_REPO", "UNKNOWN_EFFECT"])
        assert EffectTag.READ_REPO in effects
        assert EffectTag.OTHER in effects
        assert len(effects) == 2

    def test_empty_input(self):
        """Empty input produces empty set (not OTHER)."""
        effects = parse_effects([])
        assert effects == set()


# ---------------------------------------------------------------------------
# PROBE 7: Job spec carries effect_schema_version
# ---------------------------------------------------------------------------

class TestJobSpecCarriesESV:
    """enqueue_job() must stamp effect_schema_version into the job dict."""

    def test_enqueue_includes_esv(self):
        """Structural check: enqueue_job creates a dict with effect_schema_version."""
        main_path = API_DIR / "app" / "main.py"
        source = main_path.read_text()
        assert '"effect_schema_version"' in source or "'effect_schema_version'" in source, (
            "enqueue_job() does not include effect_schema_version in job dict"
        )
        assert "EFFECT_SCHEMA_VERSION" in source, (
            "main.py does not reference EFFECT_SCHEMA_VERSION constant"
        )
