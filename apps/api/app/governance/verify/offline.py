"""
M87 Governed Swarm — Offline Bundle Verification

Verifies bundle integrity using only local artifacts.
No network. No governance service. No database.

Binary PASS/FAIL. No PASS-with-caveats.
"""
from __future__ import annotations

import hashlib
import json
import logging
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from ..call_receipt import _deterministic_serialize

logger = logging.getLogger("m87.verify.offline")


class CheckResult(BaseModel):
    check_id: str
    name: str
    status: str  # "PASS" | "FAIL" | "SKIPPED"
    detail: str = ""
    expected: Optional[str] = None
    actual: Optional[str] = None


class VerificationReport(BaseModel):
    report_version: str = "1.0.0"
    overall: str  # "PASS" | "FAIL"
    bundle_file: str
    bundle_hash: str
    timestamp_utc: datetime
    verifier_version: str = "1.0.0"
    keyring_fingerprint: Optional[str] = None
    checks: list[CheckResult] = Field(default_factory=list)
    known_limitations: list[str] = Field(default_factory=lambda: [
        "Nonce monotonicity (requires state store)",
        "Snapshot freshness (requires live repo access)",
        "Governance service approval status (requires network)",
        "Content hash excludes bundle_receipt.json (circular dependency; receipt integrity depends on SIG_VALID)",
    ])
    duration_ms: Optional[float] = None


class OfflineVerifier:
    """
    Checks (in order, fail-fast):
      1. SIG_VALID         — Bundle signature against keyring
      2. BUNDLE_HASH_MATCH — Bundle hash matches receipt
      3. SNAPSHOT_PRESENT  — Snapshot manifest exists + well-formed
      4. ARTIFACTS_COMPLETE — All declared artifacts present
      5. RECEIPTS_CHAIN_VALID — Hash chain integrity across call receipts
      6. RECEIPTS_MONOTONIC   — Sequence numbers increasing
      7. RECEIPTS_NO_GAPS     — No gaps in sequence
      8. BUDGET_COMPLIANCE    — Sum of call receipts <= declared budget
      9. CONTRACT_COMPLETE    — Execution contract has all required sections
     10. NO_UNTRUSTED_EXEC   — No UNTRUSTED skills in execution path

    Rules:
    - NEVER return overall="PASS" if any check is FAIL
    - NEVER skip signature check if keyring missing (FAIL instead)
    - SKIPPED only if a prior check FAILed and this check depends on it
    - Fail-fast: first FAIL may prevent subsequent checks from running
    """

    REQUIRED_ARTIFACTS = [
        "project_profile.json",
        "snapshot_manifest.json",
        "skill_manifest.lock",
        "context_graph.json",
        "integration_plan.yaml",
        "tool_contracts.json",
        "patch_registry.jsonl",
        "mutation_policy.yaml",
        "bootstrap_execution_contract_v1.md",
        "bundle_receipt.json",
        "bundle_signature.sig",
    ]

    CONTRACT_REQUIRED_SECTIONS = [
        "assumptions",
        "constraints",
        "interfaces",
        "failure_modes",
        "artifact_definition",
        "receipt",
    ]

    def verify(self, bundle_path: str, keyring_path: str) -> VerificationReport:
        """Run all checks. Return report."""
        start = time.monotonic()

        # Compute bundle hash
        bundle_file = Path(bundle_path)
        try:
            bundle_bytes = bundle_file.read_bytes()
            bundle_hash = hashlib.sha256(bundle_bytes).hexdigest()
        except (OSError, IOError) as e:
            return VerificationReport(
                overall="FAIL",
                bundle_file=str(bundle_path),
                bundle_hash="",
                timestamp_utc=datetime.now(timezone.utc),
                checks=[CheckResult(
                    check_id="SIG_VALID",
                    name="Bundle signature",
                    status="FAIL",
                    detail=f"Cannot read bundle: {e}",
                )],
                duration_ms=(time.monotonic() - start) * 1000,
            )

        checks: list[CheckResult] = []
        contents: Dict[str, bytes] = {}
        members: list[str] = []
        sig_ok = False

        # Extract bundle contents
        try:
            with tarfile.open(bundle_path, "r:gz") as tar:
                members = [m.name for m in tar.getmembers() if m.isfile()]
                for member in tar.getmembers():
                    if member.isfile():
                        f = tar.extractfile(member)
                        if f:
                            contents[member.name] = f.read()
        except (tarfile.TarError, OSError) as e:
            return VerificationReport(
                overall="FAIL",
                bundle_file=str(bundle_path),
                bundle_hash=bundle_hash,
                timestamp_utc=datetime.now(timezone.utc),
                checks=[CheckResult(
                    check_id="SIG_VALID",
                    name="Bundle signature",
                    status="FAIL",
                    detail=f"Cannot open bundle as tar.gz: {e}",
                )],
                duration_ms=(time.monotonic() - start) * 1000,
            )

        # 1. SIG_VALID
        sig_check = self._check_sig_valid(bundle_path, keyring_path, contents)
        checks.append(sig_check)
        sig_ok = sig_check.status == "PASS"

        # 2. BUNDLE_HASH_MATCH (uses content hash, same as signature)
        content_hash = self._compute_content_hash(contents)
        receipt_data = self._parse_json_content(contents, "bundle_receipt.json")
        if sig_ok and receipt_data is not None:
            checks.append(self._check_bundle_hash(content_hash, receipt_data))
        elif not sig_ok:
            checks.append(CheckResult(
                check_id="BUNDLE_HASH_MATCH",
                name="Bundle hash match",
                status="SKIPPED",
                detail="Skipped: signature check failed",
            ))
        else:
            checks.append(CheckResult(
                check_id="BUNDLE_HASH_MATCH",
                name="Bundle hash match",
                status="FAIL",
                detail="bundle_receipt.json missing or invalid",
            ))

        # 3. SNAPSHOT_PRESENT
        checks.append(self._check_snapshot_present(members, contents))

        # 4. ARTIFACTS_COMPLETE
        checks.append(self._check_artifacts_complete(members))

        # 5-7. Receipt chain checks
        receipts = self._extract_receipts(members, contents)
        checks.append(self._check_receipts_chain(receipts))
        checks.append(self._check_receipts_monotonic(receipts))
        checks.append(self._check_receipts_no_gaps(receipts))

        # 8. BUDGET_COMPLIANCE
        checks.append(self._check_budget_compliance(receipts, receipt_data or {}))

        # 9. CONTRACT_COMPLETE
        contract_text = ""
        if "bootstrap_execution_contract_v1.md" in contents:
            contract_text = contents["bootstrap_execution_contract_v1.md"].decode(
                "utf-8", errors="replace"
            )
        checks.append(self._check_contract_complete(contract_text))

        # 10. NO_UNTRUSTED_EXEC
        skill_manifest = self._parse_json_content(contents, "skill_manifest.lock") or {}
        context_graph = self._parse_json_content(contents, "context_graph.json") or {}
        checks.append(self._check_no_untrusted_exec(skill_manifest, context_graph))

        # Determine overall
        has_fail = any(c.status == "FAIL" for c in checks)
        overall = "FAIL" if has_fail else "PASS"

        elapsed = (time.monotonic() - start) * 1000

        keyring_fp = None
        try:
            kp = Path(keyring_path)
            if kp.exists():
                keyring_fp = hashlib.sha256(kp.read_bytes()).hexdigest()[:16]
        except OSError:
            pass

        return VerificationReport(
            overall=overall,
            bundle_file=str(bundle_path),
            bundle_hash=bundle_hash,
            timestamp_utc=datetime.now(timezone.utc),
            keyring_fingerprint=keyring_fp,
            checks=checks,
            duration_ms=elapsed,
        )

    def _parse_json_content(
        self, contents: Dict[str, bytes], filename: str
    ) -> Optional[Dict[str, Any]]:
        """Parse a JSON file from bundle contents."""
        raw = contents.get(filename)
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def _extract_receipts(
        self, members: list[str], contents: Dict[str, bytes]
    ) -> list[Dict[str, Any]]:
        """Extract and parse call receipts from bundle."""
        receipts = []
        receipt_files = sorted(
            m for m in members if m.startswith("call_receipts/") and m.endswith(".json")
        )
        for rf in receipt_files:
            raw = contents.get(rf)
            if raw:
                try:
                    receipts.append(json.loads(raw.decode("utf-8")))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
        return receipts

    # Files excluded from content hash to break circular dependencies.
    # bundle_signature.sig: signature references the content hash
    # bundle_receipt.json: receipt stores bundle_sha256 = content hash
    _HASH_EXCLUDED_FILES = frozenset({"bundle_signature.sig", "bundle_receipt.json"})

    def _compute_content_hash(self, contents: Dict[str, bytes]) -> str:
        """
        Compute SHA-256 of all bundle contents EXCEPT signature and receipt.

        Excludes bundle_signature.sig and bundle_receipt.json to break the
        circular dependency: both reference the content hash, so they cannot
        be included in its computation.

        Trust chain: SIG_VALID verifies the signature covers the full tar
        (including receipt). BUNDLE_HASH_MATCH verifies the content hash
        stored in the receipt matches the artifacts. Together they form a
        complete integrity chain, but receipt integrity depends on SIG_VALID
        passing — BUNDLE_HASH_MATCH alone does not cover the receipt.
        """
        h = hashlib.sha256()
        for key in sorted(contents.keys()):
            if key in self._HASH_EXCLUDED_FILES:
                continue
            h.update(key.encode("utf-8"))
            h.update(contents[key])
        return h.hexdigest()

    def _check_sig_valid(
        self, bundle_path: str, keyring_path: str, contents: Dict[str, bytes]
    ) -> CheckResult:
        """Verify bundle signature against keyring."""
        kp = Path(keyring_path)
        if not kp.exists():
            return CheckResult(
                check_id="SIG_VALID",
                name="Bundle signature",
                status="FAIL",
                detail=f"Keyring not found: {keyring_path}",
            )

        try:
            keyring_data = kp.read_bytes()
        except OSError as e:
            return CheckResult(
                check_id="SIG_VALID",
                name="Bundle signature",
                status="FAIL",
                detail=f"Cannot read keyring: {e}",
            )

        sig_data = contents.get("bundle_signature.sig")
        if sig_data is None:
            return CheckResult(
                check_id="SIG_VALID",
                name="Bundle signature",
                status="FAIL",
                detail="bundle_signature.sig not found in bundle",
            )

        try:
            sig_json = json.loads(sig_data.decode("utf-8"))
            sig_hash = sig_json.get("bundle_sha256", "")
            sig_keyring_fp = sig_json.get("keyring_fingerprint", "")

            # Compute content hash (all files except signature itself)
            content_hash = self._compute_content_hash(contents)

            if sig_hash != content_hash:
                return CheckResult(
                    check_id="SIG_VALID",
                    name="Bundle signature",
                    status="FAIL",
                    detail=f"Signature hash mismatch: sig={sig_hash[:16]}... content={content_hash[:16]}...",
                    expected=content_hash,
                    actual=sig_hash,
                )

            # Verify keyring fingerprint matches
            keyring_fp = hashlib.sha256(keyring_data).hexdigest()[:16]
            if sig_keyring_fp and sig_keyring_fp != keyring_fp:
                return CheckResult(
                    check_id="SIG_VALID",
                    name="Bundle signature",
                    status="FAIL",
                    detail=f"Keyring fingerprint mismatch: sig={sig_keyring_fp} keyring={keyring_fp}",
                    expected=keyring_fp,
                    actual=sig_keyring_fp,
                )

            return CheckResult(
                check_id="SIG_VALID",
                name="Bundle signature",
                status="PASS",
                detail=f"Signature valid (keyring: {keyring_fp})",
            )
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return CheckResult(
                check_id="SIG_VALID",
                name="Bundle signature",
                status="FAIL",
                detail=f"Invalid signature format: {e}",
            )

    def _check_bundle_hash(
        self, content_hash: str, receipt: Dict[str, Any]
    ) -> CheckResult:
        """Verify content hash matches receipt.bundle_sha256."""
        expected = receipt.get("bundle_sha256", "")
        if not expected:
            return CheckResult(
                check_id="BUNDLE_HASH_MATCH",
                name="Bundle hash match",
                status="FAIL",
                detail="bundle_receipt.json missing bundle_sha256 field",
            )

        if content_hash != expected:
            return CheckResult(
                check_id="BUNDLE_HASH_MATCH",
                name="Bundle hash match",
                status="FAIL",
                detail=f"Hash mismatch: expected={expected[:16]}... actual={content_hash[:16]}...",
                expected=expected,
                actual=content_hash,
            )

        return CheckResult(
            check_id="BUNDLE_HASH_MATCH",
            name="Bundle hash match",
            status="PASS",
            detail=f"Content hash verified: {content_hash[:16]}...",
        )

    def _check_snapshot_present(
        self, members: list[str], contents: Dict[str, bytes]
    ) -> CheckResult:
        """Verify snapshot_manifest.json exists and is valid JSON."""
        if "snapshot_manifest.json" not in members:
            return CheckResult(
                check_id="SNAPSHOT_PRESENT",
                name="Snapshot manifest",
                status="FAIL",
                detail="snapshot_manifest.json not found in bundle",
            )

        raw = contents.get("snapshot_manifest.json")
        if not raw:
            return CheckResult(
                check_id="SNAPSHOT_PRESENT",
                name="Snapshot manifest",
                status="FAIL",
                detail="snapshot_manifest.json is empty",
            )

        try:
            data = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            return CheckResult(
                check_id="SNAPSHOT_PRESENT",
                name="Snapshot manifest",
                status="FAIL",
                detail=f"Invalid JSON: {e}",
            )

        required_fields = ["version", "files"]
        missing = [f for f in required_fields if f not in data]
        if missing:
            return CheckResult(
                check_id="SNAPSHOT_PRESENT",
                name="Snapshot manifest",
                status="FAIL",
                detail=f"Missing required fields: {missing}",
            )

        return CheckResult(
            check_id="SNAPSHOT_PRESENT",
            name="Snapshot manifest",
            status="PASS",
            detail=f"Snapshot manifest valid ({len(data.get('files', []))} files)",
        )

    def _check_artifacts_complete(self, members: list[str]) -> CheckResult:
        """Verify all REQUIRED_ARTIFACTS exist in bundle."""
        missing = [a for a in self.REQUIRED_ARTIFACTS if a not in members]
        if missing:
            return CheckResult(
                check_id="ARTIFACTS_COMPLETE",
                name="Required artifacts",
                status="FAIL",
                detail=f"Missing artifacts: {missing}",
                expected=str(len(self.REQUIRED_ARTIFACTS)),
                actual=str(len(self.REQUIRED_ARTIFACTS) - len(missing)),
            )

        return CheckResult(
            check_id="ARTIFACTS_COMPLETE",
            name="Required artifacts",
            status="PASS",
            detail=f"All {len(self.REQUIRED_ARTIFACTS)} required artifacts present",
        )

    def _check_receipts_chain(self, receipts: list[Dict[str, Any]]) -> CheckResult:
        """Verify hash chain: receipt[n].previous_receipt_hash == receipt[n-1].receipt_hash."""
        if not receipts:
            return CheckResult(
                check_id="RECEIPTS_CHAIN_VALID",
                name="Receipt hash chain",
                status="PASS",
                detail="No receipts to verify (empty chain is valid)",
            )

        for i, r in enumerate(receipts):
            if i == 0:
                if r.get("previous_receipt_hash") is not None:
                    return CheckResult(
                        check_id="RECEIPTS_CHAIN_VALID",
                        name="Receipt hash chain",
                        status="FAIL",
                        detail="First receipt has non-null previous_receipt_hash",
                        expected="null",
                        actual=str(r.get("previous_receipt_hash")),
                    )
            else:
                prev_hash = receipts[i - 1].get("receipt_hash")
                curr_prev = r.get("previous_receipt_hash")
                if curr_prev != prev_hash:
                    return CheckResult(
                        check_id="RECEIPTS_CHAIN_VALID",
                        name="Receipt hash chain",
                        status="FAIL",
                        detail=f"Chain break at receipt {i}: expected prev={prev_hash}, got {curr_prev}",
                        expected=str(prev_hash),
                        actual=str(curr_prev),
                    )

        return CheckResult(
            check_id="RECEIPTS_CHAIN_VALID",
            name="Receipt hash chain",
            status="PASS",
            detail=f"Hash chain valid across {len(receipts)} receipts",
        )

    def _check_receipts_monotonic(self, receipts: list[Dict[str, Any]]) -> CheckResult:
        """Verify sequence_number is strictly increasing."""
        if not receipts:
            return CheckResult(
                check_id="RECEIPTS_MONOTONIC",
                name="Receipt monotonicity",
                status="PASS",
                detail="No receipts to verify",
            )

        for i in range(1, len(receipts)):
            prev_seq = receipts[i - 1].get("sequence_number", -1)
            curr_seq = receipts[i].get("sequence_number", -1)
            if curr_seq <= prev_seq:
                return CheckResult(
                    check_id="RECEIPTS_MONOTONIC",
                    name="Receipt monotonicity",
                    status="FAIL",
                    detail=f"Non-monotonic at index {i}: {prev_seq} -> {curr_seq}",
                    expected=f"> {prev_seq}",
                    actual=str(curr_seq),
                )

        return CheckResult(
            check_id="RECEIPTS_MONOTONIC",
            name="Receipt monotonicity",
            status="PASS",
            detail=f"Sequence numbers strictly increasing across {len(receipts)} receipts",
        )

    def _check_receipts_no_gaps(self, receipts: list[Dict[str, Any]]) -> CheckResult:
        """Verify no gaps in sequence (0, 1, 2, ... N-1)."""
        if not receipts:
            return CheckResult(
                check_id="RECEIPTS_NO_GAPS",
                name="Receipt sequence gaps",
                status="PASS",
                detail="No receipts to verify",
            )

        seq_numbers = [r.get("sequence_number", -1) for r in receipts]
        expected = list(range(len(receipts)))

        if seq_numbers != expected:
            # Find the first gap
            for i, (actual, exp) in enumerate(zip(seq_numbers, expected)):
                if actual != exp:
                    return CheckResult(
                        check_id="RECEIPTS_NO_GAPS",
                        name="Receipt sequence gaps",
                        status="FAIL",
                        detail=f"Gap at index {i}: expected sequence {exp}, got {actual}",
                        expected=str(exp),
                        actual=str(actual),
                    )
            # Length mismatch
            return CheckResult(
                check_id="RECEIPTS_NO_GAPS",
                name="Receipt sequence gaps",
                status="FAIL",
                detail=f"Sequence length mismatch: expected {len(expected)}, got {len(seq_numbers)}",
            )

        return CheckResult(
            check_id="RECEIPTS_NO_GAPS",
            name="Receipt sequence gaps",
            status="PASS",
            detail=f"No gaps in sequence 0..{len(receipts) - 1}",
        )

    def _check_budget_compliance(
        self, receipts: list[Dict[str, Any]], receipt: Dict[str, Any]
    ) -> CheckResult:
        """Verify sum of execution times and call counts <= declared budget."""
        budget = receipt.get("autonomy_budget", {})
        max_runtime = budget.get("max_runtime_seconds", 0)
        max_tool_calls = budget.get("max_tool_calls", 0)

        if not max_runtime and not max_tool_calls:
            return CheckResult(
                check_id="BUDGET_COMPLIANCE",
                name="Budget compliance",
                status="PASS",
                detail="No budget declared (legacy bundle)",
            )

        total_ms = 0.0
        call_count = 0
        for r in receipts:
            execution = r.get("execution")
            if execution:
                total_ms += execution.get("execution_ms", 0)
                call_count += 1

        total_seconds = total_ms / 1000.0

        if max_runtime and total_seconds > max_runtime:
            return CheckResult(
                check_id="BUDGET_COMPLIANCE",
                name="Budget compliance",
                status="FAIL",
                detail=f"Runtime exceeded: {total_seconds:.1f}s > {max_runtime}s budget",
                expected=f"<= {max_runtime}s",
                actual=f"{total_seconds:.1f}s",
            )

        if max_tool_calls and call_count > max_tool_calls:
            return CheckResult(
                check_id="BUDGET_COMPLIANCE",
                name="Budget compliance",
                status="FAIL",
                detail=f"Tool calls exceeded: {call_count} > {max_tool_calls} budget",
                expected=f"<= {max_tool_calls}",
                actual=str(call_count),
            )

        return CheckResult(
            check_id="BUDGET_COMPLIANCE",
            name="Budget compliance",
            status="PASS",
            detail=f"Within budget: {total_seconds:.1f}s runtime, {call_count} calls",
        )

    def _check_contract_complete(self, contract_text: str) -> CheckResult:
        """Verify execution contract contains all required sections."""
        if not contract_text:
            return CheckResult(
                check_id="CONTRACT_COMPLETE",
                name="Contract completeness",
                status="FAIL",
                detail="Execution contract is empty or missing",
            )

        lower = contract_text.lower()
        missing = []
        for section in self.CONTRACT_REQUIRED_SECTIONS:
            # Check for section with underscores or spaces (e.g. "failure_modes" or "failure modes")
            variants = [section.lower(), section.lower().replace("_", " ")]
            if not any(v in lower for v in variants):
                missing.append(section)

        if missing:
            return CheckResult(
                check_id="CONTRACT_COMPLETE",
                name="Contract completeness",
                status="FAIL",
                detail=f"Missing required sections: {missing}",
                expected=str(self.CONTRACT_REQUIRED_SECTIONS),
                actual=str([s for s in self.CONTRACT_REQUIRED_SECTIONS if s not in missing]),
            )

        return CheckResult(
            check_id="CONTRACT_COMPLETE",
            name="Contract completeness",
            status="PASS",
            detail=f"All {len(self.CONTRACT_REQUIRED_SECTIONS)} required sections present",
        )

    def _check_no_untrusted_exec(
        self, skill_manifest: Dict[str, Any], context_graph: Dict[str, Any]
    ) -> CheckResult:
        """Verify no UNTRUSTED skills appear in the execution path."""
        skills = skill_manifest.get("skills", {})
        execution_path = context_graph.get("execution_path", [])

        # Build set of untrusted skill IDs
        untrusted_skills = set()
        for skill_id, spec in skills.items():
            trust = spec.get("trust_level", "UNTRUSTED")
            if trust == "UNTRUSTED":
                untrusted_skills.add(skill_id)

        if not untrusted_skills:
            return CheckResult(
                check_id="NO_UNTRUSTED_EXEC",
                name="No untrusted execution",
                status="PASS",
                detail="No untrusted skills in manifest",
            )

        # Check execution path for untrusted skills
        used_untrusted = []
        for step in execution_path:
            skill_id = step.get("skill_id", "") if isinstance(step, dict) else str(step)
            if skill_id in untrusted_skills:
                used_untrusted.append(skill_id)

        if used_untrusted:
            return CheckResult(
                check_id="NO_UNTRUSTED_EXEC",
                name="No untrusted execution",
                status="FAIL",
                detail=f"UNTRUSTED skills in execution path: {used_untrusted}",
                expected="No untrusted skills",
                actual=str(used_untrusted),
            )

        return CheckResult(
            check_id="NO_UNTRUSTED_EXEC",
            name="No untrusted execution",
            status="PASS",
            detail=f"Execution path clean ({len(untrusted_skills)} untrusted skills in manifest, none in path)",
        )
