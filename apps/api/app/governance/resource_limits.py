"""
Phase 5 resource governance: bounded inspection without SIGALRM fragility.

Uses subprocess-level wall-clock bounds for scans (works under async, threads, workers).
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class Limits:
    """Resource limits for governance inspection."""
    max_code_bytes: int = 250_000
    scan_timeout_seconds: int = 2
    max_response_bytes: int = 50_000


DEFAULT_LIMITS = Limits()


class GovernanceTimeout(Exception):
    """Raised when governance scan exceeds timeout."""
    pass


class GovernanceLimitExceeded(Exception):
    """Raised when input exceeds size limits."""
    pass


def enforce_size_limit(code: str, limits: Limits = DEFAULT_LIMITS) -> None:
    """Enforce code size limit before scanning."""
    if len(code.encode("utf-8", errors="ignore")) > limits.max_code_bytes:
        raise GovernanceLimitExceeded(
            f"Code exceeds max size ({limits.max_code_bytes} bytes)."
        )


def bounded_python_tripwire_scan(
    code: str,
    limits: Limits = DEFAULT_LIMITS
) -> Dict[str, Any]:
    """
    Cheap tripwire scan executed in a subprocess so timeouts are real under async runtimes.

    Scans for common exfiltration primitives:
    - Network imports (socket, requests, urllib, httpx)
    - Subprocess calls
    - Environment variable access
    - Sensitive file access (/etc, /proc)

    Returns:
        {"ok": bool, "flags": list[str]}
    """
    enforce_size_limit(code, limits)

    payload = json.dumps({"code": code}).encode("utf-8")
    cmd = ["python", "-c", _TRIPWIRE_SCRIPT]

    try:
        p = subprocess.run(
            cmd,
            input=payload,
            capture_output=True,
            timeout=limits.scan_timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise GovernanceTimeout("Tripwire scan timeout") from e

    out = (p.stdout or b"")[: limits.max_response_bytes]
    try:
        return json.loads(out.decode("utf-8", errors="ignore") or "{}")
    except Exception:
        return {"ok": False, "flags": ["scanner_output_unparseable"]}


_TRIPWIRE_SCRIPT = r"""
import json, sys, re
raw = sys.stdin.buffer.read()
try:
    data = json.loads(raw.decode("utf-8", errors="ignore"))
    code = data.get("code", "")
except Exception:
    print(json.dumps({"ok": False, "flags": ["bad_input"]}))
    sys.exit(0)

flags = []
# Basic exfil primitives
patterns = [
    (r'\bimport\s+socket\b', 'import_socket'),
    (r'\bimport\s+requests\b', 'import_requests'),
    (r'\bimport\s+urllib\b', 'import_urllib'),
    (r'\bfrom\s+urllib\b', 'from_urllib'),
    (r'\bimport\s+httpx\b', 'import_httpx'),
    (r'\bimport\s+aiohttp\b', 'import_aiohttp'),
    (r'\bsubprocess\b', 'subprocess'),
    (r'\bos\.environ\b', 'os_environ'),
    (r'\bos\.system\b', 'os_system'),
    (r'\bos\.popen\b', 'os_popen'),
    (r'\beval\s*\(', 'eval'),
    (r'\bexec\s*\(', 'exec'),
    (r'\b__import__\b', 'dunder_import'),
    (r'\bopen\(\s*["\']\/(etc|proc)\/', 'sensitive_file_access'),
]
for pat, name in patterns:
    if re.search(pat, code):
        flags.append(name)

ok = len(flags) == 0
print(json.dumps({"ok": ok, "flags": flags}))
"""


def scan_artifact_code(
    artifact_type: str,
    content: str,
    limits: Limits = DEFAULT_LIMITS
) -> Dict[str, Any]:
    """
    Scan artifact content if it's code.

    Returns:
        {"ok": bool, "flags": list[str], "skipped": bool}
    """
    if artifact_type not in ("python_code", "shell_script", "code"):
        return {"ok": True, "flags": [], "skipped": True}

    return bounded_python_tripwire_scan(content, limits)
