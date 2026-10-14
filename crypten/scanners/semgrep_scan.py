"""Runs crypTen's custom Semgrep rules against a target.

Unlike a --config=auto run, this points Semgrep at the bundled ruleset, so it
needs neither network access nor a Semgrep account. If Semgrep is not installed
the scan is skipped and the ruleset still stands on its own as a deliverable a
maintainer can run in their own CI.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from ..findings import Finding
from ..intake import Target
from ..redact import redact
from .external import ToolResult

RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "crypten-credentials.yml"

_SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def run_semgrep(target: Target, timeout: int = 120) -> ToolResult:
    executable = _find_semgrep()
    if executable is None:
        return ToolResult("semgrep", False, [], "semgrep not installed")

    cmd = [
        executable, "scan", "--config", str(RULES_FILE),
        "--json", "--quiet", "--disable-version-check", "--metrics=off",
        str(target.root),
    ]
    try:
        completed = subprocess.run(
            cmd, cwd=target.root, capture_output=True, text=True, timeout=timeout, check=False
        )
    except FileNotFoundError:
        return ToolResult("semgrep", False, [], "semgrep not installed")
    except subprocess.TimeoutExpired:
        return ToolResult("semgrep", True, [], "timed out")

    if not completed.stdout.strip():
        return ToolResult("semgrep", True, [], "no output")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return ToolResult("semgrep", True, [], "unparseable output")

    findings: list[Finding] = []
    for result in payload.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe = metadata.get("cwe", "CWE-693")
        if isinstance(cwe, list):
            cwe = cwe[0] if cwe else "CWE-693"
        findings.append(
            Finding(
                rule_id=f"semgrep.{result.get('check_id', 'rule').split('.')[-1]}",
                cwe_id=cwe,
                file_path=_relative(target.root, result.get("path", "")),
                line=result.get("start", {}).get("line", 1),
                severity=_SEMGREP_SEVERITY.get(extra.get("severity", "WARNING"), "MEDIUM"),
                confidence="MEDIUM",
                evidence=redact((extra.get("lines") or "").strip()),
                scanner="semgrep",
                title=(extra.get("message") or "").strip()[:120],
            )
        )
    return ToolResult("semgrep", True, findings)


def _find_semgrep() -> str | None:
    """Locate the semgrep executable, preferring the one in this venv.

    `python -m semgrep` was deprecated in 1.38 and now exits non-zero, so the
    executable has to be invoked directly. It lives next to the interpreter in
    the venv's scripts directory, which is not necessarily on the subprocess
    PATH, so look there before falling back to PATH.
    """
    scripts_dir = Path(sys.executable).parent
    for name in ("semgrep.exe", "semgrep"):
        candidate = scripts_dir / name
        if candidate.exists():
            return str(candidate)
    return shutil.which("semgrep")


def _relative(root: Path, raw: str) -> str:
    try:
        return Path(raw).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(raw).name
