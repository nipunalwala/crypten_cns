"""Wrappers around Bandit and pip-audit.

These are third-party scanners the project leans on for breadth: Bandit for its
established credential checks (B105, B303, B311, B324, B501) and pip-audit for
known CVEs in the target's dependencies. Both are optional - if the tool is not
installed the wrapper reports that it was skipped rather than failing the scan,
and both run as argument arrays with a timeout, never through a shell.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from ..findings import Finding
from ..intake import Target
from ..redact import redact

# Bandit test ids mapped to the project's CWE taxonomy. Bandit reports its own
# CWE where it knows one; this is the fallback and the scope filter.
_BANDIT_CWE = {
    "B105": "CWE-798", "B106": "CWE-798", "B107": "CWE-798",
    "B303": "CWE-916", "B324": "CWE-916",
    "B311": "CWE-330",
    "B501": "CWE-295", "B502": "CWE-295", "B503": "CWE-295", "B504": "CWE-295",
}


@dataclass
class ToolResult:
    scanner: str
    available: bool
    findings: list[Finding]
    note: str = ""


def run_bandit(target: Target, timeout: int = 90) -> ToolResult:
    completed = _invoke(
        [sys.executable, "-m", "bandit", "-r", str(target.root), "-f", "json", "-q"],
        cwd=target.root,
        timeout=timeout,
    )
    if completed is None:
        return ToolResult("bandit", False, [], "bandit not installed")
    # Bandit exits 1 when it finds issues; only an empty stdout is a real failure.
    if not completed.stdout.strip():
        return ToolResult("bandit", True, [], "no output")

    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return ToolResult("bandit", True, [], "unparseable output")

    findings: list[Finding] = []
    for issue in payload.get("results", []):
        test_id = issue.get("test_id", "")
        raw_cwe = issue.get("issue_cwe") or {}
        cwe_id = f"CWE-{raw_cwe['id']}" if raw_cwe.get("id") else _BANDIT_CWE.get(test_id, "CWE-693")
        rel = _relative(target.root, issue.get("filename", ""))
        findings.append(
            Finding(
                rule_id=f"bandit.{test_id}",
                cwe_id=cwe_id,
                file_path=rel,
                line=issue.get("line_number", 1),
                severity=issue.get("issue_severity", "MEDIUM").upper(),
                confidence=issue.get("issue_confidence", "MEDIUM").upper(),
                evidence=redact((issue.get("code") or "").strip().splitlines()[0] if issue.get("code") else ""),
                scanner="bandit",
                title=issue.get("issue_text", "")[:120],
            )
        )
    return ToolResult("bandit", True, findings)


def run_pip_audit(target: Target, timeout: int = 120) -> ToolResult:
    requirement_files = sorted(
        p for p in target.root.glob("**/requirements*.txt")
        if not any(part in {".venv", "venv", "node_modules"} for part in p.parts)
    )
    if not requirement_files:
        return ToolResult("pip-audit", True, [], "no requirements files")

    findings: list[Finding] = []
    any_ran = False
    for req in requirement_files:
        completed = _invoke(
            [sys.executable, "-m", "pip_audit", "-r", str(req), "-f", "json", "--no-deps"],
            cwd=target.root,
            timeout=timeout,
        )
        if completed is None:
            return ToolResult("pip-audit", False, [], "pip-audit not installed")
        any_ran = True
        if not completed.stdout.strip():
            continue
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            continue
        rel = _relative(target.root, str(req))
        findings.extend(_pip_audit_findings(payload, rel))

    note = "" if any_ran else "no requirements scanned"
    return ToolResult("pip-audit", True, findings, note)


def _pip_audit_findings(payload: dict, req_path: str) -> list[Finding]:
    deps = payload.get("dependencies", payload) if isinstance(payload, dict) else payload
    if isinstance(deps, dict):
        deps = deps.get("dependencies", [])
    out: list[Finding] = []
    for dep in deps:
        name = dep.get("name", "?")
        version = dep.get("version", "?")
        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id", "UNKNOWN")
            fixes = ", ".join(vuln.get("fix_versions", [])) or "no fixed version published"
            out.append(
                Finding(
                    rule_id=f"pip-audit.{vuln_id}",
                    cwe_id="CWE-1395",
                    file_path=req_path,
                    line=1,
                    severity="HIGH",
                    confidence="HIGH",
                    evidence=f"{name}=={version} affected by {vuln_id} (fix: {fixes})",
                    scanner="pip-audit",
                    title=f"{name} {version}: {vuln_id}",
                )
            )
    return out


def _invoke(cmd: list[str], *, cwd: Path, timeout: int) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None


def _relative(root: Path, raw: str) -> str:
    try:
        return Path(raw).resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        return Path(raw).name
