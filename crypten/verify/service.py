"""Confirm a finding, by executing a proof of concept where one is safe to run.

Findings that need target code to run (hashing, tokens, JWT, logging) go to the
isolated runner in a separate process. Findings where running proves nothing
over reading - a disabled TLS flag, a secret literal - are confirmed by
inspection instead, and labelled honestly as inspected rather than exploited.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from ..findings import Finding
from ..intake import Target, read_source, resolve_within

SANDBOX_TIMEOUT_SECONDS = 20

_SANDBOX_CWES = frozenset({"CWE-916", "CWE-759", "CWE-330", "CWE-347", "CWE-532"})
_INSPECTION_CWES = frozenset({"CWE-295", "CWE-798", "CWE-256"})


@dataclass
class Verification:
    finding: Finding
    result: str  # EXPLOITED | NOT_EXPLOITABLE | INSPECTED | INCONCLUSIVE
    summary: str
    method: str  # "sandboxed proof of concept" | "static inspection"
    details: dict
    log: list[str]

    @property
    def confirms_weakness(self) -> bool:
        return self.result in ("EXPLOITED", "INSPECTED")


def verify(target: Target, finding: Finding) -> Verification:
    cwe = finding.cwe_id.upper()
    if cwe in _SANDBOX_CWES:
        return _run_sandbox(target, finding)
    if cwe in _INSPECTION_CWES:
        return _inspect(target, finding)
    if cwe == "CWE-1395":
        return Verification(
            finding, "INSPECTED",
            "A declared dependency version has a published advisory. Confirmed against the "
            "advisory database by pip-audit; crypTen does not run the CVE's exploit.",
            "advisory database", {"advisory": finding.rule_id}, [],
        )
    return Verification(
        finding, "INCONCLUSIVE", "No verification probe is defined for this weakness.",
        "none", {}, [f"{cwe} has no probe"],
    )


def _run_sandbox(target: Target, finding: Finding) -> Verification:
    log: list[str] = []
    try:
        target_file = resolve_within(target.root, finding.file_path)
    except Exception as exc:
        return Verification(finding, "INCONCLUSIVE", str(exc), "sandboxed proof of concept", {}, [str(exc)])

    if not target_file.exists():
        return Verification(
            finding, "INCONCLUSIVE", f"target file not found: {finding.file_path}",
            "sandboxed proof of concept", {}, [],
        )

    cmd = [sys.executable, "-m", "crypten.verify.runner", finding.cwe_id, str(target_file)]
    log.append(f"spawning isolated runner: {finding.cwe_id} against {finding.file_path}")
    log.append(f"socket access disabled; wall-clock limit {SANDBOX_TIMEOUT_SECONDS}s")

    try:
        completed = subprocess.run(
            cmd,
            cwd=Path(__file__).resolve().parent.parent.parent,  # repo root, never the target
            capture_output=True,
            text=True,
            timeout=SANDBOX_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return Verification(
            finding, "INCONCLUSIVE", "the proof of concept exceeded its time limit and was killed",
            "sandboxed proof of concept", {}, log + ["killed on timeout"],
        )

    verdict = _parse_verdict(completed.stdout)
    if verdict is None:
        detail = (completed.stderr or completed.stdout or "").strip()[:200]
        return Verification(
            finding, "INCONCLUSIVE", "the runner produced no readable verdict",
            "sandboxed proof of concept", {}, log + [detail],
        )

    log.append(f"runner verdict: {verdict['result']}")
    return Verification(
        finding, verdict["result"], verdict["summary"],
        "sandboxed proof of concept", verdict.get("details", {}), log,
    )


def _parse_verdict(stdout: str) -> dict | None:
    # The runner prints one JSON object last; the target may have printed before
    # our redirect caught it, so take the final non-empty line.
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None


def _inspect(target: Target, finding: Finding) -> Verification:
    try:
        source = read_source(resolve_within(target.root, finding.file_path)) or ""
    except Exception as exc:
        return Verification(finding, "INCONCLUSIVE", str(exc), "static inspection", {}, [])

    lines = source.splitlines()
    excerpt = lines[finding.line - 1].strip() if 1 <= finding.line <= len(lines) else ""
    # A call can span lines - verify=False often sits below requests.post( - so
    # inspect the whole statement, not just the line the scanner anchored to.
    span_end = finding.end_line or finding.line
    span = " ".join(l.strip() for l in lines[finding.line - 1 : span_end]) if lines else excerpt

    if finding.cwe_id == "CWE-295":
        if "verify=False" in span.replace(" ", ""):
            return Verification(
                finding, "INSPECTED",
                "The outbound request sets verify=False, so any certificate on the path is accepted. "
                "Confirmed by inspection; crypTen does not open a real MitM connection to prove it.",
                "static inspection", {"line": excerpt}, [],
            )
        return Verification(finding, "INCONCLUSIVE", "verify=False not present in the reported statement.", "static inspection", {}, [])

    if finding.rule_id.endswith("hardcoded-secret-fallback"):
        return Verification(
            finding, "INSPECTED",
            "The secret is read from the environment but falls back to a literal in source when "
            "the variable is unset. Any deployment that misses the variable uses that literal, "
            "which is readable by anyone with the repository. Confirmed by inspection.",
            "static inspection", {"line": excerpt}, [],
        )

    if finding.cwe_id in ("CWE-798", "CWE-256"):
        if "os.getenv" in span or "os.environ" in span:
            return Verification(
                finding, "NOT_EXPLOITABLE",
                "The value is read from the environment, not hard-coded.",
                "static inspection", {}, [],
            )
        what = "A password" if finding.cwe_id == "CWE-256" else "A credential"
        return Verification(
            finding, "INSPECTED",
            f"{what} is assigned as a source literal and would ship in the repository and its "
            "git history. Confirmed by inspection.",
            "static inspection", {"line": excerpt}, [],
        )

    return Verification(finding, "INCONCLUSIVE", "no inspection rule", "static inspection", {}, [])
