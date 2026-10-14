"""The scan pipeline: run every scanner, merge, score, order.

This is the breadth half of the project's two-phase design - the net that turns a
target directory into a ranked, CWE-labelled list of findings. Verification and
remediation act on individual findings from here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import fetch
from .findings import Finding, merge
from .intake import Target, open_target
from .risk import rank, score
from .scanners import ast_rules, external, secrets_scan, semgrep_scan


@dataclass
class ScannerStatus:
    name: str
    ran: bool
    note: str = ""


@dataclass
class AuditResult:
    target: Target
    findings: list[Finding]
    scanners: list[ScannerStatus] = field(default_factory=list)

    @property
    def in_scope(self) -> list[Finding]:
        return [f for f in self.findings if f.in_scope]

    @property
    def code_weaknesses(self) -> list[Finding]:
        """In-scope findings in the application's own code.

        Excludes CWE-1395 (vulnerable dependencies): those are real and worth
        reporting, but they track the advisory database's date rather than the
        code, so the before/after comparison of the code is measured without them.
        """
        return [f for f in self.findings if f.in_scope and f.cwe_id != "CWE-1395"]

    @property
    def dependency_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.cwe_id == "CWE-1395"]

    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def score_of(self, finding: Finding) -> float:
        return score(finding).value


def audit(path: str, *, run_external: bool = True, refresh: bool = False) -> AuditResult:
    """Scan a local folder, or a public repository link cloned into lab/ first."""
    if fetch.is_repo_url(path):
        path = str(fetch.clone(path, refresh=refresh))
    target = open_target(path)
    raw: list[Finding] = []
    statuses: list[ScannerStatus] = []

    raw += ast_rules.scan(target)
    statuses.append(ScannerStatus("ast", True))

    raw += secrets_scan.scan(target)
    statuses.append(ScannerStatus("secrets", True, "git history included" if target.is_git_repo else "working tree only"))

    if run_external:
        for result in (external.run_bandit(target), external.run_pip_audit(target), semgrep_scan.run_semgrep(target)):
            raw += result.findings
            statuses.append(ScannerStatus(result.scanner, result.available, result.note))

    findings = rank(merge(raw))
    return AuditResult(target=target, findings=findings, scanners=statuses)
