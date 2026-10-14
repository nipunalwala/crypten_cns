"""Priority scoring.

The score is not a CVSS vector and does not pretend to be one. It is an ordering
heuristic for a maintainer working through a list, and every point it awards is
explained, so a reader can disagree with a specific term rather than with an
opaque number.
"""

from __future__ import annotations

from dataclasses import dataclass

from .findings import Finding

_SEVERITY_BASE = {"CRITICAL": 9.0, "HIGH": 7.0, "MEDIUM": 4.5, "LOW": 2.0, "INFO": 0.5}
_CONFIDENCE_FACTOR = {"HIGH": 1.0, "MEDIUM": 0.85, "LOW": 0.65}

# A weakness on the login path is worth more attention than the same weakness in
# a maintenance script, because it sits in front of every user account.
_AUTH_PATH_HINTS = ("auth", "login", "session", "password", "token", "account", "user", "jwt", "crypto")


@dataclass(frozen=True)
class Score:
    value: float
    reasons: tuple[tuple[str, float], ...]

    def explain(self) -> str:
        return "; ".join(f"{why} {delta:+.1f}" for why, delta in self.reasons)


def score(finding: Finding) -> Score:
    """Rank a finding from 0.0 to 10.0 with a per-term breakdown."""
    reasons: list[tuple[str, float]] = []

    base = _SEVERITY_BASE.get(finding.severity, 4.5)
    reasons.append((f"{finding.severity.lower()} severity", base))

    factor = _CONFIDENCE_FACTOR.get(finding.confidence, 0.85)
    total = base * factor
    if factor != 1.0:
        reasons.append((f"{finding.confidence.lower()} confidence", total - base))

    # Verification outcomes dominate everything else: an executed proof of
    # concept is evidence, where the rest of the score is inference.
    if finding.verification == "EXPLOITED":
        delta = 10.0 - total
        total = 10.0
        reasons.append(("exploited in lab", delta))
        return Score(round(total, 1), tuple(reasons))

    if finding.verification == "NOT_EXPLOITABLE":
        reasons.append(("verified not exploitable", -total))
        return Score(0.0, tuple(reasons))

    corroborators = len(finding.corroborated_by)
    if corroborators > 1:
        bonus = min(0.4 * (corroborators - 1), 1.2)
        total += bonus
        reasons.append((f"{corroborators} scanners agree", bonus))

    if any(hint in finding.file_path.lower() for hint in _AUTH_PATH_HINTS):
        total += 0.8
        reasons.append(("authentication path", 0.8))

    total = max(0.0, min(total, 10.0))
    return Score(round(total, 1), tuple(reasons))


def rank(findings: list[Finding]) -> list[Finding]:
    """Order findings worst-first, with a stable tiebreak for reproducible reports."""
    return sorted(
        findings,
        key=lambda f: (-score(f).value, f.file_path, f.line, f.cwe_id),
    )
