"""The finding record, and how findings from different scanners are merged.

Each scanner speaks its own dialect. A finding is the common form they are
translated into, so the rest of the tool - scoring, verification, patching,
reporting - works against one shape.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace

from . import cwe

Severity = str  # one of SEVERITY_ORDER
Confidence = str  # HIGH | MEDIUM | LOW

SEVERITY_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Scanners disagree about severity for the same weakness. When findings merge we
# keep the most alarming verdict, on the grounds that a tool that saw the issue
# more clearly is the one worth listening to.
_SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}
_CONFIDENCE_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


@dataclass
class Finding:
    """One weakness at one place in the target."""

    rule_id: str
    cwe_id: str
    file_path: str  # relative to the target root, always posix-style
    line: int
    severity: Severity
    confidence: Confidence
    evidence: str  # redacted source excerpt
    scanner: str
    title: str = ""
    end_line: int | None = None
    # Scanners that independently reported this same weakness. Agreement between
    # unrelated engines is the strongest signal available before verification.
    corroborated_by: set[str] = field(default_factory=set)
    verification: str = "UNVERIFIED"
    remediation: str = "OPEN"

    def __post_init__(self) -> None:
        self.cwe_id = self.cwe_id.upper()
        self.severity = self.severity.upper()
        self.confidence = self.confidence.upper()
        self.file_path = self.file_path.replace("\\", "/")
        self.corroborated_by.add(self.scanner)
        if not self.title:
            entry = cwe.describe(self.cwe_id)
            self.title = entry.title if entry else self.rule_id

    @property
    def key(self) -> tuple[str, int, str]:
        """Identity for merging: the same weakness at the same place."""
        return (self.file_path, self.line, self.cwe_id)

    @property
    def in_scope(self) -> bool:
        """Whether this is one of the credential weaknesses the project surveys."""
        return cwe.is_in_scope(self.cwe_id)

    def describe(self) -> cwe.CweEntry | None:
        return cwe.describe(self.cwe_id)


def merge(findings: list[Finding]) -> list[Finding]:
    """Collapse duplicate reports of the same weakness, recording who agreed.

    Two scanners flagging one line is not two problems. It is one problem with
    better evidence, so the survivor keeps the highest severity and confidence
    seen and remembers every scanner that found it.
    """
    merged: dict[tuple[str, int, str], Finding] = {}

    for item in findings:
        existing = merged.get(item.key)
        if existing is None:
            merged[item.key] = replace(item, corroborated_by=set(item.corroborated_by))
            continue

        existing.corroborated_by |= item.corroborated_by
        if _SEVERITY_RANK[item.severity] < _SEVERITY_RANK[existing.severity]:
            existing.severity = item.severity
        if _CONFIDENCE_RANK.get(item.confidence, 1) < _CONFIDENCE_RANK.get(existing.confidence, 1):
            existing.confidence = item.confidence
        # Prefer evidence from the engine that understands the code semantically.
        if item.scanner == "ast" and existing.scanner != "ast":
            existing.evidence = item.evidence
            existing.rule_id = item.rule_id

    return list(merged.values())
