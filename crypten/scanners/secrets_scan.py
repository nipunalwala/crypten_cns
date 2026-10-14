"""Secret scanning across the working tree and git history.

The AST rules catch a secret only where it is assigned to a telling name in a
parseable .py file. This scanner is the complementary net: it matches credential
*formats* anywhere, including config files the AST never parses and commits where
a secret was added and later deleted. A deleted secret is still a leaked secret.
"""

from __future__ import annotations

import math
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..findings import Finding
from ..intake import Target, read_source, relative_to, text_files
from ..redact import redact

SCANNER = "secrets"


@dataclass(frozen=True)
class _Pattern:
    rule_id: str
    cwe_id: str
    regex: re.Pattern[str]
    severity: str
    # The capture group holding the secret itself, for the entropy gate. 0 means
    # the match is distinctive enough on its own that entropy need not apply.
    value_group: int = 0
    min_entropy: float = 0.0


_PATTERNS: tuple[_Pattern, ...] = (
    _Pattern("aws-access-key", "CWE-798", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICAL"),
    _Pattern(
        "private-key-block",
        "CWE-798",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "CRITICAL",
    ),
    _Pattern(
        "db-connection-credential",
        "CWE-798",
        re.compile(
            r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:([^\s@]{4,})@",
            re.IGNORECASE,
        ),
        "HIGH",
        value_group=1,
        min_entropy=2.0,
    ),
    _Pattern(
        "secret-assignment",
        "CWE-798",
        re.compile(
            r"(?:secret_key|api_key|apikey|jwt_secret|auth_token|access_token|client_secret|"
            r"smtp_password|db_password)\s*[:=]\s*[\"']([^\"']{6,})[\"']",
            re.IGNORECASE,
        ),
        "HIGH",
        value_group=1,
        min_entropy=2.6,
    ),
    _Pattern(
        "password-literal",
        "CWE-256",
        re.compile(r"(?:password|passwd|db_pass)\s*[:=]\s*[\"']([^\"']{4,})[\"']", re.IGNORECASE),
        "HIGH",
        value_group=1,
        min_entropy=2.0,
    ),
)

_ENV_LOOKUP = re.compile(r"os\.(?:environ|getenv)", re.IGNORECASE)
_PLACEHOLDER = re.compile(
    r"your_.*here|changeme|change_me|example|placeholder|\$\{|<[^>]+>|xxxx+", re.IGNORECASE
)


def scan(target: Target) -> list[Finding]:
    findings = [f for path in text_files(target) for f in _scan_file(target, path)]
    if target.is_git_repo:
        findings.extend(_scan_history(target))
    return findings


def _scan_file(target: Target, path: Path) -> list[Finding]:
    source = read_source(path)
    if source is None:
        return []
    rel = relative_to(target, path)
    out: list[Finding] = []
    for lineno, line in enumerate(source.splitlines(), start=1):
        out.extend(_match_line(rel, lineno, line, history=False))
    return out


def _match_line(file_path: str, lineno: int, line: str, *, history: bool) -> list[Finding]:
    out: list[Finding] = []
    if _ENV_LOOKUP.search(line):
        return out
    for pattern in _PATTERNS:
        match = pattern.regex.search(line)
        if not match:
            continue
        secret = match.group(pattern.value_group) if pattern.value_group else match.group(0)
        if _PLACEHOLDER.search(secret):
            continue
        if pattern.min_entropy and _entropy(secret) < pattern.min_entropy:
            continue
        rule = f"crypten.{pattern.rule_id}" + (".git-history" if history else "")
        out.append(
            Finding(
                rule_id=rule,
                cwe_id=pattern.cwe_id,
                file_path=file_path,
                line=lineno,
                severity=pattern.severity,
                confidence="MEDIUM" if history else "HIGH",
                evidence=redact(line.strip()),
                scanner=SCANNER,
                title=("Secret in git history" if history else None) or "",
            )
        )
    return out


def _scan_history(target: Target) -> list[Finding]:
    """Scan lines added across recent history for secrets no longer in the tree."""
    try:
        completed = subprocess.run(
            ["git", "log", "-p", "-n", "50", "--no-color", "--unified=0"],
            cwd=target.root,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        # git absent or history unreadable is a degraded scan, not a failure.
        return []
    if completed.returncode != 0:
        return []

    commit = "unknown"
    current_file = "(git history)"
    out: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for line in completed.stdout.splitlines():
        if line.startswith("commit "):
            commit = line.split()[1][:10]
        elif line.startswith("+++ b/"):
            current_file = line[6:].strip()
        elif line.startswith("+") and not line.startswith("+++"):
            added = line[1:]
            for finding in _match_line(f"{current_file}@{commit}", 0, added, history=True):
                dedup = (finding.cwe_id, finding.evidence)
                if dedup in seen:
                    continue
                seen.add(dedup)
                out.append(finding)
    return out


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {c: value.count(c) for c in set(value)}
    length = len(value)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())
