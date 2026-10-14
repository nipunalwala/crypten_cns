"""Command-line entry point.

    python -m crypten scan <path> [--json out.json] [--html out.html] [--no-external]
    python -m crypten verify <path> [--cwe CWE-347]
    python -m crypten remediate <path> --cwe CWE-347 [--apply]
    python -m crypten demo

The demo subcommand runs the full pipeline against the bundled vulnerable
fixture: scan, verify every finding, then show that the secure fixture is clean.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import remediate, report
from .audit import audit
from .verify.service import verify

_FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="crypten", description="Credential-handling audit for small Python web apps")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan a target and list findings")
    p_scan.add_argument("path", help="local folder or https repository link")
    p_scan.add_argument("--refresh", action="store_true", help="re-clone a repository link instead of reusing lab/")
    p_scan.add_argument("--json", type=Path, help="write a JSON report")
    p_scan.add_argument("--html", type=Path, help="write an HTML report")
    p_scan.add_argument("--csv", type=Path, help="write a CSV report")
    p_scan.add_argument("--no-external", action="store_true", help="skip Bandit, pip-audit, Semgrep")
    p_scan.add_argument("--all", action="store_true", help="include out-of-scope findings")

    p_verify = sub.add_parser("verify", help="run proof-of-concept verification on findings")
    p_verify.add_argument("path", help="local folder or https repository link")
    p_verify.add_argument("--cwe", help="verify only findings of this CWE")

    p_rem = sub.add_parser("remediate", help="propose (and optionally apply) fixes")
    p_rem.add_argument("path", help="local folder or https repository link")
    p_rem.add_argument("--cwe", help="remediate only findings of this CWE")
    p_rem.add_argument("--apply", action="store_true", help="write the fix to disk with a .bak backup")

    sub.add_parser("demo", help="run the full pipeline against the bundled fixtures")

    args = parser.parse_args(argv)
    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "verify":
        return _cmd_verify(args)
    if args.command == "remediate":
        return _cmd_remediate(args)
    if args.command == "demo":
        return _cmd_demo()
    return 1


def _cmd_scan(args) -> int:
    result = audit(args.path, run_external=not args.no_external, refresh=args.refresh)
    findings = result.findings if args.all else result.in_scope

    print(f"crypTen scanned {result.target.name}: {len(findings)} findings")
    for status in result.scanners:
        mark = "ok" if status.ran else "skipped"
        print(f"  [{mark}] {status.name}" + (f" - {status.note}" if status.note else ""))
    print()
    for finding in findings:
        print(f"  {result.score_of(finding):>4}  {finding.severity:<8} {finding.cwe_id:<9} "
              f"{finding.file_path}:{finding.line}  {finding.rule_id}")

    if args.json:
        args.json.write_text(report.to_json(result), encoding="utf-8")
        print(f"\nJSON report: {args.json}")
    if args.html:
        args.html.write_text(report.to_html(result), encoding="utf-8")
        print(f"HTML report: {args.html}")
    if args.csv:
        args.csv.write_text(report.to_csv(result), encoding="utf-8")
        print(f"CSV report: {args.csv}")
    return 0


def _cmd_verify(args) -> int:
    result = audit(args.path, run_external=False)
    targets = [f for f in result.in_scope if not args.cwe or f.cwe_id == args.cwe.upper()]
    if not targets:
        print("No in-scope findings to verify.")
        return 0

    exploited = 0
    for finding in targets:
        outcome = verify(result.target, finding)
        finding.verification = outcome.result
        if outcome.result == "EXPLOITED":
            exploited += 1
        print(f"[{outcome.result}] {finding.cwe_id} {finding.file_path}:{finding.line}  ({outcome.method})")
        print(f"    {outcome.summary}")
        for key, value in outcome.details.items():
            print(f"      {key}: {value}")
    print(f"\n{exploited} of {len(targets)} findings exploited in the lab.")
    return 0


def _cmd_remediate(args) -> int:
    result = audit(args.path, run_external=False)
    targets = [f for f in result.in_scope if not args.cwe or f.cwe_id == args.cwe.upper()]
    if not targets:
        print("No in-scope findings to remediate.")
        return 0

    for finding in targets:
        patch = remediate.propose(result.target, finding)
        if patch is None:
            print(f"[no auto-fix] {finding.cwe_id} {finding.file_path}:{finding.line}")
            continue
        print(f"\n{finding.cwe_id} {finding.file_path}:{finding.line} - {patch.title}")
        print(f"  {patch.rationale}")
        print("  " + patch.diff.replace("\n", "\n  "))
        if args.apply:
            backup = remediate.apply(result.target, patch)
            print(f"  applied; backup at {backup.name}")
    return 0


def _cmd_demo() -> int:
    vulnerable = _FIXTURES / "vulnerable_app"
    secure = _FIXTURES / "secure_app"

    print("=" * 70)
    print("Phase A - scanning the vulnerable Campus Club Portal")
    print("=" * 70)
    result = audit(str(vulnerable))
    for finding in result.in_scope:
        print(f"  {result.score_of(finding):>4}  {finding.severity:<8} {finding.cwe_id:<9} "
              f"{finding.file_path}:{finding.line}")
    print(f"  -> {len(result.in_scope)} in-scope findings\n")

    print("=" * 70)
    print("Phase B - verifying each finding with a sandboxed proof of concept")
    print("=" * 70)
    seen: set[str] = set()
    exploited = 0
    for finding in result.in_scope:
        if finding.cwe_id in seen:
            continue
        seen.add(finding.cwe_id)
        outcome = verify(result.target, finding)
        if outcome.result == "EXPLOITED":
            exploited += 1
        print(f"  [{outcome.result}] {finding.cwe_id}: {outcome.summary}")
    print(f"  -> {exploited} weakness classes exploited, the rest confirmed by inspection\n")

    print("=" * 70)
    print("After - scanning the hardened portal")
    print("=" * 70)
    secure_result = audit(str(secure))
    print(f"  vulnerable: {len(result.code_weaknesses)} code weaknesses  ->  "
          f"secure: {len(secure_result.code_weaknesses)} code weaknesses")
    deps = len(secure_result.dependency_findings)
    if deps:
        print(f"  ({deps} dependency advisory(s) remain on the secure fixture - these track the")
        print("   advisory database's date, not the code, and are reported separately)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
