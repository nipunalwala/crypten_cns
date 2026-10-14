"""Export an audit to JSON, CSV, or a standalone HTML page.

Every value here has already passed through redaction at the scanner. The report
is evidence a maintainer can read or hand to a reviewer, so it leads with the
verified findings and says, for each, how it was confirmed.
"""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timezone

from .audit import AuditResult
from .cwe import describe
from .risk import score


def to_dict(result: AuditResult) -> dict:
    return {
        "tool": "crypTen",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": result.target.name,
        "scanners": [{"name": s.name, "ran": s.ran, "note": s.note} for s in result.scanners],
        "severity_counts": result.severity_counts(),
        "findings": [_finding_dict(result, f) for f in result.findings],
    }


def _finding_dict(result: AuditResult, finding) -> dict:
    entry = describe(finding.cwe_id)
    s = score(finding)
    return {
        "rule_id": finding.rule_id,
        "cwe_id": finding.cwe_id,
        "title": finding.title,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "priority_score": s.value,
        "priority_reasons": s.explain(),
        "file": finding.file_path,
        "line": finding.line,
        "evidence": finding.evidence,
        "scanners": sorted(finding.corroborated_by),
        "verification": finding.verification,
        "remediation": finding.remediation,
        "in_scope": finding.in_scope,
        "owasp": entry.owasp if entry else "",
        "impact": entry.impact if entry else "",
        "fix": entry.fix if entry else "",
    }


def to_json(result: AuditResult) -> str:
    return json.dumps(to_dict(result), indent=2)


def to_csv(result: AuditResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["cwe", "title", "severity", "confidence", "priority", "file", "line",
         "scanners", "verification", "remediation", "evidence"]
    )
    for finding in result.findings:
        writer.writerow(
            [finding.cwe_id, finding.title, finding.severity, finding.confidence,
             score(finding).value, finding.file_path, finding.line,
             "+".join(sorted(finding.corroborated_by)), finding.verification,
             finding.remediation, finding.evidence]
        )
    return buffer.getvalue()


def to_html(result: AuditResult) -> str:
    data = to_dict(result)
    counts = data["severity_counts"]
    rows = "\n".join(_html_row(f) for f in data["findings"])
    scanners = ", ".join(
        f"{s['name']}" + (f" ({s['note']})" if s["note"] else "") + ("" if s["ran"] else " - skipped")
        for s in data["scanners"]
    )
    chips = "".join(
        f'<span class="chip {sev.lower()}">{counts[sev]} {sev.lower()}</span>'
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(sev)
    )
    return _HTML_TEMPLATE.format(
        target=html.escape(data["target"]),
        generated=data["generated_at"],
        scanners=html.escape(scanners),
        chips=chips,
        total=len(data["findings"]),
        rows=rows or '<tr><td colspan="6">No findings.</td></tr>',
    )


def _html_row(f: dict) -> str:
    verdict = f["verification"]
    vclass = {
        "EXPLOITED": "bad", "INSPECTED": "warn",
        "NOT_EXPLOITABLE": "good", "UNVERIFIED": "muted",
    }.get(verdict, "muted")
    return f"""<tr>
  <td><span class="sev {f['severity'].lower()}">{html.escape(f['severity'])}</span></td>
  <td><strong>{html.escape(f['cwe_id'])}</strong><br><span class="muted">{html.escape(f['title'])}</span></td>
  <td><code>{html.escape(f['file'])}:{f['line']}</code><br><code class="ev">{html.escape(f['evidence'])}</code></td>
  <td>{html.escape('+'.join(f['scanners']))}</td>
  <td><span class="verdict {vclass}">{html.escape(verdict)}</span></td>
  <td>{f['priority_score']}<br><span class="muted">{html.escape(f['fix'])}</span></td>
</tr>"""


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>crypTen audit - {target}</title>
<style>
  :root {{ color-scheme: light dark; --line: #d0d7de; --muted: #656d76; --bg: #fff; --fg: #1f2328; }}
  @media (prefers-color-scheme: dark) {{ :root {{ --line:#30363d; --muted:#8b949e; --bg:#0d1117; --fg:#e6edf3; }} }}
  body {{ font: 14px/1.5 -apple-system, Segoe UI, system-ui, sans-serif; margin: 0; background: var(--bg); color: var(--fg); }}
  main {{ max-width: 1000px; margin: 0 auto; padding: 32px 20px; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .meta {{ color: var(--muted); margin-bottom: 16px; }}
  .chip {{ display: inline-block; padding: 2px 10px; border-radius: 999px; font-size: 12px; margin-right: 6px; color: #fff; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; }}
  th, td {{ text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }}
  th {{ font-size: 12px; text-transform: uppercase; color: var(--muted); }}
  code {{ font: 12px ui-monospace, SFMono-Regular, Menlo, monospace; }}
  code.ev {{ color: var(--muted); }}
  .muted {{ color: var(--muted); }}
  .sev, .verdict {{ padding: 1px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
  .critical {{ background: #cf222e; color:#fff; }} .high {{ background: #bc4c00; color:#fff; }}
  .medium {{ background: #9a6700; color:#fff; }} .low {{ background: #57606a; color:#fff; }}
  .verdict.bad {{ background:#cf222e; color:#fff; }} .verdict.warn {{ background:#9a6700; color:#fff; }}
  .verdict.good {{ background:#1a7f37; color:#fff; }} .verdict.muted {{ background:#57606a; color:#fff; }}
</style>
</head>
<body><main>
  <h1>crypTen credential-handling audit</h1>
  <div class="meta">Target <strong>{target}</strong> &middot; {generated} &middot; {total} findings<br>{chips}</div>
  <div class="meta">Scanners: {scanners}</div>
  <table>
    <thead><tr><th>Severity</th><th>Weakness</th><th>Location &amp; evidence</th><th>Found by</th><th>Verified</th><th>Priority &amp; fix</th></tr></thead>
    <tbody>
{rows}
    </tbody>
  </table>
</main></body>
</html>
"""
