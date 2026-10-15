"""FastAPI backend for the crypTen dashboard.

Thin HTTP layer over the crypten engine. The scan/verify/remediate logic lives
in the package; this exposes it and persists results so the dashboard has
history. Nothing here re-implements detection.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from crypten import remediate, report  # noqa: E402
from crypten.audit import audit  # noqa: E402
from crypten.findings import Finding  # noqa: E402
from crypten.intake import open_target  # noqa: E402
from crypten.verify.service import verify  # noqa: E402

from . import store  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"

app = FastAPI(title="crypTen", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def _startup() -> None:
    store.init()


class ScanRequest(BaseModel):
    path: str
    run_external: bool = True
    refresh: bool = False


@app.get("/api/fixtures")
def fixtures() -> dict:
    return {
        "vulnerable": str(FIXTURES / "vulnerable_app"),
        "secure": str(FIXTURES / "secure_app"),
    }


@app.post("/api/scans")
def create_scan(req: ScanRequest) -> dict:
    try:
        result = audit(req.path, run_external=req.run_external, refresh=req.refresh)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    scan_id = store.save_scan(result, result.score_of)
    return {"scan_id": scan_id, "findings": len(result.findings)}


@app.get("/api/scans")
def scans() -> list[dict]:
    return store.list_scans()


@app.get("/api/scans/{scan_id}")
def scan_detail(scan_id: str) -> dict:
    data = store.get_scan(scan_id)
    if data is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return data


@app.post("/api/findings/{finding_id}/verify")
def verify_finding(finding_id: str) -> dict:
    finding_row = store.get_finding(finding_id)
    if finding_row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    scan = store.get_scan(finding_row["scan_id"])
    target = open_target(scan["scan"]["target_path"])
    outcome = verify(target, _to_finding(finding_row))
    store.update_verification(finding_id, outcome)
    return {
        "result": outcome.result,
        "summary": outcome.summary,
        "method": outcome.method,
        "details": outcome.details,
        "log": outcome.log,
    }


@app.get("/api/findings/{finding_id}/patch")
def propose_patch(finding_id: str) -> dict:
    finding_row = store.get_finding(finding_id)
    if finding_row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    scan = store.get_scan(finding_row["scan_id"])
    target = open_target(scan["scan"]["target_path"])
    patch = remediate.propose(target, _to_finding(finding_row))
    if patch is None:
        return {"available": False}
    return {
        "available": True,
        "title": patch.title,
        "rationale": patch.rationale,
        "diff": patch.diff,
        "artifact": patch.extra_artifact,
    }


class ApplyRequest(BaseModel):
    confirm: bool = False


@app.post("/api/findings/{finding_id}/apply")
def apply_patch(finding_id: str, req: ApplyRequest) -> dict:
    if not req.confirm:
        raise HTTPException(status_code=400, detail="confirmation required to write to disk")
    finding_row = store.get_finding(finding_id)
    if finding_row is None:
        raise HTTPException(status_code=404, detail="finding not found")
    scan = store.get_scan(finding_row["scan_id"])
    target = open_target(scan["scan"]["target_path"])
    patch = remediate.propose(target, _to_finding(finding_row))
    if patch is None:
        raise HTTPException(status_code=400, detail="no automatic patch for this finding")
    try:
        backup = remediate.apply(target, patch)
    except remediate.RemediationError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    store.update_remediation(finding_id, "PATCHED")
    return {"applied": True, "backup": backup.name}


@app.get("/api/scans/{scan_id}/report.{fmt}")
def export_report(scan_id: str, fmt: str):
    data = store.get_scan(scan_id)
    if data is None:
        raise HTTPException(status_code=404, detail="scan not found")
    result = _rebuild_result(data)
    if fmt == "json":
        return PlainTextResponse(report.to_json(result), media_type="application/json")
    if fmt == "csv":
        return PlainTextResponse(report.to_csv(result), media_type="text/csv")
    if fmt == "html":
        return HTMLResponse(report.to_html(result))
    raise HTTPException(status_code=400, detail="format must be json, csv or html")


def _to_finding(row: dict) -> Finding:
    return Finding(
        rule_id=row["rule_id"], cwe_id=row["cwe_id"], file_path=row["file_path"],
        line=row["line"], end_line=row["end_line"], severity=row["severity"],
        confidence=row["confidence"], evidence=row["evidence"], scanner="ast",
        title=row["title"], verification=row["verification"], remediation=row["remediation"],
    )


def _rebuild_result(data: dict):
    """Reconstruct enough of an AuditResult for the report exporter from stored rows."""
    from crypten.audit import AuditResult, ScannerStatus

    target = open_target(data["scan"]["target_path"])
    findings = []
    for row in data["findings"]:
        f = _to_finding(row)
        f.corroborated_by = set(row["scanners"].split("+"))
        findings.append(f)
    import json as _json

    scanners = [ScannerStatus(s["name"], s["ran"], s["note"]) for s in _json.loads(data["scan"]["scanners_json"])]
    return AuditResult(target=target, findings=findings, scanners=scanners)
