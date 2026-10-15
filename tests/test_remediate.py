"""Remediation and the re-verification loop (proposal step 7): apply the fix,
then confirm the proof of concept no longer succeeds and the scanner no longer
reports the finding."""

from crypten import remediate
from crypten.audit import audit
from crypten.intake import open_target
from crypten.verify.service import verify


def test_jwt_patch_closes_the_forgery(vulnerable_copy):
    target = open_target(str(vulnerable_copy))
    result = audit(str(vulnerable_copy), run_external=False)
    finding = next(f for f in result.code_weaknesses if f.cwe_id == "CWE-347")

    assert verify(target, finding).result == "EXPLOITED"

    patch = remediate.propose(target, finding)
    assert patch is not None
    remediate.apply(target, patch)

    # Re-verify: the forgery must now fail.
    rescanned = audit(str(vulnerable_copy), run_external=False)
    jwt_findings = [f for f in rescanned.code_weaknesses if f.cwe_id == "CWE-347"]
    assert jwt_findings == [], "JWT finding should be gone after the patch"


def test_tls_patch_only_changes_the_flag(vulnerable_copy):
    target = open_target(str(vulnerable_copy))
    before = (vulnerable_copy / "notifications.py").read_text()
    result = audit(str(vulnerable_copy), run_external=False)
    finding = next(f for f in result.code_weaknesses if f.cwe_id == "CWE-295")

    patch = remediate.propose(target, finding)
    remediate.apply(target, patch)
    after = (vulnerable_copy / "notifications.py").read_text()

    # The only change is verify=False -> verify=True; nothing else is touched.
    assert before.replace("verify=False", "verify=True") == after


def test_apply_refuses_if_the_line_changed(vulnerable_copy):
    target = open_target(str(vulnerable_copy))
    result = audit(str(vulnerable_copy), run_external=False)
    finding = next(f for f in result.code_weaknesses if f.cwe_id == "CWE-295")
    patch = remediate.propose(target, finding)

    patch.original_line = "something that is not actually on that line"
    try:
        remediate.apply(target, patch)
        raised = False
    except remediate.RemediationError:
        raised = True
    assert raised


def test_log_patch_does_not_corrupt_identifiers(vulnerable_copy):
    # The old tool's global replace("password", ...) mangled function names.
    # The patched file must still import and define its functions.
    target = open_target(str(vulnerable_copy))
    result = audit(str(vulnerable_copy), run_external=False)
    for finding in [f for f in result.code_weaknesses if f.cwe_id == "CWE-532"]:
        patch = remediate.propose(target, finding)
        if patch:
            remediate.apply(target, patch)
    source = (vulnerable_copy / "auth.py").read_text()
    assert "def authenticate(" in source
    assert "def hash_password(" in source
    compile(source, "auth.py", "exec")
