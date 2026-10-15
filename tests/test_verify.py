"""Verification: the proofs of concept actually exploit the vulnerable fixture,
and report NOT_EXPLOITABLE against the secure one."""

from crypten.audit import audit
from crypten.verify.service import verify


def _first(result, cwe):
    return next(f for f in result.code_weaknesses if f.cwe_id == cwe)


def test_jwt_forgery_succeeds_on_vulnerable(vulnerable_path):
    result = audit(str(vulnerable_path), run_external=False)
    outcome = verify(result.target, _first(result, "CWE-347"))
    assert outcome.result == "EXPLOITED"
    assert outcome.details["attacks"]["wrong_key_accepted"] is True


def test_jwt_forgery_fails_on_secure(secure_path, monkeypatch):
    # The secure config fails closed without its signing key; give the probe one.
    monkeypatch.setenv("CLUBPORTAL_JWT_SECRET", "test-signing-key-32-bytes-minimum!")
    result = audit(str(secure_path), run_external=False)
    # The secure fixture has no CWE-347 finding, so verify the decoder directly
    # through a synthesised finding pointing at its auth module.
    from crypten.findings import Finding

    finding = Finding(
        rule_id="probe", cwe_id="CWE-347", file_path="auth.py", line=1,
        severity="CRITICAL", confidence="HIGH", evidence="", scanner="ast",
    )
    outcome = verify(result.target, finding)
    assert outcome.result == "NOT_EXPLOITABLE"


def test_password_table_is_cracked(vulnerable_path):
    result = audit(str(vulnerable_path), run_external=False)
    outcome = verify(result.target, _first(result, "CWE-916"))
    assert outcome.result == "EXPLOITED"
    assert len(outcome.details["recovered_accounts"]) == 3


def test_reset_token_is_predictable(vulnerable_path):
    result = audit(str(vulnerable_path), run_external=False)
    outcome = verify(result.target, _first(result, "CWE-330"))
    assert outcome.result == "EXPLOITED"
    assert outcome.details["issued_token"] == outcome.details["predicted_token"]


def test_password_is_found_in_the_log(vulnerable_path):
    result = audit(str(vulnerable_path), run_external=False)
    outcome = verify(result.target, _first(result, "CWE-532"))
    assert outcome.result == "EXPLOITED"


def test_sandbox_blocks_network_egress(tmp_path):
    # A target that phones home at import time must not be able to; the probe
    # should come back INCONCLUSIVE, never hang or actually connect.
    (tmp_path / "evil.py").write_text(
        "import socket\n"
        "socket.create_connection(('example.com', 80), timeout=2)\n"
        "def decode_auth_token(t):\n    return {}\n"
    )
    from crypten.findings import Finding
    from crypten.intake import open_target

    finding = Finding(
        rule_id="probe", cwe_id="CWE-347", file_path="evil.py", line=1,
        severity="CRITICAL", confidence="HIGH", evidence="", scanner="ast",
    )
    outcome = verify(open_target(str(tmp_path)), finding)
    assert outcome.result == "INCONCLUSIVE"
