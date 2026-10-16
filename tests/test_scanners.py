"""Detection: every in-scope weakness is found in the vulnerable fixture, and
the secure fixture is clean of code weaknesses."""

import pytest

from crypten.audit import audit
from crypten.redact import redact

EXPECTED_CWES = {"CWE-916", "CWE-759", "CWE-330", "CWE-347", "CWE-532", "CWE-798", "CWE-295"}


def test_vulnerable_fixture_covers_every_weakness(vulnerable_path):
    result = audit(str(vulnerable_path), run_external=False)
    found = {f.cwe_id for f in result.code_weaknesses}
    missing = EXPECTED_CWES - found
    assert not missing, f"scanner missed {missing}"


def test_secure_fixture_has_no_code_weaknesses(secure_path):
    result = audit(str(secure_path), run_external=False)
    assert result.code_weaknesses == [], [f.rule_id for f in result.code_weaknesses]


def test_jwt_bypass_is_the_critical_finding(vulnerable_path):
    result = audit(str(vulnerable_path), run_external=False)
    critical = [f for f in result.code_weaknesses if f.severity == "CRITICAL"]
    assert len(critical) == 1
    assert critical[0].cwe_id == "CWE-347"


def test_hash_of_a_cache_key_is_not_flagged(tmp_path):
    # The name-aware rule must not fire on a non-password MD5.
    (tmp_path / "cache.py").write_text(
        "import hashlib\n"
        "def cache_key(url):\n"
        "    return hashlib.md5(url.encode()).hexdigest()\n"
    )
    result = audit(str(tmp_path), run_external=False)
    assert [f for f in result.code_weaknesses if f.cwe_id == "CWE-916"] == []


@pytest.mark.parametrize(
    "line",
    [
        "SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'",
        "SECRET_KEY = os.getenv('SECRET_KEY') or 'dev'",
        "JWT_SECRET = os.getenv('JWT_SECRET', 'changeme')",
        "API_KEY = os.environ.get('API_KEY', default='sk-live-1234')",
    ],
)
def test_env_lookup_with_literal_fallback_is_flagged(tmp_path, line):
    (tmp_path / "config.py").write_text(f"import os\n{line}\n")
    result = audit(str(tmp_path), run_external=False)
    rules = [f.rule_id for f in result.code_weaknesses if f.cwe_id == "CWE-798"]
    assert "crypten.hardcoded-secret-fallback" in rules


@pytest.mark.parametrize(
    "line",
    [
        "SECRET_KEY = os.environ['SECRET_KEY']",
        "SECRET_KEY = os.getenv('SECRET_KEY')",
        "SECRET_KEY = os.getenv('SECRET_KEY', '')",
        "DEBUG = os.getenv('DEBUG') or 'false'",
    ],
)
def test_env_lookup_without_secret_fallback_is_clean(tmp_path, line):
    (tmp_path / "config.py").write_text(f"import os\n{line}\n")
    result = audit(str(tmp_path), run_external=False)
    assert [f for f in result.code_weaknesses if f.cwe_id == "CWE-798"] == []


def test_fallback_is_inspected_not_cleared(tmp_path):
    from crypten.verify.service import verify

    (tmp_path / "config.py").write_text(
        "import os\nSECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess'\n"
    )
    result = audit(str(tmp_path), run_external=False)
    finding = next(f for f in result.code_weaknesses if f.cwe_id == "CWE-798")
    assert verify(result.target, finding).result == "INSPECTED"


def test_fallback_patch_fails_closed_and_keeps_the_env_name(tmp_path):
    from crypten import remediate

    (tmp_path / "config.py").write_text(
        "import os\nclass Config:\n    SECRET_KEY = os.environ.get('FLASK_KEY') or 'you-will-never-guess'\n"
    )
    result = audit(str(tmp_path), run_external=False)
    finding = next(f for f in result.code_weaknesses if f.cwe_id == "CWE-798")
    patch = remediate.propose(result.target, finding)
    assert patch.patched_line.startswith('    SECRET_KEY = os.environ["FLASK_KEY"]')
    assert "you-will-never-guess" not in patch.patched_line


def test_evidence_is_redacted(vulnerable_path):
    result = audit(str(vulnerable_path), run_external=False)
    secret_finding = next(f for f in result.code_weaknesses if f.cwe_id == "CWE-798")
    assert "clubportal2023" not in secret_finding.evidence


def test_redact_masks_a_db_uri_password():
    masked = redact('DATABASE_URL = "postgres://user:Sup3rSecret@host/db"')
    assert "Sup3rSecret" not in masked
