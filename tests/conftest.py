import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture
def vulnerable_copy(tmp_path):
    """A writable copy of the vulnerable fixture, so patch tests don't touch the original."""
    dest = tmp_path / "vulnerable_app"
    shutil.copytree(FIXTURES / "vulnerable_app", dest)
    return dest


@pytest.fixture
def vulnerable_path():
    return FIXTURES / "vulnerable_app"


@pytest.fixture
def secure_path():
    return FIXTURES / "secure_app"
