"""Repository links: which forms are accepted, and which are refused before git runs."""

import pytest

from crypten import fetch
from crypten.intake import TargetError


@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/pallets/flask",
        "https://github.com/pallets/flask.git",
        "https://github.com/pallets/flask/tree/main/src",
        "  https://github.com/pallets/flask/  ",
    ],
)
def test_pasted_link_shapes_reduce_to_the_repository(url):
    assert fetch._parse(url) == ("github.com", "pallets", "flask")


def test_other_https_hosts_are_accepted():
    assert fetch._parse("https://gitlab.com/group/project") == ("gitlab.com", "group", "project")


@pytest.mark.parametrize(
    "url",
    [
        "ext::sh -c touch% /tmp/pwned",
        "file:///etc",
        "ssh://git@github.com/pallets/flask",
        "git@github.com:pallets/flask.git",
        "http://github.com/pallets/flask",
    ],
)
def test_non_https_transports_are_refused(url):
    with pytest.raises(TargetError):
        fetch._parse(url)


def test_credentials_in_the_link_are_refused():
    with pytest.raises(TargetError):
        fetch._parse("https://user:token@github.com/pallets/flask")


def test_path_traversal_in_repo_name_is_refused():
    with pytest.raises(TargetError):
        fetch._parse("https://github.com/owner/..")


def test_link_without_a_repo_is_refused():
    with pytest.raises(TargetError):
        fetch._parse("https://github.com/pallets")


def test_link_text_is_routed_to_clone_not_treated_as_a_folder():
    assert fetch.is_repo_url("https://github.com/a/b")
    assert fetch.is_repo_url("git@github.com:a/b.git")  # routed so it gets a clear refusal
    assert not fetch.is_repo_url(r"C:\lab\app")
