"""Clone a public git repository into the local lab folder.

The proposal's rule is that every target is a local copy: crypTen scans and
probes the clone, never the hosted project or any deployment of it. This module
turns a repository URL into that local copy.

Only https URLs are accepted. git also understands ssh, file:// and the ext::
transport, and ext:: in particular runs an arbitrary command to "fetch", so a
URL typed into the dashboard must not be able to select it.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from .intake import TargetError

LAB_DIR = Path(__file__).resolve().parent.parent / "lab"
CLONE_TIMEOUT_SECONDS = 180

_SAFE_SEGMENT = re.compile(r"^[A-Za-z0-9._-]+$")


def is_repo_url(text: str) -> bool:
    return text.strip().lower().startswith(("https://", "http://", "git@", "ssh://", "file://", "ext::"))


def clone(url: str, *, refresh: bool = False) -> Path:
    """Clone url into lab/<host>/<owner>/<repo> and return the local path.

    An existing clone is reused, so re-scanning the same link after applying a
    patch scans the patched copy rather than silently fetching a fresh one.
    Pass refresh=True to discard it and clone again.
    """
    host, owner, repo = _parse(url)
    dest = LAB_DIR / host / owner / repo

    if dest.exists() and (dest / ".git").is_dir() and not refresh:
        return dest
    if dest.exists():
        _remove_tree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    env = {
        **os.environ,
        # A private or mistyped repo makes git prompt for credentials; with no
        # terminal attached that prompt would hang the request until timeout.
        "GIT_TERMINAL_PROMPT": "0",
        "GCM_INTERACTIVE": "never",
    }
    cmd = [
        "git",
        "-c", "protocol.allow=never",
        "-c", "protocol.https.allow=always",
        "-c", "core.symlinks=false",
        "clone", "--no-recurse-submodules", "--",
        f"https://{host}/{owner}/{repo}.git",
        str(dest),
    ]
    try:
        completed = subprocess.run(
            cmd, capture_output=True, text=True, timeout=CLONE_TIMEOUT_SECONDS, env=env, check=False
        )
    except FileNotFoundError as exc:
        raise TargetError("git is not installed or not on PATH; it is needed to clone repository links") from exc
    except subprocess.TimeoutExpired as exc:
        _remove_tree(dest)
        raise TargetError(f"cloning {owner}/{repo} took longer than {CLONE_TIMEOUT_SECONDS}s and was stopped") from exc

    if completed.returncode != 0:
        _remove_tree(dest)
        reason = (completed.stderr or "").strip().splitlines()
        detail = reason[-1] if reason else f"git exited with {completed.returncode}"
        raise TargetError(
            f"could not clone {owner}/{repo}: {detail}. Check the link is a public repository."
        )
    return dest


def _parse(url: str) -> tuple[str, str, str]:
    """Reduce a repository link to (host, owner, repo), refusing non-https forms.

    Accepts the shapes people paste: the repo page, the .git clone URL, or a
    deeper link such as /tree/main/src, which is trimmed to the repository.
    """
    text = url.strip()
    if not text.lower().startswith("https://"):
        raise TargetError("only https repository links are supported, e.g. https://github.com/owner/repo")

    parsed = urlparse(text)
    if parsed.username or parsed.password:
        raise TargetError("repository links must not contain credentials")
    host = (parsed.hostname or "").lower()
    if not host or not re.fullmatch(r"[a-z0-9.-]+", host):
        raise TargetError(f"not a valid repository host: {parsed.hostname!r}")

    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        raise TargetError("link must point at a repository: https://<host>/<owner>/<repo>")
    owner, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    for segment in (owner, repo):
        if not _SAFE_SEGMENT.match(segment) or segment in {".", ".."}:
            raise TargetError(f"unexpected characters in repository path: {segment!r}")
    return host, owner, repo


def _remove_tree(path: Path) -> None:
    import shutil
    import stat

    # git marks pack files read-only, which shutil.rmtree cannot delete on
    # Windows without clearing the flag first.
    def _clear_readonly(func, target, _exc):
        os.chmod(target, stat.S_IWRITE)
        func(target)

    shutil.rmtree(path, onexc=_clear_readonly)
