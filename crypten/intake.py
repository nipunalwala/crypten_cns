"""Taking in a target repository.

Everything downstream resolves paths through here. A finding carries a path
string that came from a scanner's output, and a scanner's output is derived from
the target's own filenames, so it is attacker-influenced: resolve_within is the
chokepoint that keeps a crafted name from reaching a file outside the target.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = frozenset(
    {
        ".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache",
        ".ruff_cache", ".tox", ".venv", "venv", "env", "node_modules",
        "site-packages", "dist", "build", ".idea", ".vscode", ".eggs",
    }
)

TEXT_SUFFIXES = frozenset(
    {".py", ".txt", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".env", ".md"}
)

MAX_FILE_BYTES = 2 * 1024 * 1024


class TargetError(Exception):
    """The target cannot be scanned as given."""


@dataclass(frozen=True)
class Target:
    root: Path
    name: str

    @property
    def is_git_repo(self) -> bool:
        return (self.root / ".git").is_dir()


def open_target(path: str | os.PathLike[str]) -> Target:
    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise TargetError(f"target does not exist: {root}")
    if not root.is_dir():
        raise TargetError(f"target is not a directory: {root}")
    return Target(root=root, name=root.name)


def resolve_within(root: Path, relative: str) -> Path:
    """Resolve a target-relative path, refusing anything that escapes the root.

    Symlinks are resolved before the containment check, so a link inside the
    target pointing at /etc is caught here rather than being followed.
    """
    root = root.resolve()
    candidate = (root / relative).resolve()
    if candidate != root and root not in candidate.parents:
        raise TargetError(f"path escapes the target root: {relative}")
    return candidate


def python_files(target: Target) -> list[Path]:
    """Every .py file in the target, excluding vendored and generated trees."""
    return [p for p in _walk(target.root) if p.suffix == ".py"]


def text_files(target: Target) -> list[Path]:
    """Files worth reading for secrets - source plus configuration."""
    return [p for p in _walk(target.root) if p.suffix.lower() in TEXT_SUFFIXES]


def _walk(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for name in filenames:
            path = Path(dirpath) / name
            try:
                if path.is_symlink() or path.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path


def read_source(path: Path) -> str | None:
    """Read a source file, or None if it is not decodable text."""
    try:
        return path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return None


def relative_to(target: Target, path: Path) -> str:
    try:
        return path.resolve().relative_to(target.root).as_posix()
    except ValueError:
        return path.name
