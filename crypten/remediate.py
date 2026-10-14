"""Propose and apply fixes, one finding at a time.

The old tool applied patches by whole-file string replacement, which turned
content.replace("password", ...) into corruption of every identifier containing
that word. This version only ever rewrites the single line a finding points at,
keeps a .bak of the file, and leaves a unified diff the user approves first.

Password hashing is the one case a single-line swap cannot finish: moving a
stored table off MD5 means verifying the old hash once and replacing it on the
next successful login. That migration is emitted as a reviewable code artifact
(rehash_on_login) rather than pretended to be a one-line edit.
"""

from __future__ import annotations

import difflib
import re
import shutil
from dataclasses import dataclass, replace
from pathlib import Path

from .findings import Finding
from .intake import Target, resolve_within


def _rebind_line(finding: Finding, line: int) -> Finding:
    return replace(finding, line=line, corroborated_by=set(finding.corroborated_by))


@dataclass
class Patch:
    finding: Finding
    title: str
    rationale: str
    original_line: str
    patched_line: str
    diff: str
    extra_artifact: str = ""  # a larger code block the fix also needs, if any


class RemediationError(Exception):
    pass


def propose(target: Target, finding: Finding) -> Patch | None:
    """Build a proposed patch for a finding, or None if it has no auto-fix."""
    path = resolve_within(target.root, finding.file_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    transform = _TRANSFORMS.get(finding.cwe_id)
    if transform is None:
        return None

    # The scanner anchors a finding at the start of a statement, but the token
    # to rewrite (verify=False, a decode call) can sit on a continuation line.
    # Try the anchor first, then the rest of the statement's span.
    span_end = finding.end_line or finding.line
    target_line = None
    for lineno in range(finding.line, span_end + 1):
        if not (1 <= lineno <= len(lines)):
            continue
        result = transform(lines[lineno - 1])
        if result is not None and result[0] != lines[lineno - 1]:
            target_line = lineno
            break
    if target_line is None:
        return None

    finding = _rebind_line(finding, target_line)
    original = lines[target_line - 1]
    patched, title, rationale, artifact = transform(original)

    diff = "\n".join(
        difflib.unified_diff(
            [original], [patched],
            fromfile=f"a/{finding.file_path}",
            tofile=f"b/{finding.file_path}",
            lineterm="",
            n=0,
        )
    )
    return Patch(finding, title, rationale, original, patched, diff, artifact)


def apply(target: Target, patch: Patch) -> Path:
    """Write the patched line to disk, backing up the original to <file>.bak."""
    path = resolve_within(target.root, patch.finding.file_path)
    lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    index = patch.finding.line - 1
    if not (0 <= index < len(lines)):
        raise RemediationError(f"line {patch.finding.line} no longer exists in {path.name}")
    if lines[index].rstrip("\r\n") != patch.original_line:
        raise RemediationError(
            f"{path.name}:{patch.finding.line} changed since the patch was proposed; not applying"
        )

    backup = path.with_suffix(path.suffix + ".bak")
    shutil.copy2(path, backup)

    newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
    lines[index] = patch.patched_line + newline
    path.write_text("".join(lines), encoding="utf-8")
    return backup


def revert(target: Target, finding: Finding) -> None:
    path = resolve_within(target.root, finding.file_path)
    backup = path.with_suffix(path.suffix + ".bak")
    if not backup.exists():
        raise RemediationError(f"no backup to revert: {backup.name}")
    shutil.copy2(backup, path)
    backup.unlink()


def _fix_weak_hash(line: str):
    indent = _indent(line)
    patched = f"{indent}return PasswordHasher().hash(password)  # was: {line.strip()}"
    return (
        patched,
        "Hash passwords with Argon2id",
        "Replace the fast digest with Argon2id, which is memory-hard and salts each "
        "password. Add 'from argon2 import PasswordHasher' to the imports, and migrate "
        "the stored table with the rehash-on-login helper so existing users are not "
        "forced to reset.",
        _REHASH_ON_LOGIN,
    )


def _fix_insecure_random(line: str):
    indent = _indent(line)
    if "random.seed" in line:
        patched = f"{indent}pass  # removed clock seeding; secrets draws from the OS CSPRNG"
    else:
        name = _assigned_name(line) or "token"
        patched = f"{indent}{name} = secrets.token_urlsafe(32)  # was: {line.strip()}"
    return (
        patched,
        "Generate tokens with the secrets module",
        "secrets.token_urlsafe(32) draws 256 bits from the OS CSPRNG, which is not "
        "reconstructible from observed output. Add 'import secrets' to the imports.",
        "",
    )


def _fix_jwt(line: str):
    patched = re.sub(
        r"jwt\.decode\((.*?)\)",
        lambda m: f"jwt.decode({_rewrite_decode_args(m.group(1))})",
        line,
    )
    if patched == line:
        return None
    return (
        patched,
        "Verify the JWT signature with an algorithm allow-list",
        "Decode with the signing key and algorithms=['HS256'] so a forged or unsigned "
        "token is rejected. Never pass verify_signature=False or allow 'none'.",
        "",
    )


def _fix_tls(line: str):
    patched = line.replace("verify=False", "verify=True")
    if patched == line:
        return None
    return (
        patched,
        "Re-enable TLS certificate verification",
        "verify=True restores certificate checking. If the peer uses a private CA, pass "
        "verify='/path/to/ca.pem' instead of disabling verification.",
        "",
    )


def _fix_log(line: str):
    # Drop the password/token argument rather than guessing a redaction format.
    patched = re.sub(
        r"(password|passwd|pwd|token|secret)=\{[^}]+\}",
        r"\1=[redacted]",
        line,
        flags=re.IGNORECASE,
    )
    patched = re.sub(
        r"(,\s*)(password|token|secret)\b(?!=)",
        "",
        patched,
        flags=re.IGNORECASE,
    )
    if patched == line:
        patched = f"{_indent(line)}# removed credential from log line: {line.strip()}"
    return (
        patched,
        "Remove the credential from the log line",
        "Log the identifier only. Secrets in logs escape the protected store into log "
        "storage that is usually less guarded and often shipped off the host.",
        "",
    )


def _fix_hardcoded(line: str):
    name = _assigned_name(line)
    if not name:
        return None
    # Keep the variable name the code already reads, if it reads one.
    existing = re.search(r"""(?:getenv|environ\.get)\(\s*["']([^"']+)["']""", line)
    env_name = existing.group(1) if existing else name.upper()
    indent = _indent(line)
    # os.environ[...] raises at startup when the variable is missing. That is
    # the point: a missing key should stop the app, not quietly sign with a
    # default or with None.
    patched = (
        f'{indent}{name} = os.environ["{env_name}"]  '
        f"# set {env_name} in the environment; rotate the old value"
    )
    return (
        patched,
        "Require the secret from the environment",
        f"Load {name} from the environment with no fallback, so a deployment missing "
        f"{env_name} fails at startup instead of signing with a value from source. "
        "Rotate the exposed value - removing it from source does not un-leak it from git "
        "history. Add 'import os' if absent.",
        "",
    )


_TRANSFORMS = {
    "CWE-916": _fix_weak_hash,
    "CWE-759": _fix_weak_hash,
    "CWE-330": _fix_insecure_random,
    "CWE-347": _fix_jwt,
    "CWE-295": _fix_tls,
    "CWE-532": _fix_log,
    "CWE-798": _fix_hardcoded,
    "CWE-256": _fix_hardcoded,
}


def _rewrite_decode_args(args: str) -> str:
    # Keep the token (first positional) and force a verified decode.
    token = args.split(",", 1)[0].strip()
    key = "SECRET_KEY"
    for candidate in ("JWT_SECRET", "SECRET_KEY", "secret", "key"):
        if candidate in args:
            key = candidate
            break
    return f'{token}, {key}, algorithms=["HS256"]'


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _assigned_name(line: str) -> str | None:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
    return match.group(1) if match else None


# Offered alongside any password-hash fix. Rehash-on-login is what lets a small
# project adopt Argon2id without a forced password reset for every user: the
# legacy hash is verified once, then replaced in place on a successful login.
_REHASH_ON_LOGIN = '''\
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def verify_and_migrate(username, password, stored_hash, save_new_hash):
    """Verify a password against either a legacy MD5 hash or an Argon2id hash.

    On a successful login against a legacy hash, replace it with Argon2id via
    save_new_hash(username, new_hash). Existing users migrate as they log in; no
    one is forced to reset.
    """
    if stored_hash.startswith("$argon2"):
        try:
            _hasher.verify(stored_hash, password)
            return True
        except VerifyMismatchError:
            return False

    # Legacy path: constant-work comparison against the old MD5 digest.
    if hashlib.md5(password.encode()).hexdigest() == stored_hash:
        save_new_hash(username, _hasher.hash(password))
        return True
    return False
'''
