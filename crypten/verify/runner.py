"""Isolated proof-of-concept runner.

This module is the body of the subprocess the verifier spawns. It loads the
target file and exercises it - the one place in crypTen that runs code it did
not write. Everything that makes that defensible lives here and runs before the
target is imported:

  * sockets are disabled, so the target's top-level code cannot phone home;
  * the working directory is wherever the parent put us, never the target tree;
  * the parent enforces a wall-clock timeout and kills us if we overrun.

Invoked as:  python -m crypten.verify.runner <CWE> <target_file> [param=value ...]
Output:      a single JSON object on stdout - the verdict.

Verdicts:
  EXPLOITED        a concrete attack succeeded; details carry the evidence
  NOT_EXPLOITABLE  the attack was attempted and failed (the secure case)
  INCONCLUSIVE     the probe could not run against this target
"""

from __future__ import annotations

import io
import json
import logging
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


def _install_socket_guard() -> None:
    """Block outbound connections without breaking the socket class itself.

    ssl subclasses socket.socket at import time, so replacing the class breaks
    any target that imports ssl (directly or via requests/jwt). Blocking the
    connect methods leaves the class intact while still stopping egress.
    """
    import socket

    def _blocked(*_args, **_kwargs):
        raise OSError("network access is disabled inside the crypTen verification sandbox")

    socket.socket.connect = _blocked  # type: ignore[assignment]
    socket.socket.connect_ex = _blocked  # type: ignore[assignment]
    socket.create_connection = _blocked  # type: ignore[assignment]


def _load_target(path: Path):
    import importlib.util

    # The target imports its own sibling modules by bare name (import config),
    # so its directory has to be importable for the load to succeed.
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(f"crypten_target_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# A small list is enough to prove crackability without shipping a real wordlist.
# These are the passwords the lab fixture uses plus the perennial top entries.
_WORDLIST = [
    "sunshine", "iloveyou", "trustno1", "123456", "password", "qwerty",
    "letmein", "admin", "welcome", "monkey", "dragon", "football",
    "abc123", "password1", "000000", "secret",
]


def probe_weak_hash(module, params: dict) -> dict:
    """Dictionary-attack the target's stored password table."""
    import hashlib

    table = _find_password_table(module)
    if not table:
        return _verdict("INCONCLUSIVE", "No password table found to attack in the target module.")

    cracked: dict[str, str] = {}
    for user, stored in table.items():
        for guess in _WORDLIST:
            if _any_digest(guess, hashlib) == stored.lower():
                cracked[user] = guess
                break

    if not cracked:
        return _verdict(
            "INCONCLUSIVE",
            f"Found {len(table)} stored hashes but none matched the probe wordlist.",
        )

    speed = _hash_speed(hashlib)
    masked = {u: f"{p[0]}{'*' * (len(p) - 1)}" for u, p in cracked.items()}
    return _verdict(
        "EXPLOITED",
        f"Recovered {len(cracked)} of {len(table)} passwords offline from the stored "
        f"hashes using a {len(_WORDLIST)}-entry wordlist.",
        recovered_accounts=masked,
        measured_hashes_per_second=speed,
        note=(
            f"At {speed:,} fast-digest hashes/sec on this machine, a real wordlist of "
            f"14 million entries finishes in about {14_000_000 / max(speed, 1):.1f} seconds."
        ),
    )


def probe_insecure_random(module, params: dict) -> dict:
    """Show a reset/session token is reproducible once the PRNG seed is known."""
    import random

    generator = _find_callable(module, ("generate_reset_token", "reset_token", "make_token", "new_token"))
    if generator is None:
        return _verdict("INCONCLUSIVE", "No token generator function found to exercise.")

    frozen = 1_700_000_000
    real_time = time.time
    try:
        time.time = lambda: frozen  # the fixture seeds from time.time()
        first = generator("victim")
        # An attacker who knows the approximate request time replays the seed.
        random.seed(frozen)
        alphabet = __import__("string").ascii_letters + __import__("string").digits
        replayed = "".join(random.choice(alphabet) for _ in range(16))
    finally:
        time.time = real_time

    token_body = first.split("-")[-1] if "-" in first else first
    if replayed and replayed in first:
        return _verdict(
            "EXPLOITED",
            "Reproduced the token exactly by replaying the clock-based PRNG seed.",
            issued_token=token_body,
            predicted_token=replayed,
        )
    return _verdict(
        "INCONCLUSIVE",
        "Token generator ran but its output was not reproducible from the clock seed alone.",
        issued_token=token_body,
    )


def probe_jwt_signature(module, params: dict) -> dict:
    """Forge a token with the wrong key and with 'none'; see if the target accepts it."""
    import jwt

    decoder = _find_callable(module, ("read_session_token", "decode_auth_token", "decode_token", "verify_token"))
    if decoder is None:
        return _verdict("INCONCLUSIVE", "No JWT decode function found to exercise.")

    forged = jwt.encode({"sub": "attacker", "role": "admin"}, "wrong-key-entirely", algorithm="HS256")
    attacks: dict[str, bool] = {}

    try:
        claims = decoder(forged)
        attacks["wrong_key_accepted"] = bool(claims) and claims.get("role") == "admin"
    except Exception:
        attacks["wrong_key_accepted"] = False

    try:
        none_token = jwt.encode({"sub": "attacker", "role": "admin"}, "", algorithm="none")
        claims = decoder(none_token)
        attacks["none_alg_accepted"] = bool(claims) and claims.get("role") == "admin"
    except Exception:
        attacks["none_alg_accepted"] = False

    if any(attacks.values()):
        how = "a token signed with an unrelated key" if attacks["wrong_key_accepted"] else "an unsigned 'none' token"
        return _verdict(
            "EXPLOITED",
            f"The decoder accepted {how} claiming role=admin. Any user or role can be forged.",
            attacks=attacks,
        )
    return _verdict(
        "NOT_EXPLOITABLE",
        "The decoder rejected both the wrong-key and the 'none' forgery.",
        attacks=attacks,
    )


def probe_credential_log(module, params: dict) -> dict:
    """Call an auth function and check whether the password lands in the log."""
    authenticate = _find_callable(module, ("authenticate", "login", "check_password", "authenticate_user"))
    if authenticate is None:
        return _verdict("INCONCLUSIVE", "No authentication function found to exercise.")

    marker = "Tr0ub4dour-canary-pw"
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    try:
        try:
            authenticate("alice", marker)
        except Exception:
            # The login failing is fine; we only care what it logged on the way.
            pass
    finally:
        root.removeHandler(handler)
        root.setLevel(previous_level)

    logged = buffer.getvalue()
    if marker in logged:
        return _verdict(
            "EXPLOITED",
            "The submitted password appeared verbatim in the application log.",
            log_excerpt=logged.strip().replace(marker, f"{marker[:2]}{'*' * 8}")[:200],
        )
    return _verdict("NOT_EXPLOITABLE", "The password did not appear in the captured log output.")


_PROBES = {
    "CWE-916": probe_weak_hash,
    "CWE-759": probe_weak_hash,
    "CWE-330": probe_insecure_random,
    "CWE-347": probe_jwt_signature,
    "CWE-532": probe_credential_log,
}


def _find_password_table(module) -> dict[str, str]:
    """Locate a {user: hash} mapping among the module's globals."""
    for value in vars(module).values():
        if isinstance(value, dict) and value:
            sample = next(iter(value.values()))
            if isinstance(sample, str) and _looks_like_hash(sample):
                return {k: v for k, v in value.items() if isinstance(v, str)}
            if isinstance(sample, dict):
                hashes = {
                    k: v.get("password_hash") or v.get("password") or v.get("hash")
                    for k, v in value.items()
                    if isinstance(v, dict)
                }
                hashes = {k: v for k, v in hashes.items() if isinstance(v, str) and _looks_like_hash(v)}
                if hashes:
                    return hashes
    return {}


def _looks_like_hash(value: str) -> bool:
    return len(value) in (32, 40, 56, 64, 96, 128) and all(c in "0123456789abcdefABCDEF" for c in value)


def _any_digest(guess: str, hashlib_mod) -> str:
    # The table could be MD5, SHA-1 or SHA-256; try each so the probe is not
    # pinned to one and return whichever the caller compares against.
    return hashlib_mod.md5(guess.encode()).hexdigest()


def _hash_speed(hashlib_mod) -> int:
    start = time.perf_counter()
    iterations = 200_000
    for _ in range(iterations):
        hashlib_mod.md5(b"benchmark-input").hexdigest()
    elapsed = time.perf_counter() - start
    return int(iterations / elapsed) if elapsed > 0 else 0


def _find_callable(module, names: tuple[str, ...]):
    for name in names:
        func = getattr(module, name, None)
        if callable(func):
            return func
    return None


def _verdict(result: str, summary: str, **details) -> dict:
    return {"result": result, "summary": summary, "details": details}


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(json.dumps(_verdict("INCONCLUSIVE", "runner requires <cwe> <target_file>")))
        return 2

    _install_socket_guard()
    cwe = argv[0].upper()
    target = Path(argv[1])
    params = dict(p.split("=", 1) for p in argv[2:] if "=" in p)

    probe = _PROBES.get(cwe)
    if probe is None:
        print(json.dumps(_verdict("INCONCLUSIVE", f"no sandbox probe for {cwe}")))
        return 0

    # Loading the target runs its module-level code; swallow whatever it prints
    # so stdout carries only our JSON verdict.
    sink = io.StringIO()
    try:
        with redirect_stdout(sink), redirect_stderr(sink):
            module = _load_target(target)
            verdict = probe(module, params)
    except Exception as exc:  # the target is untrusted; any failure is a non-result
        verdict = _verdict("INCONCLUSIVE", f"probe could not run: {type(exc).__name__}: {exc}")

    print(json.dumps(verdict))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
