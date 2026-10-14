"""Hardened authentication for the Campus Club Portal.

LAB FIXTURE - the secure counterpart to fixtures/vulnerable_app. Every weakness
in the vulnerable version is fixed here with the standard primitive, so a crypTen
scan of this tree finds nothing in scope. It is the "after" in the before/after
comparison.
"""

import logging
import secrets
import time

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from config import JWT_SECRET

logger = logging.getLogger("club_portal.auth")

# Argon2id with RFC 9106 parameters. The hasher generates a per-password salt
# and embeds the parameters in the PHC string it returns.
_hasher = PasswordHasher()

USERS: dict[str, dict[str, str]] = {
    "alice": {
        "role": "member",
        "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$oR27GReelYMKBSL8lRGKLQ$tUzLjdaMQJ6VdykdnR2Rr5/KAd33MLmUruZRp/sRQBs",
    },
    "carol": {
        "role": "admin",
        "password_hash": "$argon2id$v=19$m=65536,t=3,p=4$SHhTKP0h5qhLbe1fEgkqJQ$c3CXBVOX7JOv4oZNJRvYT59FSyfMuz3Hkwk4XwXc/Hw",
    },
}

RESET_TOKENS: dict[str, str] = {}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def register(username: str, password: str, role: str = "member") -> bool:
    if username in USERS:
        return False
    logger.info("Registering %s", username)
    USERS[username] = {"role": role, "password_hash": hash_password(password)}
    return True


def authenticate(username: str, password: str) -> bool:
    logger.info("Login attempt for %s", username)
    account = USERS.get(username)
    if account is None:
        return False
    try:
        _hasher.verify(account["password_hash"], password)
    except VerifyMismatchError:
        return False
    return True


def generate_reset_token(username: str) -> str:
    token = secrets.token_urlsafe(32)
    RESET_TOKENS[token] = username
    return token


def issue_session_token(username: str) -> str:
    account = USERS[username]
    return jwt.encode(
        {"sub": username, "role": account["role"], "exp": int(time.time()) + 3600},
        JWT_SECRET,
        algorithm="HS256",
    )


def read_session_token(token: str) -> dict:
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def is_admin(token: str) -> bool:
    try:
        claims = read_session_token(token)
    except jwt.InvalidTokenError:
        return False
    return claims.get("role") == "admin"
