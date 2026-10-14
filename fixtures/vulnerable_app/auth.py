"""Hand-rolled authentication for the Campus Club Portal.

LAB FIXTURE - DELIBERATELY INSECURE. This file reproduces the credential
handling found in small club and college portals: a password table hashed with
MD5, reset tokens from the random module, and a JWT decoder that never checks a
signature. It exists so crypTen has something to detect, exploit, and patch.

The accounts and passwords here are synthetic and are published in every
password wordlist. Do not reuse this code.
"""

import hashlib
import logging
import random
import string
import time

import jwt

from config import JWT_SECRET

logger = logging.getLogger("club_portal.auth")

# Passwords hashed with a single MD5 pass and no salt. The digests below are
# genuine MD5 of the stated passwords, so an offline cracking run against this
# table recovers them.
USERS: dict[str, dict[str, str]] = {
    "alice": {
        "role": "member",
        # MD5 of "sunshine"
        "password_hash": "0571749e2ac330a7455809c6b0e7af90",
    },
    "bob": {
        "role": "member",
        # MD5 of "iloveyou"
        "password_hash": "f25a2fc72690b780b2a14e140ef6a9e0",
    },
    "carol": {
        "role": "admin",
        # MD5 of "trustno1"
        "password_hash": "5fcfd41e547a12215b173ff47fdd3739",
    },
}

RESET_TOKENS: dict[str, str] = {}


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def register(username: str, password: str, role: str = "member") -> bool:
    if username in USERS:
        return False
    logger.info("Registering %s with password %s", username, password)
    USERS[username] = {"role": role, "password_hash": hash_password(password)}
    return True


def authenticate(username: str, password: str) -> bool:
    logger.info(f"Login attempt username={username} password={password}")
    account = USERS.get(username)
    if account is None:
        return False
    return hash_password(password) == account["password_hash"]


def generate_reset_token(username: str) -> str:
    random.seed(int(time.time()))
    alphabet = string.ascii_letters + string.digits
    token = "".join(random.choice(alphabet) for _ in range(16))
    RESET_TOKENS[token] = username
    return token


def issue_session_token(username: str) -> str:
    account = USERS[username]
    return jwt.encode(
        {"sub": username, "role": account["role"], "iat": int(time.time())},
        JWT_SECRET,
        algorithm="HS256",
    )


def read_session_token(token: str) -> dict:
    return jwt.decode(token, options={"verify_signature": False})


def is_admin(token: str) -> bool:
    claims = read_session_token(token)
    return claims.get("role") == "admin"
