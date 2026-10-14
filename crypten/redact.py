"""Mask credential values before they reach the database, the UI, or a report.

crypTen reads other people's secrets as a side effect of looking for them. Every
piece of evidence passes through redact() on the way out of a scanner, so a
finding can say "this line assigns a hard-coded key" without the report becoming
a second copy of the key.
"""

import re

_ASSIGNMENT = re.compile(
    r"""((?:api[_-]?key|secret[_-]?key|secret|password|passwd|pwd|token|
         auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key)
         \s*[:=]\s*["'])([^"']{3,})(["'])""",
    re.IGNORECASE | re.VERBOSE,
)
_AWS_KEY = re.compile(r"\b(AKIA[0-9A-Z]{16})\b")
_JWT = re.compile(r"\b(eyJ[\w-]{8,}\.eyJ[\w-]{8,}\.[\w-]+)")
_DB_URI = re.compile(
    r"((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:/@]+:)([^\s@]+)(@)",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    r"[\s\S]*?"
    r"-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)


def mask(value: str) -> str:
    """Replace a secret with a fixed-width stand-in that keeps a short prefix.

    The prefix lets a maintainer recognise which of their keys is being reported
    without the report disclosing enough to use it. Values short enough that a
    prefix would give away a meaningful fraction are masked whole.
    """
    if not value:
        return ""
    if len(value) <= 8:
        return "*" * 8
    return f"{value[:4]}{'*' * 8}"


def redact(text: str) -> str:
    """Strip credential values out of a code snippet or log line."""
    if not text:
        return ""

    out = _PRIVATE_KEY.sub("-----BEGIN PRIVATE KEY-----[redacted]-----END PRIVATE KEY-----", text)
    out = _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{mask(m.group(2))}{m.group(3)}", out)
    out = _AWS_KEY.sub(lambda m: mask(m.group(1)), out)
    out = _JWT.sub(lambda m: mask(m.group(1)), out)
    out = _DB_URI.sub(lambda m: f"{m.group(1)}{mask(m.group(2))}{m.group(3)}", out)
    return out
