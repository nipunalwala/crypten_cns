"""Catalogue of the credential-handling weaknesses crypTen detects.

One entry per CWE in the project's scope. Everything the rest of the tool needs
to describe a weakness to a human - title, why it matters, how to fix it, where
the guidance comes from - lives here rather than being restated at each scanner.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class CweEntry:
    cwe_id: str
    title: str
    owasp: str
    summary: str
    impact: str
    fix: str
    references: tuple[str, ...] = field(default=())


CATALOGUE: dict[str, CweEntry] = {
    "CWE-256": CweEntry(
        cwe_id="CWE-256",
        title="Plaintext Storage of a Password",
        owasp="A04:2025 Cryptographic Failures",
        summary=(
            "A password is stored in a form that can be read directly - a literal in "
            "source, a plaintext column, or a config file."
        ),
        impact=(
            "Anyone who reads the store reads every password. There is no work for an "
            "attacker to do, and users who reuse the password lose their other accounts too."
        ),
        fix=(
            "Never store the password itself. Store a salted Argon2id hash and compare "
            "by re-hashing the submitted password."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/256.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html",
        ),
    ),
    "CWE-759": CweEntry(
        cwe_id="CWE-759",
        title="Use of a One-Way Hash without a Salt",
        owasp="A04:2025 Cryptographic Failures",
        summary=(
            "A password is hashed without a unique per-user salt, so the same password "
            "always produces the same digest."
        ),
        impact=(
            "Identical hashes reveal which users share a password, and a single "
            "precomputed rainbow table cracks the whole table at once rather than one "
            "account at a time."
        ),
        fix=(
            "Use a password hashing function that generates its own random salt. "
            "Argon2id embeds a 128-bit salt in the PHC string it returns."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/759.html",
            "https://pages.nist.gov/800-63-4/sp800-63b.html",
        ),
    ),
    "CWE-916": CweEntry(
        cwe_id="CWE-916",
        title="Use of Password Hash With Insufficient Computational Effort",
        owasp="A04:2025 Cryptographic Failures",
        summary=(
            "A password is hashed with a fast general-purpose digest - MD5, SHA-1, or a "
            "single SHA-256 pass - rather than a deliberately slow password hash."
        ),
        impact=(
            "These digests are built to be fast, which is exactly wrong for passwords. "
            "Commodity GPUs try billions of candidates per second against them, so a "
            "leaked table is cracked offline in hours."
        ),
        fix=(
            "Use Argon2id with a tuned work factor. The cost should be as high as the "
            "login path can tolerate."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/916.html",
            "https://www.rfc-editor.org/rfc/rfc9106",
        ),
    ),
    "CWE-798": CweEntry(
        cwe_id="CWE-798",
        title="Use of Hard-coded Credentials",
        owasp="A04:2025 Cryptographic Failures",
        summary=(
            "A signing key, database password, or API token is written as a literal in "
            "source code."
        ),
        impact=(
            "The secret is readable by anyone with the repository, and it stays in git "
            "history after it is deleted from the working tree. A leaked signing key "
            "lets an attacker mint valid sessions and tokens for any user."
        ),
        fix=(
            "Read the value from the environment or a secret manager, fail closed when "
            "it is absent, and rotate the exposed secret - removing it from source does "
            "not un-leak it."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/798.html",
            "https://doi.org/10.14722/ndss.2019.23418",
        ),
    ),
    "CWE-295": CweEntry(
        cwe_id="CWE-295",
        title="Improper Certificate Validation",
        owasp="A04:2025 Cryptographic Failures",
        summary=(
            "An outbound HTTPS call disables certificate verification, typically with "
            "verify=False in the requests library."
        ),
        impact=(
            "Any party on the network path can present its own certificate and be "
            "accepted. The connection is still encrypted, but to the attacker - so "
            "credentials and API keys sent over it are read in clear."
        ),
        fix=(
            "Leave verification on. If the peer uses a private CA, pin that CA bundle "
            "with verify='/path/to/ca.pem' rather than switching verification off."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/295.html",
            "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification",
        ),
    ),
    "CWE-532": CweEntry(
        cwe_id="CWE-532",
        title="Insertion of Sensitive Information into Log File",
        owasp="A09:2025 Logging and Alerting Failures",
        summary=(
            "A log or print statement writes a password, token, or whole request body "
            "to the application log."
        ),
        impact=(
            "Secrets escape the protected database into log storage, which is usually "
            "less guarded, often shipped to a third-party service, and retained long "
            "after the credential should have expired."
        ),
        fix=(
            "Log the non-sensitive identifier only, and install a logging filter that "
            "redacts known credential field names as a backstop."
        ),
        references=("https://cwe.mitre.org/data/definitions/532.html",),
    ),
    "CWE-330": CweEntry(
        cwe_id="CWE-330",
        title="Use of Insufficiently Random Values",
        owasp="A07:2025 Authentication Failures",
        summary=(
            "A session ID, password-reset link, or API token is generated with Python's "
            "random module or derived from a timestamp."
        ),
        impact=(
            "random uses the Mersenne Twister, which is not a CSPRNG. Its internal "
            "state can be reconstructed from enough observed output, after which every "
            "later token is predictable - including the reset token for any account."
        ),
        fix=(
            "Generate tokens with secrets.token_urlsafe(32), which draws from the "
            "operating system CSPRNG."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/330.html",
            "https://docs.python.org/3/library/secrets.html",
        ),
    ),
    "CWE-347": CweEntry(
        cwe_id="CWE-347",
        title="Improper Verification of Cryptographic Signature",
        owasp="A07:2025 Authentication Failures",
        summary=(
            "A JWT is decoded without verifying its signature, or is accepted under the "
            "'none' algorithm, or is signed with a short guessable HMAC secret."
        ),
        impact=(
            "An attacker writes their own token claiming any identity and any role. "
            "Authentication stops being a check and becomes a suggestion."
        ),
        fix=(
            "Decode with an explicit algorithm allow-list, a signing key of at least "
            "256 bits read from the environment, and a verified expiry claim."
        ),
        references=(
            "https://cwe.mitre.org/data/definitions/347.html",
            "https://www.rfc-editor.org/rfc/rfc8725",
        ),
    ),
    "CWE-1395": CweEntry(
        cwe_id="CWE-1395",
        title="Dependency on Vulnerable Third-Party Component",
        owasp="A06:2025 Vulnerable and Outdated Components",
        summary=(
            "A declared dependency version has a known published vulnerability."
        ),
        impact=(
            "The flaw is public and usually has a working exploit. When the package is "
            "an authentication or crypto library, the application inherits a credential "
            "weakness it never wrote."
        ),
        fix="Upgrade to the fixed version named in the advisory.",
        references=("https://cwe.mitre.org/data/definitions/1395.html",),
    ),
}

# Weaknesses that are not in the project's stated scope still turn up in Bandit
# and Semgrep output. They are reported, but labelled so they can be filtered out
# of the credential-handling survey.
IN_SCOPE: frozenset[str] = frozenset(CATALOGUE)


def describe(cwe_id: str) -> CweEntry | None:
    """Return the catalogue entry for a CWE, or None if it is out of scope."""
    return CATALOGUE.get(cwe_id.upper())


def is_in_scope(cwe_id: str) -> bool:
    return cwe_id.upper() in IN_SCOPE
