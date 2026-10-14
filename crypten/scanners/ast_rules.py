"""Semantic detection of credential-handling weaknesses in Python source.

Bandit and Semgrep both match shapes in the syntax tree. The weakness they share
is that neither reliably answers the question that decides whether a finding is
real: is this hash covering a *password*, or a cache key? Is this random value a
*session token*, or a jitter delay?

These rules answer it by following names. A call is in password context when one
of its arguments derives from an identifier the application itself calls a
password - a parameter, a variable, or an f-string interpolation. That is still
a heuristic, but it is a heuristic about the program rather than about the text
of one line, so it survives reformatting and it does not fire on a comment.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from ..findings import Finding
from ..intake import Target, read_source, relative_to
from ..redact import redact

SCANNER = "ast"

_PASSWORD_NAMES = re.compile(
    r"(?:^|_)(?:password|passwd|pwd|passphrase|secret|credential)s?(?:$|_)", re.IGNORECASE
)
_TOKEN_NAMES = re.compile(
    r"(?:^|_)(?:token|session|sessionid|otp|nonce|apikey|api_key|reset|verifier|csrf|state)s?(?:$|_)",
    re.IGNORECASE,
)
_SALT_NAMES = re.compile(r"(?:^|_)salts?(?:$|_)", re.IGNORECASE)
_SECRET_CONFIG_NAMES = re.compile(
    r"(?:^|_)(?:secret_key|secretkey|jwt_secret|api_key|apikey|access_token|auth_token|"
    r"client_secret|private_key|db_password|database_url|password|passwd)(?:$|_)",
    re.IGNORECASE,
)

_FAST_DIGESTS = frozenset({"md5", "sha1", "md4", "sha"})
_PLAIN_DIGESTS = frozenset({"sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"})
_WEAK_RANDOM = frozenset(
    {"random", "randint", "randrange", "choice", "choices", "sample", "shuffle", "uniform", "getrandbits"}
)
_LOG_METHODS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical", "log"})

# Strings that look like secrets but are placeholders. Flagging these trains a
# maintainer to ignore the tool, which costs more than the missed finding.
_PLACEHOLDERS = frozenset(
    {
        "", "changeme", "change_me", "your_secret_here", "xxx", "todo", "none", "null",
        "placeholder", "example", "test", "dummy", "secret", "password", "replace_me",
        "<your-key>", "string", "foo", "bar",
    }
)


def scan(target: Target) -> list[Finding]:
    findings: list[Finding] = []
    for path in _python_files(target):
        source = read_source(path)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError:
            # A file that does not parse under this interpreter is out of reach
            # for AST rules; Bandit and the secret scanner still see it.
            continue
        visitor = _Visitor(relative_to(target, path), source.splitlines())
        visitor.visit(tree)
        findings.extend(visitor.findings)
    return findings


def _python_files(target: Target) -> list[Path]:
    from ..intake import python_files

    return python_files(target)


def _dotted(node: ast.expr) -> str:
    """Render a call target as a dotted name: hashlib.md5, jwt.decode, logger.info."""
    parts: list[str] = []
    cur: ast.expr | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _names_in(node: ast.AST) -> set[str]:
    """Every identifier appearing in an expression, including inside f-strings."""
    found: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            found.add(child.id)
        elif isinstance(child, ast.Attribute):
            found.add(child.attr)
        elif isinstance(child, ast.Constant) and isinstance(child.value, str):
            # A dict lookup like user["password"] names the field as a string.
            found.add(child.value)
    return found


def _mentions(node: ast.AST, pattern: re.Pattern[str]) -> bool:
    return any(pattern.search(name) for name in _names_in(node))


def _literal_str(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


_ENV_LOOKUPS = frozenset({"os.getenv", "getenv", "os.environ.get", "environ.get"})


def _is_env_lookup(node: ast.expr) -> bool:
    return isinstance(node, ast.Call) and _dotted(node.func) in _ENV_LOOKUPS


def _env_fallback_literal(node: ast.expr) -> str | None:
    """The non-empty string a secret falls back to when its env variable is unset.

    Covers both spellings: os.getenv("K") or "literal", and os.getenv("K", "literal")
    (likewise os.environ.get).
    """
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        if any(_is_env_lookup(v) for v in node.values):
            for value in node.values:
                literal = _literal_str(value)
                if literal:
                    return literal
        return None

    if _is_env_lookup(node):
        default = node.args[1] if len(node.args) > 1 else next(
            (kw.value for kw in node.keywords if kw.arg == "default"), None
        )
        literal = _literal_str(default) if default is not None else None
        return literal or None
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, file_path: str, lines: list[str]) -> None:
        self.file_path = file_path
        self.lines = lines
        self.findings: list[Finding] = []
        # Parameters of the enclosing function count as password context: a
        # helper called hash_it(password) is still hashing a password.
        self._scope_names: list[set[str]] = [set()]

    def _snippet(self, node: ast.AST) -> str:
        line = getattr(node, "lineno", 0)
        if 1 <= line <= len(self.lines):
            return redact(self.lines[line - 1].strip())
        return ""

    def _add(
        self,
        node: ast.AST,
        rule_id: str,
        cwe_id: str,
        severity: str,
        confidence: str,
    ) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                cwe_id=cwe_id,
                file_path=self.file_path,
                line=getattr(node, "lineno", 1),
                end_line=getattr(node, "end_lineno", None),
                severity=severity,
                confidence=confidence,
                evidence=self._snippet(node),
                scanner=SCANNER,
            )
        )

    def _in_password_scope(self, node: ast.AST) -> bool:
        if _mentions(node, _PASSWORD_NAMES):
            return True
        referenced = _names_in(node)
        return any(
            _PASSWORD_NAMES.search(name)
            for scope in self._scope_names
            for name in scope & referenced
        )

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_function(node)

    def _enter_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        args = node.args
        # The function's own name carries as much intent as its parameters do:
        # generate_reset_token(username) is about tokens, not about usernames.
        params = {node.name} | {a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)}
        if args.vararg:
            params.add(args.vararg.arg)
        if args.kwarg:
            params.add(args.kwarg.arg)
        self._scope_names.append(params)
        self.generic_visit(node)
        self._scope_names.pop()

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_hardcoded_secret(node)
        self._check_plaintext_storage(node)
        # What a value is being stored as tells us what it is for, so the
        # target names are in scope while the right-hand side is examined.
        self._scope_names.append(_names_in(ast.Tuple(elts=list(node.targets))))
        self.visit(node.value)
        self._scope_names.pop()
        for target in node.targets:
            self.visit(target)

    def visit_Call(self, node: ast.Call) -> None:
        name = _dotted(node.func)
        self._check_password_hash(node, name)
        self._check_weak_random(node, name)
        self._check_jwt(node, name)
        self._check_tls(node, name)
        self._check_logging(node, name)
        self.generic_visit(node)

    def _check_password_hash(self, node: ast.Call, name: str) -> None:
        digest = name.rsplit(".", 1)[-1].lower()
        if name.startswith("hashlib.new") or digest == "new":
            named = _literal_str(node.args[0]) if node.args else None
            digest = (named or "").lower()
        elif not (name.startswith("hashlib.") or digest in _FAST_DIGESTS | _PLAIN_DIGESTS):
            return

        if digest not in _FAST_DIGESTS | _PLAIN_DIGESTS:
            return
        if not any(self._in_password_scope(arg) for arg in node.args):
            return

        if digest in _FAST_DIGESTS:
            self._add(node, "crypten.weak-password-hash", "CWE-916", "HIGH", "HIGH")
        else:
            # A single general-purpose pass is fast whatever the digest width.
            self._add(node, "crypten.fast-password-hash", "CWE-916", "HIGH", "MEDIUM")

        salted = any(_mentions(arg, _SALT_NAMES) for arg in node.args)
        if not salted:
            self._add(node, "crypten.unsalted-password-hash", "CWE-759", "HIGH", "MEDIUM")

    def _check_weak_random(self, node: ast.Call, name: str) -> None:
        func = name.rsplit(".", 1)[-1]
        # Seeding from the clock is worse than leaving the PRNG alone: it
        # narrows the search space to the handful of seconds around the
        # request, whatever the generator does afterwards.
        if name == "random.seed" and node.args and _mentions(node.args[0], re.compile(r"time|now|date|clock", re.I)):
            self._add(node, "crypten.clock-seeded-random", "CWE-330", "HIGH", "HIGH")
            return

        is_random_module = name.startswith("random.") or (
            func in _WEAK_RANDOM and not name.startswith("secrets.")
        )
        if not (is_random_module and func in _WEAK_RANDOM):
            return
        if not self._security_context(node):
            return
        self._add(node, "crypten.insecure-token-random", "CWE-330", "HIGH", "HIGH")

    def _security_context(self, node: ast.Call) -> bool:
        """Whether this value looks destined to become a token or session id."""
        if _mentions(node, _TOKEN_NAMES) or _mentions(node, _PASSWORD_NAMES):
            return True
        parent_names = {n for scope in self._scope_names for n in scope}
        return any(_TOKEN_NAMES.search(n) for n in parent_names)

    def _check_jwt(self, node: ast.Call, name: str) -> None:
        if not name.endswith("decode") or "jwt" not in name.lower():
            return

        unverified = False
        allows_none = False
        for kw in node.keywords:
            if kw.arg == "verify" and kw.value is not None:
                if isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    unverified = True
            elif kw.arg == "options" and isinstance(kw.value, ast.Dict):
                for key, value in zip(kw.value.keys, kw.value.values):
                    if (
                        isinstance(key, ast.Constant)
                        and key.value == "verify_signature"
                        and isinstance(value, ast.Constant)
                        and value.value is False
                    ):
                        unverified = True
            elif kw.arg == "algorithms" and isinstance(kw.value, (ast.List, ast.Tuple)):
                for element in kw.value.elts:
                    literal = _literal_str(element)
                    if literal is not None and literal.lower() == "none":
                        allows_none = True

        if unverified or allows_none:
            self._add(node, "crypten.jwt-signature-not-verified", "CWE-347", "CRITICAL", "HIGH")
            return

        # A decode with no algorithms argument at all leaves the choice to the
        # token, which is the algorithm-confusion case RFC 8725 warns about.
        if not any(kw.arg == "algorithms" for kw in node.keywords):
            self._add(node, "crypten.jwt-no-algorithm-allowlist", "CWE-347", "HIGH", "MEDIUM")

    def _check_tls(self, node: ast.Call, name: str) -> None:
        for kw in node.keywords:
            if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                self._add(node, "crypten.tls-verification-disabled", "CWE-295", "HIGH", "HIGH")
                return
        if name in {"ssl._create_unverified_context", "ssl._create_default_https_context"}:
            self._add(node, "crypten.tls-verification-disabled", "CWE-295", "HIGH", "HIGH")

    def _check_logging(self, node: ast.Call, name: str) -> None:
        func = name.rsplit(".", 1)[-1]
        is_log = func in _LOG_METHODS and ("log" in name.lower() or func != "log")
        if not (is_log or name == "print"):
            return
        if not node.args:
            return
        leaks_password = any(_mentions(arg, _PASSWORD_NAMES) for arg in node.args)
        leaks_token = any(_mentions(arg, _TOKEN_NAMES) for arg in node.args)
        if not (leaks_password or leaks_token):
            return
        severity = "MEDIUM" if leaks_token and not leaks_password else "HIGH"
        self._add(node, "crypten.credential-in-log", "CWE-532", severity, "HIGH")

    def _check_hardcoded_secret(self, node: ast.Assign) -> None:
        names = [
            target.id if isinstance(target, ast.Name) else target.attr
            for target in node.targets
            if isinstance(target, (ast.Name, ast.Attribute))
        ]
        if not any(_SECRET_CONFIG_NAMES.search(name) for name in names):
            return

        literal = _literal_str(node.value)
        if literal is not None:
            if literal.strip().lower() in _PLACEHOLDERS or len(literal) < 6:
                return
            self._add(node, "crypten.hardcoded-secret", "CWE-798", "HIGH", "HIGH")
            return

        # SECRET_KEY = os.getenv("SECRET_KEY") or "you-will-never-guess" reads
        # as externalised, but any deployment that forgets the variable signs
        # with the literal - which is public in the repository. Unlike a plain
        # literal, a short or placeholder fallback is no excuse here: "dev" is
        # exactly the key such a deployment ends up using.
        fallback = _env_fallback_literal(node.value)
        if fallback:
            self._add(node, "crypten.hardcoded-secret-fallback", "CWE-798", "HIGH", "MEDIUM")

    def _check_plaintext_storage(self, node: ast.Assign) -> None:
        """A password assigned straight into a store, with no hashing in between."""
        if not isinstance(node.value, ast.Name):
            return
        if not _PASSWORD_NAMES.search(node.value.id):
            return
        for target in node.targets:
            if isinstance(target, (ast.Subscript, ast.Attribute)) and _mentions(
                target, _PASSWORD_NAMES
            ):
                self._add(node, "crypten.plaintext-password-storage", "CWE-256", "HIGH", "MEDIUM")
                return
