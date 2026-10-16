# crypTen

crypTen finds insecure credential handling in small Python web apps, proves each
finding with a proof of concept that runs in a sandbox, and patches the code. It
works in three stages: **detect → verify → fix**. Each stage leaves evidence you
can inspect: a ranked finding, an exploit result or an inspection note, and a
patch with a `.bak` backup that is checked again after it is applied.

It was built for the ACNS-DC (Cryptography & Network Security) course project.

```
$ python -m crypten demo
  [EXPLOITED] CWE-916: Recovered 3 of 3 passwords offline from the stored hashes using a 16-entry wordlist.
  [EXPLOITED] CWE-532: The submitted password appeared verbatim in the application log.
  [INSPECTED] CWE-295: The outbound request sets verify=False, so any certificate on the path is accepted.
  ...
  vulnerable: 15 code weaknesses  ->  secure: 0 code weaknesses
```

## What it looks for

| CWE | Weakness | How crypTen confirms it |
|---|---|---|
| CWE-916 | Fast or obsolete password hash (MD5, SHA-1, unsalted SHA-256) | Exploited: cracks the stored digests offline |
| CWE-759 | Password hash without a salt | Exploited: same cracking run |
| CWE-347 | JWT decoded without signature verification | Exploited: a forged token is accepted |
| CWE-330 | Reset/session token from `random` or a clock seed | Exploited: the token is predicted |
| CWE-532 | Password or secret written to a log | Exploited: the secret shows up in captured log output |
| CWE-798 | Hard-coded secret, key or connection string | Inspected |
| CWE-256 | Plaintext password stored in source | Inspected |
| CWE-295 | TLS certificate verification disabled (`verify=False`) | Inspected |
| CWE-1395 | Dependency pinned to a version with a published advisory | Inspected (pip-audit) |

"Inspected" is a deliberate label. For a `verify=False` flag or a secret
literal, running the code proves nothing that reading it doesn't, so crypTen says
it confirmed the finding by inspection. It does not label these as exploits.

## How it works

1. **Detect.** Four scanners run, and their findings are merged and ranked:
   - AST rules that know the context. An `md5()` used as a cache key is not
     flagged, but an `md5()` applied to a password is.
   - A secret scanner.
   - Bandit and pip-audit.
   - Five custom Semgrep rules.
2. **Verify.** Each proof of concept runs in a separate short-lived process.
   Outbound sockets are disabled before the target's code is imported, and the
   parent process enforces a wall-clock timeout
   ([crypten/verify/runner.py](crypten/verify/runner.py)). The targets are
   untrusted repositories, so crypTen never runs their code in its own process.
3. **Fix.** `remediate` edits only the reported line, writes a `.bak` backup,
   and runs verification again to confirm the weakness is gone. For example, it
   replaces MD5 with Argon2, `random` with `secrets`, and `verify=False` with
   real verification.

Detected secrets are redacted before they reach the database, the dashboard, or
an exported report.

## Quick start

You need Python 3.10+. Node 18+ is needed only for the dashboard.

```bash
git clone https://github.com/AnupNerurkar/crypten.git
cd crypten
python -m venv .venv
.venv/Scripts/python -m pip install -r backend/requirements.txt   # Windows
# .venv/bin/python -m pip install -r backend/requirements.txt     # macOS / Linux
python -m crypten demo
```

`demo` scans the bundled vulnerable fixture and runs a proof of concept against
every finding. It then scans the hardened fixture to show the difference.

## CLI

```bash
python -m crypten scan <target> [--json r.json --html r.html --csv r.csv] [--no-external] [--all]
python -m crypten verify <target> [--cwe CWE-347]
python -m crypten remediate <target> --cwe CWE-347 [--apply]
```

`<target>` is a local folder or a public `https://` repository link:

```bash
python -m crypten scan https://github.com/miguelgrinberg/microblog
```

Repository links are cloned into `lab/<host>/<owner>/<repo>`, and everything
runs against that local copy, never against a hosted project. Later scans of the
same link reuse the clone, so a copy you have patched is rescanned in its patched
state. Pass `--refresh` to clone it again. Only `https://` links are accepted.
Git's `ssh`, `file` and `ext::` transports are refused, because `ext::` runs a
command chosen by the link.

`--no-external` skips Bandit, pip-audit and Semgrep for a fast, offline scan.
`--all` includes findings that fall outside the credential scope.

## Dashboard

The dashboard is a FastAPI backend with a React frontend. It keeps scan history
in SQLite.

```bash
.venv/Scripts/python -m uvicorn backend.app:app --port 8000     # terminal 1
cd frontend && npm install && npm run dev                       # terminal 2
```

Open http://localhost:5173 and pick a target: a bundled fixture or a repository
link. Run a scan, then click a finding to run its proof of concept and review the
proposed patch. On Windows, `scripts/run_all.ps1` starts both servers.

## Custom Semgrep rules

[crypten/rules/crypten-credentials.yml](crypten/rules/crypten-credentials.yml)
holds five rules for the credential patterns in scope. They run offline and need
no Semgrep account, so you can add them to any project's CI:

```bash
semgrep --config crypten/rules/crypten-credentials.yml <path>
```

## Tests

```bash
.venv/Scripts/python -m pytest
```

The suite covers detection, the sandboxed proofs of concept, the
remediate-then-reverify loop, and repository-link handling.

## Layout

```
crypten/              the engine (importable, no web dependency)
  scanners/           ast_rules, secrets_scan, external (bandit + pip-audit), semgrep_scan
  verify/             runner (sandboxed probes), service (spawns runner / inspects)
  rules/              custom Semgrep ruleset
backend/              FastAPI app + SQLite history over the engine
frontend/             React (Vite) dashboard
fixtures/             vulnerable_app and secure_app: the before/after lab targets
tests/                pytest suite
scripts/              launchers for the backend and dashboard
```

## About the fixtures

`fixtures/vulnerable_app` is the **Campus Club Portal**, a deliberately insecure
club portal. It contains each in-scope weakness exactly once (see its
[README](fixtures/vulnerable_app/README.md)). `fixtures/secure_app` is the same
app with every weakness fixed.

The secrets in `vulnerable_app/config.py` are fake, and the hostnames do not
resolve. The three accounts use passwords from public wordlists, and the stored
digests are real MD5 hashes of those passwords. That way the cracking proof of
concept recovers something real without exposing anyone.

## Scope and responsible use

crypTen is for auditing code you own or are authorised to test. It only works
on local copies and never scans a live deployment. Dependency advisories
(CWE-1395) are reported separately from code weaknesses because they depend on
the date of the advisory database, not on the code.
