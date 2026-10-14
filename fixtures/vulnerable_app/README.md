# Campus Club Portal - vulnerable lab fixture

A deliberately insecure stand-in for the kind of small Python web app the
crypTen survey targets: a club portal with hand-written registration, login,
password reset and session tokens.

Every weakness in the project's scope is present exactly once:

| File | Weakness | CWE |
|---|---|---|
| `auth.py` | MD5 password digest, no salt | CWE-916, CWE-759 |
| `auth.py` | reset token from `random` seeded with the clock | CWE-330 |
| `auth.py` | JWT decoded with `verify_signature: False` | CWE-347 |
| `auth.py` | password written to the application log | CWE-532 |
| `config.py` | JWT secret, database URL and SMTP password in source | CWE-798 |
| `notifications.py` | `verify=False` on an outbound call carrying credentials | CWE-295 |
| `requirements.txt` | pinned versions with published advisories | CWE-1395 |

The three accounts use passwords that appear in public wordlists
(`sunshine`, `iloveyou`, `trustno1`) and the stored digests are real MD5 of
those passwords, so an offline cracking run against the table succeeds. This is
deliberate: the proof of concept has to recover something for the before/after
evidence to mean anything.

Nothing here reaches the network. `notifications.py` points at a hostname that
does not resolve, and the verification probes never call it.
