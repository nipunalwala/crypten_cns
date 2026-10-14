# Campus Club Portal - hardened lab fixture

The secure counterpart to `../vulnerable_app`. Same portal, every weakness
fixed with the standard primitive:

- Argon2id password hashing with `verify` (CWE-916, CWE-759)
- `secrets.token_urlsafe(32)` reset tokens (CWE-330)
- JWT decode with a signing key and `algorithms=["HS256"]` (CWE-347)
- secrets read from the environment, failing closed (CWE-798)
- `verify=True` on outbound calls (CWE-295)
- logs carry the username only (CWE-532)
- current dependency versions (CWE-1395)

A crypTen scan of this tree reports zero in-scope findings. It is the "after"
side of the before/after evidence.
