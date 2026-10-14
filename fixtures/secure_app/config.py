"""Configuration for the Campus Club Portal (hardened).

LAB FIXTURE - secrets are read from the environment and the process fails to
start if the signing key is absent, so nothing sensitive lives in source.
"""

import os

JWT_SECRET = os.getenv("CLUBPORTAL_JWT_SECRET")
if not JWT_SECRET:
    raise RuntimeError("CLUBPORTAL_JWT_SECRET must be set")

SECRET_KEY = os.getenv("CLUBPORTAL_SECRET_KEY", "")
DATABASE_URL = os.getenv("CLUBPORTAL_DATABASE_URL", "")
SMTP_PASSWORD = os.getenv("CLUBPORTAL_SMTP_PASSWORD", "")

SESSION_LIFETIME_MINUTES = 60
