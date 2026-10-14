"""Configuration for the Campus Club Portal.

LAB FIXTURE - DELIBERATELY INSECURE. Secrets are committed to source, which is
how they reach a public repository and stay in its history.
"""

JWT_SECRET = "clubportal2023"
SECRET_KEY = "dev-key-please-change-in-production-8f2a"
DATABASE_URL = "postgres://portal:Summer2023!@db.internal:5432/clubportal"
SMTP_PASSWORD = "mailserver-pass-9921"

SESSION_LIFETIME_MINUTES = 240
