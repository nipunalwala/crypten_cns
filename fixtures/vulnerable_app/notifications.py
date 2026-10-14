"""Outbound notifications for the Campus Club Portal.

LAB FIXTURE - DELIBERATELY INSECURE. Certificate verification is switched off,
so the API key in the header is readable by anyone on the network path.
"""

import logging

import requests

from config import SMTP_PASSWORD

logger = logging.getLogger("club_portal.notifications")

WEBHOOK_URL = "https://hooks.clubportal.example/events"


def notify_signup(username: str, reset_token: str) -> int:
    logger.debug("Sending welcome mail for %s with reset token %s", username, reset_token)
    response = requests.post(
        WEBHOOK_URL,
        json={"event": "signup", "user": username},
        auth=("portal", SMTP_PASSWORD),
        verify=False,
        timeout=5,
    )
    return response.status_code
