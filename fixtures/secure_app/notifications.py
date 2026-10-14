"""Outbound notifications for the Campus Club Portal (hardened)."""

import logging

import requests

from config import SMTP_PASSWORD

logger = logging.getLogger("club_portal.notifications")

WEBHOOK_URL = "https://hooks.clubportal.example/events"


def notify_signup(username: str) -> int:
    logger.debug("Sending welcome mail for %s", username)
    response = requests.post(
        WEBHOOK_URL,
        json={"event": "signup", "user": username},
        auth=("portal", SMTP_PASSWORD),
        verify=True,
        timeout=5,
    )
    return response.status_code
