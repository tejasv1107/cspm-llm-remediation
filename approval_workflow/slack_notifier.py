"""Post Slack messages (incoming webhook) when a remediation PR is opened and approved."""

from __future__ import annotations

import logging
import os
from typing import Any

import requests

from ingestion.schema import FindingRecord

logger = logging.getLogger(__name__)

_URGENCY_EMOJI = {
    "REMEDIATE_NOW": ":rotating_light:",
    "REMEDIATE_7D": ":warning:",
    "MONITOR": ":eyes:",
    "SUPPRESS": ":mute:",
}


class SlackNotifier:
    """Sends Block Kit messages. With no webhook configured it logs and returns False."""

    def __init__(self, webhook_url: str | None = None, session: requests.Session | None = None, timeout: float = 10.0) -> None:
        self.webhook_url = webhook_url if webhook_url is not None else os.getenv("SLACK_WEBHOOK_URL", "")
        self.session = session or requests.Session()
        self.timeout = timeout

    def _post(self, payload: dict[str, Any]) -> bool:
        if not self.webhook_url:
            logger.info("SLACK_WEBHOOK_URL not set; skipping notification: %s", payload.get("text"))
            return False
        try:
            response = self.session.post(self.webhook_url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            return True
        except requests.RequestException:
            logger.exception("Slack notification failed")  # never let Slack break the pipeline
            return False

    @staticmethod
    def build_pr_created_message(finding: FindingRecord, pr_number: int, pr_url: str, urgency: str) -> dict[str, Any]:
        emoji = _URGENCY_EMOJI.get(urgency, ":memo:")
        return {
            "text": f"Remediation PR #{pr_number} opened for {finding.control_id or finding.title}",
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} Remediation PR opened"}},
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Finding*\n{finding.title}"},
                        {"type": "mrkdwn", "text": f"*Urgency*\n{urgency}"},
                        {"type": "mrkdwn", "text": f"*Severity*\n{finding.severity.value}"},
                        {"type": "mrkdwn", "text": f"*Client*\n{finding.client_id}"},
                    ],
                },
                {
                    "type": "actions",
                    "elements": [
                        {"type": "button", "text": {"type": "plain_text", "text": f"Review PR #{pr_number}"}, "url": pr_url}
                    ],
                },
            ],
        }

    def notify_pr_created(self, finding: FindingRecord, pr_number: int, pr_url: str, urgency: str) -> bool:
        """Announce a new remediation PR."""
        return self._post(self.build_pr_created_message(finding, pr_number, pr_url, urgency))

    def notify_pr_approved(self, pr_number: int, pr_url: str, approver: str, title: str = "") -> bool:
        """Announce that a reviewer approved a PR."""
        return self._post(
            {
                "text": f"PR #{pr_number} approved by {approver}",
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f":white_check_mark: *PR #{pr_number}* approved by *{approver}*"
                            + (f"\n{title}" if title else "")
                            + f"\n<{pr_url}|Open pull request>",
                        },
                    }
                ],
            }
        )
