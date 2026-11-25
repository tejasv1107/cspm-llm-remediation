"""Record what reviewers did with each PR (accepted / rejected / modified) in DynamoDB."""

from __future__ import annotations

import difflib
import hashlib
import os
from datetime import datetime, timezone
from decimal import Decimal
from enum import Enum
from typing import Any

import boto3


class Outcome(str, Enum):
    ACCEPTED = "accepted"   # merged exactly as generated
    MODIFIED = "modified"   # merged after the reviewer edited the generated code
    REJECTED = "rejected"   # closed without merging


def _normalise(hcl: str) -> str:
    return "\n".join(line.rstrip() for line in hcl.strip().splitlines())


def edit_similarity(generated: str, final: str) -> float:
    """Similarity in [0, 1] between generated and merged HCL (1.0 = identical)."""
    return difflib.SequenceMatcher(None, _normalise(generated), _normalise(final)).ratio()


def classify_outcome(merged: bool, generated_hcl: str, final_hcl: str | None = None) -> Outcome:
    """Closed-unmerged => rejected; merged unchanged => accepted; merged edited => modified."""
    if not merged:
        return Outcome.REJECTED
    if final_hcl is None or _normalise(final_hcl) == _normalise(generated_hcl):
        return Outcome.ACCEPTED
    return Outcome.MODIFIED


class FeedbackLogger:
    """Writes PR outcomes to a DynamoDB table keyed by (finding_id, logged_at)."""

    def __init__(self, table_name: str | None = None, dynamodb: Any | None = None) -> None:
        self.table_name = table_name or os.getenv("DYNAMODB_FEEDBACK_TABLE", "cspm-remediation-feedback")
        self.dynamodb = dynamodb or boto3.resource("dynamodb", region_name=os.getenv("AWS_REGION", "ap-south-1"))
        self.table = self.dynamodb.Table(self.table_name)

    def ensure_table(self) -> None:
        """Create the on-demand table if it does not exist (handy for dev/test)."""
        existing = {t.name for t in self.dynamodb.tables.all()}
        if self.table_name in existing:
            return
        self.dynamodb.create_table(
            TableName=self.table_name,
            KeySchema=[
                {"AttributeName": "finding_id", "KeyType": "HASH"},
                {"AttributeName": "logged_at", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "finding_id", "AttributeType": "S"},
                {"AttributeName": "logged_at", "AttributeType": "S"},
            ],
            BillingMode="PAY_PER_REQUEST",
        ).wait_until_exists()

    def log_outcome(
        self,
        finding_id: str,
        client_id: str,
        pr_number: int,
        outcome: Outcome,
        reviewer: str = "",
        generated_hcl: str = "",
        final_hcl: str | None = None,
        control_id: str = "",
        urgency: str = "",
    ) -> dict[str, Any]:
        """Persist one outcome row and return the stored item."""
        item: dict[str, Any] = {
            "finding_id": finding_id,
            "logged_at": datetime.now(timezone.utc).isoformat(),
            "client_id": client_id,
            "pr_number": pr_number,
            "outcome": outcome.value,
            "reviewer": reviewer,
            "control_id": control_id,
            "urgency": urgency,
            "generated_sha256": hashlib.sha256(generated_hcl.encode("utf-8")).hexdigest() if generated_hcl else "",
        }
        if final_hcl is not None and generated_hcl:
            # DynamoDB rejects Python floats; use Decimal.
            item["edit_similarity"] = Decimal(str(round(edit_similarity(generated_hcl, final_hcl), 4)))
        self.table.put_item(Item=item)
        return item

    def handle_pull_request_event(
        self, payload: dict[str, Any], finding_id: str, client_id: str, generated_hcl: str, final_hcl: str | None = None
    ) -> dict[str, Any] | None:
        """Log the outcome for a GitHub ``pull_request`` webhook payload with ``action == closed``."""
        if payload.get("action") != "closed":
            return None
        pr = payload["pull_request"]
        merged = bool(pr.get("merged"))
        return self.log_outcome(
            finding_id=finding_id,
            client_id=client_id,
            pr_number=int(pr["number"]),
            outcome=classify_outcome(merged, generated_hcl, final_hcl),
            reviewer=(pr.get("merged_by") or {}).get("login", ""),
            generated_hcl=generated_hcl,
            final_hcl=final_hcl,
        )
