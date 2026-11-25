"""Unified internal finding schema.

Every downstream component (classifier, RAG pipeline, approval workflow,
evaluation) consumes :class:`FindingRecord`, never raw ASFF JSON. See
``docs/finding_schema.md`` for field-level definitions.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """ASFF ``Severity.Label`` values, ordered lowest to highest."""

    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Numeric rank 0 (INFORMATIONAL) .. 4 (CRITICAL)."""
        return _SEVERITY_ORDER.index(self)


_SEVERITY_ORDER = [
    Severity.INFORMATIONAL,
    Severity.LOW,
    Severity.MEDIUM,
    Severity.HIGH,
    Severity.CRITICAL,
]


class AccountTier(str, Enum):
    """Business criticality of the account a finding belongs to."""

    PROD = "prod"
    NON_PROD = "non-prod"


class WorkflowStatus(str, Enum):
    """ASFF ``Workflow.Status`` values."""

    NEW = "NEW"
    NOTIFIED = "NOTIFIED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


def _ensure_utc(value: datetime) -> datetime:
    """Return ``value`` as a timezone-aware UTC datetime."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


@dataclass
class FindingRecord:
    """A single Security Hub finding in the project's unified schema."""

    finding_id: str
    account_id: str
    severity: Severity
    title: str
    resource_type: str
    resource_arn: str
    region: str
    created_at: datetime
    updated_at: datetime
    workflow_status: WorkflowStatus = WorkflowStatus.NEW
    account_tier: AccountTier = AccountTier.NON_PROD
    is_internet_exposed: bool = False
    recurrence_count: int = 1
    source_product: str = "Security Hub"
    recommendation_text: str = ""
    # Extras beyond the core schema: the Security Hub control (e.g. "S3.8") drives
    # module retrieval, and client_id namespaces every downstream artefact per tenant.
    control_id: str = ""
    client_id: str = ""

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity)
        self.workflow_status = WorkflowStatus(self.workflow_status)
        self.account_tier = AccountTier(self.account_tier)
        self.created_at = _ensure_utc(self.created_at)
        self.updated_at = _ensure_utc(self.updated_at)
        if self.recurrence_count < 1:
            raise ValueError("recurrence_count must be >= 1")
        if not self.client_id:
            self.client_id = self.account_id

    # ------------------------------------------------------------------ helpers
    def age_days(self, now: datetime | None = None) -> float:
        """Days between ``created_at`` and ``now`` (default: current UTC time)."""
        now = _ensure_utc(now or datetime.now(timezone.utc))
        return max((now - self.created_at).total_seconds() / 86400.0, 0.0)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable dict (enums as values, datetimes as ISO-8601)."""
        out: dict[str, Any] = {}
        for f in dataclasses.fields(self):
            value = getattr(self, f.name)
            if isinstance(value, Enum):
                value = value.value
            elif isinstance(value, datetime):
                value = value.isoformat()
            out[f.name] = value
        return out

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FindingRecord":
        """Inverse of :meth:`to_dict`; ignores unknown keys."""
        names = {f.name for f in dataclasses.fields(cls)}
        kwargs = {k: v for k, v in data.items() if k in names}
        for key in ("created_at", "updated_at"):
            if isinstance(kwargs.get(key), str):
                kwargs[key] = datetime.fromisoformat(kwargs[key].replace("Z", "+00:00"))
        return cls(**kwargs)


if __name__ == "__main__":  # pragma: no cover - quick manual check
    now = datetime.now(timezone.utc)
    demo = FindingRecord(
        finding_id="demo-1",
        account_id="111111111111",
        severity=Severity.HIGH,
        title="S3 bucket should block public access",
        resource_type="AwsS3Bucket",
        resource_arn="arn:aws:s3:::demo-bucket",
        region="ap-south-1",
        created_at=now,
        updated_at=now,
    )
    print(demo.to_json())
