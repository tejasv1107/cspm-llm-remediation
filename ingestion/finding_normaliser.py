"""Map raw ASFF (AWS Security Finding Format) JSON to :class:`FindingRecord`."""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from ingestion.schema import AccountTier, FindingRecord, Severity, WorkflowStatus

_PROD_TAG_VALUES = {"prod", "production", "prd", "live"}
_ENV_TAG_KEYS = ("environment", "env", "stage")

# Security Hub controls that report an *actual* internet-facing exposure. Posture controls
# such as S3.1 / S3.8 (Block Public Access not enabled) deliberately are not listed: they
# say a bucket *could* be made public, not that it is.
_EXPOSED_CONTROL_IDS = {"S3.2", "S3.3", "EC2.1", "EC2.13", "EC2.18", "EC2.19", "EC2.53",
                        "RDS.2", "SSM.4", "Lambda.1", "ES.2", "Opensearch.2"}
# Note: bare "public access" is deliberately absent - "should block public access" names the
# remedy, not an exposure.
_EXPOSED_TEXT = re.compile(
    r"0\.0\.0\.0/0|::/0|publicly (accessible|readable|writable|shared)|"
    r"internet[- ](facing|exposed)|open to the (world|internet)|"
    r"unrestricted (access|ingress|incoming)",
    re.IGNORECASE,
)


def parse_asff_time(value: str | None) -> datetime:
    """Parse an ASFF ISO-8601 timestamp (``...Z`` or with offset) to aware UTC."""
    if not value:
        return datetime.now(timezone.utc)
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def load_account_tier_map(raw: str | None = None) -> dict[str, AccountTier]:
    """Load ``{"account_id": "prod" | "non-prod"}`` from ``ACCOUNT_TIER_MAP`` (JSON)."""
    raw = raw if raw is not None else os.getenv("ACCOUNT_TIER_MAP", "{}")
    try:
        data = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return {str(k): AccountTier(v) for k, v in data.items()}


def extract_control_id(asff: Mapping[str, Any]) -> str:
    """Best-effort Security Hub control ID, e.g. ``S3.8`` or ``CIS.2.1.1``."""
    compliance = asff.get("Compliance", {}) or {}
    if compliance.get("SecurityControlId"):
        return compliance["SecurityControlId"]
    fields = asff.get("ProductFields", {}) or {}
    for key in ("ControlId", "RuleId"):
        if fields.get(key):
            return str(fields[key])
    arn = fields.get("StandardsControlArn", "")
    return arn.rsplit("/", 1)[-1] if arn else ""


def infer_account_tier(
    asff: Mapping[str, Any], tier_map: Mapping[str, AccountTier] | None = None
) -> AccountTier:
    """Tier from the explicit account map first, then the resource's Environment tag."""
    account_id = asff.get("AwsAccountId", "")
    if tier_map and account_id in tier_map:
        return tier_map[account_id]
    tags = (asff.get("Resources") or [{}])[0].get("Tags", {}) or {}
    for key, value in tags.items():
        if key.lower() in _ENV_TAG_KEYS and str(value).lower() in _PROD_TAG_VALUES:
            return AccountTier.PROD
    return AccountTier.NON_PROD


def infer_internet_exposed(asff: Mapping[str, Any], control_id: str = "") -> bool:
    """Heuristic: known exposure control, or exposure wording in title/description."""
    if control_id in _EXPOSED_CONTROL_IDS:
        return True
    text = f"{asff.get('Title', '')} {asff.get('Description', '')}"
    return bool(_EXPOSED_TEXT.search(text))


def normalise_finding(
    asff: Mapping[str, Any],
    tier_map: Mapping[str, AccountTier] | None = None,
    client_id: str | None = None,
) -> FindingRecord:
    """Convert one ASFF finding into a :class:`FindingRecord`.

    Raises ``KeyError`` if a mandatory ASFF field (``Id``, ``AwsAccountId``) is missing.
    """
    resources = asff.get("Resources") or [{}]
    primary = resources[0]
    control_id = extract_control_id(asff)
    severity_label = (asff.get("Severity", {}) or {}).get("Label", "INFORMATIONAL")
    status = (asff.get("Workflow", {}) or {}).get("Status", "NEW")
    recommendation = ((asff.get("Remediation", {}) or {}).get("Recommendation", {}) or {}).get("Text", "")
    account_id = asff["AwsAccountId"]

    return FindingRecord(
        finding_id=asff["Id"],
        account_id=account_id,
        severity=Severity(severity_label),
        title=asff.get("Title", ""),
        resource_type=primary.get("Type", "Other"),
        resource_arn=primary.get("Id", ""),
        region=primary.get("Region") or asff.get("Region", ""),
        created_at=parse_asff_time(asff.get("CreatedAt")),
        updated_at=parse_asff_time(asff.get("UpdatedAt")),
        workflow_status=WorkflowStatus(status),
        account_tier=infer_account_tier(asff, tier_map),
        is_internet_exposed=infer_internet_exposed(asff, control_id),
        recurrence_count=1,
        source_product=asff.get("ProductName") or asff.get("ProductArn", "").rsplit("/", 1)[-1] or "Security Hub",
        recommendation_text=recommendation,
        control_id=control_id,
        client_id=client_id or account_id,
    )


def annotate_recurrence(records: Iterable[FindingRecord]) -> list[FindingRecord]:
    """Set ``recurrence_count`` = number of findings sharing (account, control-or-title).

    A control that fails on many resources in one account signals a systemic issue.
    """
    records = list(records)
    keys = [(r.account_id, r.control_id or r.title) for r in records]
    counts = Counter(keys)
    return [replace(r, recurrence_count=counts[k]) for r, k in zip(records, keys)]


def normalise_many(
    findings: Iterable[Mapping[str, Any]],
    tier_map: Mapping[str, AccountTier] | None = None,
    skip_invalid: bool = True,
) -> list[FindingRecord]:
    """Normalise a batch and compute recurrence; malformed findings are skipped by default."""
    out: list[FindingRecord] = []
    for asff in findings:
        try:
            out.append(normalise_finding(asff, tier_map))
        except (KeyError, ValueError):
            if not skip_invalid:
                raise
    return annotate_recurrence(out)
