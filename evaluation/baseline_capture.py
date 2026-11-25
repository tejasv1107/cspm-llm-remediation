"""Daily baseline capture (AWS Lambda): log finding timestamps + WorkflowStatus to CSV on S3.

Run this *before* the remediation system goes live to build the "before" dataset for the
MTTR comparison. Each invocation writes one snapshot::

    s3://$BASELINE_S3_BUCKET/$BASELINE_S3_PREFIX/dt=YYYY-MM-DD/findings.csv

Snapshots only contain findings updated in the lookback window, so together they form an
event log: ``mttr_analyser`` de-duplicates by ``finding_id`` and takes the earliest
snapshot in which a finding appears as RESOLVED.

Schedule with EventBridge (``rate(1 day)``). Packaging: deploy this file together with the
``ingestion/`` package (``handler = evaluation.baseline_capture.lambda_handler``).
Finding and account IDs are hashed before they leave the Lambda.

Limitation: ASFF has no dedicated "resolved at" field, so ``updated_at`` on a RESOLVED
finding is used as the resolution time.
"""

from __future__ import annotations

import csv
import io
import logging
import os
from datetime import datetime, timezone
from typing import Any, Iterable

import boto3

from ingestion.anonymiser import anonymise_record
from ingestion.finding_normaliser import load_account_tier_map, normalise_finding
from ingestion.schema import FindingRecord
from ingestion.security_hub_poller import DEFAULT_FILTERS, account_filter, poll_regions

logger = logging.getLogger()
logger.setLevel(logging.INFO)

CSV_FIELDS = [
    "finding_id",
    "account_id",
    "severity",
    "control_id",
    "resource_type",
    "account_tier",
    "created_at",
    "updated_at",
    "workflow_status",
    "captured_at",
]


def build_filters(lookback_days: int, account_ids: list[str]) -> dict[str, Any]:
    """Findings updated in the last ``lookback_days`` days (any workflow status), optionally per account."""
    filters: dict[str, Any] = {"UpdatedAt": [{"DateRange": {"Value": lookback_days, "Unit": "DAYS"}}]}
    if account_ids:
        filters.update(account_filter(account_ids))
    return filters


def record_to_row(record: FindingRecord, captured_at: datetime) -> dict[str, str]:
    """One CSV row from an *already anonymised* record."""
    return {
        "finding_id": record.finding_id,
        "account_id": record.account_id,
        "severity": record.severity.value,
        "control_id": record.control_id,
        "resource_type": record.resource_type,
        "account_tier": record.account_tier.value,
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "workflow_status": record.workflow_status.value,
        "captured_at": captured_at.isoformat(),
    }


def findings_to_csv(asff_findings: Iterable[dict[str, Any]], captured_at: datetime) -> tuple[str, int]:
    """Normalise + anonymise ASFF findings and render them as CSV text. Returns (csv, row_count)."""
    tier_map = load_account_tier_map()
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS)
    writer.writeheader()
    count = 0
    for asff in asff_findings:
        try:
            record = anonymise_record(normalise_finding(asff, tier_map))
        except (KeyError, ValueError):
            logger.warning("Skipping malformed finding %s", asff.get("Id", "<no id>"))
            continue
        writer.writerow(record_to_row(record, captured_at))
        count += 1
    return buffer.getvalue(), count


def s3_key(prefix: str, when: datetime) -> str:
    return f"{prefix.strip('/')}/dt={when:%Y-%m-%d}/findings.csv"


def lambda_handler(event: dict[str, Any] | None, context: Any = None) -> dict[str, Any]:
    """Lambda entry point.

    Optional event keys: ``lookback_days`` (default ``$BASELINE_LOOKBACK_DAYS`` or 2; use 90 for the
    first run to backfill Security Hub's retention window).
    """
    event = event or {}
    bucket = os.environ["BASELINE_S3_BUCKET"]
    prefix = os.getenv("BASELINE_S3_PREFIX", "baseline")
    lookback = int(event.get("lookback_days", os.getenv("BASELINE_LOOKBACK_DAYS", "2")))
    regions = [r for r in os.getenv("SECURITY_HUB_REGIONS", os.getenv("AWS_REGION", "ap-south-1")).split(",") if r]
    accounts = [a for a in os.getenv("CLIENT_ACCOUNT_IDS", "").split(",") if a]

    now = datetime.now(timezone.utc)
    findings = poll_regions(regions, build_filters(lookback, accounts))
    body, rows = findings_to_csv(findings, now)

    key = s3_key(prefix, now)
    boto3.client("s3").put_object(
        Bucket=bucket,
        Key=key,
        Body=body.encode("utf-8"),
        ContentType="text/csv",
        ServerSideEncryption="AES256",
    )
    logger.info("Wrote %d findings to s3://%s/%s", rows, bucket, key)
    return {"statusCode": 200, "rows": rows, "bucket": bucket, "key": key}


# Re-exported so callers can import the default filters used elsewhere in the project.
__all__ = ["lambda_handler", "findings_to_csv", "build_filters", "s3_key", "CSV_FIELDS", "DEFAULT_FILTERS"]
