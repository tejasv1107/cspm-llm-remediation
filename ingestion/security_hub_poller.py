"""Poll AWS Security Hub for findings (``GetFindings``), fully paginated."""

from __future__ import annotations

import argparse
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

import boto3
from botocore.config import Config

logger = logging.getLogger(__name__)

_BOTO_CONFIG = Config(retries={"max_attempts": 8, "mode": "adaptive"})

# Only findings that still need attention, by default. ProductName is pinned to "Security Hub"
# (its own Foundational Security Best Practices / CIS checks) rather than every integrated
# product it aggregates: in a real account the vast majority of findings are Inspector
# (software/CVE vulnerabilities -- needs patching, not a Terraform resource-config change) and
# GuardDuty (behavioural threat detections), neither of which any of this project's reference
# Terraform modules can remediate. Only Security Hub's own config-check findings carry the
# "S3.8"-style ControlId this project's classifier and module retriever are keyed on.
DEFAULT_FILTERS: dict[str, list[dict[str, str]]] = {
    "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
    "WorkflowStatus": [
        {"Value": "NEW", "Comparison": "EQUALS"},
        {"Value": "NOTIFIED", "Comparison": "EQUALS"},
    ],
    "ProductName": [{"Value": "Security Hub", "Comparison": "EQUALS"}],
}


def build_client(region: str | None = None, session: boto3.session.Session | None = None):
    """Create a Security Hub client with adaptive retries."""
    session = session or boto3.session.Session()
    return session.client(
        "securityhub",
        region_name=region or os.getenv("AWS_REGION", "ap-south-1"),
        config=_BOTO_CONFIG,
    )


def account_filter(account_ids: list[str]) -> dict[str, list[dict[str, str]]]:
    """Build an ASFF filter restricting results to the given AWS account IDs."""
    return {"AwsAccountId": [{"Value": a, "Comparison": "EQUALS"} for a in account_ids]}


def poll_findings(
    client: Any,
    filters: dict[str, Any] | None = None,
    page_size: int = 100,
    max_findings: int | None = None,
) -> Iterator[dict[str, Any]]:
    """Yield raw ASFF findings, following ``NextToken`` pagination.

    ``filters`` defaults to ACTIVE + NEW/NOTIFIED findings. ``page_size`` is capped at
    100 by the API. Stops early once ``max_findings`` have been yielded.
    """
    paginator = client.get_paginator("get_findings")
    pages = paginator.paginate(
        Filters=filters if filters is not None else DEFAULT_FILTERS,
        SortCriteria=[{"Field": "UpdatedAt", "SortOrder": "desc"}],
        PaginationConfig={"PageSize": min(page_size, 100)},
    )
    yielded = 0
    for page in pages:
        for finding in page.get("Findings", []):
            yield finding
            yielded += 1
            if max_findings is not None and yielded >= max_findings:
                return
    logger.info("Polled %d findings", yielded)


def poll_regions(
    regions: list[str],
    filters: dict[str, Any] | None = None,
    max_findings_per_region: int | None = None,
) -> Iterator[dict[str, Any]]:
    """Poll several regions in turn; a failing region is logged and skipped."""
    for region in regions:
        try:
            client = build_client(region)
            yield from poll_findings(client, filters, max_findings=max_findings_per_region)
        except Exception:  # noqa: BLE001 - one bad region must not abort the sweep
            logger.exception("Failed to poll Security Hub in %s", region)


def save_raw(findings: Iterator[dict[str, Any]], out_dir: str | Path = "data/raw") -> Path:
    """Write findings as JSON Lines to ``out_dir/findings_<UTC timestamp>.jsonl``."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / f"findings_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(json.dumps(finding, default=str) + "\n")
    return path


def main() -> None:  # pragma: no cover - thin CLI
    parser = argparse.ArgumentParser(description="Export Security Hub findings to data/raw")
    parser.add_argument("--regions", default=os.getenv("SECURITY_HUB_REGIONS", "ap-south-1"))
    parser.add_argument("--accounts", default=os.getenv("CLIENT_ACCOUNT_IDS", ""))
    parser.add_argument("--max-per-region", type=int, default=None)
    args = parser.parse_args()

    filters = dict(DEFAULT_FILTERS)
    accounts = [a.strip() for a in args.accounts.split(",") if a.strip()]
    if accounts:
        filters.update(account_filter(accounts))
    regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    print(save_raw(poll_regions(regions, filters, args.max_per_region)))


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    main()
