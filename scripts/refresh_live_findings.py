"""Poll Security Hub -> normalise -> anonymise -> merge into the dashboard's live data source.

Meant to run on a schedule (cron, every 4 hours) so the dashboard reflects the real account's
current findings without a manual step. Idempotent: each run replaces the prior run's rows for
the real account's client_id, so repeated runs don't accumulate duplicates. The other synthetic
demo clients' rows (if any) are left untouched.

Run from the project root: python -m scripts.refresh_live_findings
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path

from ingestion.anonymiser import anonymise_record, hash_account_id
from ingestion.finding_normaliser import normalise_many
from ingestion.security_hub_poller import DEFAULT_FILTERS, account_filter, poll_regions, save_raw

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
logger = logging.getLogger(__name__)

FINDINGS_PATH = Path("data/anonymised/findings.jsonl")
REAL_ACCOUNT_ID = os.getenv("LIVE_DEMO_ACCOUNT_ID", "111111111111")
REGIONS = [r.strip() for r in os.getenv("SECURITY_HUB_REGIONS", "us-west-2").split(",") if r.strip()]


def main() -> None:
    logger.info("Polling Security Hub for account %s in %s", REAL_ACCOUNT_ID, REGIONS)
    filters = {**DEFAULT_FILTERS, **account_filter([REAL_ACCOUNT_ID])}

    raw_findings = list(poll_regions(REGIONS, filters))
    raw_path = save_raw(iter(raw_findings))
    logger.info("Polled %d raw findings -> %s", len(raw_findings), raw_path)

    records = normalise_many(raw_findings, skip_invalid=True)
    # Defensive, in case a filter change doesn't apply to an in-flight raw file: only Security
    # Hub's own config-check findings carry the ControlId this project is keyed on.
    records = [r for r in records if r.source_product == "Security Hub"]
    logger.info("Normalised %d infra-level (Security Hub product) findings", len(records))

    real_client_id = hash_account_id(REAL_ACCOUNT_ID)
    # anonymise_resource=False: this is the live demo account itself (explicit prior
    # authorisation), and the generated Terraform has to reference the finding's real
    # resource to actually be mergeable -- a hashed placeholder (e.g. "res-a1b2c3d4e5")
    # would make every PR cosmetic. account_id/client_id are still pseudonymised below.
    anonymised = [anonymise_record(r, anonymise_resource=False) for r in records]
    assert all(r.client_id == real_client_id for r in anonymised), "unexpected client_id after anonymising"
    real_rows = [r.to_dict() for r in anonymised]

    existing_rows: list[dict] = []
    if FINDINGS_PATH.exists():
        with FINDINGS_PATH.open(encoding="utf-8") as fh:
            existing_rows = [json.loads(line) for line in fh if line.strip()]
    kept = [r for r in existing_rows if r.get("client_id") != real_client_id]

    merged = kept + real_rows
    tmp_path = FINDINGS_PATH.with_suffix(".jsonl.tmp")
    with tmp_path.open("w", encoding="utf-8") as fh:
        for row in merged:
            fh.write(json.dumps(row) + "\n")
    tmp_path.replace(FINDINGS_PATH)  # atomic swap, dashboard never sees a half-written file

    logger.info(
        "Wrote %d rows to %s (%d synthetic/other-client + %d real, was %d real before this run)",
        len(merged), FINDINGS_PATH, len(kept), len(real_rows),
        sum(1 for r in existing_rows if r.get("client_id") == real_client_id),
    )


if __name__ == "__main__":
    main()
