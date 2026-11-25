"""Merge the real Security Hub export into the dashboard's live data source.

``dashboard/app.py`` reads ``data/anonymised/findings.jsonl`` (one FindingRecord per line).
That file has only ever held the 523-finding synthetic demo dataset -- the real 12,647-finding
export processed in ``scripts/process_real_findings.py`` went to ``data/labelled/`` instead,
in a different (flattened, feature-engineered) CSV shape that the dashboard never reads. This
script replaces the synthetic rows for the one client that has a real export (account
111111111111) with the real, anonymised FindingRecords, and leaves the other synthetic clients
untouched so the multi-tenant demo view still has four populated accounts.

Run from the project root: python -m scripts.merge_real_into_anonymised
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

from ingestion.anonymiser import anonymise_record, hash_account_id
from ingestion.finding_normaliser import normalise_many
from ingestion.schema import FindingRecord
from scripts.process_real_findings import latest_raw_file

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

FINDINGS_PATH = Path("data/anonymised/findings.jsonl")
REAL_ACCOUNT_ID = "111111111111"


def main() -> None:
    real_client_id = hash_account_id(REAL_ACCOUNT_ID)
    logger.info("Real account %s -> client_id %s", REAL_ACCOUNT_ID, real_client_id)

    existing_rows: list[dict] = []
    if FINDINGS_PATH.exists():
        with FINDINGS_PATH.open(encoding="utf-8") as fh:
            existing_rows = [json.loads(line) for line in fh if line.strip()]
    kept = [r for r in existing_rows if r.get("client_id") != real_client_id]
    logger.info("Kept %d synthetic rows for other clients (dropped %d old synthetic rows for the real account)",
                len(kept), len(existing_rows) - len(kept))

    raw_path = latest_raw_file()
    logger.info("Reading real export %s", raw_path)
    with raw_path.open(encoding="utf-8") as fh:
        asff_findings = [json.loads(line) for line in fh if line.strip()]

    records = normalise_many(asff_findings, skip_invalid=True)
    logger.info("Normalised %d / %d", len(records), len(asff_findings))
    anonymised = [anonymise_record(r, anonymise_resource=False) for r in records]
    assert all(r.client_id == real_client_id for r in anonymised), "unexpected client_id after anonymising"

    real_rows = [r.to_dict() for r in anonymised]

    # Sanity check: round-trip one record through from_dict before writing thousands of them.
    FindingRecord.from_dict(real_rows[0])

    merged = kept + real_rows
    with FINDINGS_PATH.open("w", encoding="utf-8") as fh:
        for row in merged:
            fh.write(json.dumps(row) + "\n")

    logger.info("Wrote %d rows to %s (%d synthetic + %d real)", len(merged), FINDINGS_PATH, len(kept), len(real_rows))


if __name__ == "__main__":
    main()
