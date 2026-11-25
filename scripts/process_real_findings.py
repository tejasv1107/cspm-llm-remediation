"""Normalise -> anonymise -> rule-label the real Security Hub export.

Takes the newest data/raw/findings_*.jsonl (from ingestion.security_hub_poller),
runs it through the same normalise_many / anonymise_record / label_records used
for synthetic data, and writes data/labelled/labelled_findings_real.csv in the
exact same shape as the existing synthetic labelled_findings.csv, so it's a
drop-in replacement for classifier/train.py's --data argument.

Run from the project root: python -m scripts.process_real_findings
"""
from __future__ import annotations

import glob
import json
import logging
from collections import Counter
from pathlib import Path

from classifier.labeller import label_records
from ingestion.anonymiser import anonymise_record
from ingestion.finding_normaliser import normalise_many

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def latest_raw_file() -> Path:
    files = [f for f in glob.glob("data/raw/findings_*.jsonl") if "_demo_" not in f]
    if not files:
        raise FileNotFoundError("No real (non-demo) data/raw/findings_*.jsonl found -- run the poller first")
    return Path(max(files, key=lambda f: Path(f).stat().st_mtime))


def main() -> None:
    raw_path = latest_raw_file()
    logger.info("Reading %s", raw_path)
    with raw_path.open(encoding="utf-8") as fh:
        asff_findings = [json.loads(line) for line in fh if line.strip()]
    logger.info("Loaded %d raw ASFF findings", len(asff_findings))

    records = normalise_many(asff_findings, skip_invalid=True)
    logger.info("Normalised %d / %d (some skipped for missing mandatory fields)", len(records), len(asff_findings))

    anonymised = [anonymise_record(r) for r in records]

    frame = label_records(anonymised)
    out_path = Path("data/labelled/labelled_findings_real.csv")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(out_path)

    logger.info("Wrote %d labelled real findings to %s", len(frame), out_path)
    logger.info("Urgency distribution:\n%s", frame["urgency"].value_counts().to_string())

    sev_counts = Counter(r.severity.value for r in records)
    tier_counts = Counter(r.account_tier.value for r in records)
    exposed_counts = Counter(r.is_internet_exposed for r in records)
    logger.info("Severity distribution: %s", dict(sev_counts))
    logger.info("Account tier distribution: %s", dict(tier_counts))
    logger.info("Internet-exposed distribution: %s", dict(exposed_counts))

    stats_path = Path("docs/evaluation/real_data_distribution.json")
    stats_path.parent.mkdir(parents=True, exist_ok=True)
    stats_path.write_text(json.dumps({
        "source_file": str(raw_path),
        "n_raw": len(asff_findings),
        "n_normalised": len(records),
        "n_labelled": len(frame),
        "severity_distribution": dict(sev_counts),
        "account_tier_distribution": dict(tier_counts),
        "internet_exposed_distribution": {str(k): v for k, v in exposed_counts.items()},
        "urgency_distribution": frame["urgency"].value_counts().to_dict(),
    }, indent=2))
    logger.info("Stats written to %s", stats_path)


if __name__ == "__main__":
    main()
