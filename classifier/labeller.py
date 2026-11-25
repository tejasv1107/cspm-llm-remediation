"""Rule-based auto-labeller: REMEDIATE_NOW / REMEDIATE_7D / MONITOR / SUPPRESS.

The decision matrix is documented in ``docs/labelling_methodology.md``. Labels are
*silver* labels - deterministic functions of severity, account tier, exposure,
recurrence and age - used to bootstrap the classifier when no analyst labels exist.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterable

import pandas as pd

from classifier.feature_engineering import build_feature_frame
from ingestion.schema import AccountTier, FindingRecord, Severity, WorkflowStatus


class Urgency(str, Enum):
    """Remediation urgency classes, ordered least to most urgent."""

    SUPPRESS = "SUPPRESS"
    MONITOR = "MONITOR"
    REMEDIATE_7D = "REMEDIATE_7D"
    REMEDIATE_NOW = "REMEDIATE_NOW"

    @property
    def rank(self) -> int:
        return URGENCY_ORDER.index(self)


URGENCY_ORDER: list[Urgency] = [
    Urgency.SUPPRESS,
    Urgency.MONITOR,
    Urgency.REMEDIATE_7D,
    Urgency.REMEDIATE_NOW,
]

# Escalation thresholds.
RECURRENCE_ESCALATION = 5   # same control failing this many times in one account
STALE_PROD_DAYS = 90        # prod findings left open this long get bumped

# Base matrix keyed by (severity, is_prod, is_internet_exposed).
_N, _7, _M, _S = (Urgency.REMEDIATE_NOW, Urgency.REMEDIATE_7D, Urgency.MONITOR, Urgency.SUPPRESS)
BASE_MATRIX: dict[tuple[Severity, bool, bool], Urgency] = {
    # CRITICAL
    (Severity.CRITICAL, True, True): _N,
    (Severity.CRITICAL, True, False): _N,
    (Severity.CRITICAL, False, True): _N,
    (Severity.CRITICAL, False, False): _7,
    # HIGH
    (Severity.HIGH, True, True): _N,
    (Severity.HIGH, True, False): _7,
    (Severity.HIGH, False, True): _7,
    (Severity.HIGH, False, False): _M,
    # MEDIUM
    (Severity.MEDIUM, True, True): _7,
    (Severity.MEDIUM, True, False): _M,
    (Severity.MEDIUM, False, True): _M,
    (Severity.MEDIUM, False, False): _M,
    # LOW
    (Severity.LOW, True, True): _M,
    (Severity.LOW, True, False): _M,
    (Severity.LOW, False, True): _M,
    (Severity.LOW, False, False): _S,
    # INFORMATIONAL
    (Severity.INFORMATIONAL, True, True): _S,
    (Severity.INFORMATIONAL, True, False): _S,
    (Severity.INFORMATIONAL, False, True): _S,
    (Severity.INFORMATIONAL, False, False): _S,
}


@dataclass(frozen=True)
class LabelDecision:
    """A label plus the audit trail explaining it."""

    label: Urgency
    rule_id: str
    rationale: str


def _escalate(level: Urgency) -> Urgency:
    return URGENCY_ORDER[min(level.rank + 1, len(URGENCY_ORDER) - 1)]


def label_finding(record: FindingRecord, now: datetime | None = None) -> LabelDecision:
    """Apply the decision matrix to one finding."""
    # R0: findings already closed out need no action.
    if record.workflow_status in (WorkflowStatus.SUPPRESSED, WorkflowStatus.RESOLVED):
        return LabelDecision(
            Urgency.SUPPRESS, "R0", f"workflow status is {record.workflow_status.value}"
        )

    is_prod = record.account_tier is AccountTier.PROD
    exposed = record.is_internet_exposed
    level = BASE_MATRIX[(record.severity, is_prod, exposed)]
    rule_id = f"M-{record.severity.value[:4]}-{'P' if is_prod else 'N'}-{'X' if exposed else 'I'}"
    reasons = [
        f"severity={record.severity.value}",
        f"tier={record.account_tier.value}",
        f"internet_exposed={exposed}",
    ]

    # Informational findings are never escalated: they carry no risk to amplify.
    if record.severity is not Severity.INFORMATIONAL:
        if record.recurrence_count >= RECURRENCE_ESCALATION:
            level = _escalate(level)
            rule_id += "+E1"
            reasons.append(f"recurrence {record.recurrence_count} >= {RECURRENCE_ESCALATION}")
        elif is_prod and record.age_days(now) > STALE_PROD_DAYS:
            level = _escalate(level)
            rule_id += "+E2"
            reasons.append(f"prod finding open > {STALE_PROD_DAYS} days")

    return LabelDecision(level, rule_id, "; ".join(reasons))


def label_records(records: Iterable[FindingRecord], now: datetime | None = None) -> pd.DataFrame:
    """Feature matrix plus ``urgency`` and ``rule_id`` columns, ready for training."""
    records = list(records)
    frame = build_feature_frame(records, now)
    decisions = [label_finding(r, now) for r in records]
    frame["urgency"] = [d.label.value for d in decisions]
    frame["rule_id"] = [d.rule_id for d in decisions]
    return frame


def main() -> None:  # pragma: no cover - thin CLI
    parser = argparse.ArgumentParser(description="Auto-label anonymised findings")
    parser.add_argument("--input", default="data/anonymised/findings.jsonl",
                        help="JSON Lines file of FindingRecord.to_dict() rows")
    parser.add_argument("--output", default="data/labelled/labelled_findings.csv")
    args = parser.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        records = [FindingRecord.from_dict(json.loads(line)) for line in fh if line.strip()]
    frame = label_records(records)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(args.output)
    print(f"Wrote {len(frame)} labelled findings to {args.output}")
    print(frame["urgency"].value_counts().to_string())


if __name__ == "__main__":  # pragma: no cover
    main()
