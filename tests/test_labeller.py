"""Unit tests for the rule-based labeller (classifier/labeller.py)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from classifier.feature_engineering import FEATURE_COLUMNS, extract_features
from classifier.labeller import BASE_MATRIX, URGENCY_ORDER, Urgency, label_finding, label_records
from ingestion.schema import AccountTier, FindingRecord, Severity, WorkflowStatus

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def make(severity="HIGH", prod=True, exposed=False, recurrence=1, age_days=1.0, status="NEW") -> FindingRecord:
    created = NOW - timedelta(days=age_days)
    return FindingRecord(
        finding_id="f", account_id="111111111111", severity=Severity(severity), title="t",
        resource_type="AwsS3Bucket", resource_arn="arn:aws:s3:::b", region="ap-south-1",
        created_at=created, updated_at=NOW, workflow_status=WorkflowStatus(status),
        account_tier=AccountTier.PROD if prod else AccountTier.NON_PROD,
        is_internet_exposed=exposed, recurrence_count=recurrence,
    )


def test_matrix_covers_every_severity_tier_exposure_combination():
    assert len(BASE_MATRIX) == len(Severity) * 2 * 2


@pytest.mark.parametrize(
    "severity, prod, exposed, expected",
    [
        ("CRITICAL", True, True, Urgency.REMEDIATE_NOW),
        ("CRITICAL", True, False, Urgency.REMEDIATE_NOW),
        ("CRITICAL", False, True, Urgency.REMEDIATE_NOW),
        ("CRITICAL", False, False, Urgency.REMEDIATE_7D),   # TS-02: same finding, non-prod => lower
        ("HIGH", True, True, Urgency.REMEDIATE_NOW),
        ("HIGH", True, False, Urgency.REMEDIATE_7D),
        ("HIGH", False, True, Urgency.REMEDIATE_7D),
        ("HIGH", False, False, Urgency.MONITOR),
        ("MEDIUM", True, True, Urgency.REMEDIATE_7D),
        ("MEDIUM", True, False, Urgency.MONITOR),
        ("MEDIUM", False, False, Urgency.MONITOR),
        ("LOW", True, False, Urgency.MONITOR),
        ("LOW", False, False, Urgency.SUPPRESS),
        ("INFORMATIONAL", True, True, Urgency.SUPPRESS),
    ],
)
def test_base_matrix(severity, prod, exposed, expected):
    assert label_finding(make(severity, prod, exposed), NOW).label is expected


@pytest.mark.parametrize("status", ["SUPPRESSED", "RESOLVED"])
def test_closed_findings_are_suppressed_whatever_their_severity(status):
    decision = label_finding(make("CRITICAL", True, True, status=status), NOW)
    assert decision.label is Urgency.SUPPRESS and decision.rule_id == "R0"


def test_high_recurrence_escalates_one_level():
    base = label_finding(make("HIGH", prod=False, exposed=False), NOW)
    bumped = label_finding(make("HIGH", prod=False, exposed=False, recurrence=5), NOW)
    assert base.label is Urgency.MONITOR and bumped.label is Urgency.REMEDIATE_7D
    assert bumped.rule_id.endswith("+E1")


def test_stale_prod_finding_escalates_but_stale_nonprod_does_not():
    assert label_finding(make("HIGH", True, False, age_days=120), NOW).label is Urgency.REMEDIATE_NOW
    assert label_finding(make("HIGH", False, False, age_days=120), NOW).label is Urgency.MONITOR


def test_escalation_is_capped_at_the_top_level():
    assert label_finding(make("CRITICAL", True, True, recurrence=50), NOW).label is Urgency.REMEDIATE_NOW


def test_informational_is_never_escalated():
    assert label_finding(make("INFORMATIONAL", True, True, recurrence=50), NOW).label is Urgency.SUPPRESS


def test_urgency_is_monotonic_in_severity():
    """Holding tier and exposure fixed, a more severe finding is never less urgent."""
    for prod in (True, False):
        for exposed in (True, False):
            ranks = [label_finding(make(s, prod, exposed), NOW).label.rank
                     for s in ("INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")]
            assert ranks == sorted(ranks)


def test_every_decision_has_a_rationale():
    decision = label_finding(make("HIGH", True, True), NOW)
    assert "severity=HIGH" in decision.rationale and decision.rule_id.startswith("M-")


def test_feature_vector_matches_spec():
    features = extract_features(make("CRITICAL", prod=True, exposed=True, recurrence=3, age_days=10), NOW)
    assert list(features.index) == FEATURE_COLUMNS
    assert features["severity_num"] == 4 and features["is_prod"] == 1 and features["internet_exposed"] == 1
    assert features["recurrence"] == 3 and features["age_days"] == pytest.approx(10.0)


def test_label_records_returns_training_frame():
    frame = label_records([make("CRITICAL"), make("LOW", prod=False)], NOW)
    assert list(frame.columns) == FEATURE_COLUMNS + ["urgency", "rule_id"]
    assert frame["urgency"].tolist() == ["REMEDIATE_NOW", "SUPPRESS"]
    assert [u.value for u in URGENCY_ORDER] == ["SUPPRESS", "MONITOR", "REMEDIATE_7D", "REMEDIATE_NOW"]
