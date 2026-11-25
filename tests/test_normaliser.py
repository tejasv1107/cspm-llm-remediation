"""Unit tests for ingestion/finding_normaliser.py (and the anonymiser that follows it)."""

from __future__ import annotations

import pytest

from ingestion.anonymiser import anonymise_arn, anonymise_record, anonymise_text, hash_account_id
from ingestion.finding_normaliser import (
    annotate_recurrence,
    extract_control_id,
    normalise_finding,
    normalise_many,
    parse_asff_time,
)
from ingestion.schema import AccountTier, FindingRecord, Severity, WorkflowStatus


# ------------------------------------------------------------------ normaliser
def test_core_fields_are_mapped(make_asff):
    record = normalise_finding(make_asff())
    assert record.finding_id.endswith("aaaa-1111")
    assert record.account_id == "111111111111"
    assert record.severity is Severity.CRITICAL
    assert record.resource_type == "AwsS3Bucket"
    assert record.resource_arn == "arn:aws:s3:::acme-payroll"
    assert record.region == "ap-south-1"
    assert record.workflow_status is WorkflowStatus.NEW
    assert record.control_id == "S3.8"
    assert record.recommendation_text.startswith("Enable S3 Block Public Access")
    assert record.source_product == "Security Hub"
    assert record.client_id == "111111111111"  # defaults to the account


def test_timestamps_are_timezone_aware_utc(make_asff):
    record = normalise_finding(make_asff())
    assert record.created_at.tzinfo is not None
    assert record.created_at.isoformat().startswith("2026-01-01T00:00:00")
    assert parse_asff_time("2026-03-01T05:30:00+05:30").hour == 0


def test_prod_tag_sets_tier_and_tier_map_overrides_it(make_asff):
    assert normalise_finding(make_asff()).account_tier is AccountTier.PROD
    overridden = normalise_finding(make_asff(), tier_map={"111111111111": AccountTier.NON_PROD})
    assert overridden.account_tier is AccountTier.NON_PROD


def test_untagged_resource_defaults_to_non_prod(make_asff):
    asff = make_asff(Resources=[{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::x", "Region": "ap-south-1"}])
    assert normalise_finding(asff).account_tier is AccountTier.NON_PROD


@pytest.mark.parametrize(
    "control, title, expected",
    [
        ("S3.2", "S3 buckets should prohibit public read access", True),   # known exposure control
        ("S3.8", "S3 buckets should block public access", False),           # posture, not exposure
        ("EC2.99", "Security group allows 0.0.0.0/0 on port 22", True),     # text heuristic
        ("IAM.7", "Password policies should be strong", False),
    ],
)
def test_internet_exposure_heuristic(make_asff, control, title, expected):
    asff = make_asff(Title=title, Description="", Compliance={"SecurityControlId": control})
    assert normalise_finding(asff).is_internet_exposed is expected


def test_control_id_falls_back_to_product_fields(make_asff):
    asff = make_asff(Compliance={}, ProductFields={"ControlId": "CIS.2.1.1"})
    assert extract_control_id(asff) == "CIS.2.1.1"
    asff = make_asff(Compliance={}, ProductFields={"StandardsControlArn": "arn:aws:securityhub:::ruleset/cis/v/1.2.0/rule/4.1"})
    assert extract_control_id(asff) == "4.1"


def test_missing_mandatory_field_raises(make_asff):
    asff = make_asff()
    del asff["Id"]
    with pytest.raises(KeyError):
        normalise_finding(asff)


def test_normalise_many_skips_malformed_and_counts_recurrence(make_asff):
    good_a = make_asff(Id="a")
    good_b = make_asff(Id="b")  # same account + control S3.8 => recurrence 2
    other = make_asff(Id="c", AwsAccountId="222222222222")
    bad = make_asff(Id="d", Severity={"Label": "NOT_A_SEVERITY"})
    records = normalise_many([good_a, good_b, other, bad])
    assert len(records) == 3
    by_id = {r.finding_id: r for r in records}
    assert by_id["a"].recurrence_count == by_id["b"].recurrence_count == 2
    assert by_id["c"].recurrence_count == 1


def test_normalise_many_can_be_strict(make_asff):
    with pytest.raises(ValueError):
        normalise_many([make_asff(Severity={"Label": "NOT_A_SEVERITY"})], skip_invalid=False)


def test_record_round_trips_through_dict(make_asff):
    record = normalise_finding(make_asff())
    assert FindingRecord.from_dict(record.to_dict()) == record


# ------------------------------------------------------------------ anonymiser
def test_account_hash_is_stable_salted_and_not_the_id():
    a = hash_account_id("111111111111", salt="s1")
    assert a == hash_account_id("111111111111", salt="s1")
    assert a != hash_account_id("111111111111", salt="s2")
    assert "111111111111" not in a and len(a) == 16


def test_arn_account_and_resource_are_replaced_but_shape_is_kept():
    arn = "arn:aws:ec2:ap-south-1:123456789012:instance/i-0abc123def"
    out = anonymise_arn(arn, salt="s")
    assert out.startswith("arn:aws:ec2:ap-south-1:")
    assert "123456789012" not in out and "i-0abc123def" not in out
    assert "/res-" in out and ":instance/" in out
    assert anonymise_arn(arn, salt="s") == out  # deterministic => joins across findings still work


def test_s3_bucket_and_object_names_are_never_leaked():
    assert "payroll" not in anonymise_arn("arn:aws:s3:::acme-payroll", salt="s")
    assert "payroll" not in anonymise_arn("arn:aws:s3:::acme-payroll/2026/report.csv", salt="s")


def test_free_text_account_ids_and_arns_are_scrubbed():
    text = "Account 123456789012 owns arn:aws:iam::123456789012:role/Admin"
    out = anonymise_text(text, salt="s")
    assert "123456789012" not in out and "Admin" not in out


def test_anonymise_record_hides_identifiers_but_keeps_analytic_fields(make_finding):
    original = make_finding()
    anon = anonymise_record(original, salt="s")
    assert anon.account_id != original.account_id and anon.client_id == anon.account_id
    assert "acme-payroll" not in anon.resource_arn
    assert "111111111111" not in anon.finding_id
    assert (anon.severity, anon.account_tier, anon.is_internet_exposed, anon.control_id) == (
        original.severity, original.account_tier, original.is_internet_exposed, original.control_id
    )
