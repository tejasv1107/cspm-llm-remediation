"""TS-02: the same finding in a non-production account gets a lower urgency."""

from __future__ import annotations

from classifier.labeller import Urgency
from classifier.predict import UrgencyClassifier
from ingestion.finding_normaliser import normalise_finding
from ingestion.schema import AccountTier


def test_same_finding_is_less_urgent_in_non_prod(make_asff):
    prod_asff = make_asff()  # CRITICAL, Environment=prod
    nonprod_asff = make_asff(
        Resources=[{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::acme-payroll", "Region": "ap-south-1",
                    "Tags": {"Environment": "dev"}}]
    )
    prod, nonprod = normalise_finding(prod_asff), normalise_finding(nonprod_asff)
    assert (prod.account_tier, nonprod.account_tier) == (AccountTier.PROD, AccountTier.NON_PROD)
    assert prod.severity == nonprod.severity and prod.control_id == nonprod.control_id  # identical otherwise

    classifier = UrgencyClassifier(model_uri=None)
    prod_label = classifier.classify(prod).label
    nonprod_label = classifier.classify(nonprod).label

    assert prod_label is Urgency.REMEDIATE_NOW
    assert nonprod_label is Urgency.REMEDIATE_7D
    assert nonprod_label.rank < prod_label.rank


def test_account_tier_map_can_demote_a_finding_without_tags(make_asff):
    untagged = make_asff(Resources=[{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::acme", "Region": "ap-south-1"}])
    record = normalise_finding(untagged, tier_map={"111111111111": AccountTier.NON_PROD})
    assert UrgencyClassifier(model_uri=None).classify(record).label is Urgency.REMEDIATE_7D
