"""Turn a :class:`FindingRecord` into the numeric feature vector the classifier consumes."""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

import pandas as pd

from ingestion.schema import AccountTier, FindingRecord

FEATURE_COLUMNS: list[str] = [
    "severity_num",
    "is_prod",
    "internet_exposed",
    "recurrence",
    "resource_type_encoded",
    "age_days",
]

# Fixed vocabulary => the encoding is stable between training and inference. Order is
# significant (index is the code): only ever append. Unknown types map to "Other".
RESOURCE_TYPE_VOCAB: list[str] = [
    "AwsS3Bucket",
    "AwsS3AccountPublicAccessBlock",
    "AwsEc2SecurityGroup",
    "AwsEc2Instance",
    "AwsEc2Volume",
    "AwsEc2Vpc",
    "AwsIamUser",
    "AwsIamRole",
    "AwsIamPolicy",
    "AwsIamAccessKey",
    "AwsCloudTrailTrail",
    "AwsRdsDbInstance",
    "AwsKmsKey",
    "AwsLambdaFunction",
    "AwsElbLoadBalancer",
    "AwsDynamoDbTable",
    "AwsCloudFrontDistribution",
    "AwsOpenSearchDomain",
    "AwsAccount",
    "Other",
]
_OTHER_CODE = RESOURCE_TYPE_VOCAB.index("Other")
_RESOURCE_CODES = {name: i for i, name in enumerate(RESOURCE_TYPE_VOCAB)}


def encode_resource_type(resource_type: str) -> int:
    """Ordinal code for a resource type; anything outside the vocabulary is ``Other``."""
    return _RESOURCE_CODES.get(resource_type, _OTHER_CODE)


def extract_features(record: FindingRecord, now: datetime | None = None) -> pd.Series:
    """Feature vector for one finding.

    ``now`` pins the reference time for ``age_days`` so training data is reproducible.
    """
    return pd.Series(
        {
            "severity_num": record.severity.rank,
            "is_prod": int(record.account_tier is AccountTier.PROD),
            "internet_exposed": int(record.is_internet_exposed),
            "recurrence": record.recurrence_count,
            "resource_type_encoded": encode_resource_type(record.resource_type),
            "age_days": round(record.age_days(now), 2),
        },
        name=record.finding_id,
        dtype="float64",
    )[FEATURE_COLUMNS]


def build_feature_frame(records: Iterable[FindingRecord], now: datetime | None = None) -> pd.DataFrame:
    """Feature matrix (one row per finding, indexed by ``finding_id``)."""
    rows = [extract_features(r, now) for r in records]
    if not rows:
        return pd.DataFrame(columns=FEATURE_COLUMNS, dtype="float64")
    return pd.DataFrame(rows)[FEATURE_COLUMNS]
