"""Generate synthetic AWS Security Hub findings for local demos (no AWS account needed).

Writes raw ASFF JSON Lines to data/raw/ in the same shape security_hub_poller.py would have
written them, then runs the real pipeline (normalise -> anonymise -> label) to populate
data/anonymised/findings.jsonl and data/labelled/labelled_findings.csv. This is demo data for
running the dashboard and RAG pipeline end-to-end without a live AWS account; it is not a
substitute for real Security Hub findings or for the hand-reviewed ground-truth set.

Usage:
    python scripts/generate_demo_findings.py [--count 300] [--seed 7]
"""

from __future__ import annotations

import argparse
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Real AWS account IDs from the Stratogent organization, used only as labels here — findings
# are still entirely synthetic (see the "Labels only, synthetic data" decision in the project
# history). Nothing in this script ever calls AWS; it never touches these accounts' real
# Security Hub state.
CLIENTS = [
    {"account_id": "111111111111", "name": "Stratogent (management)", "tier": "prod"},
    {"account_id": "222222222222", "name": "Stratogent-Network-Team", "tier": "prod"},
    {"account_id": "501797339528", "name": "Stratogent-CorpIT", "tier": "prod"},
    {"account_id": "471546218229", "name": "Stratogent-Infra-Team", "tier": "non-prod"},
]

# (control_id, title, description, severity, resource_type, resource_name_fmt, recommendation)
# Controls matching a module in terraform_modules/ (module_indexer reads its header to map these).
COVERED = [
    ("S3.8", "S3 general purpose buckets should block public access",
     "This control checks whether S3 buckets block public access at the bucket level.",
     "HIGH", "AwsS3Bucket", "s3:::{client}-{word}",
     "Enable S3 Block Public Access for the bucket."),
    ("EC2.13", "Security groups should not allow ingress from 0.0.0.0/0 to port 22",
     "This control checks whether a security group allows unrestricted SSH ingress.",
     "HIGH", "AwsEc2SecurityGroup", "ec2:security-group/sg-{hex}",
     "Remove the rule allowing SSH from anywhere and restrict to approved sources."),
    ("EC2.7", "EBS default encryption should be enabled",
     "This control checks whether EBS encryption by default is enabled for the region.",
     "MEDIUM", "AwsAccount", "::{account}:account",
     "Enable EBS encryption by default in the region."),
    ("CloudTrail.1", "CloudTrail should be enabled and configured with at least one multi-Region trail",
     "This control checks whether a multi-region CloudTrail trail with log file validation exists.",
     "HIGH", "AwsAccount", "::{account}:account",
     "Create a multi-region trail with log file validation enabled."),
    ("IAM.7", "Password policies for IAM users should have strong configurations",
     "This control checks the IAM account password policy against a strong-configuration baseline.",
     "MEDIUM", "AwsAccount", "::{account}:account",
     "Strengthen the account password policy (length, reuse prevention, max age)."),
    ("EC2.6", "VPC Flow Logs should be enabled in all VPCs",
     "This control checks whether VPC Flow Logs are enabled for each VPC.",
     "MEDIUM", "AwsEc2Vpc", "ec2:vpc/vpc-{hex}",
     "Enable VPC Flow Logs delivering to CloudWatch Logs."),
    ("GuardDuty.1", "GuardDuty should be enabled",
     "This control checks whether Amazon GuardDuty is enabled in the account and region.",
     "HIGH", "AwsAccount", "::{account}:account",
     "Enable the GuardDuty detector for this account and region."),
    ("EC2.2", "VPC default security group should prohibit inbound and outbound traffic",
     "This control checks whether the default security group of a VPC allows any traffic.",
     "LOW", "AwsEc2SecurityGroup", "ec2:security-group/sg-{hex}",
     "Remove all ingress and egress rules from the default security group."),
    ("S3.4", "S3 general purpose buckets should have server-side encryption configured",
     "This control checks whether an S3 bucket has default encryption configured.",
     "MEDIUM", "AwsS3Bucket", "s3:::{client}-{word}",
     "Enable default server-side encryption on the bucket."),
    ("S3.14", "S3 general purpose buckets should have versioning enabled",
     "This control checks whether versioning is enabled on an S3 bucket.",
     "LOW", "AwsS3Bucket", "s3:::{client}-{word}",
     "Enable versioning on the bucket to protect against accidental deletion."),
    ("IAM.4", "IAM Access Analyzer should be enabled",
     "This control checks whether an IAM Access Analyzer is enabled for the account.",
     "LOW", "AwsAccount", "::{account}:account",
     "Enable an account-zone IAM Access Analyzer."),
]

# Controls with NO matching module: must degrade gracefully to a manual advisory.
UNCOVERED = [
    ("RDS.8", "RDS DB instances should have deletion protection enabled",
     "This control checks whether deletion protection is enabled on an RDS instance.",
     "MEDIUM", "AwsRdsDbInstance", "rds:db/{word}-orders",
     "Enable deletion protection on the DB instance."),
    ("KMS.4", "AWS KMS key rotation should be enabled",
     "This control checks whether automatic key rotation is enabled for a KMS key.",
     "MEDIUM", "AwsKmsKey", "kms:key/{hex}",
     "Enable automatic annual key rotation."),
    ("Lambda.2", "Lambda functions should use supported runtimes",
     "This control checks whether a Lambda function uses a runtime still receiving security updates.",
     "MEDIUM", "AwsLambdaFunction", "lambda:function:{word}-handler",
     "Upgrade the function to a supported runtime."),
    ("ELB.1", "Application Load Balancer should redirect HTTP to HTTPS",
     "This control checks whether an ALB listener redirects HTTP traffic to HTTPS.",
     "MEDIUM", "AwsElbv2LoadBalancer", "elasticloadbalancing:loadbalancer/app/{word}",
     "Add an HTTP-to-HTTPS redirect listener rule."),
    ("DynamoDB.1", "DynamoDB tables should automatically scale capacity",
     "This control checks whether a DynamoDB table uses auto scaling or on-demand capacity.",
     "MEDIUM", "AwsDynamoDbTable", "dynamodb:table/{word}-sessions",
     "Enable auto scaling or switch the table to on-demand mode."),
]

WORDS = ["payroll", "orders", "ledger", "sessions", "events", "reports", "customers", "invoices", "assets", "audit"]


def _hex(rng: random.Random, n: int = 17) -> str:
    return "".join(rng.choice("0123456789abcdef") for _ in range(n))


def make_finding(rng: random.Random, client: dict, entry: tuple, now: datetime, status: str) -> dict:
    control_id, title, description, severity, resource_type, name_fmt, recommendation = entry
    region = rng.choice(["ap-south-1", "us-east-1"])

    # Build a well-formed ARN per resource type: S3 buckets have no region/account segment,
    # AwsAccount findings target the account itself, everything else is a normal service ARN.
    if resource_type == "AwsS3Bucket":
        resource_id = f"arn:aws:s3:::{client['name']}-{rng.choice(WORDS)}"
    elif resource_type == "AwsAccount":
        resource_id = f"arn:aws::{client['account_id']}:account"
    else:
        service, _, rest = name_fmt.partition(":")
        resource_id = f"arn:aws:{service}:{region}:{client['account_id']}:{rest.format(word=rng.choice(WORDS), hex=_hex(rng))}"

    created = now - timedelta(days=float(rng.expovariate(1 / 20)))
    finding_id = (
        f"arn:aws:securityhub:{region}:{client['account_id']}:subscription/"
        f"aws-foundational-security-best-practices/v/1.0.0/{control_id}/finding/{_hex(rng, 32)}"
    )
    return {
        "Id": finding_id,
        "AwsAccountId": client["account_id"],
        "ProductName": "Security Hub",
        "ProductArn": f"arn:aws:securityhub:{region}::product/aws/securityhub",
        "Title": title,
        "Description": description,
        "Severity": {"Label": severity},
        "Resources": [
            {
                "Type": resource_type,
                "Id": resource_id,
                "Region": region,
                "Tags": {"Environment": client["tier"]},
            }
        ],
        "CreatedAt": created.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "UpdatedAt": (created + timedelta(hours=float(rng.expovariate(1 / 48)))).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "Workflow": {"Status": status},
        "RecordState": "ARCHIVED" if status in ("RESOLVED", "SUPPRESSED") else "ACTIVE",
        "Compliance": {"SecurityControlId": control_id, "Status": "FAILED"},
        "Remediation": {"Recommendation": {"Text": recommendation}},
    }


def generate(count: int, seed: int, uncovered_share: float = 0.12) -> list[dict]:
    """``count`` synthetic findings spread across clients, controls and workflow statuses."""
    rng = random.Random(seed)
    now = datetime.now(timezone.utc)
    findings = []
    for _ in range(count):
        client = rng.choice(CLIENTS)
        pool, weights = (UNCOVERED, None) if rng.random() < uncovered_share else (COVERED, None)
        entry = rng.choice(pool)
        # Recurrence: occasionally repeat the same control in the same account (3-6x) to
        # exercise the recurrence-escalation rule in classifier/labeller.py.
        repeats = 1 if rng.random() > 0.15 else rng.randint(3, 6)
        status = rng.choices(["NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"], weights=[55, 20, 20, 5])[0]
        for _ in range(repeats):
            findings.append(make_finding(rng, client, entry, now, status))
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--count", type=int, default=300, help="approximate number of base findings (before recurrence repeats)")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--skip-pipeline", action="store_true", help="only write data/raw/, skip normalise/anonymise/label")
    args = parser.parse_args()

    findings = generate(args.count, args.seed)
    raw_dir = REPO_ROOT / "data" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    raw_path = raw_dir / f"findings_demo_{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}.jsonl"
    with raw_path.open("w", encoding="utf-8") as fh:
        for f in findings:
            fh.write(json.dumps(f) + "\n")
    print(f"wrote {len(findings)} raw ASFF findings to {raw_path}")

    if args.skip_pipeline:
        return

    import sys

    sys.path.insert(0, str(REPO_ROOT))
    from classifier.labeller import label_records
    from ingestion.anonymiser import anonymise_record
    from ingestion.finding_normaliser import normalise_many

    records = normalise_many(findings)
    anonymised = [anonymise_record(r) for r in records]

    anon_dir = REPO_ROOT / "data" / "anonymised"
    anon_dir.mkdir(parents=True, exist_ok=True)
    anon_path = anon_dir / "findings.jsonl"
    with anon_path.open("w", encoding="utf-8") as fh:
        for r in anonymised:
            fh.write(r.to_json() + "\n")
    print(f"wrote {len(anonymised)} normalised+anonymised findings to {anon_path}")

    labelled = label_records(anonymised)
    label_dir = REPO_ROOT / "data" / "labelled"
    label_dir.mkdir(parents=True, exist_ok=True)
    label_path = label_dir / "labelled_findings.csv"
    labelled.to_csv(label_path)
    print(f"wrote {len(labelled)} labelled findings to {label_path}")
    print(labelled["urgency"].value_counts().to_string())


if __name__ == "__main__":
    main()
