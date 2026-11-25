# Terraform modules

Reviewed, deployable modules that the RAG pipeline retrieves and adapts. Each `main.tf` is self-contained
(`terraform` block, variables, resources, outputs) and passes `terraform validate`, `terraform fmt -check`
and the OPA safety policy.

| Module | Remediates | Security Hub controls | CIS ref. | Resource types |
|---|---|---|---|---|
| [`s3_public_access_block`](s3_public_access_block/main.tf) | S3 buckets/account not blocking public access | S3.1, S3.2, S3.3, S3.8 | 2.1.1 | `AwsS3Bucket`, `AwsS3AccountPublicAccessBlock` |
| [`security_group_restrict_ssh`](security_group_restrict_ssh/main.tf) | SSH (22) open to `0.0.0.0/0` / `::/0` | EC2.13, EC2.53 | 4.1 | `AwsEc2SecurityGroup` |
| [`ebs_encryption_default`](ebs_encryption_default/main.tf) | New EBS volumes unencrypted | EC2.7 | 2.2.1 | `AwsEc2Volume`, `AwsAccount` |
| [`cloudtrail_enable`](cloudtrail_enable/main.tf) | No multi-region trail / no log validation | CloudTrail.1, .2, .4 | 2.1 | `AwsCloudTrailTrail`, `AwsAccount` |
| [`iam_password_policy`](iam_password_policy/main.tf) | Weak account password policy | IAM.7, IAM.11-IAM.17 | 1.8-1.11 | `AwsIamUser`, `AwsAccount` |
| [`vpc_flow_logs_enable`](vpc_flow_logs_enable/main.tf) | VPC has no flow logging | EC2.6 | 3.9 | `AwsEc2Vpc`, `AwsEc2FlowLog` |
| [`guardduty_enable`](guardduty_enable/main.tf) | GuardDuty not enabled | GuardDuty.1 | 4.14 (v4) | `AwsGuardDutyDetector`, `AwsAccount` |
| [`default_security_group_lockdown`](default_security_group_lockdown/main.tf) | Default security group allows traffic | EC2.2 | 5.4 (v4) | `AwsEc2SecurityGroup` |
| [`s3_bucket_encryption`](s3_bucket_encryption/main.tf) | S3 bucket has no default encryption | S3.4 | 2.1.2 | `AwsS3Bucket` |
| [`s3_bucket_versioning`](s3_bucket_versioning/main.tf) | S3 bucket has no versioning | S3.14 | - | `AwsS3Bucket` |
| [`access_analyzer_enable`](access_analyzer_enable/main.tf) | No IAM Access Analyzer | IAM.4 | 1.21 (v4) | `AwsAccount`, `AwsIamAccessAnalyzer` |

The CIS numbers are the ones this project uses. CIS renumbers controls between benchmark versions (for
example CloudTrail is 2.1 in v1.2 and 3.1 in v1.4+), so confirm them against the benchmark version you cite.
Security Hub control IDs should also be checked against the current Security Hub controls reference.

## Header format (used by the indexer)

`rag_pipeline/module_indexer.py` reads the first comment lines of every `main.tf`:

```hcl
# Module: <name>
# Description: <one sentence>
# Controls: CIS <n>; Security Hub <ID>, <ID>
# Resource-Types: <AwsResourceType>, <AwsResourceType>
# Keywords: <free text that helps semantic search>
```

To add a module: create `terraform_modules/<name>/main.tf` with this header, run
`python -m rag_pipeline.module_indexer`, and add findings for it to
`data/ground_truth/ground_truth.json`.

## Notes

- **Regional settings.** `ebs_encryption_default` is per-region; instantiate it once per region with provider
  aliases.
- **`security_group_restrict_ssh`** creates the approved rules first, then revokes the public rules with the
  AWS CLI (`terraform_data` + `local-exec`), so the Terraform runner needs the AWS CLI. Set
  `revoke_public_ssh = false` to skip the revoke step.
- **`cloudtrail_enable`** creates its own log bucket (versioned, encrypted, public access blocked, no
  `force_destroy`).
- **`guardduty_enable`** fails to apply if a GuardDuty detector already exists in the account/region
  (only one is allowed per region) — check first if unsure, e.g. if GuardDuty is managed centrally via
  AWS Organizations.
- **`default_security_group_lockdown`** and **`vpc_flow_logs_enable`** target a `vpc_id` directly; they
  don't require importing the VPC itself (`aws_default_security_group` adopts the existing default SG,
  `aws_flow_log` is a sidecar resource).
- Modules declare `aws >= 5.0`; none configure a provider block.
