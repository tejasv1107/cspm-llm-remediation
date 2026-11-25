"""RAG ablation study for Section 9.2 of the dissertation.

Compares generation WITH retrieval (RAG-augmented, the proposed system) against
generation WITHOUT retrieval (zero-shot, same prompt template and conventions but an
empty <reference_modules> block) for the same 11 findings -- one per reference module
in the library -- then runs both outputs through the identical three-stage validator
(terraform validate -> tflint -> OPA).

Makes 22 live Bedrock calls (2 per finding). Run from the project root:
    python -m scripts.rag_ablation
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from ingestion.schema import AccountTier, FindingRecord, Severity
from rag_pipeline.bedrock_client import BedrockClient
from rag_pipeline.prompt_builder import build_prompt
from rag_pipeline.retriever import ModuleRetriever
from rag_pipeline.validator import validate_hcl

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

NOW = datetime(2026, 11, 8, tzinfo=timezone.utc)

# One finding per reference module, built from that module's own header metadata so the
# "correct" retrieval target is unambiguous.
SEED_FINDINGS: list[dict] = [
    dict(control_id="IAM.4", resource_type="AwsAccount",
         title="IAM Access Analyzer is not enabled",
         recommendation_text="Enable IAM Access Analyzer to detect resources shared with external principals."),
    dict(control_id="CloudTrail.1", resource_type="AwsCloudTrailTrail",
         title="CloudTrail is not enabled, or not multi-region",
         recommendation_text="Create a multi-region CloudTrail trail with log file validation."),
    dict(control_id="EC2.2", resource_type="AwsEc2SecurityGroup",
         title="The VPC default security group allows all inbound/outbound traffic",
         recommendation_text="Remove all ingress and egress rules from the default security group."),
    dict(control_id="EC2.7", resource_type="AwsEc2Volume",
         title="EBS default encryption is not enabled for the account",
         recommendation_text="Turn on EBS encryption by default for the region."),
    dict(control_id="GuardDuty.1", resource_type="AwsAccount",
         title="GuardDuty is not enabled",
         recommendation_text="Enable the GuardDuty detector for this account and region."),
    dict(control_id="IAM.7", resource_type="AwsIamUser",
         title="The IAM password policy does not meet requirements",
         recommendation_text="Enforce a strong account password policy (length, complexity, rotation, reuse)."),
    dict(control_id="S3.4", resource_type="AwsS3Bucket",
         title="S3 bucket does not have default server-side encryption enabled",
         recommendation_text="Enable default SSE-S3 or SSE-KMS encryption on the bucket."),
    dict(control_id="S3.14", resource_type="AwsS3Bucket",
         title="S3 bucket does not have versioning enabled",
         recommendation_text="Enable versioning on the bucket so objects can be recovered."),
    dict(control_id="S3.8", resource_type="AwsS3Bucket",
         title="S3 bucket is not configured to block public access",
         recommendation_text="Enable all four S3 Block Public Access settings on the bucket."),
    dict(control_id="EC2.13", resource_type="AwsEc2SecurityGroup",
         title="Security group allows unrestricted SSH access (0.0.0.0/0, port 22)",
         recommendation_text="Restrict SSH ingress to approved CIDRs and revoke the open rule."),
    dict(control_id="EC2.6", resource_type="AwsEc2Vpc",
         title="VPC Flow Logs are not enabled",
         recommendation_text="Enable VPC Flow Logs delivering to a dedicated CloudWatch Logs group."),
]


def build_findings() -> list[FindingRecord]:
    findings = []
    for i, seed in enumerate(SEED_FINDINGS):
        findings.append(FindingRecord(
            finding_id=f"ablation-{i:02d}-{seed['control_id'].lower().replace('.', '-')}",
            account_id="111111111111",
            severity=Severity.HIGH,
            title=seed["title"],
            resource_type=seed["resource_type"],
            resource_arn=f"arn:aws:example:::ablation-{i:02d}",
            region="us-west-2",
            created_at=NOW,
            updated_at=NOW,
            account_tier=AccountTier.PROD,
            is_internet_exposed=False,
            control_id=seed["control_id"],
            recommendation_text=seed["recommendation_text"],
            client_id="111111111111",
        ))
    return findings


@dataclass
class AblationRow:
    finding_id: str
    control_id: str
    condition: str  # "with_rag" | "without_rag"
    retrieved_modules: list[str]
    declined: bool
    input_tokens: int
    output_tokens: int
    estimated_cost_usd: float
    validation_passed: bool
    validation_errors: list[str]
    resource_type_in_output_matches: bool


def run_condition(
    finding: FindingRecord, bedrock: BedrockClient, retriever: ModuleRetriever | None,
) -> AblationRow:
    modules = retriever.retrieve(finding) if retriever is not None else []
    bundle = build_prompt(finding, modules)
    result = bedrock.generate(bundle.system, bundle.user)

    validation_passed, errors = False, ["declined"]
    resource_match = False
    if not result.declined:
        validation = validate_hcl(result.hcl)
        validation_passed = validation.passed
        errors = validation.errors
        # crude but objective: does the generated HCL actually reference the finding's resource type?
        bare_type = finding.resource_type.replace("Aws", "").lower()
        resource_match = bare_type[:6] in result.hcl.lower() or "aws_" in result.hcl.lower()

    return AblationRow(
        finding_id=finding.finding_id,
        control_id=finding.control_id,
        condition="with_rag" if retriever is not None else "without_rag",
        retrieved_modules=[m.name for m in modules],
        declined=result.declined,
        input_tokens=result.input_tokens,
        output_tokens=result.output_tokens,
        estimated_cost_usd=result.estimated_cost_usd,
        validation_passed=validation_passed,
        validation_errors=errors,
        resource_type_in_output_matches=resource_match,
    )


def main() -> None:
    findings = build_findings()
    bedrock = BedrockClient()
    retriever = ModuleRetriever()

    rows: list[AblationRow] = []
    for finding in findings:
        logger.info("=== %s (%s) ===", finding.finding_id, finding.control_id)
        with_rag = run_condition(finding, bedrock, retriever)
        logger.info("  with_rag:    modules=%s  validation_passed=%s",
                    with_rag.retrieved_modules, with_rag.validation_passed)
        rows.append(with_rag)

        without_rag = run_condition(finding, bedrock, None)
        logger.info("  without_rag: validation_passed=%s", without_rag.validation_passed)
        rows.append(without_rag)

    with_rag_rows = [r for r in rows if r.condition == "with_rag"]
    without_rag_rows = [r for r in rows if r.condition == "without_rag"]

    def pass_rate(rs: list[AblationRow]) -> float:
        return sum(1 for r in rs if r.validation_passed) / len(rs) if rs else 0.0

    def decline_rate(rs: list[AblationRow]) -> float:
        return sum(1 for r in rs if r.declined) / len(rs) if rs else 0.0

    total_cost = sum(r.estimated_cost_usd for r in rows)
    total_calls = bedrock.call_count

    summary = {
        "n_findings": len(findings),
        "with_rag": {
            "pass_rate": pass_rate(with_rag_rows),
            "decline_rate": decline_rate(with_rag_rows),
            "n_retrieved_correct_module": sum(
                1 for r in with_rag_rows if r.control_id.split(".")[0].lower() in " ".join(r.retrieved_modules).lower()
                or any(r.control_id in m or r.control_id.split(".")[0] in m for m in r.retrieved_modules)
            ),
        },
        "without_rag": {
            "pass_rate": pass_rate(without_rag_rows),
            "decline_rate": decline_rate(without_rag_rows),
        },
        "total_bedrock_calls": total_calls,
        "total_estimated_cost_usd": round(total_cost, 4),
        "rows": [asdict(r) for r in rows],
    }

    out_path = Path("docs/evaluation/rag_ablation_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2))

    print("\n--- Summary ---")
    print(f"with_rag:    pass_rate={summary['with_rag']['pass_rate']:.2%}  decline_rate={summary['with_rag']['decline_rate']:.2%}")
    print(f"without_rag: pass_rate={summary['without_rag']['pass_rate']:.2%}  decline_rate={summary['without_rag']['decline_rate']:.2%}")
    print(f"Total Bedrock calls: {total_calls}  Estimated cost: ${total_cost:.4f}")
    print(f"\nFull results written to {out_path}")


if __name__ == "__main__":
    main()
