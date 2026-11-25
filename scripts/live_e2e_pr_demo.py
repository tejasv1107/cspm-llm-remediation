"""One live, end-to-end run of the full pipeline against a real GitHub repository.

classify -> dedupe (GitHub) -> retrieve -> prompt -> generate (Bedrock) -> validate -> open PR.
This is the evidence for Layer 4 (Section 12.1): the first real pull request opened by
this system, as opposed to the mocked GitHubPRClient exercised in tests/test_scenarios/.

Run from the project root: python -m scripts.live_e2e_pr_demo
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from approval_workflow.github_pr import GitHubPRClient, branch_name, file_path
from classifier.predict import Prediction, UrgencyClassifier
from ingestion.schema import AccountTier, FindingRecord, Severity
from rag_pipeline.bedrock_client import BedrockClient
from rag_pipeline.prompt_builder import build_manual_advisory, build_prompt, requires_manual_remediation
from rag_pipeline.retriever import ModuleRetriever
from rag_pipeline.validator import ValidationResult, summarise, validate_hcl

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def build_finding() -> FindingRecord:
    now = datetime(2026, 11, 8, tzinfo=timezone.utc)
    return FindingRecord(
        finding_id="live-e2e-s3-8-demo",
        account_id="111111111111",
        severity=Severity.CRITICAL,
        title="S3 bucket is not configured to block public access",
        resource_type="AwsS3Bucket",
        resource_arn="arn:aws:s3:::demo-payroll-exports",
        region="us-west-2",
        created_at=now,
        updated_at=now,
        account_tier=AccountTier.PROD,
        is_internet_exposed=True,
        control_id="S3.8",
        recommendation_text="Enable all four S3 Block Public Access settings on the bucket.",
        client_id="111111111111",
    )


def main() -> None:
    finding = build_finding()
    classifier = UrgencyClassifier()  # loads the registered 'champion' model
    retriever = ModuleRetriever()
    bedrock = BedrockClient()
    github = GitHubPRClient()

    logger.info("Step 1: classify")
    prediction: Prediction = classifier.classify(finding)
    logger.info("  urgency=%s source=%s top_features=%s", prediction.label.value, prediction.source, prediction.top_features)

    logger.info("Step 2: check for an existing open PR for this finding")
    existing = github.find_existing_pr(finding)
    if existing is not None:
        logger.info("  duplicate: PR #%s already open at %s -- stopping (no LLM call)", existing.number, existing.html_url)
        return

    logger.info("Step 3: retrieve reference modules")
    modules = retriever.retrieve(finding, k=3)
    logger.info("  retrieved: %s", [m.name for m in modules])
    if requires_manual_remediation(modules):
        logger.info("  no module matched -- advisory only: %s", build_manual_advisory(finding))
        return

    logger.info("Step 4: build prompt and generate (live Bedrock call)")
    bundle = build_prompt(finding, modules, prediction)
    generation = bedrock.generate(bundle.system, bundle.user)
    logger.info("  declined=%s tokens_in=%d tokens_out=%d cost=$%.4f",
                generation.declined, generation.input_tokens, generation.output_tokens, generation.estimated_cost_usd)
    if generation.declined:
        logger.info("  model declined -- advisory only")
        return

    logger.info("Step 5: validate (terraform validate -> tflint -> OPA)")
    validation: ValidationResult = validate_hcl(generation.hcl)
    logger.info("%s", summarise(validation))
    if not validation.passed:
        logger.info("  validation failed -- no PR opened")
        return

    logger.info("Step 6: open the pull request")
    pr = github.create_remediation_pr(finding, generation.hcl, prediction, validation, bundle)
    logger.info("  PR #%d: %s (created=%s)", pr.number, pr.url, pr.created)

    record = {
        "finding_id": finding.finding_id,
        "control_id": finding.control_id,
        "prediction": {"label": prediction.label.value, "source": prediction.source,
                       "top_features": prediction.top_features},
        "retrieved_modules": [m.name for m in modules],
        "generation": {"input_tokens": generation.input_tokens, "output_tokens": generation.output_tokens,
                        "estimated_cost_usd": generation.estimated_cost_usd, "hcl": generation.hcl},
        "validation_passed": validation.passed,
        "pr": {"number": pr.number, "url": pr.url, "branch": pr.branch, "path": pr.path, "created": pr.created},
    }
    out_path = Path("docs/evaluation/live_e2e_pr_demo_result.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))
    print(f"\nPR URL: {pr.url}")
    print(f"Full record written to {out_path}")


if __name__ == "__main__":
    main()
