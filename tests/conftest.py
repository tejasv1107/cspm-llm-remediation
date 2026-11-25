"""Shared fixtures: ASFF factory, offline retriever, fake Bedrock/GitHub, and a pipeline runner.

There is no production orchestrator module in the project layout, so ``run_pipeline`` below
is the reference glue (classify -> retrieve -> prompt -> generate -> validate -> PR) that the
TS-0x scenario tests exercise.
"""

from __future__ import annotations

import copy
import io
import itertools
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable
from unittest.mock import MagicMock

import pytest
from github import UnknownObjectException

from approval_workflow.github_pr import GitHubPRClient, PullRequestResult, branch_name, file_path
from classifier.predict import Prediction, UrgencyClassifier
from ingestion.finding_normaliser import annotate_recurrence, normalise_finding
from ingestion.schema import FindingRecord
from rag_pipeline.bedrock_client import BedrockClient, GenerationResult
from rag_pipeline.module_indexer import HashingEmbedder, index_modules
from rag_pipeline.prompt_builder import (
    PromptBundle,
    build_manual_advisory,
    build_prompt,
    requires_manual_remediation,
)
from rag_pipeline.retriever import ModuleRetriever, RetrievedModule
from rag_pipeline.validator import StageResult, ValidationResult, validate_hcl

REPO_ROOT = Path(__file__).resolve().parents[1]

SAFE_S3_HCL = """\
terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = ">= 5.0" }
  }
}

# Fixes S3.8 for the affected bucket
resource "aws_s3_bucket_public_access_block" "fix" {
  bucket                  = "{bucket}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
"""


# ----------------------------------------------------------------------- ASFF
_BASE_ASFF: dict[str, Any] = {
    "Id": "arn:aws:securityhub:ap-south-1:111111111111:subscription/aws-foundational-security-best-practices/v/1.0.0/S3.8/finding/aaaa-1111",
    "AwsAccountId": "111111111111",
    "ProductName": "Security Hub",
    "Title": "S3 general purpose buckets should block public access",
    "Description": "This control checks whether S3 general purpose buckets block public access at the bucket level.",
    "Severity": {"Label": "CRITICAL"},
    "Resources": [
        {"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::acme-payroll", "Region": "ap-south-1", "Tags": {"Environment": "prod"}}
    ],
    "CreatedAt": "2026-01-01T00:00:00.000Z",
    "UpdatedAt": "2026-01-02T00:00:00.000Z",
    "Workflow": {"Status": "NEW"},
    "Compliance": {"SecurityControlId": "S3.8", "Status": "FAILED"},
    "Remediation": {"Recommendation": {"Text": "Enable S3 Block Public Access for the bucket."}},
}


@pytest.fixture
def make_asff() -> Callable[..., dict[str, Any]]:
    """Factory: deep copy of a critical prod S3.8 finding with top-level keys overridden."""

    def _make(**overrides: Any) -> dict[str, Any]:
        asff = copy.deepcopy(_BASE_ASFF)
        asff.update(overrides)
        return asff

    return _make


@pytest.fixture
def make_finding(make_asff) -> Callable[..., FindingRecord]:
    """Factory: normalised FindingRecord built from :func:`make_asff` overrides."""

    def _make(**overrides: Any) -> FindingRecord:
        return annotate_recurrence([normalise_finding(make_asff(**overrides))])[0]

    return _make


# ------------------------------------------------------------------ retrieval
@pytest.fixture
def retriever(tmp_path) -> ModuleRetriever:
    """Retriever over the real Terraform modules using the offline hashing embedder."""
    embedder = HashingEmbedder()
    chroma = tmp_path / "chroma"
    index_modules(REPO_ROOT / "terraform_modules", chroma, embedder)
    return ModuleRetriever(chroma_path=str(chroma), embedder=embedder)


# ---------------------------------------------------------------------- fakes
def fake_bedrock(hcl_for_prompt: Callable[[str], str] | str, barrier=None) -> BedrockClient:
    """A BedrockClient whose boto3 client is a MagicMock returning canned Messages-API replies.

    ``hcl_for_prompt`` is HCL text, or a function of the user prompt (to echo prompt content).
    ``barrier`` (threading.Barrier) forces concurrent callers to overlap.
    """
    calls: list[dict[str, Any]] = []

    def _invoke(**kwargs: Any) -> dict[str, Any]:
        body = json.loads(kwargs["body"])
        user_prompt = body["messages"][0]["content"][0]["text"]
        calls.append({"system": body["system"], "user": user_prompt})
        if barrier is not None:
            barrier.wait(timeout=10)
        hcl = hcl_for_prompt(user_prompt) if callable(hcl_for_prompt) else hcl_for_prompt
        payload = {
            "content": [{"type": "text", "text": f"```hcl\n{hcl}\n```"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 100, "output_tokens": 50},
        }
        return {"body": io.BytesIO(json.dumps(payload).encode())}

    boto_client = MagicMock()
    boto_client.invoke_model.side_effect = _invoke
    client = BedrockClient(client=boto_client)
    client.calls = calls  # type: ignore[attr-defined]
    return client


def fake_github(repo_full_name: str = "acme/remediations") -> tuple[GitHubPRClient, MagicMock]:
    """A GitHubPRClient over a stateful MagicMock repo. Returns (client, repo)."""
    repo = MagicMock()
    opened: list[MagicMock] = []
    numbers = itertools.count(100)  # next() is atomic, so concurrent callers never share a number
    repo.get_branch.return_value.commit.sha = "base-sha"
    repo.get_contents.side_effect = UnknownObjectException(404, {}, {})

    def _create_pull(**kwargs: Any) -> MagicMock:
        pr = MagicMock()
        pr.number = next(numbers)
        pr.html_url = f"https://github.com/{repo_full_name}/pull/{pr.number}"
        pr.head_ref = kwargs["head"]
        opened.append(pr)
        return pr

    repo.create_pull.side_effect = _create_pull
    repo.get_pulls.side_effect = lambda **kw: [p for p in opened if kw["head"].endswith(p.head_ref)]

    github = MagicMock()
    github.get_repo.return_value = repo
    return GitHubPRClient(repo_full_name=repo_full_name, base_branch="main", github=github), repo


def passing_validation() -> ValidationResult:
    return ValidationResult([StageResult("terraform_validate", True), StageResult("tflint", True), StageResult("opa", True)])


@pytest.fixture
def stub_terraform_and_tflint(monkeypatch):
    """Replace the two stages that need network/binaries; the OPA stage stays real."""
    import rag_pipeline.validator as validator

    monkeypatch.setattr(validator, "run_terraform_validate", lambda workdir: StageResult("terraform_validate", True))
    monkeypatch.setattr(validator, "run_tflint", lambda workdir, config=None: StageResult("tflint", True))


needs_opa = pytest.mark.skipif(shutil.which("opa") is None, reason="opa binary not on PATH")


# ----------------------------------------------------------------- pipeline
@dataclass
class PipelineOutcome:
    prediction: Prediction | None = None
    modules: list[RetrievedModule] = field(default_factory=list)
    bundle: PromptBundle | None = None
    generation: GenerationResult | None = None
    validation: ValidationResult | None = None
    pr: PullRequestResult | None = None
    advisory: str | None = None


@pytest.fixture
def run_pipeline() -> Callable[..., PipelineOutcome]:
    """classify -> dedupe -> retrieve -> prompt -> generate -> validate -> PR.

    Every check that's free (classification, the GitHub duplicate lookup, retrieval) runs before
    the one step that costs real money (``bedrock.generate``), so a finding that's already been
    remediated, is too low-urgency, or has no matching module never reaches the LLM at all.
    """

    def _run(
        finding: FindingRecord,
        retriever: ModuleRetriever,
        bedrock: BedrockClient,
        github: GitHubPRClient,
        validate: Callable[[str], ValidationResult] = validate_hcl,
    ) -> PipelineOutcome:
        out = PipelineOutcome()
        out.prediction = UrgencyClassifier(model_uri=None).classify(finding)
        if out.prediction.label.value in ("SUPPRESS", "MONITOR"):
            return out

        existing = github.find_existing_pr(finding)
        if existing is not None:
            out.pr = PullRequestResult(existing.number, existing.html_url, branch_name(finding), file_path(finding), created=False)
            return out

        out.modules = retriever.retrieve(finding, k=3)
        if requires_manual_remediation(out.modules):
            out.advisory = build_manual_advisory(finding)
            return out
        out.bundle = build_prompt(finding, out.modules, out.prediction)
        out.generation = bedrock.generate(out.bundle.system, out.bundle.user)
        if out.generation.declined:
            out.advisory = build_manual_advisory(finding)
            return out
        out.validation = validate(out.generation.hcl)
        if out.validation.passed:
            out.pr = github.create_remediation_pr(finding, out.generation.hcl, out.prediction, out.validation, out.bundle)
        return out

    return _run
