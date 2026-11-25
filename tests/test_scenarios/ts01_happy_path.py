"""TS-01: a critical production finding is classified REMEDIATE_NOW and ends as a valid PR."""

from __future__ import annotations

from classifier.labeller import Urgency
from conftest import SAFE_S3_HCL, fake_bedrock, fake_github, needs_opa


@needs_opa
def test_critical_prod_finding_becomes_a_valid_pr(make_finding, retriever, run_pipeline, stub_terraform_and_tflint):
    finding = make_finding()  # CRITICAL, prod-tagged, S3.8
    bedrock = fake_bedrock(SAFE_S3_HCL.replace("{bucket}", "acme-payroll"))
    github, repo = fake_github()

    out = run_pipeline(finding, retriever, bedrock, github)  # OPA stage runs for real

    # classified as most urgent
    assert out.prediction.label is Urgency.REMEDIATE_NOW

    # RAG picked the right module first
    assert out.modules[0].name == "s3_public_access_block"
    assert out.modules[0].resource_type_match and out.modules[0].control_match
    assert out.bundle.has_reference_modules

    # generated code passed the whole validation chain
    assert out.validation.passed, out.validation.errors

    # a PR was opened with the code and full context
    assert out.pr.created and out.pr.number == 100
    repo.create_git_ref.assert_called_once()
    _, kwargs = repo.create_pull.call_args
    assert kwargs["head"] == out.pr.branch and kwargs["base"] == "main"
    assert finding.finding_id in kwargs["body"] and "REMEDIATE_NOW" in kwargs["body"]
    assert "s3_public_access_block" in kwargs["body"]

    args, create_kwargs = repo.create_file.call_args
    assert args[0] == out.pr.path and args[0].startswith("remediations/111111111111/")
    assert "aws_s3_bucket_public_access_block" in args[2]  # committed content is the generated HCL
    assert create_kwargs["branch"] == out.pr.branch


def test_happy_path_with_stubbed_policy_stage(make_finding, retriever, run_pipeline, monkeypatch, stub_terraform_and_tflint):
    """Same flow without needing the opa binary: the policy stage is stubbed to pass."""
    import rag_pipeline.validator as validator

    monkeypatch.setattr(validator, "run_opa", lambda hcl, policy_dir=None: validator.StageResult("opa", True))
    github, repo = fake_github()
    out = run_pipeline(make_finding(), retriever, fake_bedrock(SAFE_S3_HCL.replace("{bucket}", "acme-payroll")), github)
    assert out.prediction.label is Urgency.REMEDIATE_NOW and out.pr.created
    repo.create_pull.assert_called_once()
