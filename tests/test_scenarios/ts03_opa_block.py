"""TS-03: dangerous generated Terraform must be rejected by OPA and never reach GitHub."""

from __future__ import annotations

import pytest

from conftest import fake_bedrock, fake_github, needs_opa

DANGEROUS_HCL = """\
resource "aws_security_group" "fix" {
  name = "fix"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "logs" {
  bucket        = "acme-payroll"
  force_destroy = true
}

data "aws_iam_policy_document" "admin" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
"""


@needs_opa
def test_opa_rejects_dangerous_terraform_and_no_pr_is_opened(make_finding, retriever, run_pipeline, stub_terraform_and_tflint):
    github, repo = fake_github()

    out = run_pipeline(make_finding(), retriever, fake_bedrock(DANGEROUS_HCL), github)

    assert out.generation is not None  # the model did produce code...
    assert not out.validation.passed  # ...but validation refused it
    opa = out.validation.stage("opa")
    assert opa is not None and not opa.passed
    joined = " | ".join(opa.errors)
    assert "0.0.0.0/0" in joined, "world-open ingress rule did not fire"
    assert "wildcard action" in joined, "wildcard IAM rule did not fire"
    assert "force_destroy" in joined, "force_destroy rule did not fire"

    assert out.pr is None
    repo.create_pull.assert_not_called()
    repo.create_file.assert_not_called()
    repo.create_git_ref.assert_not_called()


@needs_opa
@pytest.mark.parametrize(
    "snippet, needle",
    [
        ('resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  cidr_blocks = ["0.0.0.0/0"]\n}\n', "0.0.0.0/0"),
        ('resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  ipv6_cidr_blocks = ["::/0"]\n}\n', "::/0"),
        ('resource "aws_s3_bucket" "b" {\n  force_destroy = true\n}\n', "force_destroy"),
        ('resource "aws_iam_role_policy_attachment" "a" {\n  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"\n}\n', "AdministratorAccess"),
    ],
)
def test_each_forbidden_pattern_is_caught_individually(snippet, needle):
    from rag_pipeline.validator import run_opa

    result = run_opa(snippet)
    assert not result.passed and needle in " ".join(result.errors)


def test_failed_validation_blocks_the_pr_even_without_the_opa_binary(make_finding, retriever, run_pipeline):
    """Orchestration guarantee independent of tooling: a failing ValidationResult means no PR."""
    from rag_pipeline.validator import StageResult, ValidationResult

    failing = lambda hcl: ValidationResult([StageResult("opa", False, ["aws_s3_bucket.logs: force_destroy = true"])])  # noqa: E731
    github, repo = fake_github()
    out = run_pipeline(make_finding(), retriever, fake_bedrock(DANGEROUS_HCL), github, validate=failing)
    assert out.pr is None
    repo.create_pull.assert_not_called()
