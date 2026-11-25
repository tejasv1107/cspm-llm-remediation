"""Unit tests for the terraform validate -> tflint -> OPA pipeline (rag_pipeline/validator.py).

Orchestration and parsing are tested with mocked subprocesses. Tests marked ``needs_opa``
evaluate the real rego policy and are skipped when the ``opa`` binary is not installed.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

import rag_pipeline.validator as validator
from rag_pipeline.validator import StageResult, hcl_to_opa_input, run_opa, run_terraform_validate, run_tflint, validate_hcl
from conftest import needs_opa  # noqa: E402  (pytest puts tests/ on sys.path)

REPO_ROOT = Path(__file__).resolve().parents[1]

BAD_HCL = """
resource "aws_security_group" "web" {
  name = "web"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_s3_bucket" "b" {
  bucket        = "x"
  force_destroy = true
}
data "aws_iam_policy_document" "d" {
  statement {
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}
"""

GOOD_HCL = """
resource "aws_s3_bucket_public_access_block" "ok" {
  bucket                  = "x"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_security_group" "egress_only" {
  name = "egress-only"
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
"""


def proc(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


# --------------------------------------------------------------- HCL -> OPA input
def test_hcl_is_normalised_for_opa():
    doc = hcl_to_opa_input(BAD_HCL)
    types = {(r["type"], r["name"]) for r in doc["resources"]}
    assert types == {("aws_security_group", "web"), ("aws_s3_bucket", "b")}
    assert doc["data"][0]["type"] == "aws_iam_policy_document"
    bucket = next(r for r in doc["resources"] if r["type"] == "aws_s3_bucket")
    assert bucket["config"]["bucket"] == "x" and bucket["config"]["force_destroy"] is True
    assert "__is_block__" not in json.dumps(doc) and '"\\"' not in json.dumps(doc)


# ------------------------------------------------------------------- orchestration
def _stub_stages(monkeypatch, tf=True, lint=True, opa=True):
    order: list[str] = []

    def stage(name, passed):
        def _run(*args, **kwargs):
            order.append(name)
            return StageResult(name, passed, [] if passed else [f"{name} failed"])
        return _run

    monkeypatch.setattr(validator, "run_terraform_validate", stage("terraform_validate", tf))
    monkeypatch.setattr(validator, "run_tflint", stage("tflint", lint))
    monkeypatch.setattr(validator, "run_opa", stage("opa", opa))
    return order


def test_stages_run_in_order_and_all_pass(monkeypatch):
    order = _stub_stages(monkeypatch)
    result = validate_hcl("# empty")
    assert result.passed and order == ["terraform_validate", "tflint", "opa"]


@pytest.mark.parametrize(
    "flags, expected_run, expected_skipped",
    [
        (dict(tf=False), ["terraform_validate"], ["tflint", "opa"]),
        (dict(lint=False), ["terraform_validate", "tflint"], ["opa"]),
        (dict(opa=False), ["terraform_validate", "tflint", "opa"], []),
    ],
)
def test_first_failure_short_circuits_later_stages(monkeypatch, flags, expected_run, expected_skipped):
    order = _stub_stages(monkeypatch, **flags)
    result = validate_hcl("# empty")
    assert not result.passed
    assert order == expected_run
    assert [s.name for s in result.stages if s.skipped] == expected_skipped


def test_can_run_all_stages_even_after_a_failure(monkeypatch):
    order = _stub_stages(monkeypatch, tf=False)
    validate_hcl("# empty", stop_on_failure=False)
    assert order == ["terraform_validate", "tflint", "opa"]


def test_errors_are_prefixed_with_the_stage_name(monkeypatch):
    _stub_stages(monkeypatch, lint=False)
    assert validate_hcl("# empty").errors == ["[tflint] tflint failed"]


# ---------------------------------------------------------- fail closed & parsing
@pytest.mark.parametrize("runner", [lambda: run_terraform_validate(Path(".")), lambda: run_tflint(Path(".")), lambda: run_opa(GOOD_HCL)])
def test_missing_binary_fails_closed(monkeypatch, runner):
    monkeypatch.setattr(validator.shutil, "which", lambda name: None)
    result = runner()
    assert not result.passed and "not found on PATH" in result.errors[0]


def test_terraform_validate_reports_diagnostics(monkeypatch):
    monkeypatch.setattr(validator.shutil, "which", lambda name: "/bin/terraform")
    report = {"valid": False, "diagnostics": [{"severity": "error", "summary": "Unsupported argument", "detail": "no such attr"}]}
    calls = iter([proc(0), proc(1, json.dumps(report))])
    monkeypatch.setattr(validator, "_run", lambda *a, **k: next(calls))
    result = run_terraform_validate(Path("."))
    assert not result.passed and result.errors == ["Unsupported argument: no such attr"]


def test_terraform_init_failure_is_reported(monkeypatch):
    monkeypatch.setattr(validator.shutil, "which", lambda name: "/bin/terraform")
    monkeypatch.setattr(validator, "_run", lambda *a, **k: proc(1, stderr="registry unreachable"))
    result = run_terraform_validate(Path("."))
    assert not result.passed and "registry unreachable" in result.errors[0]


def test_tflint_issues_are_parsed(monkeypatch):
    monkeypatch.setattr(validator.shutil, "which", lambda name: "/bin/tflint")
    report = {"issues": [{"rule": {"name": "terraform_unused_declarations"}, "message": "variable unused",
                          "range": {"start": {"line": 7}}}], "errors": []}
    monkeypatch.setattr(validator, "_run", lambda *a, **k: proc(2, json.dumps(report)))
    result = run_tflint(Path("."), config=Path("does-not-exist.hcl"))
    assert not result.passed and result.errors == ["terraform_unused_declarations (line 7): variable unused"]


def test_tflint_clean_run_passes(monkeypatch):
    monkeypatch.setattr(validator.shutil, "which", lambda name: "/bin/tflint")
    monkeypatch.setattr(validator, "_run", lambda *a, **k: proc(0))
    assert run_tflint(Path("."), config=Path("does-not-exist.hcl")).passed


def test_unparseable_hcl_fails_the_opa_stage(monkeypatch):
    monkeypatch.setattr(validator.shutil, "which", lambda name: "/bin/opa")
    result = run_opa('resource "aws_s3_bucket" "b" {')
    assert not result.passed and "could not parse HCL" in result.errors[0]


# ------------------------------------------------------------- real OPA evaluation
@needs_opa
def test_opa_rejects_all_three_dangerous_patterns():
    result = run_opa(BAD_HCL)
    assert not result.passed
    joined = " | ".join(result.errors)
    assert "0.0.0.0/0" in joined and "wildcard action" in joined and "force_destroy" in joined


@needs_opa
def test_opa_accepts_safe_hcl_and_ignores_egress():
    assert run_opa(GOOD_HCL).passed


@needs_opa
@pytest.mark.parametrize("module", sorted(p.name for p in (REPO_ROOT / "terraform_modules").iterdir() if p.is_dir()))
def test_shipped_terraform_modules_pass_the_policy(module):
    hcl = (REPO_ROOT / "terraform_modules" / module / "main.tf").read_text(encoding="utf-8")
    result = run_opa(hcl)
    assert result.passed, result.errors


@needs_opa
def test_opa_flags_inline_jsonencode_wildcards_but_not_deny_statements():
    wildcard = 'resource "aws_iam_policy" "p" {\n  name = "p"\n  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })\n}\n'
    deny_all = 'resource "aws_iam_policy" "p" {\n  name = "p"\n  policy = jsonencode({ Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }] })\n}\n'
    assert not run_opa(wildcard).passed
    assert run_opa(deny_all).passed
