"""TS-06: a duplicate finding must not produce a second PR."""

from __future__ import annotations

from approval_workflow.github_pr import branch_name
from conftest import SAFE_S3_HCL, fake_bedrock, fake_github, passing_validation

always_valid = lambda hcl: passing_validation()  # noqa: E731


def test_same_finding_twice_opens_only_one_pr(make_finding, retriever, run_pipeline):
    finding = make_finding()
    bedrock = fake_bedrock(SAFE_S3_HCL.replace("{bucket}", "acme-payroll"))
    github, repo = fake_github()

    first = run_pipeline(finding, retriever, bedrock, github, always_valid)
    second = run_pipeline(finding, retriever, bedrock, github, always_valid)

    assert first.pr.created is True
    assert second.pr.created is False
    assert second.pr.number == first.pr.number and second.pr.url == first.pr.url

    repo.create_pull.assert_called_once()
    repo.create_file.assert_called_once()
    repo.create_git_ref.assert_called_once()

    # The whole point: a finding that already has an open PR must never reach the LLM again.
    # Bedrock is the only step in the pipeline with a real per-call cost.
    assert bedrock._client.invoke_model.call_count == 1
    assert second.generation is None


def test_branch_name_is_deterministic_per_finding(make_finding):
    a, b = make_finding(), make_finding()
    assert branch_name(a) == branch_name(b)
    assert branch_name(a) != branch_name(make_finding(Id="a-different-finding-id"))


def test_a_different_finding_still_gets_its_own_pr(make_finding, retriever, run_pipeline):
    bedrock = fake_bedrock(SAFE_S3_HCL.replace("{bucket}", "acme-payroll"))
    github, repo = fake_github()

    first = run_pipeline(make_finding(), retriever, bedrock, github, always_valid)
    other = run_pipeline(make_finding(Id="another-finding"), retriever, bedrock, github, always_valid)

    assert other.pr.created and other.pr.number != first.pr.number
    assert repo.create_pull.call_count == 2
