"""TS-04: no matching Terraform module -> graceful degradation (advisory, no hallucinated code)."""

from __future__ import annotations

from conftest import fake_bedrock, fake_github, SAFE_S3_HCL


def rds_finding(make_finding):
    return make_finding(
        Id="arn:aws:securityhub:ap-south-1:111111111111:subscription/x/RDS.8/finding/1",
        Title="RDS DB instances should have deletion protection enabled",
        Description="Deletion protection prevents accidental removal of the database.",
        Compliance={"SecurityControlId": "RDS.8"},
        Resources=[{"Type": "AwsRdsDbInstance", "Id": "arn:aws:rds:ap-south-1:111111111111:db:orders",
                    "Region": "ap-south-1", "Tags": {"Environment": "prod"}}],
        Remediation={"Recommendation": {"Text": "Enable deletion protection on the DB instance."}},
    )


def test_retriever_returns_nothing_when_no_module_fits(make_finding, retriever):
    assert retriever.retrieve(rds_finding(make_finding), k=3) == []


def test_pipeline_degrades_to_a_manual_advisory(make_finding, retriever, run_pipeline):
    bedrock = fake_bedrock(SAFE_S3_HCL)  # would be wrong for RDS: must never be called
    github, repo = fake_github()

    out = run_pipeline(rds_finding(make_finding), retriever, bedrock, github)

    assert out.modules == [] and out.generation is None and out.pr is None
    assert out.advisory is not None
    assert "RDS.8" in out.advisory and "manual" in out.advisory.lower()
    assert "Enable deletion protection" in out.advisory  # carries Security Hub's own guidance
    bedrock._client.invoke_model.assert_not_called()  # no LLM call, so nothing to hallucinate
    repo.create_pull.assert_not_called()


def test_pipeline_also_degrades_if_the_model_declines(make_finding, retriever, run_pipeline):
    """The model may itself answer NO_SAFE_REMEDIATION even when modules were retrieved."""
    import io
    import json
    from unittest.mock import MagicMock

    from rag_pipeline.bedrock_client import BedrockClient

    boto = MagicMock()
    payload = {"content": [{"type": "text", "text": "NO_SAFE_REMEDIATION"}], "stop_reason": "end_turn", "usage": {}}
    boto.invoke_model.return_value = {"body": io.BytesIO(json.dumps(payload).encode())}
    github, repo = fake_github()

    out = run_pipeline(make_finding(), retriever, BedrockClient(client=boto), github)

    assert out.generation.declined and out.advisory is not None and out.pr is None
    repo.create_pull.assert_not_called()
