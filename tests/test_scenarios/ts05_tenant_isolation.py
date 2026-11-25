"""TS-05: two clients processed simultaneously -> no cross-contamination."""

from __future__ import annotations

import re
import threading
from concurrent.futures import ThreadPoolExecutor

from conftest import SAFE_S3_HCL, fake_bedrock, fake_github, passing_validation

CLIENTS = {
    "111111111111": "alpha-payroll",
    "222222222222": "beta-ledger",
}


def _finding_for(make_finding, account_id: str, bucket: str):
    return make_finding(
        Id=f"arn:aws:securityhub:ap-south-1:{account_id}:subscription/x/S3.8/finding/{account_id}",
        AwsAccountId=account_id,
        Resources=[{"Type": "AwsS3Bucket", "Id": f"arn:aws:s3:::{bucket}", "Region": "ap-south-1",
                    "Tags": {"Environment": "prod"}}],
    )


def _echo_bucket_hcl(user_prompt: str) -> str:
    """Fake model: writes HCL for whichever bucket appears in the prompt it was given."""
    bucket = re.search(r"resource_arn: arn:aws:s3:::(\S+)", user_prompt).group(1)
    return SAFE_S3_HCL.replace("{bucket}", bucket)


def test_concurrent_clients_do_not_cross_contaminate(make_finding, retriever, run_pipeline):
    findings = {acct: _finding_for(make_finding, acct, bucket) for acct, bucket in CLIENTS.items()}
    # The barrier holds each thread inside the Bedrock call until both arrive: real overlap.
    bedrock = fake_bedrock(_echo_bucket_hcl, barrier=threading.Barrier(2))
    github, repo = fake_github()
    always_valid = lambda hcl: passing_validation()  # noqa: E731

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            acct: pool.submit(run_pipeline, f, retriever, bedrock, github, always_valid)
            for acct, f in findings.items()
        }
        outcomes = {acct: fut.result(timeout=30) for acct, fut in futures.items()}

    for acct, bucket in CLIENTS.items():
        other_acct, other_bucket = next((a, b) for a, b in CLIENTS.items() if a != acct)
        out = outcomes[acct]
        assert out.pr is not None and out.pr.created

        # prompt sent to the model contains only this client's data
        assert bucket in out.bundle.user and f"`{acct}`" not in out.bundle.user  # own bucket, no raw ids leaked
        assert other_bucket not in out.bundle.user and other_acct not in out.bundle.user

        # generated code is for this client's bucket only
        assert bucket in out.generation.hcl and other_bucket not in out.generation.hcl

        # repository artefacts are namespaced per client
        assert out.pr.path.startswith(f"remediations/{acct}/") and other_acct not in out.pr.path
        assert out.pr.branch.startswith(f"cspm/{acct}/") and other_acct not in out.pr.branch

    # distinct branches, PRs and files
    assert len({o.pr.branch for o in outcomes.values()}) == 2
    assert len({o.pr.number for o in outcomes.values()}) == 2
    assert repo.create_pull.call_count == 2

    # each committed file and each PR body mentions only its own client
    for call in repo.create_file.call_args_list:
        path, _, content = call.args
        owner = next(a for a in CLIENTS if f"remediations/{a}/" in path)
        other = next(b for a, b in CLIENTS.items() if a != owner)
        assert CLIENTS[owner] in content and other not in content
    for call in repo.create_pull.call_args_list:
        body = call.kwargs["body"]
        owners = [a for a in CLIENTS if f"`{a}`" in body]
        assert len(owners) == 1, "PR body must reference exactly one client"

    # each Bedrock invocation saw exactly one client's bucket
    assert len(bedrock.calls) == 2
    for call in bedrock.calls:
        assert sum(bucket in call["user"] for bucket in CLIENTS.values()) == 1
