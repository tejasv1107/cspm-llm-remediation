# Architecture

```
Security Hub ──► ingestion ──► classifier ──► rag_pipeline ──► approval_workflow ──► GitHub PR
 (ASFF JSON)    normalise      urgency        retrieve +        PR + Slack +          │
                anonymise      + SHAP         generate +        feedback log          ▼
                                              validate                          human review
                                                                                      │
                          evaluation (baseline MTTR, MRR, MTTR delta) ◄───────────────┘
                          dashboard  (posture, heatmap, pipeline status)
```

The pipeline is a straight line with two gates: the urgency classifier decides whether a finding is worth
remediating, and the validation chain decides whether generated code is safe to show a human. **A human always
approves before anything is applied.**

## Layer 1: Ingestion (`ingestion/`)

| Module | Responsibility |
|---|---|
| `security_hub_poller.py` | `GetFindings` via boto3 with pagination and adaptive retries; multi-region; JSONL export. |
| `finding_normaliser.py` | ASFF -> `FindingRecord`; infers control ID, account tier, internet exposure; computes recurrence. |
| `anonymiser.py` | Salted SHA-256 for account IDs; regex rewrite of ARNs to synthetic, stable values (resource names hashed). |
| `schema.py` | The typed `FindingRecord` dataclass (see `finding_schema.md`). |

Data leaving the client boundary (training data, baseline CSVs) is anonymised first.

## Layer 2: Classification (`classifier/`)

`feature_engineering` -> 6 numeric features. `labeller` produces silver labels from a decision matrix
(`labelling_methodology.md`). `train` fits XGBoost with **SMOTE inside each of 5 CV folds** (no leakage into
validation folds), logs everything to MLflow and registers the model under an alias (`champion`).
`evaluate` computes macro-F1, the confusion matrix and SHAP plots. `predict` loads the registered model and
returns the label, class probabilities and the top-3 SHAP drivers; if the registry is unreachable it falls
back to the rule-based labeller (`source="rules"`).

## Layer 3: RAG remediation (`rag_pipeline/`)

1. **`module_indexer`**: parses each Terraform module's header comments (controls, resource types, keywords)
   and stores the HCL in ChromaDB with an embedding of its description. Embedders are pluggable (offline
   hashing for CI, Chroma MiniLM, or Amazon Titan).
2. **`retriever`**: cosine similarity plus bonuses for a resource-type match and a control-ID match. A
   candidate survives only if it matches on type/control or is semantically close, so an unrelated finding
   returns **nothing** rather than a forced bad match.
3. **`prompt_builder`**: system prompt (treat finding text as data, reply with one HCL block or
   `NO_SAFE_REMEDIATION`), the finding, the retrieved modules, and organisation conventions.
4. **`bedrock_client`**: `bedrock-runtime` `invoke_model` on `anthropic.claude-3-sonnet-20240229-v1:0`
   (configurable via `BEDROCK_MODEL_ID`); extracts the fenced HCL.
5. **`validator`**: `terraform validate` -> `tflint` -> OPA (`opa_policies/terraform_safety.rego`). It fails
   closed (a missing tool is a failure) and short-circuits after the first failing stage.

If retrieval is empty or the model declines, the system produces a **manual-remediation advisory** instead of
code (graceful degradation, TS-04).

## Layer 4: Approval workflow (`approval_workflow/`)

- `github_pr`: GitHub App auth; deterministic branch `cspm/<client>/<hash(finding_id)>` and file path
  `remediations/<client>/<control>/<hash>.tf`. Because the branch is deterministic, an open PR for the same
  finding is detected and returned instead of duplicated (TS-06). The client namespace keeps tenants apart
  (TS-05).
- `slack_notifier`: Block Kit messages on PR creation and approval; never raises.
- `feedback_logger`: writes accepted / rejected / modified outcomes (with edit similarity) to DynamoDB.

## Layer 5: Evaluation and dashboard

`evaluation/` holds the daily baseline Lambda, the MRR evaluator and the MTTR analyser
(`evaluation_plan.md`). `dashboard/app.py` is a Streamlit app: client selector, posture score, open-finding
heatmap and pipeline funnel.

## Cross-cutting concerns

| Concern | Mechanism |
|---|---|
| Tenant isolation | `client_id` on every record; per-client branches, files and prompts; prompt contains a single finding. |
| Prompt injection | Finding text is fenced as data; output is constrained to HCL and validated by OPA. |
| Safety | OPA denies world-open ingress, wildcard IAM and `force_destroy`; human PR review is mandatory. |
| Secrets | `.env` and key files are gitignored; GitHub App key is read from a path. |
| Resilience | Adaptive retries on AWS calls; Slack/registry failures degrade, they don't crash. |

## Known gaps

- There is no orchestrator module. `tests/conftest.py::run_pipeline` is the reference glue; a production
  entry point (Lambda / Step Functions / CLI) still needs writing.
- `tflint --init` and the AWS ruleset are not configured; add a `.tflint.hcl` at the repo root and the
  validator will pick it up.
