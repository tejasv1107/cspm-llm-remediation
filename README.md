# cspm-llm-remediation

An AI-driven Cloud Security Posture Management (CSPM) system. It ingests **AWS Security Hub** findings,
classifies their urgency with **XGBoost + SHAP**, generates **Terraform** remediation code with a **RAG pipeline**
(**ChromaDB** + **Amazon Bedrock**, Claude 3 Sonnet), and delivers each fix as a **GitHub pull request** through a
human approval workflow.

```
Security Hub ─► ingestion ─► classifier ─► rag_pipeline ─────────► approval_workflow ─► GitHub PR ─► human review
 (ASFF)         normalise     XGBoost       retrieve modules         PR + Slack +
                anonymise     + SHAP        generate (Bedrock)       DynamoDB feedback
                                            validate: terraform validate → tflint → OPA
```

Full description: [docs/architecture.md](docs/architecture.md).

## Repository layout

| Path | Purpose |
|---|---|
| `ingestion/` | Poll Security Hub, normalise ASFF to `FindingRecord`, anonymise |
| `classifier/` | Features, rule-based labeller, XGBoost training (SMOTE, 5-fold CV, MLflow), SHAP evaluation, prediction |
| `rag_pipeline/` | Module indexer, retriever, prompt builder, Bedrock client, validator |
| `approval_workflow/` | GitHub PRs, Slack notifications, DynamoDB feedback log |
| `evaluation/` | Baseline capture (Lambda), MRR evaluator, MTTR analyser |
| `dashboard/` | Streamlit app |
| `terraform_modules/` | Five reviewed remediation modules ([list](terraform_modules/README.md)) |
| `opa_policies/` | Safety policy (no `0.0.0.0/0` ingress, no wildcard IAM, no `force_destroy`) |
| `data/` | `raw/`, `anonymised/`, `labelled/` are gitignored; `ground_truth/` is tracked |
| `notebooks/` | EDA, classifier training, RAG evaluation, MTTR analysis |
| `tests/` | Unit tests and the six TS-0x scenario tests |
| `docs/` | Architecture, schema, labelling methodology, evaluation plan |

## Setup

Developed and tested on **Python 3.14** only. The pins in `requirements.txt` are recent releases, so use a
current Python (older interpreters were not tried).

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1          # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env                # then fill in real values (never commit .env)
```

External tools (not installable with pip) used by the validator and tests:

| Tool | Needed for | Behaviour if missing |
|---|---|---|
| `terraform` | `terraform validate` stage | Stage fails (fail closed) |
| `tflint` | lint stage | Stage fails (fail closed) |
| `opa` | safety-policy stage | Stage fails; `needs_opa` tests are skipped |

## Quick start

```bash
# 1. Index the Terraform modules (EMBEDDER=hash works offline; default downloads MiniLM)
python -m rag_pipeline.module_indexer

# 2. Export and label findings
python -m ingestion.security_hub_poller
python -m classifier.labeller --input data/anonymised/findings.jsonl

# 3. Train (or add --synthetic for a smoke test with generated data)
python -m classifier.train --data data/labelled/labelled_findings.csv

# 4. Evaluate retrieval and open the dashboard
python -m evaluation.mrr_evaluator
streamlit run dashboard/app.py
```

## Tests

```bash
pytest            # unit tests + scenarios TS-01..TS-06
```

Everything runs offline: AWS, Bedrock and GitHub are mocked, and retrieval uses the offline hashing embedder.
Tests that evaluate the real OPA policy need the `opa` binary on `PATH` and are skipped otherwise.

## Things to know before you rely on it

- **Bedrock model.** The default `BEDROCK_MODEL_ID` is `anthropic.claude-3-sonnet-20240229-v1:0`, as specified.
  Older Claude models are retired on a schedule, so confirm it is still enabled for your account and region
  in the Bedrock console; the ID is configurable through `.env`.
- **Silver labels.** The classifier is trained on rule-derived labels, so its near-perfect scores measure rule
  recovery rather than analyst agreement. See [docs/labelling_methodology.md](docs/labelling_methodology.md).
- **Ground truth is seed data.** `data/ground_truth/ground_truth.json` (104 findings, covering all 11
  `terraform_modules/`) is a starting set; replace it with expert-labelled real findings before reporting MRR.
- **Retrieval thresholds are per embedder.** Each embedder carries a `default_min_similarity` below which an
  unrelated finding retrieves nothing (graceful degradation). The MiniLM value (0.5) was fitted on only five
  negative examples with a thin margin, and the Titan value is uncalibrated. Re-tune both against real ground
  truth (`notebooks/03_rag_evaluation.ipynb` has a threshold sweep).
- **No orchestrator yet.** `tests/conftest.py::run_pipeline` shows the intended end-to-end flow; a production
  entry point still needs to be written.
- **Windows path length.** MLflow nests artefacts deeply. Under a long project path
  (OneDrive folders are long) you can hit `MAX_PATH`; enable Windows long paths or point
  `MLFLOW_TRACKING_URI` / the artefact root at a short directory such as `C:\mlflow`.
