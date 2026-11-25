# Evaluation plan

Four questions, each with a metric, a comparison, a null hypothesis and the code that computes it.

| # | Question | Component |
|---|---|---|
| E1 | Can the classifier prioritise findings the way an analyst would? | `classifier/` |
| E2 | Does retrieval surface the right Terraform module? | `rag_pipeline/retriever.py` |
| E3 | Is the generated Terraform valid, safe and acceptable to reviewers? | `rag_pipeline/`, `approval_workflow/` |
| E4 | Does the system shorten time-to-remediate? | `evaluation/` |

## E1. Urgency classification

- **Metrics:** macro-F1 (primary; the classes are imbalanced), per-class precision/recall, recall on
  `REMEDIATE_NOW`, confusion matrix. Report mean and standard deviation over the 5 CV folds plus a held-out
  20% split.
- **Explainability:** global mean-|SHAP| and per-class beeswarm plots (`classifier/evaluate.py`).
- **Baselines:** (a) majority class; (b) the rule-based labeller itself; (c) logistic regression.
- **Validity:** silver-label circularity is described in `labelling_methodology.md` section 7. The headline
  number must come from an **analyst-labelled subset** (>= 200 findings), with Cohen's kappa
  (analyst vs. rules) reported alongside.
- **H0-1:** the XGBoost model's macro-F1 on the analyst-labelled subset is no better than the rule-based
  labeller's. *Test:* paired bootstrap over findings, alpha = 0.05.

## E2. Retrieval quality

- **Data:** `data/ground_truth/ground_truth.json`. Currently **seed data**: 99 positives (one finding per
  Security Hub control each `terraform_modules/` module covers, 9 per module across all 11 modules), 5
  negatives with no module. Replace it with real anonymised findings labelled by an expert before reporting
  results.
- **Metrics:** MRR@3 (primary), Hit@1, Hit@3, and `no_module_accuracy` (share of negatives that correctly
  retrieve nothing). `evaluation/mrr_evaluator.py`.
- **Baselines:** keyword-only (resource-type match); hashing embedder; MiniLM; Titan embeddings.
- **H0-2:** MRR@3 of the hybrid retriever is no higher than the resource-type-only baseline.
  *Test:* paired bootstrap on per-finding reciprocal ranks.
- **Caveat:** with only five modules the task is easy and MRR saturates. Report it alongside module-corpus
  size and grow the corpus before drawing conclusions.

## E3. Generation quality and reviewer acceptance

- **Metrics**
  - *Validity rate:* share of generated files that pass `terraform validate`, `tflint` and OPA, per stage
    and cumulatively.
  - *Safety block rate:* share rejected by OPA (also run against a red-team set of deliberately dangerous
    prompts; scenario TS-03).
  - *Acceptance:* PR outcome distribution (accepted / modified / rejected) from DynamoDB, and the
    `edit_similarity` of modified PRs.
  - *Graceful degradation:* on findings with no module, share that produce an advisory rather than code
    (TS-04).
- **Comparison:** the same findings with the LLM given no retrieved modules (ablation).
- **H0-3:** retrieval-augmented generation does not raise the cumulative validity rate over the no-retrieval
  ablation. *Test:* McNemar's test on paired pass/fail outcomes.

## E4. Time to remediate (MTTR)

- **Design:** before/after. `evaluation/baseline_capture.py` (Lambda, daily) records finding timestamps and
  `WorkflowStatus` for the baseline period; the same capture runs after go-live. `evaluation/mttr_analyser.py`
  computes TTR = resolved time minus `created_at`.
- **Metrics:** mean and median MTTR overall and per severity; % change.
- **H0-4:** MTTR after deployment is >= MTTR before. *Test:* one-sided Mann-Whitney U (TTR is skewed), alpha
  = 0.05.
- **Threats:** ASFF has no "resolved at" field, so `UpdatedAt` on a RESOLVED finding is a proxy;
  seasonality and change of finding mix between periods; only findings observed as resolved are counted
  (right-censoring), so also report the unresolved share; and remediation may happen without the tool.

## Scenario tests (functional)

| ID | Behaviour | File |
|---|---|---|
| TS-01 | Critical prod finding -> `REMEDIATE_NOW` -> valid PR | `tests/test_scenarios/ts01_happy_path.py` |
| TS-02 | Same finding, non-prod -> lower urgency | `ts02_nonprod.py` |
| TS-03 | Dangerous Terraform is rejected by OPA | `ts03_opa_block.py` |
| TS-04 | No matching module -> advisory, no code | `ts04_no_module.py` |
| TS-05 | Two clients concurrently, no cross-contamination | `ts05_tenant_isolation.py` |
| TS-06 | Duplicate finding -> no second PR | `ts06_duplicate.py` |

## Reproducibility

Fixed seeds (`random_state=42`); a pinned `requirements.txt`; MLflow logs parameters, metrics, plots and the
model; the ground-truth file is version-controlled.
