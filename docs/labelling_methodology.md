# Labelling methodology

*Dissertation appendix: decision matrix for auto-labelling findings.*

Implementation: [`classifier/labeller.py`](../classifier/labeller.py). Tests:
[`tests/test_labeller.py`](../tests/test_labeller.py).

## 1. Purpose and status of the labels

No analyst-labelled urgency data exists at project start. The rule-based labeller assigns each finding one of
four urgency classes so the classifier can be trained. These are **silver labels**: deterministic, reproducible
and auditable, but not human ground truth. Every label carries a `rule_id` and a plain-language rationale.

## 2. Classes

| Class | Meaning | Target action |
|---|---|---|
| `REMEDIATE_NOW` | Actively dangerous or high-impact in a business-critical context | Fix immediately; PR raised at once |
| `REMEDIATE_7D` | Material risk, not an emergency | Fix within seven days |
| `MONITOR` | Low risk in context | Track; revisit if context changes |
| `SUPPRESS` | No action needed | Hide from queues |

## 3. Inputs

| Input | Source field | Values |
|---|---|---|
| Severity | `severity` (ASFF `Severity.Label`) | CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL |
| Tier | `account_tier` (resource `Environment` tag or account map) | prod / non-prod |
| Exposure | `is_internet_exposed` (known exposure controls + text heuristics) | yes / no |
| Recurrence | `recurrence_count` (findings sharing account + control) | integer >= 1 |
| Age | `created_at` vs. reference time | days |
| Status | `workflow_status` | NEW, NOTIFIED, RESOLVED, SUPPRESSED |

## 4. Procedure

1. **R0: closed findings.** `RESOLVED` or `SUPPRESSED` findings are labelled `SUPPRESS` and evaluation stops.
2. **Base label** from the matrix below (severity x tier x exposure).
3. **Escalation** (never applied to INFORMATIONAL; at most one level in total):
   - **E1**: `recurrence_count >= 5` raises the label one level.
   - **E2**: otherwise, a *prod* finding open for more than 90 days raises the label one level.

Levels, lowest to highest: `SUPPRESS < MONITOR < REMEDIATE_7D < REMEDIATE_NOW`. Escalation is capped at
`REMEDIATE_NOW`.

## 5. Base decision matrix

Columns are tier / exposure: **P-X** = prod, internet-exposed; **P-I** = prod, internal; **N-X** = non-prod,
exposed; **N-I** = non-prod, internal.

| Severity | P-X | P-I | N-X | N-I |
|---|---|---|---|---|
| CRITICAL | NOW | NOW | NOW | 7D |
| HIGH | NOW | 7D | 7D | MONITOR |
| MEDIUM | 7D | MONITOR | MONITOR | MONITOR |
| LOW | MONITOR | MONITOR | MONITOR | SUPPRESS |
| INFORMATIONAL | SUPPRESS | SUPPRESS | SUPPRESS | SUPPRESS |

(NOW = `REMEDIATE_NOW`, 7D = `REMEDIATE_7D`.) `rule_id` format: `M-<SEV4>-<P|N>-<X|I>` plus `+E1` / `+E2`
when escalated, e.g. `M-HIGH-N-I+E1`.

## 6. Design rationale

- **Severity dominates, context modulates.** Tier and exposure move a finding by at most two levels, and never
  make a CRITICAL finding lower than `REMEDIATE_7D`.
- **Exposure counts only when real.** Controls that report *posture* (S3.1 / S3.8: Block Public Access not
  enabled) do not set `is_internet_exposed`; controls reporting an actual public resource (S3.2, EC2.13, ...)
  do.
- **Recurrence and age** capture systemic or neglected issues that severity alone understates.
- **Monotonicity:** holding the other inputs fixed, higher severity never yields lower urgency (unit-tested).

## 7. Threats to validity

1. **Circularity.** Labels are functions of the same features the classifier sees, so a tree model can
   reproduce the rules almost perfectly (synthetic-data smoke test: macro-F1 about 0.99). A high score against
   silver labels measures rule recovery, **not** agreement with security analysts.
2. **Remedy:** have at least one analyst label a stratified sample (recommended n >= 200) blind to the rule
   output, report Cohen's kappa between analyst and rules, and evaluate the model on that subset.
3. **Class imbalance:** REMEDIATE_NOW is rare in real data; SMOTE is applied inside cross-validation folds only.
4. **Threshold arbitrariness:** the 5-recurrence and 90-day thresholds are engineering judgements; run a
   sensitivity analysis and report it.
5. **Heuristic exposure flag:** it uses control IDs and keywords; false negatives lower urgency.
