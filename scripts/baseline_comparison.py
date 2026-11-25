"""Comparative baseline experiment for Objective O1 / Section 9.1 of the dissertation.

Compares three models on the same stratified 5-fold CV splits and the same held-out
test set: a severity-only rule baseline, a logistic-regression baseline, and the
proposed XGBoost classifier. Paired across identical fold indices so a paired t-test
on macro-F1 is valid.

Run from the project root: python -m scripts.baseline_comparison
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from scipy import stats
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from classifier.train import DEFAULT_PARAMS, _smote_k, load_labelled
from classifier.labeller import URGENCY_ORDER

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

import sys
DATA_PATH = sys.argv[1] if len(sys.argv) > 1 else "data/labelled/labelled_findings.csv"
RANDOM_STATE = 42
N_SPLITS = 5


class SeverityOnlyBaseline:
    """Baseline 1: predicts urgency from the majority training label per severity_num.

    Mirrors how a severity-only CSPM tool (native AWS Security Hub severity,
    Prisma Cloud, Wiz) would triage: tier, exposure and recurrence are ignored.
    """

    def fit(self, X: pd.DataFrame, y: pd.Series) -> "SeverityOnlyBaseline":
        self.global_mode_ = int(y.mode().iloc[0])
        table: dict[int, int] = {}
        for sev, grp in y.groupby(X["severity_num"]):
            table[int(sev)] = int(grp.mode().iloc[0])
        self.table_ = table
        return self

    def predict(self, X: pd.DataFrame) -> np.ndarray:
        return np.array([self.table_.get(int(s), self.global_mode_) for s in X["severity_num"]])


def build_logreg_pipeline(y_train: pd.Series) -> ImbPipeline:
    return ImbPipeline(
        [
            ("smote", SMOTE(k_neighbors=_smote_k(y_train), random_state=RANDOM_STATE)),
            ("scale", StandardScaler()),
            ("logreg", LogisticRegression(max_iter=2000, random_state=RANDOM_STATE)),
        ]
    )


def build_xgb_pipeline(y_train: pd.Series) -> ImbPipeline:
    return ImbPipeline(
        [
            ("smote", SMOTE(k_neighbors=_smote_k(y_train), random_state=RANDOM_STATE)),
            ("xgb", XGBClassifier(num_class=len(URGENCY_ORDER), **DEFAULT_PARAMS)),
        ]
    )


MODEL_BUILDERS = {
    "rule_based_severity_only": lambda y_train: SeverityOnlyBaseline(),
    "logistic_regression": build_logreg_pipeline,
    "xgboost_proposed": build_xgb_pipeline,
}


def cross_validate_all(X: pd.DataFrame, y: pd.Series) -> dict[str, list[float]]:
    """Run every model on the *same* fold indices so paired tests are valid."""
    skf = StratifiedKFold(n_splits=N_SPLITS, shuffle=True, random_state=RANDOM_STATE)
    folds = list(skf.split(X, y))
    scores: dict[str, list[float]] = {name: [] for name in MODEL_BUILDERS}

    for fold, (tr, va) in enumerate(folds, start=1):
        X_tr, X_va = X.iloc[tr], X.iloc[va]
        y_tr, y_va = y.iloc[tr], y.iloc[va]
        for name, builder in MODEL_BUILDERS.items():
            model = builder(y_tr)
            model.fit(X_tr, y_tr)
            score = f1_score(y_va, model.predict(X_va), average="macro")
            scores[name].append(float(score))
        logger.info(
            "fold %d: rule=%.4f  logreg=%.4f  xgboost=%.4f",
            fold, scores["rule_based_severity_only"][-1],
            scores["logistic_regression"][-1], scores["xgboost_proposed"][-1],
        )
    return scores


def held_out_eval(X_train, y_train, X_test, y_test) -> dict[str, dict[str, float]]:
    results: dict[str, dict[str, float]] = {}
    for name, builder in MODEL_BUILDERS.items():
        model = builder(y_train)
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        results[name] = {
            "macro_f1": float(f1_score(y_test, pred, average="macro")),
            "accuracy": float(accuracy_score(y_test, pred)),
        }
    return results


def paired_ttest(scores: dict[str, list[float]]) -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {}
    xgb = scores["xgboost_proposed"]
    for name in ("rule_based_severity_only", "logistic_regression"):
        t, p = stats.ttest_rel(xgb, scores[name])
        out[f"xgboost_vs_{name}"] = {"t": float(t), "p": float(p)}
    return out


def main() -> None:
    X, y = load_labelled(DATA_PATH)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )

    logger.info("=== 5-fold stratified CV on training split (n=%d) ===", len(X_train))
    cv_scores = cross_validate_all(X_train, y_train)

    cv_summary = {
        name: {"mean": float(np.mean(s)), "std": float(np.std(s)), "folds": s}
        for name, s in cv_scores.items()
    }

    logger.info("=== Held-out test evaluation (n=%d) ===", len(X_test))
    test_results = held_out_eval(X_train, y_train, X_test, y_test)

    logger.info("=== Paired t-test (XGBoost vs each baseline, across 5 CV folds) ===")
    significance = paired_ttest(cv_scores)

    report = {
        "data_path": DATA_PATH,
        "n_train": len(X_train),
        "n_test": len(X_test),
        "label_distribution_train": {int(k): int(v) for k, v in Counter(y_train).items()},
        "cv_macro_f1": cv_summary,
        "held_out_macro_f1": test_results,
        "significance_paired_ttest": significance,
    }

    out_name = "baseline_comparison_results_real.json" if "real" in DATA_PATH else "baseline_comparison_results.json"
    out_path = Path("docs/evaluation") / out_name
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2))

    print("\n--- Summary ---")
    for name, s in cv_summary.items():
        print(f"{name:28s} CV macro-F1 = {s['mean']:.4f} +/- {s['std']:.4f}   "
              f"held-out = {test_results[name]['macro_f1']:.4f}")
    for k, v in significance.items():
        print(f"{k}: t={v['t']:.3f}, p={v['p']:.4f}")
    print(f"\nFull results written to {out_path}")


if __name__ == "__main__":
    main()
