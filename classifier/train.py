"""Train the XGBoost urgency classifier: SMOTE inside 5-fold CV, tracked in MLflow."""

from __future__ import annotations

import argparse
import logging
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import mlflow
import mlflow.xgboost
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from mlflow.tracking import MlflowClient
from sklearn.metrics import f1_score
from sklearn.model_selection import StratifiedKFold, train_test_split
from xgboost import XGBClassifier

from classifier.evaluate import evaluate_model, plot_confusion_matrix, plot_shap_summary
from classifier.feature_engineering import FEATURE_COLUMNS
from classifier.labeller import URGENCY_ORDER, label_records
from ingestion.schema import AccountTier, FindingRecord, Severity, WorkflowStatus

logger = logging.getLogger(__name__)

DEFAULT_MODEL_NAME = "cspm-urgency-classifier"
DEFAULT_ALIAS = "champion"
LABEL_TO_INT = {u.value: i for i, u in enumerate(URGENCY_ORDER)}

DEFAULT_PARAMS: dict[str, Any] = {
    "n_estimators": 200,
    "max_depth": 5,
    "learning_rate": 0.1,
    "subsample": 0.9,
    "colsample_bytree": 0.9,
    "objective": "multi:softprob",
    "eval_metric": "mlogloss",
    "random_state": 42,
    "n_jobs": 1,
}


# --------------------------------------------------------------------------- data
def load_labelled(path: str | Path) -> tuple[pd.DataFrame, pd.Series]:
    """Load ``labelled_findings.csv`` -> (features, integer labels)."""
    frame = pd.read_csv(path, index_col=0)
    return frame[FEATURE_COLUMNS], frame["urgency"].map(LABEL_TO_INT).astype(int)


def make_synthetic_labelled_data(n: int = 2000, seed: int = 42) -> tuple[pd.DataFrame, pd.Series]:
    """Generate ``n`` random findings and auto-label them (smoke tests / demos only)."""
    rng = np.random.default_rng(seed)
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    severities = list(Severity)
    types = ["AwsS3Bucket", "AwsEc2SecurityGroup", "AwsIamUser", "AwsCloudTrailTrail",
             "AwsEc2Volume", "AwsRdsDbInstance", "AwsKmsKey", "AwsAccount"]
    records = []
    for i in range(n):
        created = now - timedelta(days=float(rng.exponential(30)))
        records.append(
            FindingRecord(
                finding_id=f"syn-{i}",
                account_id="000000000000",
                severity=severities[int(rng.choice(5, p=[0.05, 0.2, 0.35, 0.28, 0.12]))],
                title="synthetic finding",
                resource_type=str(rng.choice(types)),
                resource_arn=f"arn:aws:s3:::syn-{i}",
                region="ap-south-1",
                created_at=created,
                updated_at=now,
                workflow_status=WorkflowStatus.NEW,
                account_tier=AccountTier.PROD if rng.random() < 0.4 else AccountTier.NON_PROD,
                is_internet_exposed=bool(rng.random() < 0.25),
                recurrence_count=int(1 + rng.poisson(1.5)),
            )
        )
    frame = label_records(records, now=now)
    return frame[FEATURE_COLUMNS], frame["urgency"].map(LABEL_TO_INT).astype(int)


# ------------------------------------------------------------------------- model
def _smote_k(y: pd.Series) -> int:
    """SMOTE needs k_neighbors < smallest class size."""
    return max(1, min(5, int(y.value_counts().min()) - 1))


def build_pipeline(y_train: pd.Series, params: dict[str, Any] | None = None) -> ImbPipeline:
    """SMOTE -> XGBoost. Resampling happens only on the data passed to ``fit``."""
    merged = {**DEFAULT_PARAMS, **(params or {})}
    return ImbPipeline(
        [
            ("smote", SMOTE(k_neighbors=_smote_k(y_train), random_state=merged["random_state"])),
            ("xgb", XGBClassifier(num_class=len(URGENCY_ORDER), **merged)),
        ]
    )


def cross_validate(
    X: pd.DataFrame, y: pd.Series, params: dict[str, Any] | None = None, n_splits: int = 5
) -> dict[str, Any]:
    """Stratified k-fold CV. SMOTE is fit per training fold, so validation folds stay untouched."""
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    scores: list[float] = []
    for fold, (tr, va) in enumerate(skf.split(X, y), start=1):
        pipe = build_pipeline(y.iloc[tr], params)
        pipe.fit(X.iloc[tr], y.iloc[tr])
        score = f1_score(y.iloc[va], pipe.predict(X.iloc[va]), average="macro")
        scores.append(float(score))
        logger.info("fold %d macro-F1 = %.4f", fold, score)
    return {"fold_scores": scores, "mean": float(np.mean(scores)), "std": float(np.std(scores))}


def train(
    X: pd.DataFrame,
    y: pd.Series,
    params: dict[str, Any] | None = None,
    model_name: str = DEFAULT_MODEL_NAME,
    alias: str = DEFAULT_ALIAS,
    register: bool = True,
) -> dict[str, Any]:
    """CV + final fit + held-out evaluation, all logged to one MLflow run."""
    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "sqlite:///mlflow.db"))
    mlflow.set_experiment("cspm-urgency-classifier")
    merged = {**DEFAULT_PARAMS, **(params or {})}

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    with mlflow.start_run() as run:
        mlflow.log_params({**merged, "n_train": len(X_train), "n_test": len(X_test), "cv_folds": 5})
        cv = cross_validate(X_train, y_train, merged, n_splits=5)
        for i, s in enumerate(cv["fold_scores"], start=1):
            mlflow.log_metric("cv_macro_f1", s, step=i)
        mlflow.log_metrics({"cv_macro_f1_mean": cv["mean"], "cv_macro_f1_std": cv["std"]})

        # Final model: SMOTE the full training split, then fit a plain XGBClassifier so the
        # logged artefact has no imblearn dependency at inference time.
        smote = SMOTE(k_neighbors=_smote_k(y_train), random_state=merged["random_state"])
        X_res, y_res = smote.fit_resample(X_train, y_train)
        model = XGBClassifier(num_class=len(URGENCY_ORDER), **merged)
        model.fit(X_res, y_res)

        metrics = evaluate_model(model, X_test, y_test)
        mlflow.log_metrics({"test_macro_f1": metrics["macro_f1"], "test_accuracy": metrics["accuracy"]})

        with tempfile.TemporaryDirectory() as tmp:
            plot_confusion_matrix(y_test, model.predict(X_test), Path(tmp) / "confusion_matrix.png")
            plot_shap_summary(model, X_test, tmp)
            mlflow.log_artifacts(tmp, artifact_path="evaluation")

        info = mlflow.xgboost.log_model(
            model,
            name="model",
            input_example=X_train.head(5),
            registered_model_name=model_name if register else None,
        )
        version = getattr(info, "registered_model_version", None)
        if register and version:
            MlflowClient().set_registered_model_alias(model_name, alias, str(version))

    return {"run_id": run.info.run_id, "cv": cv, "test": metrics, "model": model, "version": version}


def main() -> None:  # pragma: no cover - thin CLI
    logging.basicConfig(level=logging.INFO)
    parser = argparse.ArgumentParser(description="Train the urgency classifier")
    parser.add_argument("--data", default="data/labelled/labelled_findings.csv")
    parser.add_argument("--synthetic", action="store_true", help="use generated data (smoke test)")
    parser.add_argument("--no-register", action="store_true")
    args = parser.parse_args()

    X, y = make_synthetic_labelled_data() if args.synthetic else load_labelled(args.data)
    result = train(X, y, register=not args.no_register)
    print(f"CV macro-F1: {result['cv']['mean']:.4f} +/- {result['cv']['std']:.4f}")
    print(f"Held-out macro-F1: {result['test']['macro_f1']:.4f}")


if __name__ == "__main__":  # pragma: no cover
    main()
