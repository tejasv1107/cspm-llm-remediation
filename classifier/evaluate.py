"""Evaluate the urgency classifier: macro-F1, per-class report, confusion matrix, SHAP plots."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")  # headless: write PNGs, never open a window
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import shap  # noqa: E402
from sklearn.metrics import (  # noqa: E402
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)

from classifier.feature_engineering import FEATURE_COLUMNS  # noqa: E402
from classifier.labeller import URGENCY_ORDER  # noqa: E402

CLASS_NAMES = [u.value for u in URGENCY_ORDER]
_LABELS = list(range(len(CLASS_NAMES)))


def evaluate_model(model: Any, X: pd.DataFrame, y_true: pd.Series | np.ndarray) -> dict[str, Any]:
    """Macro/weighted F1, accuracy, per-class report and confusion matrix."""
    y_pred = model.predict(X)
    return {
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", labels=_LABELS, zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", labels=_LABELS, zero_division=0)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "report": classification_report(
            y_true, y_pred, labels=_LABELS, target_names=CLASS_NAMES, output_dict=True, zero_division=0
        ),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=_LABELS).tolist(),
    }


def plot_confusion_matrix(y_true, y_pred, out_path: str | Path) -> Path:
    """Save a row-normalised confusion matrix (recall per class on the diagonal)."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    ConfusionMatrixDisplay.from_predictions(
        y_true, y_pred, labels=_LABELS, display_labels=CLASS_NAMES,
        normalize="true", cmap="Blues", ax=ax, colorbar=False, values_format=".2f",
    )
    ax.set_title("Urgency classifier - confusion matrix (row-normalised)")
    plt.setp(ax.get_xticklabels(), rotation=25, ha="right")
    fig.tight_layout()
    fig.savefig(out_path, dpi=150)
    plt.close(fig)
    return out_path


def shap_values_for(model: Any, X: pd.DataFrame) -> np.ndarray:
    """SHAP values shaped ``(n_samples, n_features, n_classes)`` across SHAP versions."""
    values = shap.TreeExplainer(model).shap_values(X)
    if isinstance(values, list):  # older SHAP: list of (n, f) per class
        values = np.stack(values, axis=-1)
    return np.asarray(values)


def plot_shap_summary(model: Any, X: pd.DataFrame, out_dir: str | Path) -> list[Path]:
    """Save a global mean-|SHAP| bar chart plus one beeswarm per urgency class."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    values = shap_values_for(model, X[FEATURE_COLUMNS])
    paths: list[Path] = []

    global_importance = np.abs(values).mean(axis=(0, 2))
    order = np.argsort(global_importance)
    fig, ax = plt.subplots(figsize=(6.5, 4))
    ax.barh(np.array(FEATURE_COLUMNS)[order], global_importance[order], color="#2a78d6")
    ax.set_xlabel("mean |SHAP value| (all classes)")
    ax.set_title("Feature importance")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    paths.append(out_dir / "shap_global_importance.png")
    fig.savefig(paths[-1], dpi=150)
    plt.close(fig)

    for k, name in enumerate(CLASS_NAMES):
        shap.summary_plot(values[:, :, k], X[FEATURE_COLUMNS], show=False, plot_size=(7, 4))
        plt.title(f"SHAP - {name}")
        plt.tight_layout()
        paths.append(out_dir / f"shap_{name.lower()}.png")
        plt.savefig(paths[-1], dpi=150)
        plt.close("all")
    return paths


def main() -> None:  # pragma: no cover - thin CLI
    import mlflow.xgboost

    from classifier.predict import DEFAULT_MODEL_URI
    from classifier.train import load_labelled

    parser = argparse.ArgumentParser(description="Evaluate a registered urgency model")
    parser.add_argument("--model-uri", default=DEFAULT_MODEL_URI)
    parser.add_argument("--data", default="data/labelled/labelled_findings.csv")
    parser.add_argument("--out", default="artifacts/evaluation")
    args = parser.parse_args()

    X, y = load_labelled(args.data)
    model = mlflow.xgboost.load_model(args.model_uri)
    metrics = evaluate_model(model, X, y)
    print(f"macro-F1={metrics['macro_f1']:.4f}  accuracy={metrics['accuracy']:.4f}")
    print(pd.DataFrame(metrics["report"]).T.round(3).to_string())
    plot_confusion_matrix(y, model.predict(X), Path(args.out) / "confusion_matrix.png")
    plot_shap_summary(model, X, args.out)


if __name__ == "__main__":  # pragma: no cover
    main()
