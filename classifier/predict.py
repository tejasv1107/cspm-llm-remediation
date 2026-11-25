"""Classify a single finding using the model in the MLflow registry."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import numpy as np

from classifier.feature_engineering import FEATURE_COLUMNS, extract_features
from classifier.labeller import URGENCY_ORDER, Urgency, label_finding
from ingestion.schema import FindingRecord

logger = logging.getLogger(__name__)

DEFAULT_MODEL_NAME = os.getenv("MLFLOW_MODEL_NAME", "cspm-urgency-classifier")
DEFAULT_ALIAS = os.getenv("MLFLOW_MODEL_ALIAS", "champion")
DEFAULT_MODEL_URI = f"models:/{DEFAULT_MODEL_NAME}@{DEFAULT_ALIAS}"


@dataclass
class Prediction:
    """Classifier output for one finding."""

    label: Urgency
    probabilities: dict[str, float]
    top_features: list[tuple[str, float]] = field(default_factory=list)  # (feature, SHAP value)
    source: str = "model"  # "model" or "rules" (fallback)


def load_registered_model(model_uri: str = DEFAULT_MODEL_URI) -> Any:
    """Load an XGBoost model from the MLflow registry (default: the ``champion`` alias)."""
    import mlflow
    import mlflow.xgboost

    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "sqlite:///mlflow.db"))
    return mlflow.xgboost.load_model(model_uri)


class UrgencyClassifier:
    """Wraps model loading, prediction, SHAP explanation and a rule-based fallback."""

    def __init__(
        self,
        model: Any | None = None,
        model_uri: str | None = DEFAULT_MODEL_URI,
        fallback_to_rules: bool = True,
    ) -> None:
        """Pass ``model`` directly, or a ``model_uri`` to load from the registry.

        ``model_uri=None`` with no ``model`` skips loading and uses the rule-based labeller.
        """
        self.fallback_to_rules = fallback_to_rules
        self._explainer = None
        self.model = model
        if self.model is None and model_uri:
            try:
                self.model = load_registered_model(model_uri)
            except Exception:  # noqa: BLE001 - registry down / no model yet
                if not fallback_to_rules:
                    raise
                logger.warning("Could not load %s; using rule-based fallback", model_uri, exc_info=True)

    def classify(self, record: FindingRecord, now: datetime | None = None, explain: bool = True) -> Prediction:
        """Predict the urgency of ``record`` (top-3 SHAP features included when ``explain``)."""
        if self.model is None:
            decision = label_finding(record, now)
            return Prediction(decision.label, {u.value: float(u is decision.label) for u in URGENCY_ORDER},
                              source="rules")

        row = extract_features(record, now).to_frame().T[FEATURE_COLUMNS]
        proba = self.model.predict_proba(row)[0]
        idx = int(np.argmax(proba))
        prediction = Prediction(
            label=URGENCY_ORDER[idx],
            probabilities={u.value: float(p) for u, p in zip(URGENCY_ORDER, proba)},
        )
        if explain:
            prediction.top_features = self._top_features(row, idx)
        return prediction

    def _top_features(self, row, class_index: int, k: int = 3) -> list[tuple[str, float]]:
        import shap

        if self._explainer is None:
            self._explainer = shap.TreeExplainer(self.model)
        values = self._explainer.shap_values(row)
        values = np.stack(values, axis=-1) if isinstance(values, list) else np.asarray(values)
        contrib = values[0, :, class_index]
        order = np.argsort(-np.abs(contrib))[:k]
        return [(FEATURE_COLUMNS[i], float(contrib[i])) for i in order]


if __name__ == "__main__":  # pragma: no cover
    print(f"Default model URI: {DEFAULT_MODEL_URI}")
