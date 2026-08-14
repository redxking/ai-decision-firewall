from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np

from .features import FEATURE_NAMES, extract_features, vectorize
from .schemas import IdentityCase
from .utils import read_jsonl, write_json


@dataclass(slots=True)
class ModelAssessment:
    compromise_probability: float
    model_version: str
    top_positive_factors: list[dict[str, float]]
    top_negative_factors: list[dict[str, float]]
    feature_values: dict[str, float]
    feature_trace: dict[str, list[str]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class LogisticRiskModel:
    """Small interpretable model used only to exercise the decision-control architecture."""

    def __init__(self) -> None:
        self.feature_names = list(FEATURE_NAMES)
        self.means = np.zeros(len(self.feature_names), dtype=float)
        self.scales = np.ones(len(self.feature_names), dtype=float)
        self.weights = np.zeros(len(self.feature_names), dtype=float)
        self.intercept = 0.0
        self.version = "synthetic-logistic-v0.1"
        self.training_metadata: dict[str, Any] = {}

    @staticmethod
    def _sigmoid(values: np.ndarray) -> np.ndarray:
        values = np.clip(values, -30.0, 30.0)
        return 1.0 / (1.0 + np.exp(-values))

    def fit(
        self,
        x: np.ndarray,
        y: np.ndarray,
        *,
        epochs: int = 3500,
        learning_rate: float = 0.045,
        l2: float = 0.012,
    ) -> dict[str, float]:
        if x.ndim != 2 or x.shape[1] != len(self.feature_names):
            raise ValueError("Unexpected training matrix shape.")
        if len(x) != len(y) or len(y) == 0:
            raise ValueError("Training features and labels must be non-empty and aligned.")

        self.means = x.mean(axis=0)
        self.scales = x.std(axis=0)
        self.scales[self.scales < 1e-8] = 1.0
        z = (x - self.means) / self.scales
        weights = np.zeros(z.shape[1], dtype=float)
        intercept = 0.0

        positives = max(1.0, float(y.sum()))
        negatives = max(1.0, float(len(y) - y.sum()))
        sample_weights = np.where(y > 0.5, len(y) / (2.0 * positives), len(y) / (2.0 * negatives))

        for _ in range(epochs):
            logits = z @ weights + intercept
            predictions = self._sigmoid(logits)
            error = (predictions - y) * sample_weights
            grad_w = (z.T @ error) / len(y) + l2 * weights
            grad_b = float(error.mean())
            weights -= learning_rate * grad_w
            intercept -= learning_rate * grad_b

        self.weights = weights
        self.intercept = intercept
        final_predictions = self._sigmoid(z @ weights + intercept)
        epsilon = 1e-12
        loss = float(-np.mean(y * np.log(final_predictions + epsilon) + (1.0 - y) * np.log(1.0 - final_predictions + epsilon)))
        accuracy = float(np.mean((final_predictions >= 0.5) == (y >= 0.5)))
        self.training_metadata = {
            "examples": int(len(y)),
            "epochs": epochs,
            "learning_rate": learning_rate,
            "l2": l2,
            "training_log_loss": round(loss, 8),
            "training_accuracy": round(accuracy, 8),
        }
        return {"log_loss": loss, "accuracy": accuracy}

    def predict_probability(self, features: dict[str, float]) -> tuple[float, np.ndarray]:
        x = np.asarray(vectorize(features), dtype=float)
        z = (x - self.means) / self.scales
        contributions = z * self.weights
        probability = float(self._sigmoid(np.asarray([contributions.sum() + self.intercept]))[0])
        return probability, contributions

    def assess(self, case: IdentityCase) -> ModelAssessment:
        features, trace = extract_features(case)
        probability, contributions = self.predict_probability(features)
        factor_rows = [
            {"feature": name, "contribution": round(float(value), 6), "value": round(float(features[name]), 6)}
            for name, value in zip(self.feature_names, contributions, strict=True)
        ]
        positives = sorted((row for row in factor_rows if row["contribution"] > 0), key=lambda row: row["contribution"], reverse=True)[:5]
        negatives = sorted((row for row in factor_rows if row["contribution"] < 0), key=lambda row: row["contribution"])[:5]
        return ModelAssessment(
            compromise_probability=round(probability, 8),
            model_version=self.version,
            top_positive_factors=positives,
            top_negative_factors=negatives,
            feature_values={key: round(value, 6) for key, value in features.items()},
            feature_trace=trace,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_type": "logistic_regression",
            "version": self.version,
            "feature_names": self.feature_names,
            "means": self.means.tolist(),
            "scales": self.scales.tolist(),
            "weights": self.weights.tolist(),
            "intercept": self.intercept,
            "training_metadata": self.training_metadata,
            "limitations": [
                "Trained entirely on synthetic data generated by the POC scenario engine.",
                "Not suitable for operational security decisions.",
                "The model is a replaceable recommender; it has no action authority.",
            ],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "LogisticRiskModel":
        model = cls()
        if list(value["feature_names"]) != list(FEATURE_NAMES):
            raise ValueError("Model feature schema does not match the running code.")
        model.version = str(value["version"])
        model.means = np.asarray(value["means"], dtype=float)
        model.scales = np.asarray(value["scales"], dtype=float)
        model.weights = np.asarray(value["weights"], dtype=float)
        model.intercept = float(value["intercept"])
        model.training_metadata = dict(value.get("training_metadata", {}))
        return model

    def save(self, path: str | Path) -> None:
        write_json(path, self.to_dict())

    @classmethod
    def load(cls, path: str | Path) -> "LogisticRiskModel":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def train_from_files(cases_path: str | Path, labels_path: str | Path, output_path: str | Path) -> LogisticRiskModel:
    cases = [IdentityCase.from_dict(row) for row in read_jsonl(cases_path)]
    labels_by_id = {row["case_id"]: bool(row["compromised"]) for row in read_jsonl(labels_path)}
    x_rows: list[list[float]] = []
    y_rows: list[float] = []
    for case in cases:
        features, _ = extract_features(case)
        x_rows.append(vectorize(features))
        y_rows.append(1.0 if labels_by_id[case.case_id] else 0.0)
    model = LogisticRiskModel()
    model.fit(np.asarray(x_rows, dtype=float), np.asarray(y_rows, dtype=float))
    model.save(output_path)
    return model


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the synthetic POC compromise-risk model.")
    parser.add_argument("--cases", required=True)
    parser.add_argument("--labels", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    model = train_from_files(args.cases, args.labels, args.output)
    print(json.dumps(model.training_metadata, indent=2))


if __name__ == "__main__":
    main()
