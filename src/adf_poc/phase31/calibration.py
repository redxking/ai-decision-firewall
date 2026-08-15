from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np


def _logit(score: float) -> float:
    bounded = min(max(float(score), 1e-8), 1.0 - 1e-8)
    return math.log(bounded / (1.0 - bounded))


def _sigmoid(value: float) -> float:
    bounded = min(max(value, -30.0), 30.0)
    return 1.0 / (1.0 + math.exp(-bounded))


@dataclass(frozen=True, slots=True)
class PlattCalibrator:
    coefficient: float
    intercept: float
    input_mean: float
    input_scale: float
    epochs: int
    learning_rate: float
    l2: float

    @classmethod
    def fit(
        cls,
        scores: list[float],
        labels: list[int],
        *,
        epochs: int,
        learning_rate: float = 0.05,
        l2: float = 0.001,
    ) -> "PlattCalibrator":
        if len(scores) != len(labels) or not scores:
            raise ValueError("Calibration scores and labels must be non-empty and aligned.")
        if any(type(label) is not int or label not in (0, 1) for label in labels):
            raise ValueError("Calibration labels must be exact binary integers.")
        if any(not math.isfinite(score) or not 0.0 <= score <= 1.0 for score in scores):
            raise ValueError("Calibration scores must be finite probabilities.")
        x = np.asarray([_logit(score) for score in scores], dtype=np.float64)
        y = np.asarray(labels, dtype=np.float64)
        input_mean = float(x.mean())
        input_scale = float(x.std())
        if input_scale < 1e-12:
            input_scale = 1.0
        z = (x - input_mean) / input_scale
        coefficient = 1.0
        positive_rate = min(max(float(y.mean()), 1e-8), 1.0 - 1e-8)
        intercept = _logit(positive_rate)
        for _ in range(epochs):
            logits = np.clip(z * coefficient + intercept, -30.0, 30.0)
            predictions = 1.0 / (1.0 + np.exp(-logits))
            error = predictions - y
            grad_coefficient = float(np.mean(error * z)) + l2 * coefficient
            grad_intercept = float(np.mean(error))
            coefficient -= learning_rate * grad_coefficient
            intercept -= learning_rate * grad_intercept
        return cls(
            coefficient=float(coefficient),
            intercept=float(intercept),
            input_mean=input_mean,
            input_scale=input_scale,
            epochs=epochs,
            learning_rate=learning_rate,
            l2=l2,
        )

    def predict(self, score: float) -> float:
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise ValueError("Calibration input must be a finite probability.")
        standardized = (_logit(score) - self.input_mean) / self.input_scale
        return _sigmoid(self.coefficient * standardized + self.intercept)

    def to_dict(self) -> dict[str, float | int]:
        return {
            "coefficient": round(self.coefficient, 12),
            "intercept": round(self.intercept, 12),
            "input_mean": round(self.input_mean, 12),
            "input_scale": round(self.input_scale, 12),
            "epochs": self.epochs,
            "learning_rate": self.learning_rate,
            "l2": self.l2,
        }
