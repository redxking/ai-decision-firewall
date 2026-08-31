from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from adf_poc.utils import read_json, sha256_file


class PlanValidationError(ValueError):
    """Raised when a Phase 3.1 evaluation plan is unsafe or ambiguous."""


REQUIRED_METRICS = frozenset(
    {
        "roc_auc",
        "average_precision",
        "brier_score",
        "log_loss",
        "expected_calibration_error",
        "precision",
        "recall",
        "false_positive_rate",
        "selective_risk",
    }
)


@dataclass(frozen=True, slots=True)
class DatasetBinding:
    role: str
    path: str
    sha256: str
    records: int

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DatasetBinding":
        return cls(
            role=str(value["role"]),
            path=str(value["path"]),
            sha256=str(value["sha256"]),
            records=int(value["records"]),
        )


@dataclass(frozen=True, slots=True)
class ModelEvaluationPlan:
    plan_id: str
    status: str
    evaluation_mode: str
    data_classification: str
    historical_payload_access_prohibited: bool
    live_action_prohibited: bool
    source_bindings: tuple[DatasetBinding, ...]
    train_fraction: float
    calibration_fraction: float
    evaluation_fraction: float
    timestamp_field: str
    baseline_id: str
    challenger_id: str
    training_epochs: int
    calibration_epochs: int
    classification_threshold: float
    calibration_bins: int
    abstention_margins: tuple[float, ...]
    metrics: tuple[str, ...]
    strata: tuple[str, ...]
    promotion_gate_status: str
    performance_thresholds: tuple[dict[str, Any], ...]

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        schema_path: str | Path,
    ) -> "ModelEvaluationPlan":
        raw = read_json(path)
        schema = read_json(schema_path)
        if not isinstance(raw, dict) or not isinstance(schema, dict):
            raise PlanValidationError("Plan and schema must be JSON objects.")
        errors = sorted(
            Draft202012Validator(schema).iter_errors(raw),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
        if errors:
            first = errors[0]
            location = ".".join(str(part) for part in first.absolute_path) or "$"
            raise PlanValidationError(
                f"Model-evaluation plan schema failure at {location}: {first.message}"
            )

        split = raw["split"]
        candidates = raw["candidates"]
        baseline = next(item for item in candidates if item["role"] == "BASELINE")
        challenger = next(item for item in candidates if item["role"] == "CHALLENGER")
        plan = cls(
            plan_id=raw["plan_id"],
            status=raw["status"],
            evaluation_mode=raw["evaluation_mode"],
            data_classification=raw["data_classification"],
            historical_payload_access_prohibited=raw[
                "historical_payload_access_prohibited"
            ],
            live_action_prohibited=raw["live_action_prohibited"],
            source_bindings=tuple(
                DatasetBinding.from_dict(item) for item in raw["dataset_bindings"]
            ),
            train_fraction=float(split["train_fraction"]),
            calibration_fraction=float(split["calibration_fraction"]),
            evaluation_fraction=float(split["evaluation_fraction"]),
            timestamp_field=split["timestamp_field"],
            baseline_id=baseline["model_id"],
            challenger_id=challenger["model_id"],
            training_epochs=int(baseline["fit"]["epochs"]),
            calibration_epochs=int(challenger["fit"]["epochs"]),
            classification_threshold=float(raw["classification_threshold"]),
            calibration_bins=int(raw["calibration_bins"]),
            abstention_margins=tuple(float(value) for value in raw["abstention_margins"]),
            metrics=tuple(raw["metrics"]),
            strata=tuple(raw["strata"]),
            promotion_gate_status=raw["promotion"]["gate_status"],
            performance_thresholds=tuple(raw["promotion"]["performance_thresholds"]),
        )
        plan._validate_safety_invariants()
        return plan

    def _validate_safety_invariants(self) -> None:
        if self.status != "DRAFT":
            raise PlanValidationError(
                "The repository Phase 3.1 plan must remain DRAFT until owner review."
            )
        if self.evaluation_mode != "SYNTHETIC_MECHANISM":
            raise PlanValidationError(
                "This executable increment supports synthetic mechanism evaluation only."
            )
        if self.data_classification != "SYNTHETIC_REPOSITORY_FIXTURE":
            raise PlanValidationError("Historical or live data is not authorized.")
        if not self.historical_payload_access_prohibited or not self.live_action_prohibited:
            raise PlanValidationError(
                "Historical payload access and live action must both remain prohibited."
            )
        fractions = (
            self.train_fraction,
            self.calibration_fraction,
            self.evaluation_fraction,
        )
        if any(not math.isfinite(value) or value <= 0.0 for value in fractions):
            raise PlanValidationError("Temporal split fractions must be finite and positive.")
        if not math.isclose(math.fsum(fractions), 1.0, rel_tol=0.0, abs_tol=1e-12):
            raise PlanValidationError("Temporal split fractions must sum exactly to one.")
        if self.timestamp_field != "opened_at":
            raise PlanValidationError("The current temporal split is bound to opened_at.")
        roles = [binding.role for binding in self.source_bindings]
        if sorted(roles) != [
            "source_pool_cases_a",
            "source_pool_cases_b",
            "source_pool_labels_a",
            "source_pool_labels_b",
        ]:
            raise PlanValidationError("Dataset bindings must contain the four closed source roles.")
        if len({binding.path for binding in self.source_bindings}) != len(self.source_bindings):
            raise PlanValidationError("Dataset binding paths must be unique.")
        if self.baseline_id == self.challenger_id:
            raise PlanValidationError("Baseline and challenger model identifiers must differ.")
        if not 100 <= self.training_epochs <= 10_000:
            raise PlanValidationError("Baseline training epochs are outside the bounded range.")
        if not 100 <= self.calibration_epochs <= 10_000:
            raise PlanValidationError("Calibration epochs are outside the bounded range.")
        if not 0.0 < self.classification_threshold < 1.0:
            raise PlanValidationError("Classification threshold must be strictly inside (0, 1).")
        if not 2 <= self.calibration_bins <= 100:
            raise PlanValidationError("Calibration bin count is outside the bounded range.")
        if tuple(sorted(set(self.abstention_margins))) != self.abstention_margins:
            raise PlanValidationError("Abstention margins must be unique and increasing.")
        if any(not 0.0 <= value < 0.5 for value in self.abstention_margins):
            raise PlanValidationError("Abstention margins must fall in [0, 0.5).")
        if not REQUIRED_METRICS.issubset(self.metrics):
            missing = sorted(REQUIRED_METRICS.difference(self.metrics))
            raise PlanValidationError(f"Required metrics are missing: {missing}.")
        if len(set(self.metrics)) != len(self.metrics):
            raise PlanValidationError("Metrics cannot be duplicated.")
        if tuple(self.strata) != ("scenario", "asset_criticality_band", "privilege_level"):
            raise PlanValidationError("The synthetic mechanism evaluation requires all three strata.")
        if self.promotion_gate_status != "OWNER_THRESHOLDS_REQUIRED":
            raise PlanValidationError("Synthetic evaluation cannot authorize model promotion.")
        if self.performance_thresholds:
            raise PlanValidationError(
                "Performance thresholds require owner approval and real evaluation authority."
            )

    def verify_source_bindings(self, repo_root: str | Path) -> None:
        root = Path(repo_root).resolve()
        for binding in self.source_bindings:
            relative = Path(binding.path)
            if relative.is_absolute() or ".." in relative.parts:
                raise PlanValidationError(f"Unsafe dataset path: {binding.path!r}.")
            candidate = root / relative
            component = root
            for part in relative.parts:
                component /= part
                if component.is_symlink():
                    raise PlanValidationError(
                        f"Dataset binding cannot traverse a symlink: {binding.path!r}."
                    )
            target = candidate.resolve()
            try:
                target.relative_to(root)
            except ValueError as exc:
                raise PlanValidationError(
                    f"Dataset binding escapes the repository: {binding.path!r}."
                ) from exc
            if not target.is_file():
                raise PlanValidationError(
                    f"Dataset binding must be a regular repository file: {binding.path!r}."
                )
            observed = sha256_file(target)
            if observed != binding.sha256:
                raise PlanValidationError(
                    f"Dataset binding digest mismatch for {binding.path!r}."
                )
            with target.open("rb") as handle:
                count = sum(1 for line in handle if line.strip())
            if count != binding.records:
                raise PlanValidationError(
                    f"Dataset binding record-count mismatch for {binding.path!r}."
                )

    def to_summary(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "status": self.status,
            "evaluation_mode": self.evaluation_mode,
            "data_classification": self.data_classification,
            "historical_payload_access_prohibited": self.historical_payload_access_prohibited,
            "live_action_prohibited": self.live_action_prohibited,
            "split": {
                "strategy": "TEMPORAL",
                "train_fraction": self.train_fraction,
                "calibration_fraction": self.calibration_fraction,
                "evaluation_fraction": self.evaluation_fraction,
                "timestamp_field": self.timestamp_field,
            },
            "baseline_id": self.baseline_id,
            "challenger_id": self.challenger_id,
            "metrics": list(self.metrics),
            "strata": list(self.strata),
            "promotion_gate_status": self.promotion_gate_status,
        }
