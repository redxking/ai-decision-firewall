from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
from jsonschema import Draft202012Validator

from adf_poc.features import extract_features, vectorize
from adf_poc.model import LogisticRiskModel
from adf_poc.schemas import IdentityCase
from adf_poc.utils import read_json, read_jsonl, sha256_file, sha256_json, write_json

from .calibration import PlattCalibrator
from .contracts import ModelEvaluationPlan, PlanValidationError
from .metrics import binary_metrics, selective_risk_curve


@dataclass(frozen=True, slots=True)
class EvaluationRow:
    case_id: str
    opened_at: datetime
    label: int
    scenario: str
    asset_criticality_band: str
    privilege_level: str
    features: tuple[float, ...]


def _parse_timestamp(value: Any, *, label: str) -> datetime:
    if type(value) is not str:
        raise PlanValidationError(f"{label} must be an ISO-8601 string.")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PlanValidationError(f"{label} is not a valid ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PlanValidationError(f"{label} must include a UTC offset.")
    return parsed


def _criticality_band(value: float) -> str:
    if value < 0.34:
        return "LOW"
    if value < 0.67:
        return "MEDIUM"
    return "HIGH"


def _load_rows(plan: ModelEvaluationPlan, repo_root: Path) -> list[EvaluationRow]:
    bindings = {binding.role: binding for binding in plan.source_bindings}
    case_paths = [
        repo_root / bindings["source_pool_cases_a"].path,
        repo_root / bindings["source_pool_cases_b"].path,
    ]
    label_paths = [
        repo_root / bindings["source_pool_labels_a"].path,
        repo_root / bindings["source_pool_labels_b"].path,
    ]
    case_values = [row for path in case_paths for row in read_jsonl(path)]
    label_values = [row for path in label_paths for row in read_jsonl(path)]
    labels: dict[str, dict[str, Any]] = {}
    for row in label_values:
        case_id = row.get("case_id")
        if type(case_id) is not str or not case_id:
            raise PlanValidationError("Every label row requires a non-empty case_id.")
        if case_id in labels:
            raise PlanValidationError(f"Duplicate label case_id: {case_id!r}.")
        if type(row.get("compromised")) is not bool:
            raise PlanValidationError(f"Label {case_id!r} requires an exact Boolean compromised value.")
        if type(row.get("scenario")) is not str or not row["scenario"]:
            raise PlanValidationError(f"Label {case_id!r} requires a scenario stratum.")
        labels[case_id] = row

    rows: list[EvaluationRow] = []
    seen_cases: set[str] = set()
    for raw_case in case_values:
        case = IdentityCase.from_dict(raw_case)
        if case.case_id in seen_cases:
            raise PlanValidationError(f"Duplicate case_id: {case.case_id!r}.")
        seen_cases.add(case.case_id)
        label = labels.get(case.case_id)
        if label is None:
            raise PlanValidationError(f"Case {case.case_id!r} has no evaluation label.")
        feature_values, _ = extract_features(case)
        rows.append(
            EvaluationRow(
                case_id=case.case_id,
                opened_at=_parse_timestamp(raw_case.get(plan.timestamp_field), label=f"case[{case.case_id}].{plan.timestamp_field}"),
                label=1 if label["compromised"] else 0,
                scenario=label["scenario"],
                asset_criticality_band=_criticality_band(float(case.asset_criticality)),
                privilege_level=case.privilege_level,
                features=tuple(vectorize(feature_values)),
            )
        )
    if set(labels) != seen_cases:
        extras = sorted(set(labels).difference(seen_cases))
        raise PlanValidationError(f"Evaluation labels contain unknown case IDs: {extras[:3]}.")
    return sorted(rows, key=lambda row: (row.opened_at, row.case_id))


def _next_timestamp_boundary(rows: list[EvaluationRow], index: int) -> int:
    if index <= 0 or index >= len(rows):
        return index
    timestamp = rows[index - 1].opened_at
    while index < len(rows) and rows[index].opened_at == timestamp:
        index += 1
    return index


def temporal_split(
    rows: list[EvaluationRow], plan: ModelEvaluationPlan
) -> tuple[list[EvaluationRow], list[EvaluationRow], list[EvaluationRow]]:
    if len(rows) < 30:
        raise PlanValidationError("At least 30 rows are required for a three-way temporal split.")
    train_end = _next_timestamp_boundary(rows, int(len(rows) * plan.train_fraction))
    calibration_end = _next_timestamp_boundary(
        rows, int(len(rows) * (plan.train_fraction + plan.calibration_fraction))
    )
    training = rows[:train_end]
    calibration = rows[train_end:calibration_end]
    evaluation = rows[calibration_end:]
    if not training or not calibration or not evaluation:
        raise PlanValidationError("Temporal split produced an empty partition.")
    if not training[-1].opened_at < calibration[0].opened_at:
        raise PlanValidationError("Training and calibration timestamps overlap.")
    if not calibration[-1].opened_at < evaluation[0].opened_at:
        raise PlanValidationError("Calibration and evaluation timestamps overlap.")
    ids = [
        {row.case_id for row in training},
        {row.case_id for row in calibration},
        {row.case_id for row in evaluation},
    ]
    if ids[0] & ids[1] or ids[0] & ids[2] or ids[1] & ids[2]:
        raise PlanValidationError("Temporal partitions are not case-disjoint.")
    return training, calibration, evaluation


def _partition_summary(rows: list[EvaluationRow]) -> dict[str, Any]:
    return {
        "records": len(rows),
        "positives": sum(row.label for row in rows),
        "negatives": len(rows) - sum(row.label for row in rows),
        "start": rows[0].opened_at.isoformat(),
        "end": rows[-1].opened_at.isoformat(),
        "case_id_digest": sha256_json([row.case_id for row in rows]),
    }


def _score(model: LogisticRiskModel, rows: list[EvaluationRow]) -> list[float]:
    scores: list[float] = []
    for row in rows:
        features = dict(zip(model.feature_names, row.features, strict=True))
        probability, _ = model.predict_probability(features)
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise PlanValidationError("Model emitted a non-finite or out-of-range score.")
        scores.append(probability)
    return scores


def _subgroup_metrics(
    rows: list[EvaluationRow],
    scores: list[float],
    *,
    field: str,
    threshold: float,
    bins: int,
) -> list[dict[str, Any]]:
    groups: dict[str, list[int]] = defaultdict(list)
    for index, row in enumerate(rows):
        groups[str(getattr(row, field))].append(index)
    output: list[dict[str, Any]] = []
    for value, indexes in sorted(groups.items()):
        labels = [rows[index].label for index in indexes]
        subset_scores = [scores[index] for index in indexes]
        metrics = binary_metrics(
            labels,
            subset_scores,
            threshold=threshold,
            calibration_bins=bins,
        )
        output.append({"value": value, "metrics": metrics})
    return output


def _metric_delta(challenger: dict[str, Any], baseline: dict[str, Any], key: str) -> float:
    return round(float(challenger[key]) - float(baseline[key]), 8)


def run_synthetic_benchmark(
    *,
    plan_path: str | Path,
    schema_path: str | Path,
    result_schema_path: str | Path,
    repo_root: str | Path,
    output_path: str | Path | None = None,
) -> dict[str, Any]:
    root = Path(repo_root).resolve()
    plan = ModelEvaluationPlan.load(plan_path, schema_path=schema_path)
    plan.verify_source_bindings(root)
    rows = _load_rows(plan, root)
    training, calibration, evaluation = temporal_split(rows, plan)

    baseline_model = LogisticRiskModel()
    baseline_model.version = plan.baseline_id
    train_x = np.asarray([row.features for row in training], dtype=np.float64)
    train_y = np.asarray([row.label for row in training], dtype=np.float64)
    baseline_model.fit(train_x, train_y, epochs=plan.training_epochs)

    calibration_scores = _score(baseline_model, calibration)
    calibrator = PlattCalibrator.fit(
        calibration_scores,
        [row.label for row in calibration],
        epochs=plan.calibration_epochs,
    )
    baseline_scores = _score(baseline_model, evaluation)
    challenger_scores = [calibrator.predict(score) for score in baseline_scores]
    labels = [row.label for row in evaluation]
    baseline_metrics = binary_metrics(
        labels,
        baseline_scores,
        threshold=plan.classification_threshold,
        calibration_bins=plan.calibration_bins,
    )
    challenger_metrics = binary_metrics(
        labels,
        challenger_scores,
        threshold=plan.classification_threshold,
        calibration_bins=plan.calibration_bins,
    )
    baseline_metrics["selective_risk"] = selective_risk_curve(
        labels, baseline_scores, margins=plan.abstention_margins
    )
    challenger_metrics["selective_risk"] = selective_risk_curve(
        labels, challenger_scores, margins=plan.abstention_margins
    )

    result: dict[str, Any] = {
        "schema_version": "0.3.1",
        "result_type": "SYNTHETIC_MODEL_EVALUATION_MECHANISM",
        "plan": plan.to_summary(),
        "plan_sha256": sha256_file(plan_path),
        "input_bindings": [
            {
                "role": binding.role,
                "path": binding.path,
                "sha256": binding.sha256,
                "records": binding.records,
            }
            for binding in plan.source_bindings
        ],
        "partitions": {
            "training": _partition_summary(training),
            "calibration": _partition_summary(calibration),
            "evaluation": _partition_summary(evaluation),
        },
        "models": {
            plan.baseline_id: {
                "role": "BASELINE",
                "model_family": "logistic_regression",
                "training_metadata": baseline_model.training_metadata,
                "metrics": baseline_metrics,
                "strata": {
                    field: _subgroup_metrics(
                        evaluation,
                        baseline_scores,
                        field=field,
                        threshold=plan.classification_threshold,
                        bins=plan.calibration_bins,
                    )
                    for field in plan.strata
                },
            },
            plan.challenger_id: {
                "role": "CHALLENGER",
                "model_family": "platt_calibrated_logistic_regression",
                "calibrator": calibrator.to_dict(),
                "metrics": challenger_metrics,
                "strata": {
                    field: _subgroup_metrics(
                        evaluation,
                        challenger_scores,
                        field=field,
                        threshold=plan.classification_threshold,
                        bins=plan.calibration_bins,
                    )
                    for field in plan.strata
                },
            },
        },
        "comparison": {
            "challenger_minus_baseline": {
                key: _metric_delta(challenger_metrics, baseline_metrics, key)
                for key in (
                    "roc_auc",
                    "average_precision",
                    "brier_score",
                    "log_loss",
                    "expected_calibration_error",
                    "precision",
                    "recall",
                    "false_positive_rate",
                )
            },
            "interpretation": "Mechanism observation only; no superiority or promotion claim.",
        },
        "promotion": {
            "decision": "NOT_AUTHORIZED",
            "reason_codes": [
                "SYNTHETIC_DATA_ONLY",
                "OWNER_THRESHOLDS_NOT_APPROVED",
                "HISTORICAL_VALIDATION_NOT_PERFORMED",
            ],
        },
        "safety_boundary": {
            "historical_payload_accessed": False,
            "live_data_accessed": False,
            "action_credentials_present": False,
            "broker_constructed": False,
            "target_constructed": False,
            "operational_effects": 0,
        },
        "limitations": [
            "All rows originate from the repository synthetic generator family.",
            "Temporal partitioning prevents case overlap but does not create operational representativeness.",
            "The challenger calibrates one synthetic logistic model; it is not an EBM or gradient-boosted operational candidate.",
            "No performance threshold, model promotion, live integration, or action authority is approved.",
        ],
    }

    result_schema = read_json(result_schema_path)
    errors = sorted(
        Draft202012Validator(result_schema).iter_errors(result),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "$"
        raise PlanValidationError(
            f"Model-evaluation result schema failure at {location}: {first.message}"
        )
    if output_path is not None:
        write_json(output_path, result)
    return result
