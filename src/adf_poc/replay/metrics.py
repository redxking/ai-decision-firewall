from __future__ import annotations

from collections import Counter
from statistics import mean
from typing import Any, Iterable


DISPOSITIONS = (
    "NO_ACTION",
    "INVESTIGATE",
    "CONTAIN_REVERSIBLE",
    "ESCALATE_HUMAN",
)


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def build_comparisons(
    decisions: Iterable[dict[str, Any]], adjudications: Iterable[dict[str, Any]]
) -> list[dict[str, Any]]:
    decision_by_case = {row["case_id"]: row for row in decisions}
    comparisons: list[dict[str, Any]] = []
    for label in sorted(adjudications, key=lambda row: row["case_id"]):
        decision = decision_by_case[label["case_id"]]
        comparisons.append(
            {
                "case_id": label["case_id"],
                "decision_disposition": decision["final_disposition"],
                "adjudicated_disposition": label["adjudicated_disposition"],
                "disposition_match": (
                    decision["final_disposition"] == label["adjudicated_disposition"]
                ),
                "compromise_probability": float(decision["compromise_probability"]),
                "compromised": label["compromised"],
                "adjudication_confidence": float(label["confidence"]),
                "rationale_codes": list(label["rationale_codes"]),
            }
        )
    return comparisons


def compute_replay_metrics(
    *,
    dataset_id: str,
    data_origin: str,
    historical_case_count: int,
    execution_mode: str,
    decisions: list[dict[str, Any]],
    adjudications: list[dict[str, Any]],
    audit_assurance: dict[str, Any],
) -> dict[str, Any]:
    counts = Counter(row["final_disposition"] for row in decisions)
    comparisons = build_comparisons(decisions, adjudications)
    labels = [1 if row["compromised"] else 0 for row in comparisons]
    scores = [float(row["compromise_probability"]) for row in comparisons]
    predictions = [1 if score >= 0.5 else 0 for score in scores]
    tp = sum(1 for truth, prediction in zip(labels, predictions, strict=True) if truth and prediction)
    tn = sum(1 for truth, prediction in zip(labels, predictions, strict=True) if not truth and not prediction)
    fp = sum(1 for truth, prediction in zip(labels, predictions, strict=True) if not truth and prediction)
    fn = sum(1 for truth, prediction in zip(labels, predictions, strict=True) if truth and not prediction)
    brier = mean((score - truth) ** 2 for score, truth in zip(scores, labels, strict=True)) if labels else None

    authorization_count = sum(
        1 for row in decisions if bool(row.get("authorization", {}).get("issued"))
    )
    broker_invocations = sum(
        int(row.get("execution_control", {}).get("broker_invocations", 0))
        for row in decisions
    )
    operational_effects = sum(
        int(row.get("execution_control", {}).get("operational_effects", 0))
        for row in decisions
    )
    action_results = sum(len(row.get("action_results", [])) for row in decisions)
    counterfactual_actions = sum(len(row.get("counterfactual_actions", [])) for row in decisions)
    agreement_count = sum(1 for row in comparisons if row["disposition_match"])

    return {
        "schema_version": "0.2.0",
        "dataset_id": dataset_id,
        "data_origin": data_origin,
        "historical_case_count": historical_case_count,
        "execution_mode": execution_mode,
        "scope": {
            "cases_evaluated": len(decisions),
            "adjudicated_cases": len(comparisons),
            "adjudication_coverage": round(_safe_div(len(comparisons), len(decisions)), 6),
        },
        "decisions": {
            "disposition_counts": {name: counts.get(name, 0) for name in DISPOSITIONS},
            "counterfactual_action_count": counterfactual_actions,
        },
        "adjudication": {
            "disposition_match_count": agreement_count,
            "disposition_match_rate": (
                round(_safe_div(agreement_count, len(comparisons)), 6)
                if comparisons
                else None
            ),
            "classification_at_0_5": {
                "true_positive": tp,
                "true_negative": tn,
                "false_positive": fp,
                "false_negative": fn,
                "accuracy": (
                    round(_safe_div(tp + tn, len(comparisons)), 6)
                    if comparisons
                    else None
                ),
                "brier_score": round(brier, 6) if brier is not None else None,
            },
        },
        "read_only_assurance": {
            "live_actions_enabled": False,
            "authorization_tokens_issued": authorization_count,
            "broker_invocations": broker_invocations,
            "operational_effects": operational_effects,
            "action_results": action_results,
            "adjudications_loaded_after_decisions": True,
            "runtime_label_file_passed_to_engine": False,
            "audit_validation_enforced": audit_assurance["audit_validation_enforced"],
            "audit_chain_valid": audit_assurance["audit_chain_valid"],
            "audit_record_count": audit_assurance["audit_record_count"],
            "execution_suppression_records": audit_assurance[
                "execution_suppression_records"
            ],
            "authorization_evaluated_records": audit_assurance[
                "authorization_evaluated_records"
            ],
            "decision_finalized_records": audit_assurance[
                "decision_finalized_records"
            ],
            "action_executed_audit_records": audit_assurance[
                "action_executed_audit_records"
            ],
        },
    }
