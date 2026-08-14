from __future__ import annotations

import csv
import math
from collections import Counter, defaultdict
from pathlib import Path
from statistics import mean, median
from typing import Any

from .audit import AuditLogger
from .schemas import Disposition
from .utils import read_jsonl, write_json


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _roc_auc(labels: list[int], scores: list[float]) -> float:
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return 0.0
    ordered = sorted(zip(scores, labels), key=lambda row: row[0])
    rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = (index + 1 + end) / 2.0
        rank_sum += average_rank * sum(label for _, label in ordered[index:end])
        index = end
    return (rank_sum - positives * (positives + 1) / 2.0) / (positives * negatives)


def _expected_calibration_error(labels: list[int], scores: list[float], bins: int = 10) -> float:
    total = len(labels)
    if total == 0:
        return 0.0
    error = 0.0
    for bin_index in range(bins):
        lower = bin_index / bins
        upper = (bin_index + 1) / bins
        members = [i for i, score in enumerate(scores) if lower <= score < upper or (bin_index == bins - 1 and score == 1.0)]
        if not members:
            continue
        confidence = mean(scores[i] for i in members)
        accuracy = mean(labels[i] for i in members)
        error += len(members) / total * abs(confidence - accuracy)
    return error


def evaluate(
    *,
    decisions_path: str | Path,
    labels_path: str | Path,
    audit_path: str | Path,
    output_dir: str | Path,
    max_automation_criticality: float = 0.75,
) -> dict[str, Any]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    decisions = read_jsonl(decisions_path)
    labels_by_id = {row["case_id"]: row for row in read_jsonl(labels_path)}
    aligned = [(decision, labels_by_id[decision["case_id"]]) for decision in decisions]

    y_true = [1 if label["compromised"] else 0 for _, label in aligned]
    scores = [float(decision["compromise_probability"]) for decision, _ in aligned]
    y_pred = [1 if score >= 0.5 else 0 for score in scores]
    tp = sum(1 for truth, pred in zip(y_true, y_pred, strict=True) if truth == 1 and pred == 1)
    tn = sum(1 for truth, pred in zip(y_true, y_pred, strict=True) if truth == 0 and pred == 0)
    fp = sum(1 for truth, pred in zip(y_true, y_pred, strict=True) if truth == 0 and pred == 1)
    fn = sum(1 for truth, pred in zip(y_true, y_pred, strict=True) if truth == 1 and pred == 0)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)

    dispositions = Counter(decision["final_disposition"] for decision, _ in aligned)
    contained = [(decision, label) for decision, label in aligned if decision["final_disposition"] == Disposition.CONTAIN_REVERSIBLE.value]
    contained_true = sum(1 for _, label in contained if label["compromised"])
    contained_false = len(contained) - contained_true
    compromised_total = sum(y_true)
    benign_total = len(y_true) - compromised_total
    escalated_true = sum(
        1 for decision, label in aligned
        if decision["final_disposition"] == Disposition.ESCALATE_HUMAN.value and label["compromised"]
    )

    unsafe_rows: list[str] = []
    poison_total = 0
    poison_automated = 0
    traceable = 0
    authorization_without_verifier = 0
    action_rows = []
    post_action_rows = []
    expected_matches = 0
    latencies: list[float] = []

    for decision, label in aligned:
        contained_now = decision["final_disposition"] == Disposition.CONTAIN_REVERSIBLE.value
        evidence = decision["evidence_assessment"]
        if evidence["poisoned_evidence"]:
            poison_total += 1
            if contained_now:
                poison_automated += 1
        if contained_now and (
            decision["break_glass"]
            or float(decision["asset_criticality"]) > max_automation_criticality
            or evidence["poisoned_evidence"]
            or evidence["conflict_count"] > 0
        ):
            unsafe_rows.append(decision["case_id"])
        input_ids = set(decision["traceability"]["input_event_ids"])
        cited_ids = set(decision["traceability"]["cited_evidence_event_ids"])
        feature_ids = {event_id for ids in decision["traceability"]["feature_trace"].values() for event_id in ids}
        if cited_ids.issubset(input_ids) and feature_ids.issubset(input_ids):
            traceable += 1
        if decision["authorization"]["issued"] and not decision["independent_verification"]["passed"]:
            authorization_without_verifier += 1
        for result in decision["action_results"]:
            action_rows.append(bool(result["success"]))
        if decision["action_results"]:
            post_action_rows.append(bool(decision["post_action_verification"]["passed"]))
        if decision["final_disposition"] == label["expected_disposition"]:
            expected_matches += 1
        latencies.append(float(decision["latency_ms"]))

    audit_valid, audit_errors = AuditLogger.verify(audit_path)
    brier = mean((score - truth) ** 2 for score, truth in zip(scores, y_true, strict=True)) if scores else 0.0
    log_loss = -mean(
        truth * math.log(max(score, 1e-12)) + (1 - truth) * math.log(max(1.0 - score, 1e-12))
        for score, truth in zip(scores, y_true, strict=True)
    ) if scores else 0.0

    per_scenario_rows: list[dict[str, Any]] = []
    scenario_groups: dict[str, list[tuple[dict[str, Any], dict[str, Any]]]] = defaultdict(list)
    for decision, label in aligned:
        scenario_groups[label["scenario"]].append((decision, label))
    for scenario, rows in sorted(scenario_groups.items()):
        scenario_total = len(rows)
        scenario_compromised = sum(1 for _, label in rows if label["compromised"])
        scenario_contained = sum(1 for decision, _ in rows if decision["final_disposition"] == Disposition.CONTAIN_REVERSIBLE.value)
        scenario_false_contain = sum(
            1 for decision, label in rows
            if decision["final_disposition"] == Disposition.CONTAIN_REVERSIBLE.value and not label["compromised"]
        )
        scenario_investigate = sum(1 for decision, _ in rows if decision["final_disposition"] == Disposition.INVESTIGATE.value)
        scenario_escalate = sum(1 for decision, _ in rows if decision["final_disposition"] == Disposition.ESCALATE_HUMAN.value)
        scenario_no_action = sum(1 for decision, _ in rows if decision["final_disposition"] == Disposition.NO_ACTION.value)
        per_scenario_rows.append({
            "scenario": scenario,
            "cases": scenario_total,
            "compromised": scenario_compromised,
            "contain_reversible": scenario_contained,
            "false_containment": scenario_false_contain,
            "investigate": scenario_investigate,
            "escalate_human": scenario_escalate,
            "no_action": scenario_no_action,
            "expected_disposition_match_rate": round(_safe_div(
                sum(1 for decision, label in rows if decision["final_disposition"] == label["expected_disposition"]),
                scenario_total,
            ), 6),
        })

    metrics = {
        "scope": {
            "cases_evaluated": len(aligned),
            "compromised_cases": compromised_total,
            "benign_cases": benign_total,
            "data_type": "synthetic",
            "operational_validity": "not established",
        },
        "model": {
            "accuracy_at_0_5": round(_safe_div(tp + tn, len(y_true)), 6),
            "precision_at_0_5": round(precision, 6),
            "recall_at_0_5": round(recall, 6),
            "f1_at_0_5": round(f1, 6),
            "roc_auc": round(_roc_auc(y_true, scores), 6),
            "brier_score": round(brier, 6),
            "log_loss": round(log_loss, 6),
            "expected_calibration_error_10_bin": round(_expected_calibration_error(y_true, scores), 6),
            "confusion_matrix": {"true_positive": tp, "true_negative": tn, "false_positive": fp, "false_negative": fn},
        },
        "decision_control": {
            "disposition_counts": dict(dispositions),
            "autonomous_containment_count": len(contained),
            "autonomous_containment_precision": round(_safe_div(contained_true, len(contained)), 6),
            "false_containment_count": contained_false,
            "false_containment_rate_per_benign_case": round(_safe_div(contained_false, benign_total), 6),
            "compromise_autonomous_containment_coverage": round(_safe_div(contained_true, compromised_total), 6),
            "compromise_contain_or_escalate_coverage": round(_safe_div(contained_true + escalated_true, compromised_total), 6),
            "investigation_abstention_rate": round(_safe_div(dispositions[Disposition.INVESTIGATE.value], len(aligned)), 6),
            "expected_disposition_match_rate": round(_safe_div(expected_matches, len(aligned)), 6),
        },
        "safety_and_assurance": {
            "unsafe_automation_count": len(unsafe_rows),
            "unsafe_automation_case_ids": unsafe_rows,
            "poisoned_evidence_cases": poison_total,
            "poisoned_evidence_autonomous_actions": poison_automated,
            "authorization_without_independent_verifier": authorization_without_verifier,
            "evidence_traceability_rate": round(_safe_div(traceable, len(aligned)), 6),
            "action_command_success_rate": round(_safe_div(sum(action_rows), len(action_rows)), 6),
            "post_action_verification_pass_rate": round(_safe_div(sum(post_action_rows), len(post_action_rows)), 6),
            "audit_chain_valid": audit_valid,
            "audit_chain_errors": audit_errors,
        },
        "performance": {
            "mean_decision_latency_ms": round(mean(latencies), 3) if latencies else 0.0,
            "median_decision_latency_ms": round(median(latencies), 3) if latencies else 0.0,
            "max_decision_latency_ms": round(max(latencies), 3) if latencies else 0.0,
        },
        "per_scenario": per_scenario_rows,
        "interpretation": [
            "These results validate POC mechanics against a synthetic generator, not real-world security efficacy.",
            "Because the model and evaluation data share a synthetic scenario family, performance is optimistic and must not be used for production authorization.",
            "The primary POC success criteria are policy enforcement, abstention, traceability, authorization separation, and post-action verification.",
        ],
    }
    write_json(output / "metrics.json", metrics)

    with (output / "per_scenario_metrics.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(per_scenario_rows[0].keys()) if per_scenario_rows else ["scenario"])
        writer.writeheader()
        writer.writerows(per_scenario_rows)

    summary_fields = [
        "case_id", "scenario", "compromised", "expected_disposition", "final_disposition",
        "compromise_probability", "evidence_quality", "asset_criticality", "break_glass",
        "authorization_issued", "post_action_verified", "latency_ms",
    ]
    with (output / "decision_summary.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=summary_fields)
        writer.writeheader()
        for decision, label in aligned:
            writer.writerow({
                "case_id": decision["case_id"],
                "scenario": label["scenario"],
                "compromised": label["compromised"],
                "expected_disposition": label["expected_disposition"],
                "final_disposition": decision["final_disposition"],
                "compromise_probability": decision["compromise_probability"],
                "evidence_quality": decision["evidence_assessment"]["evidence_quality"],
                "asset_criticality": decision["asset_criticality"],
                "break_glass": decision["break_glass"],
                "authorization_issued": decision["authorization"]["issued"],
                "post_action_verified": decision["post_action_verification"]["passed"],
                "latency_ms": decision["latency_ms"],
            })
    return metrics
