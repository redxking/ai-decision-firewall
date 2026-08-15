from __future__ import annotations

import math


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def _round(value: float) -> float:
    return round(float(value), 8)


def _validate(labels: list[int], scores: list[float]) -> None:
    if len(labels) != len(scores) or not labels:
        raise ValueError("Labels and scores must be non-empty and aligned.")
    if any(type(label) is not int or label not in (0, 1) for label in labels):
        raise ValueError("Labels must be exact binary integers.")
    if any(not math.isfinite(score) or not 0.0 <= score <= 1.0 for score in scores):
        raise ValueError("Scores must be finite probabilities in [0, 1].")


def roc_auc(labels: list[int], scores: list[float]) -> float:
    _validate(labels, scores)
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return 0.0
    ordered = sorted(zip(scores, labels, strict=True), key=lambda row: row[0])
    rank_sum = 0.0
    index = 0
    while index < len(ordered):
        end = index + 1
        while end < len(ordered) and ordered[end][0] == ordered[index][0]:
            end += 1
        average_rank = (index + 1 + end) / 2.0
        rank_sum += average_rank * sum(label for _, label in ordered[index:end])
        index = end
    return (rank_sum - positives * (positives + 1) / 2.0) / (
        positives * negatives
    )


def average_precision(labels: list[int], scores: list[float]) -> float:
    _validate(labels, scores)
    positives = sum(labels)
    if positives == 0:
        return 0.0
    ordered = sorted(
        zip(scores, labels, strict=True), key=lambda row: row[0], reverse=True
    )
    true_positives = 0
    precision_sum = 0.0
    for rank, (_, label) in enumerate(ordered, start=1):
        if label == 1:
            true_positives += 1
            precision_sum += true_positives / rank
    return precision_sum / positives


def expected_calibration_error(
    labels: list[int], scores: list[float], *, bins: int
) -> float:
    _validate(labels, scores)
    if bins < 2:
        raise ValueError("Calibration bins must be at least two.")
    total = len(labels)
    error = 0.0
    for bin_index in range(bins):
        lower = bin_index / bins
        upper = (bin_index + 1) / bins
        members = [
            index
            for index, score in enumerate(scores)
            if lower <= score < upper or (bin_index == bins - 1 and score == 1.0)
        ]
        if not members:
            continue
        confidence = math.fsum(scores[index] for index in members) / len(members)
        observed = math.fsum(labels[index] for index in members) / len(members)
        error += len(members) / total * abs(confidence - observed)
    return error


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float]:
    if total == 0:
        return [0.0, 0.0]
    proportion = successes / total
    denominator = 1.0 + z * z / total
    center = (proportion + z * z / (2.0 * total)) / denominator
    margin = (
        z
        * math.sqrt(
            proportion * (1.0 - proportion) / total + z * z / (4.0 * total * total)
        )
        / denominator
    )
    return [_round(max(0.0, center - margin)), _round(min(1.0, center + margin))]


def binary_metrics(
    labels: list[int],
    scores: list[float],
    *,
    threshold: float,
    calibration_bins: int,
) -> dict[str, object]:
    _validate(labels, scores)
    predictions = [1 if score >= threshold else 0 for score in scores]
    tp = sum(1 for truth, pred in zip(labels, predictions, strict=True) if truth == pred == 1)
    tn = sum(1 for truth, pred in zip(labels, predictions, strict=True) if truth == pred == 0)
    fp = sum(1 for truth, pred in zip(labels, predictions, strict=True) if truth == 0 and pred == 1)
    fn = sum(1 for truth, pred in zip(labels, predictions, strict=True) if truth == 1 and pred == 0)
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    false_positive_rate = _safe_div(fp, fp + tn)
    brier = math.fsum((score - truth) ** 2 for score, truth in zip(scores, labels, strict=True)) / len(labels)
    log_loss = -math.fsum(
        truth * math.log(max(score, 1e-12))
        + (1 - truth) * math.log(max(1.0 - score, 1e-12))
        for score, truth in zip(scores, labels, strict=True)
    ) / len(labels)
    return {
        "count": len(labels),
        "positives": sum(labels),
        "negatives": len(labels) - sum(labels),
        "threshold": threshold,
        "roc_auc": _round(roc_auc(labels, scores)),
        "average_precision": _round(average_precision(labels, scores)),
        "brier_score": _round(brier),
        "log_loss": _round(log_loss),
        "expected_calibration_error": _round(
            expected_calibration_error(labels, scores, bins=calibration_bins)
        ),
        "accuracy": _round(_safe_div(tp + tn, len(labels))),
        "precision": _round(precision),
        "recall": _round(recall),
        "f1": _round(_safe_div(2.0 * precision * recall, precision + recall)),
        "false_positive_rate": _round(false_positive_rate),
        "confusion_matrix": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "precision_ci95_wilson": wilson_interval(tp, tp + fp),
        "recall_ci95_wilson": wilson_interval(tp, tp + fn),
        "false_positive_rate_ci95_wilson": wilson_interval(fp, fp + tn),
    }


def selective_risk_curve(
    labels: list[int], scores: list[float], *, margins: tuple[float, ...]
) -> list[dict[str, float | int]]:
    _validate(labels, scores)
    rows: list[dict[str, float | int]] = []
    for margin in margins:
        selected = [
            index
            for index, score in enumerate(scores)
            if abs(score - 0.5) >= margin
        ]
        errors = sum(
            1
            for index in selected
            if (1 if scores[index] >= 0.5 else 0) != labels[index]
        )
        rows.append(
            {
                "abstention_margin": margin,
                "selected_count": len(selected),
                "coverage": _round(_safe_div(len(selected), len(labels))),
                "selective_risk": _round(_safe_div(errors, len(selected))),
            }
        )
    return rows
