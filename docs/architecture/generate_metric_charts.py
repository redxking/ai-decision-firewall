"""Regenerate the version-bound historical Phase 1 v0.1 metric charts.

The charts are historical synthetic-simulation visuals. They are not Phase 2
or P2-CE-005 results. Run from any directory; repository paths are resolved
from this file.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import tempfile
from collections import Counter
from pathlib import Path

import matplotlib as mpl
import matplotlib.pyplot as plt
from matplotlib import ft2font
from PIL import __version__ as pillow_version


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASELINE = ROOT / "outputs" / "baseline"

COLORS = {
    "NO_ACTION": "#0072B2",
    "INVESTIGATE": "#E69F00",
    "CONTAIN_REVERSIBLE": "#009E73",
    "ESCALATE_HUMAN": "#CC79A7",
    "benign": "#56B4E9",
    "compromised": "#D55E00",
}
LABELS = {
    "NO_ACTION": "No action",
    "INVESTIGATE": "Investigate",
    "CONTAIN_REVERSIBLE": "Contain reversible",
    "ESCALATE_HUMAN": "Escalate human",
}
ORDER = ["NO_ACTION", "INVESTIGATE", "CONTAIN_REVERSIBLE", "ESCALATE_HUMAN"]
HATCHES = {"NO_ACTION": "", "INVESTIGATE": "///", "CONTAIN_REVERSIBLE": "xx", "ESCALATE_HUMAN": ".."}
FOOTNOTE = (
    "Source: outputs/baseline • legacy Phase 1 v0.1 synthetic POC • "
    "400 generated cases • seed 20260814\n"
    "Not Phase 2.5 / P2-CE-005 evidence • P2-CE-005 = CE-0 NOT_EVALUATED"
)

# These digests were computed from the chart-consumed projections of the
# intended, committed Phase 1 v0.1 baseline at repository commit 08ce203c.
# Runtime latency and other unused fields are deliberately excluded: they are
# not chart inputs and must not make regenerated output authoritative.
FROZEN_CHART_PROJECTION_SHA256 = {
    "metrics.json": "6bd0d758aad37b954633cdfda631d5a53551d7f50693926862c456b15f7234d8",
    "run_manifest.json": "50b06cfd149a7ee435ba153a45b13469e8d2fe2752172f7adaf50f9e7570fd77",
    "decision_summary.csv": "de76d9b43a282915eedbea45ff0b952b458a4e568decfeab71f3b08706859c8d",
    "per_scenario_metrics.csv": "2b4bb2482884ef807cc5b2588d418ea9cdaa4ebdc960579b6fc8594910e5efa1",
}

FROZEN_RENDER_ENVIRONMENT = {
    "matplotlib": "3.11.1",
    "freetype": "2.14.3",
    "pillow": "12.3.0",
}


def _verify_render_environment() -> None:
    """Reject byte checks outside the chart package's frozen renderer."""

    observed = {
        "matplotlib": mpl.__version__,
        "freetype": ft2font.__freetype_version__,
        "pillow": pillow_version,
    }
    if observed != FROZEN_RENDER_ENVIRONMENT:
        expected_text = ", ".join(
            f"{name}={version}"
            for name, version in FROZEN_RENDER_ENVIRONMENT.items()
        )
        observed_text = ", ".join(
            f"{name}={version}" for name, version in observed.items()
        )
        raise RuntimeError(
            "metric-chart byte reproduction requires the frozen documentation "
            f"renderer ({expected_text}); observed {observed_text}. Install "
            "requirements-docs.txt before generating or checking renders."
        )


def _projection_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _verify_frozen_chart_inputs(
    metrics: dict,
    decisions: list[dict[str, str]],
    scenarios: list[dict[str, str]],
    manifest: dict,
) -> None:
    projections = {
        "metrics.json": {
            "source": "outputs/baseline/metrics.json",
            "fields": [
                "scope.cases_evaluated",
                "decision_control.disposition_counts",
            ],
            "values": {
                "cases_evaluated": metrics["scope"]["cases_evaluated"],
                "disposition_counts": metrics["decision_control"]["disposition_counts"],
            },
        },
        "run_manifest.json": {
            "source": "outputs/baseline/run_manifest.json",
            "fields": ["poc_version", "seed", "train_cases", "test_cases"],
            "values": {
                key: manifest[key]
                for key in ("poc_version", "seed", "train_cases", "test_cases")
            },
        },
        "decision_summary.csv": {
            "source": "outputs/baseline/decision_summary.csv",
            "fields": ["case_id", "compromised", "compromise_probability"],
            "rows": [
                [
                    row["case_id"],
                    row["compromised"],
                    row["compromise_probability"],
                ]
                for row in decisions
            ],
        },
        "per_scenario_metrics.csv": {
            "source": "outputs/baseline/per_scenario_metrics.csv",
            "fields": [
                "scenario",
                "cases",
                "no_action",
                "investigate",
                "contain_reversible",
                "escalate_human",
            ],
            "rows": [
                [
                    row["scenario"],
                    row["cases"],
                    row["no_action"],
                    row["investigate"],
                    row["contain_reversible"],
                    row["escalate_human"],
                ]
                for row in scenarios
            ],
        },
    }
    for name, projection in projections.items():
        observed = _projection_digest(projection)
        expected = FROZEN_CHART_PROJECTION_SHA256[name]
        if observed != expected:
            raise ValueError(
                f"{name} chart-consumed projection does not match the frozen "
                f"Phase 1 v0.1 baseline: expected {expected}, observed {observed}"
            )


def _configure() -> None:
    mpl.use("Agg")
    mpl.rcParams.update(
        {
            "font.family": "DejaVu Sans",
            "font.size": 10,
            "axes.titlesize": 17,
            "axes.titleweight": "bold",
            "axes.labelsize": 10,
            "axes.edgecolor": "#6B7280",
            "axes.linewidth": 0.8,
            "xtick.color": "#374151",
            "ytick.color": "#374151",
            "text.color": "#1F2937",
            "figure.facecolor": "white",
            "axes.facecolor": "white",
            "savefig.facecolor": "white",
            "svg.hashsalt": "adf-phase1-v0.1-baseline",
        }
    )


def _load() -> tuple[dict, list[dict[str, str]], list[dict[str, str]], dict]:
    metrics = json.loads((BASELINE / "metrics.json").read_text(encoding="utf-8"))
    manifest = json.loads((BASELINE / "run_manifest.json").read_text(encoding="utf-8"))
    with (BASELINE / "decision_summary.csv").open(newline="", encoding="utf-8") as handle:
        decisions = list(csv.DictReader(handle))
    with (BASELINE / "per_scenario_metrics.csv").open(newline="", encoding="utf-8") as handle:
        scenarios = list(csv.DictReader(handle))

    if manifest.get("poc_version") != "0.1.0" or manifest.get("seed") != 20260814:
        raise ValueError("metric charts are bound to the Phase 1 v0.1 seed-20260814 baseline")
    if len(decisions) != 400 or int(metrics["scope"]["cases_evaluated"]) != 400:
        raise ValueError("expected exactly 400 committed baseline decisions")
    csv_counts = Counter(row["final_disposition"] for row in decisions)
    expected_counts = metrics["decision_control"]["disposition_counts"]
    if dict(csv_counts) != expected_counts:
        raise ValueError("decision_summary.csv disposition totals do not match metrics.json")
    if sum(int(row["cases"]) for row in scenarios) != 400:
        raise ValueError("per-scenario case totals do not equal 400")
    _verify_frozen_chart_inputs(metrics, decisions, scenarios, manifest)
    return metrics, decisions, scenarios, manifest


def _finish(fig: plt.Figure, output: Path) -> None:
    fig.text(0.01, 0.012, FOOTNOTE, ha="left", va="bottom", fontsize=7.5, color="#4B5563")
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(
        output.with_suffix(".png"),
        dpi=200,
        bbox_inches="tight",
        pad_inches=0.12,
        metadata={"Software": "AI Decision Firewall deterministic metric-chart generator"},
    )
    fig.savefig(
        output.with_suffix(".svg"),
        bbox_inches="tight",
        pad_inches=0.12,
        metadata={"Date": None, "Creator": "AI Decision Firewall deterministic metric-chart generator"},
    )
    plt.close(fig)


def _disposition_chart(metrics: dict, output_dir: Path) -> None:
    counts = metrics["decision_control"]["disposition_counts"]
    fig, ax = plt.subplots(figsize=(10.8, 6.1))
    values = [counts[key] for key in ORDER]
    bars = ax.bar(
        [LABELS[key] for key in ORDER],
        values,
        color=[COLORS[key] for key in ORDER],
        edgecolor="#374151",
        linewidth=0.6,
    )
    for bar, key, value in zip(bars, ORDER, values):
        bar.set_hatch(HATCHES[key])
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 4,
            str(value),
            ha="center",
            va="bottom",
            fontweight="bold",
        )
    ax.set_title(
        "Historical Phase 1 v0.1 Synthetic Baseline — Disposition Counts",
        loc="left",
        pad=18,
    )
    ax.text(
        0,
        1.01,
        "400 generated test cases; legacy POC counts only",
        transform=ax.transAxes,
        fontsize=10,
        color="#4B5563",
    )
    ax.set_ylabel("Cases")
    ax.set_ylim(0, max(values) * 1.20)
    ax.grid(axis="y", color="#D1D5DB", linewidth=0.7, alpha=0.8)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    fig.subplots_adjust(bottom=0.15, top=0.83, left=0.10, right=0.98)
    _finish(fig, output_dir / "05_disposition_counts")


def _probability_chart(decisions: list[dict[str, str]], output_dir: Path) -> None:
    benign = [
        float(row["compromise_probability"])
        for row in decisions
        if row["compromised"] == "False"
    ]
    compromised = [
        float(row["compromise_probability"])
        for row in decisions
        if row["compromised"] == "True"
    ]
    bins = [index / 20 for index in range(21)]
    fig, ax = plt.subplots(figsize=(10.8, 6.1))
    ax.hist(
        [benign, compromised],
        bins=bins,
        stacked=True,
        color=[COLORS["benign"], COLORS["compromised"]],
        edgecolor="white",
        linewidth=0.6,
        label=[
            f"Synthetic benign (n={len(benign)})",
            f"Synthetic compromised (n={len(compromised)})",
        ],
    )
    ax.axvline(
        0.5,
        color="#374151",
        linestyle="--",
        linewidth=1.2,
        label="0.5 model-score threshold",
    )
    ax.set_title(
        "Historical Phase 1 v0.1 Synthetic Baseline — Model Score Distribution",
        loc="left",
        pad=18,
    )
    ax.text(
        0,
        1.01,
        "Shared synthetic scenario family makes this optimistic; operational calibration is not established",
        transform=ax.transAxes,
        fontsize=10,
        color="#4B5563",
    )
    ax.set_xlabel("Uncalibrated model score (baseline field: compromise_probability)")
    ax.set_ylabel("Cases per 0.05 bin")
    ax.set_xlim(0, 1)
    ax.grid(axis="y", color="#D1D5DB", linewidth=0.7, alpha=0.8)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.15), ncol=3)
    fig.subplots_adjust(bottom=0.24, top=0.83, left=0.10, right=0.98)
    _finish(fig, output_dir / "06_probability_distribution")


def _scenario_chart(scenarios: list[dict[str, str]], output_dir: Path) -> None:
    ordered = sorted(scenarios, key=lambda row: (-int(row["cases"]), row["scenario"]))
    labels = [row["scenario"].replace("_", " ") for row in ordered]
    fig, ax = plt.subplots(figsize=(12.0, 8.4))
    left = [0] * len(ordered)
    columns = {
        "NO_ACTION": "no_action",
        "INVESTIGATE": "investigate",
        "CONTAIN_REVERSIBLE": "contain_reversible",
        "ESCALATE_HUMAN": "escalate_human",
    }
    for key in ORDER:
        values = [int(row[columns[key]]) for row in ordered]
        bars = ax.barh(
            labels,
            values,
            left=left,
            color=COLORS[key],
            edgecolor="white",
            linewidth=0.6,
            hatch=HATCHES[key],
            label=LABELS[key],
        )
        for bar, offset, value in zip(bars, left, values):
            if not value:
                continue
            center = offset + value / 2
            ax.text(
                center,
                bar.get_y() + bar.get_height() / 2,
                str(value),
                ha="center",
                va="center",
                fontsize=8,
                fontweight="bold",
                color="white" if value >= 5 else "#111827",
            )
        left = [offset + value for offset, value in zip(left, values)]
    ax.invert_yaxis()
    ax.set_title(
        "Historical Phase 1 v0.1 Synthetic Baseline — Dispositions by Generated Scenario",
        loc="left",
        pad=18,
    )
    ax.text(
        0,
        1.01,
        "Disposition counts by generated scenario; scenario coverage is not historical representativeness",
        transform=ax.transAxes,
        fontsize=10,
        color="#4B5563",
    )
    ax.set_xlabel("Cases")
    ax.set_ylabel("")
    ax.grid(axis="x", color="#D1D5DB", linewidth=0.7, alpha=0.8)
    ax.set_axisbelow(True)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.09), ncol=4)
    fig.subplots_adjust(bottom=0.15, top=0.86, left=0.23, right=0.98)
    _finish(fig, output_dir / "07_scenario_outcomes")


def _generate(output_dir: Path) -> None:
    metrics, decisions, scenarios, _manifest = _load()
    _disposition_chart(metrics, output_dir)
    _probability_chart(decisions, output_dir)
    _scenario_chart(scenarios, output_dir)


def _check() -> None:
    with tempfile.TemporaryDirectory(prefix="adf-metric-chart-check-") as temp_dir:
        generated = Path(temp_dir)
        _generate(generated)
        mismatches = []
        for stem in (
            "05_disposition_counts",
            "06_probability_distribution",
            "07_scenario_outcomes",
        ):
            for suffix in (".png", ".svg"):
                expected = HERE / f"{stem}{suffix}"
                observed = generated / f"{stem}{suffix}"
                if not expected.exists() or expected.read_bytes() != observed.read_bytes():
                    mismatches.append(expected.name)
        if mismatches:
            raise SystemExit("stale or missing generated charts: " + ", ".join(mismatches))
    print("Metric charts are current and source totals are consistent.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="regenerate in a temporary directory and compare bytes",
    )
    args = parser.parse_args()
    _verify_render_environment()
    _configure()
    if args.check:
        _check()
    else:
        _generate(HERE)
        print("Generated Phase 1 v0.1 metric charts (PNG and SVG).")


if __name__ == "__main__":
    main()
