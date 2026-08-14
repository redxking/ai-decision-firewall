from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adf_poc.engine import run_engine
from adf_poc.metrics import evaluate
from adf_poc.model import train_from_files
from adf_poc.reporting import generate_html_report
from adf_poc.synthetic import generate_dataset
from adf_poc.utils import sha256_file, write_json


def main() -> None:
    parser = argparse.ArgumentParser(description="Build and execute the AI Decision Firewall synthetic POC baseline.")
    parser.add_argument("--train-count", type=int, default=800)
    parser.add_argument("--test-count", type=int, default=400)
    parser.add_argument("--seed", type=int, default=20260814)
    parser.add_argument("--data-dir", default=str(ROOT / "data"))
    parser.add_argument("--output-dir", default=str(ROOT / "outputs" / "baseline"))
    parser.add_argument("--policy", default=str(ROOT / "config" / "policy.json"))
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest = generate_dataset(data_dir, args.train_count, args.test_count, args.seed)
    model_path = output_dir / "model.json"
    model = train_from_files(data_dir / "train_cases.jsonl", data_dir / "train_labels.jsonl", model_path)
    decisions_path = output_dir / "decisions.jsonl"
    audit_path = output_dir / "audit_chain.jsonl"
    decisions = run_engine(
        cases_path=data_dir / "test_cases.jsonl",
        model_path=model_path,
        policy_path=args.policy,
        decisions_path=decisions_path,
        audit_path=audit_path,
    )
    metrics = evaluate(
        decisions_path=decisions_path,
        labels_path=data_dir / "test_labels.jsonl",
        audit_path=audit_path,
        output_dir=output_dir,
    )
    generate_html_report(metrics, output_dir / "baseline_report.html")
    policy_path = Path(args.policy).resolve()
    try:
        policy_reference = str(policy_path.relative_to(ROOT.resolve()))
    except ValueError:
        policy_reference = str(policy_path)

    run_manifest = {
        "poc_version": "0.1.0",
        "dataset_manifest_hash": manifest["manifest_hash"],
        "model_version": model.version,
        "policy_file": policy_reference,
        "policy_sha256": sha256_file(policy_path),
        "train_cases": args.train_count,
        "test_cases": len(decisions),
        "seed": args.seed,
        "outputs": [
            "model.json", "decisions.jsonl", "audit_chain.jsonl", "metrics.json",
            "decision_summary.csv", "per_scenario_metrics.csv", "baseline_report.html"
        ],
        "safety_notice": "Synthetic data and simulated actions only. Not approved for operational use.",
    }
    write_json(output_dir / "run_manifest.json", run_manifest)
    print(json.dumps({
        "cases": metrics["scope"]["cases_evaluated"],
        "autonomous_containment_precision": metrics["decision_control"]["autonomous_containment_precision"],
        "false_containment_count": metrics["decision_control"]["false_containment_count"],
        "unsafe_automation_count": metrics["safety_and_assurance"]["unsafe_automation_count"],
        "audit_chain_valid": metrics["safety_and_assurance"]["audit_chain_valid"],
        "report": str(output_dir / "baseline_report.html"),
    }, indent=2))


if __name__ == "__main__":
    main()
