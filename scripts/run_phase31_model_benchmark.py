#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from adf_poc.phase31 import ModelEvaluationPlan, run_synthetic_benchmark


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PLAN = REPO_ROOT / "config" / "phase31_model_evaluation_plan.json"
PLAN_SCHEMA = REPO_ROOT / "contracts" / "v0.3.1" / "model-evaluation-plan.schema.json"
RESULT_SCHEMA = REPO_ROOT / "contracts" / "v0.3.1" / "model-evaluation-result.schema.json"


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate or execute the Phase 3.1 synthetic-only model evaluation mechanism. "
            "No historical-data or live-action mode exists."
        )
    )
    parser.add_argument("--plan", default=str(DEFAULT_PLAN))
    parser.add_argument("--validate-plan", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()

    plan = ModelEvaluationPlan.load(args.plan, schema_path=PLAN_SCHEMA)
    plan.verify_source_bindings(REPO_ROOT)
    if args.validate_plan:
        print(
            json.dumps(
                {
                    "status": "PLAN_VALID",
                    "plan_id": plan.plan_id,
                    "evaluation_mode": plan.evaluation_mode,
                    "promotion_gate_status": plan.promotion_gate_status,
                },
                sort_keys=True,
            )
        )
        return 0
    if not args.output:
        parser.error("--output is required unless --validate-plan is used")
    output = Path(args.output)
    if output.exists() and (output.is_symlink() or not output.is_file()):
        parser.error("--output must be a new path or an existing regular file")
    if output.exists():
        parser.error("--output already exists; benchmark results are no-clobber")
    result = run_synthetic_benchmark(
        plan_path=args.plan,
        schema_path=PLAN_SCHEMA,
        result_schema_path=RESULT_SCHEMA,
        repo_root=REPO_ROOT,
        output_path=output,
    )
    print(
        json.dumps(
            {
                "status": "COMPLETE_SYNTHETIC_ONLY",
                "plan_id": plan.plan_id,
                "evaluation_records": result["partitions"]["evaluation"]["records"],
                "promotion_decision": result["promotion"]["decision"],
                "output": str(output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
