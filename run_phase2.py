from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from adf_poc.replay import ReplayHarness


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Run the Phase 2 historical-replay or shadow-read-only harness. "
            "This entry point exposes no live-action mode."
        )
    )
    parser.add_argument(
        "--config",
        default=str(ROOT / "config" / "phase2_replay.json"),
        help="Path to a fail-closed Phase 2 replay configuration.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate configuration, manifest, digests, attestations, and cases without running the engine.",
    )
    args = parser.parse_args()

    harness = ReplayHarness.from_config(args.config, repository_root=ROOT)
    if args.validate_only:
        manifest, case_batch = harness.validate_inputs()
        print(
            json.dumps(
                {
                    "status": "VALID",
                    "dataset_id": manifest.dataset_id,
                    "data_origin": manifest.data_origin,
                    "historical_case_count": manifest.historical_case_count,
                    "execution_mode": manifest.intended_mode,
                    "cases": len(case_batch.records),
                    "input_records": (
                        len(case_batch.qualification_records)
                        if case_batch.qualification_records
                        else len(case_batch.records)
                    ),
                    "accepted_records": len(case_batch.records),
                    "quarantined_records": len(case_batch.rejection_records),
                    "record_failure_policy": harness.config.record_failure_policy,
                    "mapping_warnings": len(case_batch.mapping_warnings),
                    "live_actions_enabled": False,
                    **(
                        {"gate_b_preflight": harness.gate_b_preflight_summary}
                        if harness.gate_b_preflight_summary is not None
                        else {}
                    ),
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    result = harness.run()
    assurance = result.metrics["read_only_assurance"]
    summary = {
        "status": "COMPLETE_READ_ONLY",
        "dataset_id": result.dataset_id,
        "data_origin": result.data_origin,
        "historical_case_count": result.historical_case_count,
        "execution_mode": result.execution_mode,
        "cases": result.metrics["scope"]["cases_evaluated"],
        "authorization_tokens_issued": assurance["authorization_tokens_issued"],
        "broker_invocations": assurance["broker_invocations"],
        "operational_effects": assurance["operational_effects"],
        "metrics": str(result.metrics_path),
    }
    if "record_qualification" in result.metrics:
        qualification = result.metrics["record_qualification"]
        summary["input_records"] = qualification["input_records"]
        summary["accepted_records"] = qualification["accepted_records"]
        summary["quarantined_records"] = qualification["rejected_records"]
        summary["complete_accounting"] = qualification["complete_accounting"]
    if result.gate_b_preflight is not None:
        summary["gate_b_preflight"] = result.gate_b_preflight
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
