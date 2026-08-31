#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from adf_poc.phase3.corpus import run_corpus, write_corpus_summary


ROOT = Path(__file__).resolve().parent


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the deterministic Phase 3 credential-gated adversarial corpus "
            "through the closed synthetic execution boundary."
        )
    )
    parser.add_argument(
        "--policy",
        type=Path,
        default=ROOT / "config" / "phase3_policy.json",
        help="Validated Phase 3 policy path.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=ROOT / "outputs" / "local" / "phase3-corpus",
        help="Absent or empty directory for the bounded JSON summary.",
    )
    args = parser.parse_args()

    summary = run_corpus(args.policy)
    destination = write_corpus_summary(args.output_dir, summary)
    print(
        json.dumps(
            {
                "corpus_id": summary["corpus_id"],
                "status": summary["status"],
                "scenario_count": summary["scenario_count"],
                "passed": summary["passed"],
                "failed": summary["failed"],
                "failure_scenario_ids": summary["failure_scenario_ids"],
                "summary_path": str(destination),
                "execution_mode": summary["execution_mode"],
                "live_actions_possible": summary["live_actions_possible"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
