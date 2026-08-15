from __future__ import annotations

import ast
import json
import math
import os
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from adf_poc.phase31.benchmark import run_synthetic_benchmark, temporal_split
from adf_poc.phase31.calibration import PlattCalibrator
from adf_poc.phase31.contracts import (
    DatasetBinding,
    ModelEvaluationPlan,
    PlanValidationError,
)
from adf_poc.phase31.metrics import binary_metrics, selective_risk_curve
from adf_poc.utils import read_json, sha256_file, write_json


ROOT = Path(__file__).resolve().parents[1]
PLAN = ROOT / "config" / "phase31_model_evaluation_plan.json"
PLAN_SCHEMA = ROOT / "contracts" / "v0.3.1" / "model-evaluation-plan.schema.json"
RESULT_SCHEMA = ROOT / "contracts" / "v0.3.1" / "model-evaluation-result.schema.json"
SCRIPT = ROOT / "scripts" / "run_phase31_model_benchmark.py"


class Phase31ModelEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.plan = ModelEvaluationPlan.load(PLAN, schema_path=PLAN_SCHEMA)
        cls.plan.verify_source_bindings(ROOT)
        cls.result = run_synthetic_benchmark(
            plan_path=PLAN,
            schema_path=PLAN_SCHEMA,
            result_schema_path=RESULT_SCHEMA,
            repo_root=ROOT,
        )

    def test_plan_is_synthetic_only_and_cannot_promote(self) -> None:
        self.assertEqual(self.plan.status, "DRAFT")
        self.assertEqual(self.plan.evaluation_mode, "SYNTHETIC_MECHANISM")
        self.assertTrue(self.plan.historical_payload_access_prohibited)
        self.assertTrue(self.plan.live_action_prohibited)
        self.assertEqual(self.plan.promotion_gate_status, "OWNER_THRESHOLDS_REQUIRED")
        self.assertEqual(self.plan.performance_thresholds, ())

    def test_plan_rejects_historical_mode_and_promotion_thresholds(self) -> None:
        source = read_json(PLAN)
        mutations = []
        historical = deepcopy(source)
        historical["data_classification"] = "HISTORICAL_RESTRICTED"
        mutations.append(historical)
        promoted = deepcopy(source)
        promoted["promotion"]["performance_thresholds"] = [
            {"metric": "brier_score", "maximum": 0.2}
        ]
        mutations.append(promoted)
        live = deepcopy(source)
        live["live_action_prohibited"] = False
        mutations.append(live)
        with tempfile.TemporaryDirectory() as directory:
            for index, mutation in enumerate(mutations):
                path = Path(directory) / f"mutation-{index}.json"
                write_json(path, mutation)
                with self.subTest(index=index):
                    with self.assertRaises(PlanValidationError):
                        ModelEvaluationPlan.load(path, schema_path=PLAN_SCHEMA)

    def test_source_bindings_reject_digest_drift(self) -> None:
        source = read_json(PLAN)
        source["dataset_bindings"][0]["sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "plan.json"
            write_json(path, source)
            plan = ModelEvaluationPlan.load(path, schema_path=PLAN_SCHEMA)
            with self.assertRaisesRegex(PlanValidationError, "digest mismatch"):
                plan.verify_source_bindings(ROOT)

    def test_source_bindings_reject_symlink_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            bindings = []
            roles = (
                "source_pool_cases_a",
                "source_pool_cases_b",
                "source_pool_labels_a",
                "source_pool_labels_b",
            )
            for index, role in enumerate(roles):
                target = real / f"source-{index}.jsonl"
                target.write_text('{"record": 1}\n', encoding="utf-8")
                bindings.append(
                    DatasetBinding(
                        role=role,
                        path=f"link/source-{index}.jsonl",
                        sha256=sha256_file(target),
                        records=1,
                    )
                )
            (root / "link").symlink_to(real, target_is_directory=True)
            plan = replace(self.plan, source_bindings=tuple(bindings))
            with self.assertRaisesRegex(PlanValidationError, "traverse a symlink"):
                plan.verify_source_bindings(root)

    def test_temporal_partitions_are_disjoint_and_ordered(self) -> None:
        partitions = self.result["partitions"]
        self.assertEqual(
            sum(partition["records"] for partition in partitions.values()), 1200
        )
        self.assertLess(partitions["training"]["end"], partitions["calibration"]["start"])
        self.assertLess(partitions["calibration"]["end"], partitions["evaluation"]["start"])
        self.assertEqual(len({partitions[name]["case_id_digest"] for name in partitions}), 3)

    def test_benchmark_is_deterministic_and_schema_validated(self) -> None:
        repeated = run_synthetic_benchmark(
            plan_path=PLAN,
            schema_path=PLAN_SCHEMA,
            result_schema_path=RESULT_SCHEMA,
            repo_root=ROOT,
        )
        self.assertEqual(self.result, repeated)
        self.assertEqual(self.result["promotion"]["decision"], "NOT_AUTHORIZED")
        self.assertEqual(
            self.result["safety_boundary"],
            {
                "historical_payload_accessed": False,
                "live_data_accessed": False,
                "action_credentials_present": False,
                "broker_constructed": False,
                "target_constructed": False,
                "operational_effects": 0,
            },
        )

    def test_challenger_observation_does_not_claim_superiority(self) -> None:
        comparison = self.result["comparison"]
        self.assertEqual(
            comparison["interpretation"],
            "Mechanism observation only; no superiority or promotion claim.",
        )
        baseline = self.result["models"][self.plan.baseline_id]["metrics"]
        challenger = self.result["models"][self.plan.challenger_id]["metrics"]
        self.assertEqual(baseline["roc_auc"], challenger["roc_auc"])
        self.assertLess(challenger["brier_score"], baseline["brier_score"])
        self.assertLess(challenger["log_loss"], baseline["log_loss"])

    def test_metrics_cover_discrimination_calibration_error_and_abstention(self) -> None:
        metrics = binary_metrics(
            [0, 0, 1, 1],
            [0.1, 0.4, 0.6, 0.9],
            threshold=0.5,
            calibration_bins=4,
        )
        self.assertEqual(metrics["confusion_matrix"], {"tp": 2, "tn": 2, "fp": 0, "fn": 0})
        self.assertEqual(metrics["roc_auc"], 1.0)
        self.assertEqual(metrics["average_precision"], 1.0)
        self.assertAlmostEqual(metrics["brier_score"], 0.085)
        curve = selective_risk_curve(
            [0, 0, 1, 1], [0.1, 0.4, 0.6, 0.9], margins=(0.0, 0.2)
        )
        self.assertEqual(curve[0]["coverage"], 1.0)
        self.assertEqual(curve[1]["selected_count"], 2)

    def test_calibrator_rejects_invalid_values(self) -> None:
        for scores, labels in (
            ([0.1, math.nan], [0, 1]),
            ([0.1, 1.1], [0, 1]),
            ([0.1, 0.9], [0, True]),
            ([], []),
        ):
            with self.subTest(scores=scores, labels=labels):
                with self.assertRaises(ValueError):
                    PlattCalibrator.fit(scores, labels, epochs=100)

    def test_cli_validates_executes_and_refuses_overwrite(self) -> None:
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(ROOT / "src")
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        validate = subprocess.run(
            [sys.executable, str(SCRIPT), "--validate-plan"],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(validate.returncode, 0, validate.stderr)
        self.assertEqual(json.loads(validate.stdout)["status"], "PLAN_VALID")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.json"
            first = subprocess.run(
                [sys.executable, str(SCRIPT), "--output", str(output)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(json.loads(first.stdout)["status"], "COMPLETE_SYNTHETIC_ONLY")
            second = subprocess.run(
                [sys.executable, str(SCRIPT), "--output", str(output)],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(second.returncode, 0)
            self.assertIn("no-clobber", second.stderr)

    def test_phase31_has_no_action_or_historical_adapter_import(self) -> None:
        forbidden_modules = {
            "adf_poc.actions",
            "adf_poc.engine",
            "adf_poc.execution",
            "adf_poc.phase3.authorization",
            "adf_poc.phase3.engine",
            "adf_poc.phase3.simulation",
            "socket",
            "subprocess",
        }
        observed: set[str] = set()
        for path in (ROOT / "src" / "adf_poc" / "phase31").glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    observed.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    observed.add(node.module)
        self.assertFalse(observed & forbidden_modules, observed & forbidden_modules)


if __name__ == "__main__":
    unittest.main()
