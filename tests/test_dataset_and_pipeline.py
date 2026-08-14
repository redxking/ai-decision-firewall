from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from adf_poc.engine import run_engine
from adf_poc.metrics import evaluate
from adf_poc.model import train_from_files
from adf_poc.synthetic import generate_dataset
from adf_poc.utils import read_jsonl


ROOT = Path(__file__).resolve().parents[1]


class DatasetAndPipelineTests(unittest.TestCase):
    def test_ground_truth_is_separate_from_case_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            generate_dataset(directory, train_count=20, test_count=10, seed=42)
            case = read_jsonl(Path(directory) / "test_cases.jsonl")[0]
            self.assertNotIn("compromised", case)
            self.assertNotIn("scenario", case)
            self.assertNotIn("expected_disposition", case)

    def test_small_end_to_end_run_preserves_safety_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = root / "data"
            output = root / "output"
            generate_dataset(data, train_count=180, test_count=90, seed=2026)
            model_path = output / "model.json"
            output.mkdir(parents=True, exist_ok=True)
            train_from_files(data / "train_cases.jsonl", data / "train_labels.jsonl", model_path)
            decisions_path = output / "decisions.jsonl"
            audit_path = output / "audit.jsonl"
            run_engine(
                cases_path=data / "test_cases.jsonl",
                model_path=model_path,
                policy_path=ROOT / "config" / "policy.json",
                decisions_path=decisions_path,
                audit_path=audit_path,
            )
            metrics = evaluate(
                decisions_path=decisions_path,
                labels_path=data / "test_labels.jsonl",
                audit_path=audit_path,
                output_dir=output,
            )
            safety = metrics["safety_and_assurance"]
            self.assertEqual(safety["unsafe_automation_count"], 0)
            self.assertEqual(safety["poisoned_evidence_autonomous_actions"], 0)
            self.assertEqual(safety["authorization_without_independent_verifier"], 0)
            self.assertTrue(safety["audit_chain_valid"])
            self.assertEqual(safety["evidence_traceability_rate"], 1.0)


if __name__ == "__main__":
    unittest.main()
