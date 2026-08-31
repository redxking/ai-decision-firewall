from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from adf_poc.phase3.corpus import run_corpus, write_corpus_summary


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "phase3_policy.json"


class Phase3AdversarialCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.summary = run_corpus(POLICY_PATH)

    def test_all_declared_scenarios_and_cross_cutting_invariants_pass(self) -> None:
        summary = self.summary
        self.assertEqual(summary["corpus_id"], "P3-ADVERSARIAL-CORPUS-46")
        self.assertEqual(summary["scenario_count"], 46)
        self.assertEqual(summary["passed"], 46)
        self.assertEqual(summary["failed"], 0)
        self.assertEqual(summary["status"], "PASS")
        self.assertEqual(summary["failure_scenario_ids"], [])
        self.assertFalse(summary["live_actions_possible"])
        self.assertEqual(summary["execution_mode"], "synthetic_simulation")
        self.assertEqual(
            {name: row["total"] for name, row in summary["category_counts"].items()},
            {
                "authorization_bypass": 10,
                "broker_verifier": 6,
                "canonical": 4,
                "combined_attack": 4,
                "metamorphic": 6,
                "single_factor": 16,
            },
        )
        self.assertEqual(len({row["scenario_id"] for row in summary["scenarios"]}), 46)
        self.assertTrue(all(row["status"] == "PASS" for row in summary["scenarios"]))
        self.assertTrue(
            all(
                all(check["passed"] for check in row["invariants"])
                for row in summary["scenarios"]
            )
        )

    def test_corpus_is_deterministic_and_exports_no_reusable_authority(self) -> None:
        second = run_corpus(POLICY_PATH)
        self.assertEqual(second, self.summary)
        serialized = json.dumps(self.summary, sort_keys=True).lower()
        for prohibited in (
            '"signature"',
            '"token_id"',
            '"nonce"',
            "signing_key",
            "source_master_key",
        ):
            self.assertNotIn(prohibited, serialized)

    def test_summary_writer_requires_an_absent_or_empty_destination(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            absent = root / "absent"
            destination = write_corpus_summary(absent, self.summary)
            self.assertEqual(destination.parent, absent)
            persisted = json.loads(destination.read_text(encoding="utf-8"))
            self.assertEqual(persisted, self.summary)

            occupied = root / "occupied"
            occupied.mkdir()
            sentinel = occupied / "sentinel.txt"
            sentinel.write_text("preserve", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                write_corpus_summary(occupied, self.summary)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve")

            regular_file = root / "regular-file"
            regular_file.write_text("preserve", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                write_corpus_summary(regular_file, self.summary)
            self.assertEqual(regular_file.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
