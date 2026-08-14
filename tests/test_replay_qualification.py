from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from adf_poc.engine import run_engine
from adf_poc.replay.adapters import AdapterCaseBatch
from adf_poc.replay.harness import ReplayHarness, ReplaySafetyViolation


ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def make_qualification_repository(root: Path) -> Path:
    shutil.copytree(
        ROOT / "data" / "phase2_qualification",
        root / "data" / "phase2_qualification",
    )
    shutil.copytree(ROOT / "contracts", root / "contracts")
    (root / "config").mkdir(parents=True)
    (root / "outputs" / "baseline").mkdir(parents=True)
    shutil.copyfile(ROOT / "config" / "policy.json", root / "config" / "policy.json")
    shutil.copyfile(
        ROOT / "outputs" / "baseline" / "model.json",
        root / "outputs" / "baseline" / "model.json",
    )
    config = json.loads(
        (ROOT / "config" / "phase2_qualification.json").read_text(encoding="utf-8")
    )
    config["output_dir"] = "outputs/replay/qualification-test"
    config_path = root / "config" / "phase2_qualification.json"
    write_json(config_path, config)
    return config_path


class ReplayQualificationIntegrationTests(unittest.TestCase):
    def test_fixture_matches_predeclared_outcomes_and_complete_accounting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_qualification_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            manifest, batch = harness.validate_inputs()

            self.assertEqual(len(batch.qualification_records), 7)
            self.assertEqual(len(batch.records), 3)
            self.assertEqual(len(batch.rejection_records), 4)
            cases_entry = manifest.file_for_role("cases")
            assert cases_entry is not None
            harness._validate_qualification_batch(
                batch,
                cases_entry=cases_entry,
                dataset_id=manifest.dataset_id,
            )

            expected = json.loads(
                (
                    root
                    / "data"
                    / "phase2_qualification"
                    / "expected_qualification.json"
                ).read_text(encoding="utf-8")
            )
            observed = [
                {
                    key: row[key]
                    for key in (
                        "nonblank_record_number",
                        "raw_line_sha256",
                        "status",
                        "error_category",
                        "error_code",
                    )
                }
                for row in batch.qualification_records
            ]
            self.assertEqual(observed, expected["records"])

            result = harness.run()
            accounting = result.metrics["record_qualification"]
            self.assertEqual(accounting["input_records"], 7)
            self.assertEqual(accounting["accepted_records"], 3)
            self.assertEqual(accounting["rejected_records"], 4)
            self.assertEqual(accounting["decision_records"], 3)
            self.assertTrue(accounting["complete_accounting"])
            self.assertFalse(accounting["historical_metrics_available"])
            self.assertEqual(
                accounting["rejection_reason_counts"],
                {
                    "SEMANTICS/CANONICAL_CONTEXT_MISMATCH": 1,
                    "SEMANTICS/INVALID_TIMESTAMP": 1,
                    "STRUCTURE/MISSING_REQUIRED_FIELD": 1,
                    "SYNTAX/INVALID_JSON": 1,
                },
            )
            assurance = result.metrics["read_only_assurance"]
            for key in (
                "authorization_tokens_issued",
                "broker_invocations",
                "operational_effects",
                "action_results",
            ):
                self.assertEqual(assurance[key], 0, key)

            run_manifest = json.loads(result.run_manifest_path.read_text(encoding="utf-8"))
            self.assertTrue(
                run_manifest["record_qualification"]["complete_accounting_verified"]
            )
            self.assertIn(
                "qualification_accounting", run_manifest["deterministic_artifacts"]
            )
            self.assertIn("rejections", run_manifest["deterministic_artifacts"])

    def test_forged_or_incomplete_ledger_is_rejected_before_engine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_qualification_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            manifest, batch = harness.validate_inputs()
            cases_entry = manifest.file_for_role("cases")
            assert cases_entry is not None

            missing = AdapterCaseBatch(
                records=batch.records,
                qualification_records=batch.qualification_records[:-1],
                rejection_records=batch.rejection_records[:-1],
            )
            with self.assertRaises(ReplaySafetyViolation):
                harness._validate_qualification_batch(
                    missing,
                    cases_entry=cases_entry,
                    dataset_id=manifest.dataset_id,
                )

            changed = [copy.deepcopy(row) for row in batch.qualification_records]
            changed[0]["raw_line_sha256"] = "0" * 64
            forged = AdapterCaseBatch(
                records=batch.records,
                qualification_records=tuple(changed),
                rejection_records=batch.rejection_records,
            )
            with self.assertRaises(ReplaySafetyViolation):
                harness._validate_qualification_batch(
                    forged,
                    cases_entry=cases_entry,
                    dataset_id=manifest.dataset_id,
                )

            substituted_records = list(copy.deepcopy(batch.records))
            substituted_records[0]["subject_id"] = "substituted-subject"
            substituted = AdapterCaseBatch(
                records=tuple(substituted_records),
                qualification_records=batch.qualification_records,
                rejection_records=batch.rejection_records,
            )
            with self.assertRaises(ReplaySafetyViolation):
                harness._validate_qualification_batch(
                    substituted,
                    cases_entry=cases_entry,
                    dataset_id=manifest.dataset_id,
                )

            mutations = []

            wrong_line = [copy.deepcopy(row) for row in batch.qualification_records]
            wrong_line[0]["physical_line_number"] = 2
            mutations.append(("wrong-line", wrong_line))

            accepted_with_error = [
                copy.deepcopy(row) for row in batch.qualification_records
            ]
            accepted_with_error[0]["error_category"] = "SYNTAX"
            accepted_with_error[0]["error_code"] = "INVALID_JSON"
            mutations.append(("accepted-with-error", accepted_with_error))

            quarantined_without_error = [
                copy.deepcopy(row) for row in batch.qualification_records
            ]
            quarantined_without_error[3]["error_category"] = ""
            quarantined_without_error[3]["error_code"] = ""
            mutations.append(("quarantined-without-error", quarantined_without_error))

            mismatched_error_pair = [
                copy.deepcopy(row) for row in batch.qualification_records
            ]
            mismatched_error_pair[3]["error_category"] = "SYNTAX"
            mismatched_error_pair[3]["error_code"] = "INVALID_TIMESTAMP"
            mutations.append(("mismatched-error-pair", mismatched_error_pair))

            payload_field = [copy.deepcopy(row) for row in batch.qualification_records]
            payload_field[0]["raw_payload"] = "must-never-be-accepted"
            mutations.append(("payload-field", payload_field))

            for label, changed_rows in mutations:
                changed_rejections = tuple(
                    row
                    for row in changed_rows
                    if row.get("status") == "QUARANTINED"
                )
                candidate = AdapterCaseBatch(
                    records=batch.records,
                    qualification_records=tuple(changed_rows),
                    rejection_records=changed_rejections,
                )
                with self.subTest(label=label), self.assertRaises(
                    ReplaySafetyViolation
                ):
                    harness._validate_qualification_batch(
                        candidate,
                        cases_entry=cases_entry,
                        dataset_id=manifest.dataset_id,
                    )

    def test_validate_only_rejects_adapter_substitution_and_empty_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_qualification_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            _, batch = harness.validate_inputs()

            substituted_records = list(copy.deepcopy(batch.records))
            substituted_records[0]["subject_id"] = "validate-only-substitution"
            substituted = AdapterCaseBatch(
                records=tuple(substituted_records),
                qualification_records=batch.qualification_records,
                rejection_records=batch.rejection_records,
            )
            with patch.object(
                harness._adapter,
                "load_cases",
                return_value=substituted,
            ), self.assertRaises(ReplaySafetyViolation):
                harness.validate_inputs()

            empty = AdapterCaseBatch(
                records=(),
                qualification_records=batch.qualification_records,
                rejection_records=batch.rejection_records,
            )
            with patch.object(
                harness._adapter,
                "load_cases",
                return_value=empty,
            ), patch.object(
                harness,
                "_validate_qualification_batch",
            ), self.assertRaises(ReplaySafetyViolation):
                harness.validate_inputs()

    def test_qualification_and_rejection_schemas_are_closed(self) -> None:
        qualification_schema = json.loads(
            (
                ROOT / "contracts" / "v0.2.0" / "replay-qualification.schema.json"
            ).read_text(encoding="utf-8")
        )
        rejection_schema = json.loads(
            (
                ROOT / "contracts" / "v0.2.0" / "replay-rejection.schema.json"
            ).read_text(encoding="utf-8")
        )
        registry = Registry().with_resource(
            qualification_schema["$id"],
            Resource.from_contents(qualification_schema),
        )
        qualification_validator = Draft202012Validator(qualification_schema)
        rejection_validator = Draft202012Validator(
            rejection_schema,
            registry=registry,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_qualification_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            _, batch = harness.validate_inputs()

        accepted = copy.deepcopy(batch.qualification_records[0])
        rejected = copy.deepcopy(batch.rejection_records[0])
        self.assertFalse(list(qualification_validator.iter_errors(accepted)))
        self.assertFalse(list(qualification_validator.iter_errors(rejected)))
        self.assertFalse(list(rejection_validator.iter_errors(rejected)))
        self.assertTrue(list(rejection_validator.iter_errors(accepted)))

        rejected["raw_payload"] = "prohibited"
        self.assertTrue(list(qualification_validator.iter_errors(rejected)))
        self.assertTrue(list(rejection_validator.iter_errors(rejected)))

    def test_qualification_outputs_are_byte_deterministic(self) -> None:
        snapshots: list[dict[str, bytes]] = []
        deterministic_names = (
            "qualification_accounting.jsonl",
            "rejections.jsonl",
            "normalized_cases.jsonl",
            "normalization_diagnostics.json",
            "replay_decisions.jsonl",
            "adjudication_comparison.jsonl",
            "replay_metrics.json",
        )
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config_path = make_qualification_repository(root)
                result = ReplayHarness.from_config(
                    config_path, repository_root=root
                ).run()
                snapshots.append(
                    {
                        name: (result.output_dir / name).read_bytes()
                        for name in deterministic_names
                    }
                )
        self.assertEqual(snapshots[0], snapshots[1])

    def test_engine_cannot_replace_metadata_only_qualification_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_qualification_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)

            def tampering_runner(**kwargs):
                decisions = run_engine(**kwargs)
                output_dir = Path(kwargs["decisions_path"]).parent
                (output_dir / "qualification_accounting.jsonl").write_text(
                    '{"raw_payload":"must-not-survive"}\n', encoding="utf-8"
                )
                (output_dir / "rejections.jsonl").write_text(
                    '{"raw_payload":"must-not-survive"}\n', encoding="utf-8"
                )
                return decisions

            with patch.object(
                ReplayHarness,
                "_default_engine_runner",
                return_value=tampering_runner,
            ):
                result = harness.run()

            accounting = result.qualification_accounting_path
            rejections = result.rejections_path
            assert accounting is not None and rejections is not None
            self.assertNotIn("raw_payload", accounting.read_text(encoding="utf-8"))
            self.assertNotIn("raw_payload", rejections.read_text(encoding="utf-8"))
            self.assertEqual(len(accounting.read_text(encoding="utf-8").splitlines()), 7)
            self.assertEqual(len(rejections.read_text(encoding="utf-8").splitlines()), 4)


if __name__ == "__main__":
    unittest.main()
