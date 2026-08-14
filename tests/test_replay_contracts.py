from __future__ import annotations

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from adf_poc.replay.adapters import CanonicalJSONLAdapter
from adf_poc.replay.contracts import (
    ContractValidationError,
    MAX_EVENTS_PER_CASE,
    MAX_JSONL_LINE_BYTES,
    MAX_UNTRUSTED_TEXT_CHARS,
    ManifestValidationError,
    ReplayConfig,
    ReplayConfigurationError,
    load_and_validate_manifest,
    load_jsonl_objects,
    validate_case_record,
    validate_case_records,
)
from adf_poc.replay.normalizer import normalize_cases_with_diagnostics


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "data" / "phase2_starter"


def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def copy_fixture(root: Path) -> Path:
    target = root / "phase2_starter"
    shutil.copytree(FIXTURE, target)
    return target / "manifest.json"


class ReplayContractTests(unittest.TestCase):
    def test_starter_manifest_cases_and_temporal_normalization_validate(self) -> None:
        manifest = load_and_validate_manifest(FIXTURE / "manifest.json")
        self.assertEqual(manifest.schema_version, "0.2.0")
        self.assertEqual(manifest.data_origin, "SYNTHETIC_FIXTURE")
        self.assertEqual(manifest.historical_case_count, 0)
        self.assertFalse(manifest.attestations["direct_identifiers_present"])
        cases_entry = manifest.file_for_role("cases")
        self.assertIsNotNone(cases_entry)
        batch = CanonicalJSONLAdapter().load_cases(cases_entry)
        normalized, diagnostics = normalize_cases_with_diagnostics(batch.records)
        self.assertEqual(len(normalized), 3)
        self.assertEqual(diagnostics["temporal_reordering_warning_count"], 3)
        for case in normalized:
            ordering = [
                (
                    event["observed_at"],
                    event["collected_at"],
                    event["source_type"],
                    event["source_instance"],
                    event["event_id"],
                )
                for event in case["events"]
            ]
            self.assertEqual(ordering, sorted(ordering))

    def test_timestamp_normalization_preserves_subsecond_precision(self) -> None:
        candidate = load_jsonl_objects(FIXTURE / "cases.jsonl", label="cases")[0]
        candidate["opened_at"] = "2026-08-01T00:00:00.123456+00:00"
        normalized, _ = normalize_cases_with_diagnostics([candidate])
        self.assertEqual(
            normalized[0]["opened_at"], "2026-08-01T00:00:00.123456+00:00"
        )

    def test_configuration_allows_only_read_only_modes_and_false_live_actions(self) -> None:
        valid = {
            "schema_version": "0.2.0",
            "execution_mode": "HISTORICAL_REPLAY",
            "live_actions_enabled": False,
            "dataset_manifest": "data/manifest.json",
            "model_path": "model.json",
            "policy_path": "policy.json",
            "output_dir": "outputs/replay/test",
            "contract_adapter": "canonical_jsonl_v0.2",
            "deterministic_outputs": True,
            "zero_effects_required": True,
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for mode in ("HISTORICAL_REPLAY", "SHADOW_READ_ONLY"):
                value = dict(valid, execution_mode=mode)
                write_json(path, value)
                self.assertEqual(ReplayConfig.load(path).execution_mode, mode)
            for mode in ("SYNTHETIC_SIMULATION", "LIVE", "historical_replay"):
                with self.subTest(mode=mode):
                    write_json(path, dict(valid, execution_mode=mode))
                    with self.assertRaises(ReplayConfigurationError):
                        ReplayConfig.load(path)
            write_json(path, dict(valid, live_actions_enabled=True))
            with self.assertRaises(ReplayConfigurationError):
                ReplayConfig.load(path)

    def test_runtime_label_leakage_is_rejected_at_any_depth(self) -> None:
        record = load_jsonl_objects(FIXTURE / "cases.jsonl", label="cases")[0]
        for mutation in ("top", "nested"):
            candidate = copy.deepcopy(record)
            if mutation == "top":
                candidate["compromised"] = False
            else:
                candidate["events"][0]["attributes"]["expected_disposition"] = "NO_ACTION"
            with self.subTest(mutation=mutation), self.assertRaises(
                ContractValidationError
            ):
                validate_case_record(candidate)

    def test_versions_timestamps_ranges_and_inventory_equality_are_enforced(self) -> None:
        original = load_jsonl_objects(FIXTURE / "cases.jsonl", label="cases")[0]
        mutations = []
        wrong_version = copy.deepcopy(original)
        wrong_version["schema_version"] = "0.1.0"
        mutations.append(wrong_version)
        naive_time = copy.deepcopy(original)
        naive_time["opened_at"] = "2026-08-01T12:00:00"
        mutations.append(naive_time)
        bad_range = copy.deepcopy(original)
        bad_range["asset_criticality"] = 1.1
        mutations.append(bad_range)
        reversed_time = copy.deepcopy(original)
        reversed_time["events"][0]["collected_at"] = "2026-08-01T11:00:00+00:00"
        mutations.append(reversed_time)
        break_glass_mismatch = copy.deepcopy(original)
        inventory = next(
            event
            for event in break_glass_mismatch["events"]
            if event["source_type"] == "asset_inventory"
        )
        inventory["attributes"]["break_glass"] = True
        mutations.append(break_glass_mismatch)
        criticality_mismatch = copy.deepcopy(original)
        inventory = next(
            event
            for event in criticality_mismatch["events"]
            if event["source_type"] == "asset_inventory"
        )
        inventory["attributes"]["asset_criticality"] = 0.99
        mutations.append(criticality_mismatch)
        for index, candidate in enumerate(mutations):
            with self.subTest(index=index), self.assertRaises(ContractValidationError):
                validate_case_record(candidate)

    def test_case_and_event_identifiers_must_be_globally_unique(self) -> None:
        records = load_jsonl_objects(FIXTURE / "cases.jsonl", label="cases")
        duplicate_case = copy.deepcopy(records)
        duplicate_case[1]["case_id"] = duplicate_case[0]["case_id"]
        for event in duplicate_case[1]["events"]:
            event["case_id"] = duplicate_case[0]["case_id"]
        with self.assertRaises(ContractValidationError):
            validate_case_records(duplicate_case)
        duplicate_event = copy.deepcopy(records)
        duplicate_event[1]["events"][0]["event_id"] = duplicate_event[0]["events"][0][
            "event_id"
        ]
        with self.assertRaises(ContractValidationError):
            validate_case_records(duplicate_event)

    def test_manifest_rejects_digest_count_and_path_confinement_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = copy_fixture(root)
            baseline = read_json(manifest_path)

            wrong_digest = copy.deepcopy(baseline)
            wrong_digest["files"][0]["sha256"] = "0" * 64
            write_json(manifest_path, wrong_digest)
            with self.assertRaises(ManifestValidationError):
                load_and_validate_manifest(manifest_path)

            wrong_count = copy.deepcopy(baseline)
            wrong_count["files"][0]["record_count"] += 1
            write_json(manifest_path, wrong_count)
            with self.assertRaises(ManifestValidationError):
                load_and_validate_manifest(manifest_path)

            outside = root / "outside.jsonl"
            shutil.copyfile(FIXTURE / "cases.jsonl", outside)
            escaped = copy.deepcopy(baseline)
            escaped["files"][0]["path"] = "../outside.jsonl"
            escaped["files"][0]["sha256"] = sha256(outside)
            write_json(manifest_path, escaped)
            with self.assertRaises(ManifestValidationError):
                load_and_validate_manifest(manifest_path)

    def test_historical_attestations_and_case_count_are_mandatory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = copy_fixture(Path(directory))
            baseline = read_json(manifest_path)
            historical = copy.deepcopy(baseline)
            historical["data_origin"] = "HISTORICAL_DEIDENTIFIED"
            historical["historical_case_count"] = 3
            write_json(manifest_path, historical)
            self.assertEqual(load_and_validate_manifest(manifest_path).historical_case_count, 3)

            unapproved = copy.deepcopy(historical)
            unapproved["attestations"]["approved_for_replay"] = False
            write_json(manifest_path, unapproved)
            with self.assertRaises(ManifestValidationError):
                load_and_validate_manifest(manifest_path)

            direct_identifiers = copy.deepcopy(historical)
            direct_identifiers["attestations"]["direct_identifiers_present"] = True
            write_json(manifest_path, direct_identifiers)
            with self.assertRaises(ManifestValidationError):
                load_and_validate_manifest(manifest_path)

            wrong_historical_count = copy.deepcopy(historical)
            wrong_historical_count["historical_case_count"] = 2
            write_json(manifest_path, wrong_historical_count)
            with self.assertRaises(ManifestValidationError):
                load_and_validate_manifest(manifest_path)

    def test_historical_adjudications_must_be_physically_separate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            manifest_path = copy_fixture(Path(directory))
            value = read_json(manifest_path)
            value["files"][1]["path"] = value["files"][0]["path"]
            value["files"][1]["sha256"] = value["files"][0]["sha256"]
            value["files"][1]["record_count"] = value["files"][0]["record_count"]
            write_json(manifest_path, value)
            with self.assertRaises(ManifestValidationError):
                load_and_validate_manifest(manifest_path)

    def test_record_event_line_and_untrusted_text_bounds_are_enforced(self) -> None:
        original = load_jsonl_objects(FIXTURE / "cases.jsonl", label="cases")[0]
        too_many_events = copy.deepcopy(original)
        too_many_events["events"] = [
            copy.deepcopy(original["events"][0]) for _ in range(MAX_EVENTS_PER_CASE + 1)
        ]
        with self.assertRaises(ContractValidationError):
            validate_case_record(too_many_events)

        too_much_text = copy.deepcopy(original)
        too_much_text["events"][0]["untrusted_text"] = "x" * (
            MAX_UNTRUSTED_TEXT_CHARS + 1
        )
        with self.assertRaises(ContractValidationError):
            validate_case_record(too_much_text)

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.jsonl"
            path.write_text(
                json.dumps({"value": "x" * MAX_JSONL_LINE_BYTES}) + "\n",
                encoding="utf-8",
            )
            with self.assertRaises(ContractValidationError):
                load_jsonl_objects(path, label="oversized")


if __name__ == "__main__":
    unittest.main()
