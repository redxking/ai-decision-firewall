from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from adf_poc.replay.reference_features import (
    ReferenceFeatureAssuranceError,
    verify_reference_feature_projections,
)
from adf_poc.utils import canonical_json


ROOT = Path(__file__).resolve().parents[1]
RECORD_KEYS = {
    "schema_version",
    "case_id",
    "normalized_case_sha256",
    "expected_projection_sha256",
    "observed_projection_sha256",
    "matched",
}


def read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def load_bundle(name: str) -> tuple[list[dict], list[dict]]:
    root = ROOT / "evidence" / name
    return (
        read_jsonl(root / "normalized_cases.jsonl"),
        read_jsonl(root / "engine_decisions.jsonl"),
    )


def select_case(
    cases: list[dict], decisions: list[dict], case_id: str
) -> tuple[list[dict], list[dict]]:
    return (
        [copy.deepcopy(next(row for row in cases if row["case_id"] == case_id))],
        [copy.deepcopy(next(row for row in decisions if row["case_id"] == case_id))],
    )


def rehash_decision(decision: dict) -> None:
    decision.pop("decision_record_hash", None)
    encoded = json.dumps(
        decision, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    decision["decision_record_hash"] = hashlib.sha256(encoded).hexdigest()


class ReferenceFeatureAssuranceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.starter_cases, cls.starter_decisions = load_bundle("phase2_starter")
        cls.qualification_cases, cls.qualification_decisions = load_bundle(
            "phase2_qualification"
        )
        schema = json.loads(
            (
                ROOT
                / "contracts"
                / "v0.2.0"
                / "reference-feature-assurance.schema.json"
            ).read_text(encoding="utf-8")
        )
        cls.schema_validator = Draft202012Validator(schema)

    def assert_code(self, expected: str, function, *args) -> None:
        with self.assertRaises(ReferenceFeatureAssuranceError) as raised:
            function(*args)
        self.assertEqual(raised.exception.code, expected)
        self.assertEqual(str(raised.exception), expected)

    def test_committed_positive_fixtures_match_and_validate_schema(self) -> None:
        for name, cases, decisions in (
            ("starter", self.starter_cases, self.starter_decisions),
            (
                "qualification",
                self.qualification_cases,
                self.qualification_decisions,
            ),
        ):
            with self.subTest(bundle=name):
                records = verify_reference_feature_projections(cases, decisions)
                self.assertEqual(len(records), 3)
                self.assertEqual(
                    [row["case_id"] for row in records],
                    sorted(row["case_id"] for row in cases),
                )
                for record in records:
                    self.assertEqual(set(record), RECORD_KEYS)
                    self.assertTrue(record["matched"])
                    self.assertEqual(
                        record["expected_projection_sha256"],
                        record["observed_projection_sha256"],
                    )
                    self.assertEqual(
                        list(self.schema_validator.iter_errors(record)), []
                    )
                    serialized = json.dumps(record, sort_keys=True)
                    self.assertNotIn("feature_values", serialized)
                    self.assertNotIn("feature_trace", serialized)

    def test_results_are_sorted_regardless_of_input_order(self) -> None:
        records = verify_reference_feature_projections(
            list(reversed(self.starter_cases)),
            list(reversed(self.starter_decisions)),
        )
        self.assertEqual(
            [row["case_id"] for row in records],
            sorted(row["case_id"] for row in self.starter_cases),
        )

    def test_opaque_attributes_do_not_change_feature_projection(self) -> None:
        cases, decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-benign-001",
        )
        baseline = verify_reference_feature_projections(cases, decisions)[0]
        cases[0]["events"][0]["attributes"]["opaque_context"] = {
            "nested": ["ignored", 42, False]
        }
        mutated = verify_reference_feature_projections(cases, decisions)[0]
        self.assertNotEqual(
            baseline["normalized_case_sha256"],
            mutated["normalized_case_sha256"],
        )
        self.assertEqual(
            baseline["expected_projection_sha256"],
            mutated["expected_projection_sha256"],
        )

    def test_normalized_case_digest_uses_repository_canonical_json(self) -> None:
        cases, decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-benign-001",
        )
        cases[0]["events"][0]["attributes"]["opaque_unicode"] = "caf\u00e9"
        record = verify_reference_feature_projections(cases, decisions)[0]
        expected = hashlib.sha256(canonical_json(cases[0]).encode("utf-8")).hexdigest()
        self.assertEqual(record["normalized_case_sha256"], expected)

    def test_event_order_is_a_projection_metamorphic_invariant(self) -> None:
        cases, decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-malicious-001",
        )
        baseline = verify_reference_feature_projections(cases, decisions)[0]
        cases[0]["events"].reverse()
        reordered = verify_reference_feature_projections(cases, decisions)[0]
        self.assertNotEqual(
            baseline["normalized_case_sha256"],
            reordered["normalized_case_sha256"],
        )
        self.assertEqual(
            baseline["expected_projection_sha256"],
            reordered["expected_projection_sha256"],
        )

    def test_coherent_rehashed_feature_value_mutation_is_blocked(self) -> None:
        cases, decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-malicious-001",
        )
        decisions[0]["model_assessment"]["feature_values"]["threat_ip"] = 0.0
        rehash_decision(decisions[0])
        self.assert_code(
            "REFERENCE_FEATURE_PROJECTION_MISMATCH",
            verify_reference_feature_projections,
            cases,
            decisions,
        )

    def test_coherent_rehashed_feature_trace_mutation_is_blocked(self) -> None:
        cases, decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-malicious-001",
        )
        shortened = [decisions[0]["model_assessment"]["feature_trace"]["threat_ip"][0]]
        decisions[0]["model_assessment"]["feature_trace"]["threat_ip"] = shortened
        decisions[0]["traceability"]["feature_trace"]["threat_ip"] = list(shortened)
        rehash_decision(decisions[0])
        self.assert_code(
            "REFERENCE_FEATURE_PROJECTION_MISMATCH",
            verify_reference_feature_projections,
            cases,
            decisions,
        )

    def test_coherent_rehashed_source_context_mutation_is_blocked(self) -> None:
        cases, decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-malicious-001",
        )
        cti = next(
            event
            for event in cases[0]["events"]
            if event["source_type"] == "threat_intel"
        )
        cti["source_type"] = "ticket"
        rehash_decision(decisions[0])
        self.assert_code(
            "REFERENCE_FEATURE_SOURCE_CONTEXT",
            verify_reference_feature_projections,
            cases,
            decisions,
        )

    def test_failed_login_contract_accepts_integral_float(self) -> None:
        cases, decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-benign-001",
        )
        identity = next(
            event for event in cases[0]["events"] if event["source_type"] == "identity"
        )
        identity["attributes"]["failed_logins"] = 10.0
        decisions[0]["model_assessment"]["feature_values"][
            "failed_login_intensity"
        ] = 0.5
        rehash_decision(decisions[0])
        records = verify_reference_feature_projections(cases, decisions)
        self.assertEqual(len(records), 1)
        self.assertTrue(records[0]["matched"])

    def test_failed_login_contract_rejects_bad_type_and_range(self) -> None:
        base_cases, base_decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-benign-001",
        )
        for value, code in (
            (True, "REFERENCE_FEATURE_ATTRIBUTE_TYPE"),
            (1.5, "REFERENCE_FEATURE_ATTRIBUTE_TYPE"),
            (-1, "REFERENCE_FEATURE_ATTRIBUTE_RANGE"),
            (1_000_001, "REFERENCE_FEATURE_ATTRIBUTE_RANGE"),
            (10**400, "REFERENCE_FEATURE_ATTRIBUTE_RANGE"),
        ):
            with self.subTest(value=value):
                cases = copy.deepcopy(base_cases)
                identity = next(
                    event
                    for event in cases[0]["events"]
                    if event["source_type"] == "identity"
                )
                identity["attributes"]["failed_logins"] = value
                self.assert_code(
                    code,
                    verify_reference_feature_projections,
                    cases,
                    base_decisions,
                )

    def test_inventory_context_is_required_and_exactly_bound(self) -> None:
        base_cases, decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-benign-001",
        )
        inventory = next(
            event
            for event in base_cases[0]["events"]
            if event["source_type"] == "asset_inventory"
        )

        missing = copy.deepcopy(base_cases)
        missing_inventory = next(
            event
            for event in missing[0]["events"]
            if event["source_type"] == "asset_inventory"
        )
        del missing_inventory["attributes"]["break_glass"]
        self.assert_code(
            "REFERENCE_FEATURE_INVENTORY_SHAPE",
            verify_reference_feature_projections,
            missing,
            decisions,
        )

        mismatched = copy.deepcopy(base_cases)
        mismatched_inventory = next(
            event
            for event in mismatched[0]["events"]
            if event["source_type"] == "asset_inventory"
        )
        mismatched_inventory["attributes"]["asset_id"] = "different-asset"
        self.assert_code(
            "REFERENCE_FEATURE_INVENTORY_BINDING",
            verify_reference_feature_projections,
            mismatched,
            decisions,
        )
        self.assertEqual(inventory["attributes"]["asset_id"], base_cases[0]["asset_id"])

    def test_collection_time_cannot_precede_observation_time(self) -> None:
        cases, decisions = select_case(
            self.starter_cases,
            self.starter_decisions,
            "phase2-synthetic-benign-001",
        )
        cases[0]["events"][0]["collected_at"] = "2026-08-01T11:54:00+00:00"
        self.assert_code(
            "REFERENCE_FEATURE_EVENT_TIME_ORDER",
            verify_reference_feature_projections,
            cases,
            decisions,
        )

    def test_case_sets_must_be_exact_and_unique(self) -> None:
        self.assert_code(
            "REFERENCE_FEATURE_CASE_ID_DUPLICATE",
            verify_reference_feature_projections,
            self.starter_cases + [copy.deepcopy(self.starter_cases[0])],
            self.starter_decisions,
        )
        self.assert_code(
            "REFERENCE_FEATURE_CASE_SET",
            verify_reference_feature_projections,
            self.starter_cases,
            self.starter_decisions[:-1],
        )

    def test_reference_module_has_no_forbidden_production_imports(self) -> None:
        source_path = ROOT / "src" / "adf_poc" / "replay" / "reference_features.py"
        tree = ast.parse(source_path.read_text(encoding="utf-8"))
        allowed = {
            "__future__",
            "datetime",
            "hashlib",
            "json",
            "math",
            "re",
            "typing",
        }
        imported: set[str] = set()
        relative_imports: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    relative_imports.append(node.module or "")
                elif node.module:
                    imported.add(node.module)
        self.assertEqual(relative_imports, [])
        self.assertEqual(imported - allowed, set())


if __name__ == "__main__":
    unittest.main()
