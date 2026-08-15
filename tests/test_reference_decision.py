from __future__ import annotations

import ast
import copy
import hashlib
import json
import math
from pathlib import Path
import unittest
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.engine import DecisionFirewallEngine
from adf_poc.execution import ExecutionMode
from adf_poc.model import LogisticRiskModel
from adf_poc.policy import PolicyConfig
import adf_poc.replay.reference_decision as reference_decision_module
from adf_poc.replay.reference_decision import (
    ASSURANCE_KIND,
    RECOMPUTATION_SCOPE,
    ReferenceDecisionAssuranceError,
    verify_reference_decision_path,
)
from adf_poc.schemas import IdentityCase


ROOT = Path(__file__).resolve().parents[1]
MODEL_BYTES = (ROOT / "outputs" / "baseline" / "model.json").read_bytes()
POLICY_BYTES = (ROOT / "config" / "policy.json").read_bytes()
RECEIPT_KEYS = {
    "schema_version",
    "assurance_kind",
    "recomputation_scope",
    "case_id",
    "normalized_case_sha256",
    "model_source_sha256",
    "policy_source_sha256",
    "expected_evidence_sha256",
    "observed_evidence_sha256",
    "expected_model_sha256",
    "observed_model_sha256",
    "expected_policy_sha256",
    "observed_policy_sha256",
    "expected_verifier_sha256",
    "observed_verifier_sha256",
    "expected_final_surface_sha256",
    "observed_final_surface_sha256",
    "expected_source_to_decision_sha256",
    "observed_source_to_decision_sha256",
    "execution_mode",
    "read_only",
    "matched",
}


def bundle_bytes(name: str) -> tuple[bytes, bytes]:
    root = ROOT / "evidence" / name
    return (
        (root / "normalized_cases.jsonl").read_bytes(),
        (root / "engine_decisions.jsonl").read_bytes(),
    )


def parse_jsonl(raw: bytes) -> list[dict]:
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def canonical_jsonl(rows: list[dict]) -> bytes:
    return b"".join(
        json.dumps(
            row,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
        + b"\n"
        for row in rows
    )


def canonical_json(value: dict) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def json_nesting_depth(value) -> int:
    if isinstance(value, dict):
        return 1 + max(
            (json_nesting_depth(child) for child in value.values()), default=0
        )
    if isinstance(value, list):
        return 1 + max((json_nesting_depth(child) for child in value), default=0)
    return 0


def rehash_decision(decision: dict) -> None:
    decision.pop("decision_record_hash", None)
    decision["decision_record_hash"] = hashlib.sha256(
        canonical_json(decision)
    ).hexdigest()


class ReferenceDecisionPathTests(unittest.TestCase):
    starter_cases: bytes
    starter_decisions: bytes
    qualification_cases: bytes
    qualification_decisions: bytes

    @classmethod
    def setUpClass(cls) -> None:
        cls.starter_cases, cls.starter_decisions = bundle_bytes("phase2_starter")
        cls.qualification_cases, cls.qualification_decisions = bundle_bytes(
            "phase2_qualification"
        )

    def verify(
        self,
        cases: bytes,
        decisions: bytes,
        *,
        model: bytes = MODEL_BYTES,
        policy: bytes = POLICY_BYTES,
        mode: str = "historical_replay",
    ) -> list[dict]:
        return verify_reference_decision_path(
            cases_jsonl=cases,
            decisions_jsonl=decisions,
            model_json=model,
            policy_json=policy,
            expected_execution_mode=mode,
        )

    def assert_code(self, expected: str, function, *args, **kwargs) -> None:
        with self.assertRaises(ReferenceDecisionAssuranceError) as raised:
            function(*args, **kwargs)
        self.assertEqual(raised.exception.code, expected)
        self.assertEqual(str(raised.exception), expected)

    def mutated_decisions(self, mutator) -> bytes:
        decisions = parse_jsonl(self.starter_decisions)
        mutator(decisions[0])
        rehash_decision(decisions[0])
        return canonical_jsonl(decisions)

    def test_committed_starter_and_qualification_decisions_match(self) -> None:
        for name, cases, decisions in (
            ("starter", self.starter_cases, self.starter_decisions),
            (
                "qualification",
                self.qualification_cases,
                self.qualification_decisions,
            ),
        ):
            with self.subTest(bundle=name):
                receipts = self.verify(cases, decisions)
                self.assertEqual(len(receipts), 3)
                self.assertEqual(
                    [row["case_id"] for row in receipts],
                    sorted(row["case_id"] for row in receipts),
                )
                for row in receipts:
                    self.assertEqual(set(row), RECEIPT_KEYS)
                    self.assertEqual(row["assurance_kind"], ASSURANCE_KIND)
                    self.assertEqual(row["recomputation_scope"], RECOMPUTATION_SCOPE)
                    self.assertTrue(row["read_only"])
                    self.assertTrue(row["matched"])
                    for stage in (
                        "evidence",
                        "model",
                        "policy",
                        "verifier",
                        "final_surface",
                        "source_to_decision",
                    ):
                        self.assertEqual(
                            row[f"expected_{stage}_sha256"],
                            row[f"observed_{stage}_sha256"],
                        )

    def test_receipts_are_deterministic_sorted_and_metadata_only(self) -> None:
        baseline = self.verify(self.starter_cases, self.starter_decisions)
        reversed_cases = (
            b"\n".join(
                reversed([line for line in self.starter_cases.splitlines() if line])
            )
            + b"\n"
        )
        reversed_decisions = (
            b"\n".join(
                reversed([line for line in self.starter_decisions.splitlines() if line])
            )
            + b"\n"
        )
        repeated = self.verify(reversed_cases, reversed_decisions)
        self.assertEqual(baseline, repeated)
        serialized = json.dumps(baseline, sort_keys=True)
        for prohibited in (
            "feature_values",
            "feature_trace",
            "evidence_assessment",
            "compromise_probability",
            "proposal",
            "authorization",
            "untrusted_text",
            "subject_id",
            "asset_id",
        ):
            self.assertNotIn(prohibited, serialized)

    def test_shadow_read_only_mode_is_recomputed_without_actions(self) -> None:
        decisions = parse_jsonl(self.starter_decisions)
        for decision in decisions:
            decision["execution_mode"] = "shadow_read_only"
            decision["execution_control"]["mode"] = "shadow_read_only"
            rehash_decision(decision)
        receipts = self.verify(
            self.starter_cases,
            canonical_jsonl(decisions),
            mode="shadow_read_only",
        )
        self.assertEqual(len(receipts), 3)
        self.assertTrue(all(row["read_only"] for row in receipts))
        self.assertTrue(
            all(row["execution_mode"] == "shadow_read_only" for row in receipts)
        )

    def test_layer_specific_coherent_mutations_fail_at_first_affected_stage(
        self,
    ) -> None:
        mutations = (
            (
                "REFERENCE_DECISION_EVIDENCE_MISMATCH",
                lambda row: row["evidence_assessment"].__setitem__(
                    "evidence_quality", 0.0
                ),
            ),
            (
                "REFERENCE_DECISION_MODEL_MISMATCH",
                lambda row: row["model_assessment"].__setitem__(
                    "compromise_probability", 0.5
                ),
            ),
            (
                "REFERENCE_DECISION_POLICY_MISMATCH",
                lambda row: row["proposal"]["policy_rules_applied"].append(
                    "FORGED-RULE"
                ),
            ),
            (
                "REFERENCE_DECISION_VERIFIER_MISMATCH",
                lambda row: row["independent_verification"].__setitem__(
                    "passed", False
                ),
            ),
            (
                "REFERENCE_DECISION_FINAL_SURFACE_MISMATCH",
                lambda row: row["authorization"].__setitem__("issued", True),
            ),
        )
        for expected, mutator in mutations:
            with self.subTest(code=expected):
                self.assert_code(
                    expected,
                    self.verify,
                    self.starter_cases,
                    self.mutated_decisions(mutator),
                )

    def test_rehashed_read_only_safety_mutations_are_blocked(self) -> None:
        mutations = (
            lambda row: row["execution_control"].__setitem__(
                "authorization_attempted", True
            ),
            lambda row: row["execution_control"].__setitem__("operational_effects", 1),
            lambda row: row["action_results"].append(
                {"action": "revoke_active_sessions", "success": True}
            ),
            lambda row: row["post_action_verification"].__setitem__("applicable", True),
        )
        for mutator in mutations:
            with self.subTest(mutator=mutator):
                self.assert_code(
                    "REFERENCE_DECISION_FINAL_SURFACE_MISMATCH",
                    self.verify,
                    self.starter_cases,
                    self.mutated_decisions(mutator),
                )

    def test_stale_record_hash_fails_before_stage_comparison(self) -> None:
        decisions = parse_jsonl(self.starter_decisions)
        decisions[0]["authorization"]["issued"] = True
        self.assert_code(
            "REFERENCE_DECISION_RECORD_HASH",
            self.verify,
            self.starter_cases,
            canonical_jsonl(decisions),
        )

    def test_duplicate_members_and_nonfinite_numbers_fail_closed(self) -> None:
        self.assert_code(
            "REFERENCE_DECISION_DUPLICATE_KEY",
            self.verify,
            b'{"case_id":"a","case_id":"b"}\n',
            self.starter_decisions,
        )
        duplicate_model = MODEL_BYTES.replace(
            b'"intercept": 0.2208073648859561,',
            b'"intercept": 0.2208073648859561,"intercept": 0.0,',
        )
        self.assert_code(
            "REFERENCE_DECISION_DUPLICATE_KEY",
            self.verify,
            self.starter_cases,
            self.starter_decisions,
            model=duplicate_model,
        )
        for token in (b"NaN", b"Infinity", b"-Infinity", b"1e400"):
            with self.subTest(token=token):
                model = MODEL_BYTES.replace(b"0.2208073648859561", token, 1)
                self.assert_code(
                    "REFERENCE_DECISION_NONFINITE",
                    self.verify,
                    self.starter_cases,
                    self.starter_decisions,
                    model=model,
                )

    def test_model_policy_and_mode_boundaries_fail_closed(self) -> None:
        model = json.loads(MODEL_BYTES)
        model["feature_names"] = model["feature_names"][:-1]
        self.assert_code(
            "REFERENCE_DECISION_MODEL_FEATURES",
            self.verify,
            self.starter_cases,
            self.starter_decisions,
            model=canonical_json(model),
        )
        policy = json.loads(POLICY_BYTES)
        policy["thresholds"]["no_action_max_probability"] = 0.99
        self.assert_code(
            "REFERENCE_DECISION_POLICY_RANGE",
            self.verify,
            self.starter_cases,
            self.starter_decisions,
            policy=canonical_json(policy),
        )
        self.assert_code(
            "REFERENCE_DECISION_MODE",
            self.verify,
            self.starter_cases,
            self.starter_decisions,
            mode="synthetic_simulation",
        )

    def test_cancellation_heavy_model_uses_the_shared_deterministic_sum(self) -> None:
        case_row = parse_jsonl(self.starter_cases)[0]
        baseline_decision = parse_jsonl(self.starter_decisions)[0]
        baseline_features = baseline_decision["model_assessment"]["feature_values"]
        model_document = json.loads(MODEL_BYTES)
        model_document["means"] = [
            baseline_features[name] - 1.0 if index < 3 else baseline_features[name]
            for index, name in enumerate(model_document["feature_names"])
        ]
        model_document["scales"] = [1.0] * len(model_document["feature_names"])
        model_document["weights"] = [1.0e16, 1.0, -1.0e16] + [0.0] * (
            len(model_document["feature_names"]) - 3
        )
        model_document["intercept"] = 0.0
        model_bytes = canonical_json(model_document)

        engine = DecisionFirewallEngine(
            model=LogisticRiskModel.from_dict(model_document),
            policy_config=PolicyConfig(**json.loads(POLICY_BYTES)),
            audit_logger=AuditLogger(None),
            execution_mode=ExecutionMode.HISTORICAL_REPLAY,
        )
        decision = engine.process(IdentityCase.from_dict(case_row))
        self.assertEqual(
            decision["compromise_probability"],
            round(1.0 / (1.0 + math.exp(-1.0)), 8),
        )
        receipts = self.verify(
            canonical_jsonl([case_row]),
            canonical_jsonl([decision]),
            model=model_bytes,
        )
        self.assertEqual(len(receipts), 1)
        self.assertTrue(receipts[0]["matched"])

    def test_evidence_means_use_the_shared_ordered_fsum_rule(self) -> None:
        case_row = parse_jsonl(self.starter_cases)[0]
        self.assertEqual(len(case_row["events"]), 7)
        for index in range(3):
            event = copy.deepcopy(case_row["events"][index])
            event["event_id"] += f"-mean-regression-{index}"
            event["provenance_id"] += f"-mean-regression-{index}"
            case_row["events"].append(event)
        trust_scores = (
            0.480344,
            0.344176,
            0.490775,
            0.169594,
            0.548405,
            0.399473,
            0.427501,
            0.64763,
            0.236837,
            0.12087,
        )
        for event, trust_score in zip(case_row["events"], trust_scores, strict=True):
            event["trust_score"] = trust_score

        engine = DecisionFirewallEngine(
            model=LogisticRiskModel.from_dict(json.loads(MODEL_BYTES)),
            policy_config=PolicyConfig(**json.loads(POLICY_BYTES)),
            audit_logger=AuditLogger(None),
            execution_mode=ExecutionMode.HISTORICAL_REPLAY,
        )
        decision = engine.process(IdentityCase.from_dict(case_row))
        self.assertEqual(
            decision["evidence_assessment"]["mean_source_trust"],
            0.38656,
        )
        receipts = self.verify(
            canonical_jsonl([case_row]),
            canonical_jsonl([decision]),
        )
        self.assertEqual(len(receipts), 1)
        self.assertTrue(receipts[0]["matched"])

    def test_document_jsonl_line_and_record_limits_are_exact(self) -> None:
        exact_jsonl_bytes = max(len(self.starter_cases), len(self.starter_decisions))
        exact_line_bytes = max(
            len(line)
            for raw in (self.starter_cases, self.starter_decisions)
            for line in raw.splitlines(keepends=True)
        )
        with (
            patch.object(
                reference_decision_module,
                "_MAX_MODEL_BYTES",
                len(MODEL_BYTES),
            ),
            patch.object(
                reference_decision_module,
                "_MAX_POLICY_BYTES",
                len(POLICY_BYTES),
            ),
            patch.object(
                reference_decision_module,
                "_MAX_JSONL_BYTES",
                exact_jsonl_bytes,
            ),
            patch.object(
                reference_decision_module,
                "_MAX_JSONL_LINE_BYTES",
                exact_line_bytes,
            ),
            patch.object(reference_decision_module, "_MAX_JSONL_RECORDS", 3),
        ):
            self.assertEqual(
                len(self.verify(self.starter_cases, self.starter_decisions)), 3
            )

        over_limit_patches = (
            ("_MAX_MODEL_BYTES", len(MODEL_BYTES) - 1),
            ("_MAX_POLICY_BYTES", len(POLICY_BYTES) - 1),
            ("_MAX_JSONL_BYTES", exact_jsonl_bytes - 1),
            ("_MAX_JSONL_LINE_BYTES", exact_line_bytes - 1),
            ("_MAX_JSONL_RECORDS", 2),
        )
        for name, value in over_limit_patches:
            with (
                self.subTest(limit=name),
                patch.object(reference_decision_module, name, value),
            ):
                self.assert_code(
                    "REFERENCE_DECISION_RESOURCE_LIMIT",
                    self.verify,
                    self.starter_cases,
                    self.starter_decisions,
                )

    def test_json_nesting_limit_is_string_aware_and_fail_closed(self) -> None:
        model = json.loads(MODEL_BYTES)
        model["training_metadata"] = {
            "braces_are_text": '{[\\"still text\\"]}',
        }
        model_bytes = canonical_json(model)
        exact_depth = max(
            json_nesting_depth(value)
            for value in (
                *parse_jsonl(self.starter_cases),
                *parse_jsonl(self.starter_decisions),
                model,
                json.loads(POLICY_BYTES),
            )
        )
        with patch.object(
            reference_decision_module,
            "_MAX_JSON_NESTING_DEPTH",
            exact_depth,
        ):
            self.assertEqual(
                len(
                    self.verify(
                        self.starter_cases,
                        self.starter_decisions,
                        model=model_bytes,
                    )
                ),
                3,
            )

        with patch.object(
            reference_decision_module,
            "_MAX_JSON_NESTING_DEPTH",
            exact_depth - 1,
        ):
            self.assert_code(
                "REFERENCE_DECISION_JSON_NESTING",
                self.verify,
                self.starter_cases,
                self.starter_decisions,
                model=model_bytes,
            )

        nested: object = "leaf"
        for _ in range(exact_depth + 1):
            nested = {"nested": nested}
        model["training_metadata"] = {"root": nested}
        with patch.object(
            reference_decision_module,
            "_MAX_JSON_NESTING_DEPTH",
            exact_depth,
        ):
            self.assert_code(
                "REFERENCE_DECISION_JSON_NESTING",
                self.verify,
                self.starter_cases,
                self.starter_decisions,
                model=canonical_json(model),
            )

    def test_case_event_text_and_attribute_limits_are_exact(self) -> None:
        cases = parse_jsonl(self.starter_cases)
        exact_events = max(len(case["events"]) for case in cases)
        with patch.object(
            reference_decision_module, "_MAX_EVENTS_PER_CASE", exact_events
        ):
            self.assertEqual(
                len(self.verify(canonical_jsonl(cases), self.starter_decisions)), 3
            )
        with patch.object(
            reference_decision_module, "_MAX_EVENTS_PER_CASE", exact_events - 1
        ):
            self.assert_code(
                "REFERENCE_DECISION_RESOURCE_LIMIT",
                self.verify,
                canonical_jsonl(cases),
                self.starter_decisions,
            )

        cases[0]["events"][0]["untrusted_text"] = "x" * 128
        text_cases = canonical_jsonl(cases)
        with patch.object(reference_decision_module, "_MAX_UNTRUSTED_TEXT_CHARS", 128):
            self.assertEqual(len(self.verify(text_cases, self.starter_decisions)), 3)
        with patch.object(reference_decision_module, "_MAX_UNTRUSTED_TEXT_CHARS", 127):
            self.assert_code(
                "REFERENCE_DECISION_RESOURCE_LIMIT",
                self.verify,
                text_cases,
                self.starter_decisions,
            )

        cases[0]["events"][0]["attributes"]["opaque_padding"] = "x" * 512
        padded_attributes = cases[0]["events"][0]["attributes"]
        exact_attribute_bytes = len(canonical_json(padded_attributes))
        attribute_cases = canonical_jsonl(cases)
        with patch.object(
            reference_decision_module,
            "_MAX_ATTRIBUTES_BYTES",
            exact_attribute_bytes,
        ):
            self.assertEqual(
                len(self.verify(attribute_cases, self.starter_decisions)), 3
            )
        with patch.object(
            reference_decision_module,
            "_MAX_ATTRIBUTES_BYTES",
            exact_attribute_bytes - 1,
        ):
            self.assert_code(
                "REFERENCE_DECISION_RESOURCE_LIMIT",
                self.verify,
                attribute_cases,
                self.starter_decisions,
            )

    def test_unused_model_metadata_and_limitations_are_bounded(self) -> None:
        model = json.loads(MODEL_BYTES)
        training_bytes = len(canonical_json(model["training_metadata"]))
        limitations_bytes = len(canonical_json(model["limitations"]))
        with (
            patch.object(
                reference_decision_module,
                "_MAX_TRAINING_METADATA_BYTES",
                training_bytes,
            ),
            patch.object(
                reference_decision_module,
                "_MAX_LIMITATIONS",
                len(model["limitations"]),
            ),
            patch.object(
                reference_decision_module,
                "_MAX_LIMITATIONS_BYTES",
                limitations_bytes,
            ),
        ):
            self.assertEqual(
                len(
                    self.verify(
                        self.starter_cases,
                        self.starter_decisions,
                        model=canonical_json(model),
                    )
                ),
                3,
            )

        large_metadata = copy.deepcopy(model)
        large_metadata["training_metadata"] = {"unused": "x" * 512}
        large_metadata_bytes = len(canonical_json(large_metadata["training_metadata"]))
        with patch.object(
            reference_decision_module,
            "_MAX_TRAINING_METADATA_BYTES",
            large_metadata_bytes - 1,
        ):
            self.assert_code(
                "REFERENCE_DECISION_RESOURCE_LIMIT",
                self.verify,
                self.starter_cases,
                self.starter_decisions,
                model=canonical_json(large_metadata),
            )

        with patch.object(
            reference_decision_module,
            "_MAX_LIMITATIONS_BYTES",
            limitations_bytes - 1,
        ):
            self.assert_code(
                "REFERENCE_DECISION_RESOURCE_LIMIT",
                self.verify,
                self.starter_cases,
                self.starter_decisions,
            )
        with patch.object(
            reference_decision_module,
            "_MAX_LIMITATIONS",
            len(model["limitations"]) - 1,
        ):
            self.assert_code(
                "REFERENCE_DECISION_RESOURCE_LIMIT",
                self.verify,
                self.starter_cases,
                self.starter_decisions,
            )

    def test_case_and_decision_sets_must_be_exact_and_unique(self) -> None:
        cases = parse_jsonl(self.starter_cases)
        decisions = parse_jsonl(self.starter_decisions)
        self.assert_code(
            "REFERENCE_DECISION_CASE_DUPLICATE",
            self.verify,
            canonical_jsonl(cases + [copy.deepcopy(cases[0])]),
            self.starter_decisions,
        )
        self.assert_code(
            "REFERENCE_DECISION_DECISION_DUPLICATE",
            self.verify,
            self.starter_cases,
            canonical_jsonl(decisions + [copy.deepcopy(decisions[0])]),
        )
        self.assert_code(
            "REFERENCE_DECISION_CASE_SET",
            self.verify,
            canonical_jsonl(cases[:-1]),
            self.starter_decisions,
        )

    def test_module_has_standard_library_only_import_boundary(self) -> None:
        source = (
            ROOT / "src" / "adf_poc" / "replay" / "reference_decision.py"
        ).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.partition(".")[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.partition(".")[0])
        self.assertEqual(
            imported_roots,
            {
                "__future__",
                "datetime",
                "hashlib",
                "io",
                "json",
                "math",
                "re",
                "typing",
            },
        )
        for prohibited in (
            "adf_poc.evidence",
            "adf_poc.features",
            "adf_poc.feature_contract",
            "adf_poc.model",
            "adf_poc.policy",
            "adf_poc.verifier",
            "adf_poc.engine",
            "adf_poc.metrics",
            "adf_poc.actions",
        ):
            self.assertNotIn(prohibited, source)


if __name__ == "__main__":
    unittest.main()
