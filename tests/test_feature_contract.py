from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from adf_poc.feature_contract import (
    FeatureContractError,
    MAX_FAILED_LOGINS,
    MODELED_ATTRIBUTE_SOURCES,
)
from adf_poc.features import extract_features
from adf_poc.evidence import assess_evidence
from adf_poc.replay.contracts import (
    ContractValidationError,
    load_jsonl_objects,
    validate_case_record,
)
from adf_poc.replay.qualification import qualify_case_file
from adf_poc.schemas import IdentityCase


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_CASES = ROOT / "data" / "phase2_starter" / "cases.jsonl"
CASE_SCHEMA = json.loads(
    (ROOT / "contracts" / "v0.2.0" / "replay-case.schema.json").read_text(
        encoding="utf-8"
    )
)
SCHEMA_VALIDATOR = Draft202012Validator(
    CASE_SCHEMA,
    format_checker=FormatChecker(),
)


def _fixture_case() -> dict[str, Any]:
    return copy.deepcopy(
        load_jsonl_objects(FIXTURE_CASES, label="feature-contract fixture")[0]
    )


def _event(record: dict[str, Any], source_type: str) -> dict[str, Any]:
    return next(
        event for event in record["events"] if event["source_type"] == source_type
    )


def _identity_case(record: dict[str, Any]) -> IdentityCase:
    value = copy.deepcopy(record)
    value.pop("schema_version")
    return IdentityCase.from_dict(value)


def _assert_schema_valid(test: unittest.TestCase, record: dict[str, Any]) -> None:
    test.assertEqual(list(SCHEMA_VALIDATOR.iter_errors(record)), [])


def _assert_schema_invalid(test: unittest.TestCase, record: dict[str, Any]) -> None:
    test.assertNotEqual(list(SCHEMA_VALIDATOR.iter_errors(record)), [])


class FeatureContractTests(unittest.TestCase):
    def test_string_boolean_and_string_nan_fail_every_model_input_boundary(
        self,
    ) -> None:
        boolean_string = _fixture_case()
        _event(boolean_string, "endpoint")["attributes"]["credential_dumping"] = "false"
        numeric_string = _fixture_case()
        _event(numeric_string, "identity")["attributes"]["failed_logins"] = "nan"

        for label, candidate in (
            ("boolean-string", boolean_string),
            ("numeric-string", numeric_string),
        ):
            with self.subTest(label=label):
                _assert_schema_invalid(self, candidate)
                with self.assertRaises(ContractValidationError):
                    validate_case_record(candidate)
                with self.assertRaises(FeatureContractError):
                    extract_features(_identity_case(candidate))

    def test_nonfinite_negative_and_overflow_failed_logins_fail_closed(self) -> None:
        for value in (
            float("nan"),
            float("inf"),
            10.5,
            True,
            -1,
            MAX_FAILED_LOGINS + 1,
            10**400,
        ):
            candidate = _fixture_case()
            _event(candidate, "identity")["attributes"]["failed_logins"] = value
            with self.subTest(
                value_type=type(value).__name__, value_sign=str(value)[:1]
            ):
                with self.assertRaises(ContractValidationError):
                    validate_case_record(candidate)
                with self.assertRaises(FeatureContractError):
                    extract_features(_identity_case(candidate))
                if isinstance(value, int) or value == 10.5:
                    _assert_schema_invalid(self, candidate)

    def test_unauthorized_modeled_source_fails_but_opaque_context_is_ignored(
        self,
    ) -> None:
        unauthorized = _fixture_case()
        _event(unauthorized, "user_context")["attributes"]["credential_dumping"] = True
        _assert_schema_invalid(self, unauthorized)
        with self.assertRaises(ContractValidationError):
            validate_case_record(unauthorized)
        with self.assertRaises(FeatureContractError):
            extract_features(_identity_case(unauthorized))

        baseline = _fixture_case()
        extended = copy.deepcopy(baseline)
        _event(extended, "user_context")["attributes"]["vendor_extension"] = {
            "credential_dumping": True,
            "failed_logins": "nan",
            "arbitrary_context": [1, 2, 3],
        }
        _assert_schema_valid(self, extended)
        validate_case_record(extended)
        self.assertEqual(
            extract_features(_identity_case(extended)),
            extract_features(_identity_case(baseline)),
        )

    def test_source_conflict_is_exact_boolean_and_network_authorized(self) -> None:
        baseline = _fixture_case()
        network = _event(baseline, "network")
        network["attributes"]["source_conflict"] = False
        _assert_schema_valid(self, baseline)
        validate_case_record(baseline)
        self.assertEqual(assess_evidence(_identity_case(baseline)).conflict_count, 0)

        string_value = copy.deepcopy(baseline)
        _event(string_value, "network")["attributes"]["source_conflict"] = "false"
        _assert_schema_invalid(self, string_value)
        with self.assertRaises(ContractValidationError):
            validate_case_record(string_value)
        with self.assertRaises(FeatureContractError):
            assess_evidence(_identity_case(string_value))

        wrong_source = copy.deepcopy(baseline)
        del _event(wrong_source, "network")["attributes"]["source_conflict"]
        _event(wrong_source, "identity")["attributes"]["source_conflict"] = True
        _assert_schema_invalid(self, wrong_source)
        with self.assertRaises(ContractValidationError):
            validate_case_record(wrong_source)
        with self.assertRaises(FeatureContractError):
            assess_evidence(_identity_case(wrong_source))

        raw = (
            json.dumps(wrong_source, separators=(",", ":"), sort_keys=True).encode(
                "utf-8"
            )
            + b"\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.jsonl"
            path.write_bytes(raw)
            result = qualify_case_file(
                path,
                hashlib.sha256(raw).hexdigest(),
                dataset_id="evidence-signal-qualification",
            )
        self.assertEqual(result.rejected_record_count, 1)
        self.assertEqual(
            result.rejection_records[0]["error_code"],
            "UNAUTHORIZED_DECISION_SIGNAL",
        )

    def test_nonfinite_numbers_are_rejected_even_in_opaque_nested_context(self) -> None:
        for value in (float("nan"), float("inf")):
            candidate = _fixture_case()
            _event(candidate, "user_context")["attributes"]["opaque_context"] = {
                "nested": [value]
            }
            with self.subTest(value=str(value)):
                with self.assertRaisesRegex(
                    ContractValidationError,
                    "non-finite JSON number",
                ):
                    validate_case_record(candidate)

    def test_failed_login_boundaries_are_valid_and_saturate_as_declared(self) -> None:
        for value, expected in (
            (0, 0.0),
            (10.0, 0.5),
            (MAX_FAILED_LOGINS, 1.0),
        ):
            candidate = _fixture_case()
            _event(candidate, "identity")["attributes"]["failed_logins"] = value
            with self.subTest(value=value):
                _assert_schema_valid(self, candidate)
                validate_case_record(candidate)
                features, _ = extract_features(_identity_case(candidate))
                self.assertEqual(features["failed_login_intensity"], expected)

    def test_every_modeled_key_accepts_only_its_authorized_source_matrix(
        self,
    ) -> None:
        baseline = _fixture_case()
        available_sources = {event["source_type"] for event in baseline["events"]}
        for key, authorized_sources in MODELED_ATTRIBUTE_SOURCES.items():
            value: bool | float = 10.0 if key == "failed_logins" else True
            for source_type in sorted(authorized_sources):
                candidate = _fixture_case()
                _event(candidate, source_type)["attributes"][key] = value
                with self.subTest(key=key, source=source_type, authorized=True):
                    _assert_schema_valid(self, candidate)
                    validate_case_record(candidate)
                    features, _ = extract_features(_identity_case(candidate))
                    feature_name = (
                        "failed_login_intensity" if key == "failed_logins" else key
                    )
                    self.assertGreater(features[feature_name], 0.0)

            for unauthorized_source in sorted(available_sources - authorized_sources):
                unauthorized = _fixture_case()
                _event(unauthorized, unauthorized_source)["attributes"][key] = value
                with self.subTest(
                    key=key,
                    source=unauthorized_source,
                    authorized=False,
                ):
                    _assert_schema_invalid(self, unauthorized)
                    with self.assertRaises(ContractValidationError):
                        validate_case_record(unauthorized)
                    with self.assertRaises(FeatureContractError):
                        extract_features(_identity_case(unauthorized))

            unrecognized_source = _fixture_case()
            unrecognized_event = _event(unrecognized_source, "user_context")
            unrecognized_event["source_type"] = "ticket"
            unrecognized_event["source_instance"] = "synthetic-ticket"
            unrecognized_event["attributes"] = {key: value}
            with self.subTest(
                key=key,
                source="ticket",
                authorized=False,
            ):
                _assert_schema_invalid(self, unrecognized_source)
                with self.assertRaises(ContractValidationError):
                    validate_case_record(unrecognized_source)
                with self.assertRaises(FeatureContractError):
                    extract_features(_identity_case(unrecognized_source))

    def test_asset_inventory_id_and_privilege_are_required_and_canonical(self) -> None:
        baseline = _fixture_case()
        _assert_schema_valid(self, baseline)
        validate_case_record(baseline)

        for field in ("asset_id", "privilege_level"):
            missing = _fixture_case()
            del _event(missing, "asset_inventory")["attributes"][field]
            invalid_type = _fixture_case()
            _event(invalid_type, "asset_inventory")["attributes"][field] = False
            mismatch = _fixture_case()
            _event(mismatch, "asset_inventory")["attributes"][field] = (
                "different-asset" if field == "asset_id" else "different-privilege"
            )
            with self.subTest(field=field, mutation="missing"):
                _assert_schema_invalid(self, missing)
                with self.assertRaises(ContractValidationError):
                    validate_case_record(missing)
            with self.subTest(field=field, mutation="invalid-type"):
                _assert_schema_invalid(self, invalid_type)
                with self.assertRaises(ContractValidationError):
                    validate_case_record(invalid_type)
            with self.subTest(field=field, mutation="mismatch"):
                with self.assertRaises(ContractValidationError):
                    validate_case_record(mismatch)
                with self.assertRaises(FeatureContractError):
                    extract_features(_identity_case(mismatch))

        criticality_mismatch = _fixture_case()
        root_criticality = float(criticality_mismatch["asset_criticality"])
        _event(criticality_mismatch, "asset_inventory")["attributes"][
            "asset_criticality"
        ] = (root_criticality + 5e-13)
        with self.assertRaises(ContractValidationError):
            validate_case_record(criticality_mismatch)
        with self.assertRaises(FeatureContractError):
            extract_features(_identity_case(criticality_mismatch))

    def test_direct_extraction_rejects_invalid_canonical_root_context(self) -> None:
        for field, value in (
            ("asset_criticality", float("nan")),
            ("asset_criticality", float("inf")),
            ("asset_criticality", 2.0),
            ("asset_criticality", True),
            ("privilege_level", False),
            ("privilege_level", "invalid privilege"),
        ):
            candidate = _fixture_case()
            candidate[field] = value
            with self.subTest(field=field, value_type=type(value).__name__):
                with self.assertRaises(FeatureContractError):
                    extract_features(_identity_case(candidate))

    def test_new_failures_remain_sanitized_record_local_qualification_results(
        self,
    ) -> None:
        cases: list[tuple[dict[str, Any], str]] = []
        boolean_string = _fixture_case()
        _event(boolean_string, "endpoint")["attributes"]["credential_dumping"] = "false"
        cases.append((boolean_string, "INVALID_BOOLEAN"))
        numeric_string = _fixture_case()
        _event(numeric_string, "identity")["attributes"]["failed_logins"] = "nan"
        cases.append((numeric_string, "INVALID_TYPE"))
        overflow = _fixture_case()
        _event(overflow, "identity")["attributes"]["failed_logins"] = 10**400
        cases.append((overflow, "NUMERIC_OUT_OF_RANGE"))
        unauthorized = _fixture_case()
        _event(unauthorized, "user_context")["attributes"]["credential_dumping"] = True
        cases.append((unauthorized, "UNAUTHORIZED_MODELED_SIGNAL"))

        for index, (candidate, expected_code) in enumerate(cases):
            raw = (
                json.dumps(candidate, separators=(",", ":"), sort_keys=True).encode(
                    "utf-8"
                )
                + b"\n"
            )
            with self.subTest(index=index, expected_code=expected_code):
                with tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / "cases.jsonl"
                    path.write_bytes(raw)
                    result = qualify_case_file(
                        path,
                        hashlib.sha256(raw).hexdigest(),
                        dataset_id="feature-contract-qualification",
                    )
                self.assertEqual(result.accepted_record_count, 0)
                self.assertEqual(result.rejected_record_count, 1)
                self.assertEqual(
                    result.rejection_records[0]["error_code"], expected_code
                )


if __name__ == "__main__":
    unittest.main()
