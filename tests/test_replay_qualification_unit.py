from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adf_poc.replay.contracts import (
    MAX_JSONL_LINE_BYTES,
    ContractValidationError,
    load_jsonl_objects,
    validate_case_record,
)
from adf_poc.replay.qualification import (
    MAX_JSON_NESTING_DEPTH,
    QualificationFatalError,
    qualify_case_file,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_CASES = ROOT / "data" / "phase2_starter" / "cases.jsonl"
DATASET_ID = "phase2-qualification-unit"


def _fixture_case(index: int = 0) -> dict:
    return copy.deepcopy(load_jsonl_objects(FIXTURE_CASES, label="fixture cases")[index])


def _json_line(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _retag_case(value: dict, suffix: str) -> None:
    value["case_id"] = f"qualification-{suffix}"
    for index, event in enumerate(value["events"]):
        event["case_id"] = value["case_id"]
        event["event_id"] = f"qualification-{suffix}-event-{index}"


def _write_source(root: Path, physical_lines: list[bytes]) -> tuple[Path, str]:
    raw = b"\n".join(physical_lines) + b"\n"
    path = root / "cases.jsonl"
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


class _ReadFaultHandle:
    """Binary source handle that fails on one selected second-pass read call."""

    def __init__(self, raw: bytes, *, fail_on_readline: int) -> None:
        self._handle = io.BytesIO(raw)
        self._fail_on_readline = fail_on_readline
        self._readline_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        self._handle.close()

    def read(self, size: int = -1) -> bytes:
        return self._handle.read(size)

    def seek(self, offset: int) -> int:
        return self._handle.seek(offset)

    def readline(self, size: int = -1) -> bytes:
        self._readline_calls += 1
        if self._readline_calls == self._fail_on_readline:
            raise OSError("SENSITIVE-SOURCE-READ-FAILURE-MUST-NOT-ECHO")
        return self._handle.readline(size)


class ReplayQualificationUnitTests(unittest.TestCase):
    def test_accepted_and_quarantined_rows_have_exact_accounting(self) -> None:
        accepted = _fixture_case()
        missing = _fixture_case(1)
        del missing["subject_id"]
        invalid_timestamp = _fixture_case(2)
        invalid_timestamp["opened_at"] = "not-a-timestamp"
        context_mismatch = _fixture_case(1)
        _retag_case(context_mismatch, "context")
        inventory = next(
            event
            for event in context_mismatch["events"]
            if event["source_type"] == "asset_inventory"
        )
        inventory["attributes"]["break_glass"] = True
        malformed = b'{"opaque":"do-not-echo",'

        with tempfile.TemporaryDirectory() as directory:
            lines = [
                b"   ",
                _json_line(accepted),
                malformed,
                _json_line(missing),
                _json_line(invalid_timestamp),
                _json_line(context_mismatch),
            ]
            path, digest = _write_source(Path(directory), lines)
            result = qualify_case_file(path, digest, dataset_id=DATASET_ID)

        self.assertEqual(result.input_record_count, 5)
        self.assertEqual(result.accepted_record_count, 1)
        self.assertEqual(result.rejected_record_count, 4)
        self.assertEqual(
            result.input_record_count,
            result.accepted_record_count + result.rejected_record_count,
        )
        self.assertEqual(
            [row["physical_line_number"] for row in result.accounting_records],
            [2, 3, 4, 5, 6],
        )
        self.assertEqual(
            [row["nonblank_record_number"] for row in result.accounting_records],
            [1, 2, 3, 4, 5],
        )
        self.assertEqual(
            [row["status"] for row in result.accounting_records],
            ["ACCEPTED", "QUARANTINED", "QUARANTINED", "QUARANTINED", "QUARANTINED"],
        )
        self.assertEqual(
            [row["error_code"] for row in result.rejection_records],
            [
                "INVALID_JSON",
                "MISSING_REQUIRED_FIELD",
                "INVALID_TIMESTAMP",
                "CANONICAL_CONTEXT_MISMATCH",
            ],
        )
        self.assertEqual(
            result.accounting_records[2]["raw_line_sha256"],
            hashlib.sha256(_json_line(missing)).hexdigest(),
        )
        self.assertTrue(
            all(
                row["qualification_run_id"] == result.qualification_run_id
                for row in result.accounting_records
            )
        )
        self.assertEqual(result.accounting_records[0]["error_category"], "")
        self.assertEqual(result.accounting_records[0]["error_code"], "")

    def test_rejection_and_result_representations_do_not_echo_payload(self) -> None:
        secret = "RAW-PAYLOAD-MUST-NEVER-APPEAR"
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(
                Path(directory),
                [f'{{"untrusted_text":"{secret}"'.encode("utf-8")],
            )
            result = qualify_case_file(path, digest, dataset_id=DATASET_ID)

        self.assertNotIn(secret, repr(result))
        self.assertNotIn(secret, repr(result.accounting_records))
        self.assertNotIn(secret, repr(result.rejection_records))
        self.assertNotIn("untrusted_text", repr(result.rejection_records))

    def test_non_object_and_ordinary_contract_defects_are_quarantined(self) -> None:
        invalid_enum = _fixture_case(0)
        _retag_case(invalid_enum, "invalid-enum")
        invalid_enum["events"][0]["integrity"] = "invented"
        invalid_range = _fixture_case(1)
        _retag_case(invalid_range, "invalid-range")
        invalid_range["asset_criticality"] = 2.0
        empty_events = _fixture_case(2)
        _retag_case(empty_events, "empty-events")
        empty_events["events"] = []
        parent_mismatch = _fixture_case(0)
        _retag_case(parent_mismatch, "parent-mismatch")
        parent_mismatch["events"][0]["case_id"] = "different-parent"
        duplicate_entity_reference = _fixture_case(0)
        _retag_case(duplicate_entity_reference, "duplicate-entity-reference")
        duplicate_entity_reference["events"][0]["entity_refs"] = [
            duplicate_entity_reference["subject_id"],
            duplicate_entity_reference["subject_id"],
        ]

        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(
                Path(directory),
                [
                    _json_line(["not", "an", "object"]),
                    _json_line(invalid_enum),
                    _json_line(invalid_range),
                    _json_line(empty_events),
                    _json_line(parent_mismatch),
                    _json_line(duplicate_entity_reference),
                ],
            )
            result = qualify_case_file(path, digest, dataset_id=DATASET_ID)

        self.assertEqual(result.accepted_record_count, 0)
        self.assertEqual(result.rejected_record_count, 6)
        self.assertEqual(
            [
                (row["error_category"], row["error_code"])
                for row in result.rejection_records
            ],
            [
                ("STRUCTURE", "RECORD_NOT_OBJECT"),
                ("SEMANTICS", "INVALID_ENUM_VALUE"),
                ("SEMANTICS", "NUMERIC_OUT_OF_RANGE"),
                ("SEMANTICS", "EMPTY_REQUIRED_COLLECTION"),
                ("SEMANTICS", "CASE_EVENT_ID_MISMATCH"),
                ("SEMANTICS", "DUPLICATE_ENTITY_REFERENCE"),
            ],
        )

    def test_oversized_numeric_is_a_sanitized_record_local_range_failure(self) -> None:
        candidate = _fixture_case()
        oversized_value = int("9" * 400)
        candidate["asset_criticality"] = oversized_value

        with self.assertRaises(ContractValidationError) as fail_dataset_error:
            validate_case_record(candidate)
        self.assertNotIn(str(oversized_value), str(fail_dataset_error.exception))

        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(Path(directory), [_json_line(candidate)])
            result = qualify_case_file(path, digest, dataset_id=DATASET_ID)

        self.assertEqual(result.accepted_record_count, 0)
        self.assertEqual(result.rejected_record_count, 1)
        self.assertEqual(
            (
                result.rejection_records[0]["error_category"],
                result.rejection_records[0]["error_code"],
            ),
            ("SEMANTICS", "NUMERIC_OUT_OF_RANGE"),
        )

    def test_runtime_label_leakage_is_a_sanitized_fatal_failure(self) -> None:
        secret = "LABEL-PAYLOAD-MUST-NOT-ECHO"
        candidate = _fixture_case()
        candidate["events"][0]["attributes"]["ground_truth"] = secret
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(Path(directory), [_json_line(candidate)])
            with self.assertRaises(QualificationFatalError) as raised:
                qualify_case_file(path, digest, dataset_id=DATASET_ID)

        self.assertEqual(raised.exception.error_category, "POLICY")
        self.assertEqual(raised.exception.error_code, "RUNTIME_LABEL_LEAKAGE")
        self.assertEqual(raised.exception.physical_line_number, 1)
        self.assertNotIn(secret, str(raised.exception))
        self.assertNotIn("ground_truth", str(raised.exception))

    def test_explicit_unsupported_schema_version_is_fatal(self) -> None:
        candidate = _fixture_case()
        candidate["schema_version"] = "99.0.0"
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(Path(directory), [_json_line(candidate)])
            with self.assertRaises(QualificationFatalError) as raised:
                qualify_case_file(path, digest, dataset_id=DATASET_ID)
        self.assertEqual(raised.exception.error_category, "STRUCTURE")
        self.assertEqual(raised.exception.error_code, "UNSUPPORTED_SCHEMA_VERSION")
        self.assertNotIn("99.0.0", str(raised.exception))

    def test_duplicate_case_or_event_identifier_is_fatal_across_parseable_rows(self) -> None:
        first = _fixture_case(0)
        duplicate_case = _fixture_case(1)
        duplicate_case["case_id"] = first["case_id"]
        for event in duplicate_case["events"]:
            event["case_id"] = first["case_id"]

        first_for_event = _fixture_case(0)
        duplicate_event = _fixture_case(1)
        duplicate_event["opened_at"] = "ordinary-quarantine-defect"
        duplicate_event["events"][0]["event_id"] = first_for_event["events"][0][
            "event_id"
        ]
        duplicate_event_within_case = _fixture_case(2)
        duplicate_event_within_case["events"][1]["event_id"] = (
            duplicate_event_within_case["events"][0]["event_id"]
        )

        scenarios = (
            ([first, duplicate_case], "DUPLICATE_CASE_ID", 2),
            ([first_for_event, duplicate_event], "DUPLICATE_EVENT_ID", 2),
            ([duplicate_event_within_case], "DUPLICATE_EVENT_ID", 1),
        )
        for records, expected_code, expected_record_number in scenarios:
            with self.subTest(
                expected_code=expected_code
            ), tempfile.TemporaryDirectory() as directory:
                path, digest = _write_source(
                    Path(directory), [_json_line(record) for record in records]
                )
                with self.assertRaises(QualificationFatalError) as raised:
                    qualify_case_file(path, digest, dataset_id=DATASET_ID)
                self.assertEqual(raised.exception.error_category, "DUPLICATE")
                self.assertEqual(raised.exception.error_code, expected_code)
                self.assertEqual(
                    raised.exception.nonblank_record_number,
                    expected_record_number,
                )

    def test_full_physical_line_bound_includes_delimiter_but_hash_excludes_it(self) -> None:
        within_bound_payload = b"x" * (MAX_JSONL_LINE_BYTES - 1)
        within_bound_crlf_payload = b"x" * (MAX_JSONL_LINE_BYTES - 2)
        oversized_payload = b"x" * MAX_JSONL_LINE_BYTES
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accepted_path, accepted_digest = _write_source(
                root,
                [within_bound_payload],
            )
            result = qualify_case_file(
                accepted_path,
                accepted_digest,
                dataset_id=DATASET_ID,
            )
            self.assertEqual(result.rejected_record_count, 1)
            self.assertEqual(result.rejection_records[0]["error_code"], "INVALID_JSON")
            self.assertEqual(
                result.rejection_records[0]["raw_line_sha256"],
                hashlib.sha256(within_bound_payload).hexdigest(),
            )

            crlf_path = root / "crlf-cases.jsonl"
            crlf_raw = within_bound_crlf_payload + b"\r\n"
            crlf_path.write_bytes(crlf_raw)
            crlf_result = qualify_case_file(
                crlf_path,
                hashlib.sha256(crlf_raw).hexdigest(),
                dataset_id=DATASET_ID,
            )
            self.assertEqual(
                crlf_result.rejection_records[0]["raw_line_sha256"],
                hashlib.sha256(within_bound_crlf_payload).hexdigest(),
            )

            path, digest = _write_source(root, [oversized_payload])
            with self.assertRaises(QualificationFatalError) as raised:
                qualify_case_file(path, digest, dataset_id=DATASET_ID)

        self.assertEqual(raised.exception.error_category, "RESOURCE_LIMIT")
        self.assertEqual(raised.exception.error_code, "LINE_TOO_LARGE")
        self.assertEqual(
            raised.exception.raw_line_sha256,
            hashlib.sha256(oversized_payload).hexdigest(),
        )

    def test_invalid_utf8_and_record_count_overflow_are_sanitized_fatal_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(Path(directory), [b"\xff"])
            with self.assertRaises(QualificationFatalError) as invalid_utf8:
                qualify_case_file(path, digest, dataset_id=DATASET_ID)
        self.assertEqual(invalid_utf8.exception.error_category, "ENCODING")
        self.assertEqual(invalid_utf8.exception.error_code, "INVALID_UTF8")

        with tempfile.TemporaryDirectory() as directory:
            first = _fixture_case(0)
            second = _fixture_case(1)
            path, digest = _write_source(
                Path(directory), [_json_line(first), _json_line(second)]
            )
            with patch(
                "adf_poc.replay.qualification.MAX_RECORDS_PER_FILE", 1
            ), self.assertRaises(QualificationFatalError) as record_limit:
                qualify_case_file(path, digest, dataset_id=DATASET_ID)
        self.assertEqual(record_limit.exception.error_category, "RESOURCE_LIMIT")
        self.assertEqual(record_limit.exception.error_code, "RECORD_COUNT_EXCEEDED")
        self.assertEqual(record_limit.exception.nonblank_record_number, 2)

    def test_deep_json_is_a_deterministic_sanitized_fatal_resource_failure(self) -> None:
        depth = MAX_JSON_NESTING_DEPTH + 1
        deep_payload = b"[" * depth + b"0" + b"]" * depth
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(Path(directory), [deep_payload])
            with self.assertRaises(QualificationFatalError) as raised:
                qualify_case_file(path, digest, dataset_id=DATASET_ID)
        self.assertEqual(raised.exception.error_category, "RESOURCE_LIMIT")
        self.assertEqual(
            raised.exception.error_code,
            "JSON_NESTING_DEPTH_EXCEEDED",
        )
        self.assertNotIn(deep_payload[:32].decode("ascii"), str(raised.exception))

        # Structural characters inside a JSON string do not consume nesting budget.
        string_control = _fixture_case()
        string_control["events"][0]["untrusted_text"] = "[{" * depth
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(Path(directory), [_json_line(string_control)])
            result = qualify_case_file(path, digest, dataset_id=DATASET_ID)
        self.assertEqual(result.accepted_record_count, 1)

    def test_second_pass_and_oversized_line_read_faults_are_sanitized(self) -> None:
        scenarios = (
            (b"{}\n", 1),
            (b"x" * (MAX_JSONL_LINE_BYTES + 2) + b"\n", 2),
        )
        for raw, fail_on_readline in scenarios:
            with self.subTest(fail_on_readline=fail_on_readline):
                handle = _ReadFaultHandle(
                    raw,
                    fail_on_readline=fail_on_readline,
                )
                with patch.object(Path, "open", return_value=handle), self.assertRaises(
                    QualificationFatalError
                ) as raised:
                    qualify_case_file(
                        "controlled-source.jsonl",
                        hashlib.sha256(raw).hexdigest(),
                        dataset_id=DATASET_ID,
                    )
                self.assertEqual(raised.exception.error_category, "INTERNAL")
                self.assertEqual(raised.exception.error_code, "SOURCE_READ_FAILURE")
                self.assertNotIn(
                    "SENSITIVE-SOURCE-READ-FAILURE-MUST-NOT-ECHO",
                    str(raised.exception),
                )

    def test_qualification_is_repeatable_for_identical_source_and_context(self) -> None:
        accepted = _fixture_case()
        missing = _fixture_case(1)
        del missing["asset_id"]
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(
                Path(directory), [_json_line(accepted), _json_line(missing)]
            )
            first = qualify_case_file(path, digest, dataset_id=DATASET_ID)
            second = qualify_case_file(path, digest, dataset_id=DATASET_ID)

        self.assertEqual(first.qualification_run_id, second.qualification_run_id)
        self.assertEqual(first.accepted_records, second.accepted_records)
        self.assertEqual(first.accounting_records, second.accounting_records)
        self.assertEqual(first.rejection_records, second.rejection_records)

    def test_unmapped_contract_failure_aborts_without_echoing_validator_text(self) -> None:
        candidate = _fixture_case()
        secret = "UPSTREAM-VALIDATOR-TEXT-MUST-NOT-ECHO"
        with tempfile.TemporaryDirectory() as directory:
            path, digest = _write_source(Path(directory), [_json_line(candidate)])
            with patch(
                "adf_poc.replay.qualification.validate_case_record",
                side_effect=ContractValidationError(secret),
            ), self.assertRaises(QualificationFatalError) as raised:
                qualify_case_file(path, digest, dataset_id=DATASET_ID)

        self.assertEqual(raised.exception.error_category, "INTERNAL")
        self.assertEqual(raised.exception.error_code, "UNKNOWN_VALIDATION_FAILURE")
        self.assertNotIn(secret, str(raised.exception))

    def test_source_digest_is_verified_before_record_classification(self) -> None:
        secret = "MALFORMED-PAYLOAD-MUST-NOT-BE-CLASSIFIED"
        with tempfile.TemporaryDirectory() as directory:
            path, _ = _write_source(Path(directory), [secret.encode("utf-8")])
            with self.assertRaises(QualificationFatalError) as raised:
                qualify_case_file(path, "0" * 64, dataset_id=DATASET_ID)

        self.assertEqual(raised.exception.error_category, "INTERNAL")
        self.assertEqual(raised.exception.error_code, "SOURCE_DIGEST_MISMATCH")
        self.assertIsNone(raised.exception.physical_line_number)
        self.assertNotIn(secret, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
