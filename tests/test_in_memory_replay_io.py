from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.replay.contracts import (
    MAX_JSONL_LINE_BYTES,
    ContractValidationError,
    load_jsonl_bytes,
    load_jsonl_objects,
)
from adf_poc.replay.qualification import (
    QualificationFatalError,
    qualify_case_bytes,
    qualify_case_file,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_CASES = ROOT / "data" / "phase2_starter" / "cases.jsonl"
DATASET_ID = "phase2-in-memory-io"


class InMemoryReplayIOTests(unittest.TestCase):
    def test_memory_audit_rows_are_verified_and_caller_mutation_is_isolated(
        self,
    ) -> None:
        audit = AuditLogger(None)
        returned = audit.append("ONE", {"nested": {"value": 1}})
        audit.append("TWO", {"value": 2})

        returned["payload"]["nested"]["value"] = 999
        first_read = audit.read_all()
        self.assertEqual(first_read[0]["payload"]["nested"]["value"], 1)
        first_read[0]["payload"]["nested"]["value"] = 888
        second_read = audit.read_all()
        self.assertEqual(second_read[0]["payload"]["nested"]["value"], 1)

        before_verification = copy.deepcopy(second_read)
        valid, errors = AuditLogger.verify_rows(second_read)
        self.assertTrue(valid)
        self.assertEqual(errors, [])
        self.assertEqual(second_read, before_verification)

        tampered = copy.deepcopy(second_read)
        tampered[0]["payload"]["nested"]["value"] = 777
        valid, errors = AuditLogger.verify_rows(tampered)
        self.assertFalse(valid)
        self.assertTrue(errors)

    def test_file_audit_behavior_remains_compatible_with_row_verification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = AuditLogger(path)
            audit.append("ONE", {"value": 1})
            audit.append("TWO", {"value": 2})
            rows = audit.read_all()

            self.assertEqual(AuditLogger.verify(path), (True, []))
            self.assertEqual(AuditLogger.verify_rows(rows), (True, []))

    def test_bytes_jsonl_loader_matches_path_loader_and_enforces_bounds(self) -> None:
        content = FIXTURE_CASES.read_bytes()
        self.assertEqual(
            load_jsonl_bytes(content, label="byte cases"),
            load_jsonl_objects(FIXTURE_CASES, label="path cases"),
        )

        invalid_inputs = (
            (b"[]\n", "must be a JSON object"),
            (b'{"incomplete":true\n', "is not valid JSON"),
            (b'{"value":1,"value":2}\n', "duplicate JSON object members"),
            (
                b'{"outer":{"value":1,"value":2}}\n',
                "duplicate JSON object members",
            ),
            (b'{"value":"\xff"}\n', "Unable to read"),
            (b'{"value":NaN}\n', "is not valid JSON"),
            (b'{"value":1e400}\n', "non-finite JSON number"),
            (
                json.dumps({"value": "x" * MAX_JSONL_LINE_BYTES}).encode("utf-8")
                + b"\n",
                "exceeds",
            ),
        )
        for raw, expected_message in invalid_inputs:
            with self.subTest(expected_message=expected_message):
                with self.assertRaisesRegex(ContractValidationError, expected_message):
                    load_jsonl_bytes(raw, label="bounded byte input")

        with patch("adf_poc.replay.contracts.MAX_RECORDS_PER_FILE", 1):
            with self.assertRaisesRegex(ContractValidationError, "record limit"):
                load_jsonl_bytes(b"{}\n{}\n", label="bounded byte input")

    def test_bytes_qualification_matches_file_without_opening_a_path(self) -> None:
        content = FIXTURE_CASES.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        expected = qualify_case_file(
            FIXTURE_CASES,
            digest,
            dataset_id=DATASET_ID,
        )

        with patch(
            "adf_poc.replay.qualification.Path.open",
            side_effect=AssertionError("byte qualification must not open a path"),
        ):
            actual = qualify_case_bytes(
                content,
                digest,
                dataset_id=DATASET_ID,
            )
        self.assertEqual(actual, expected)

        with self.assertRaises(QualificationFatalError) as context:
            qualify_case_bytes(
                content,
                "0" * 64,
                dataset_id=DATASET_ID,
            )
        self.assertEqual(context.exception.error_code, "SOURCE_DIGEST_MISMATCH")


if __name__ == "__main__":
    unittest.main()
