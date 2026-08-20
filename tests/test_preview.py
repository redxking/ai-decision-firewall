from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from adf_poc.audit import AuditLogger
from run_preview import main


class DeveloperPreviewTests(unittest.TestCase):
    @staticmethod
    def invoke(arguments: list[str]) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = main(arguments)
        return status, stdout.getvalue(), stderr.getvalue()

    def test_demo_reopen_status_and_safe_reset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "preview"
            status, output, _error = self.invoke(["demo", "--root", str(root)])
            self.assertEqual(status, 0)
            demo = json.loads(output)
            self.assertEqual(
                [row["decision_outcome"] for row in demo["results"]],
                ["ALLOW", "ESCALATE"],
            )
            self.assertTrue(demo["results"][0]["adapter_receipt_recorded"])
            self.assertFalse(demo["results"][1]["adapter_receipt_recorded"])
            rows_after_first = AuditLogger(root / "state" / "audit.jsonl").read_all()
            self.assertGreater(len(rows_after_first), 0)
            self.assertEqual(self.invoke(["status", "--root", str(root)])[0], 0)
            self.assertEqual(
                self.invoke(
                    [
                        "scenario",
                        "workstation",
                        "--root",
                        str(root),
                        "--request-id",
                        "PREVIEW-REOPEN-001",
                    ]
                )[0],
                0,
            )
            valid, errors = AuditLogger.verify(root / "state" / "audit.jsonl")
            self.assertTrue(valid, errors)
            self.assertGreater(
                len(AuditLogger(root / "state" / "audit.jsonl").read_all()),
                len(rows_after_first),
            )
            self.assertEqual(self.invoke(["reset", "--root", str(root)])[0], 2)
            self.assertTrue(root.exists())
            self.assertEqual(
                self.invoke(
                    [
                        "reset",
                        "--root",
                        str(root),
                        "--confirm-synthetic-preview",
                    ]
                )[0],
                0,
            )
            self.assertFalse(root.exists())

    def test_reset_refuses_unmarked_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve() / "not-preview"
            root.mkdir(mode=0o700)
            (root / "important.json").write_text(json.dumps({"keep": True}))
            self.assertEqual(
                self.invoke(
                    [
                        "reset",
                        "--root",
                        str(root),
                        "--confirm-synthetic-preview",
                    ]
                )[0],
                2,
            )
            self.assertTrue((root / "important.json").exists())

    def test_generate_submit_and_tamper_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            root = base / "preview"
            request = base / "request.json"
            self.assertEqual(
                self.invoke(
                    [
                        "generate",
                        "workstation",
                        "--root",
                        str(root),
                        "--output",
                        str(request),
                        "--request-id",
                        "PREVIEW-FILE-001",
                    ]
                )[0],
                0,
            )
            status, output, _error = self.invoke(
                ["submit", "--root", str(root), "--file", str(request)]
            )
            self.assertEqual(status, 0)
            submitted = json.loads(output)
            self.assertEqual(submitted["status"], "DURABLE_RESULT_RETRIEVED")
            self.assertTrue(submitted["adapter_receipt_recorded"])
            self.assertNotIn("authorization", submitted)
            self.assertNotIn("replayed", submitted)
            rows = len(AuditLogger(root / "state" / "audit.jsonl").read_all())
            tampered = base / "tampered.json"
            value = json.loads(request.read_text())
            value["context"]["live_action"] = True
            tampered.write_text(json.dumps(value), encoding="utf-8")
            tampered.chmod(0o600)
            self.assertEqual(
                self.invoke(["submit", "--root", str(root), "--file", str(tampered)])[
                    0
                ],
                2,
            )
            self.assertEqual(
                len(AuditLogger(root / "state" / "audit.jsonl").read_all()), rows
            )


if __name__ == "__main__":
    unittest.main()
