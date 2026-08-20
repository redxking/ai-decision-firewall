from __future__ import annotations

import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from adf_poc.audit import AuditDurabilityError, AuditLogger
from adf_poc.phase3.audit import validate_phase3_audit_chain
from adf_poc.phase3.scenarios import request_json
from tests.phase3_support import new_harness, workstation_case


class StageAStorageFailureCampaignTests(unittest.TestCase):
    def _durable_case(self, root: Path, *, request_id: str):
        harness = new_harness(
            audit_path=root / "audit.jsonl",
            control_ledger_path=root / "control.sqlite3",
            synthetic_adapter_path=root / "adapter.sqlite3",
        )
        raw = request_json(workstation_case(harness, request_id=request_id))
        return harness, raw

    def _reopen_and_reconcile(self, root: Path, harness, raw: str):
        reopened = new_harness(
            now=harness.clock(),
            audit_path=root / "audit.jsonl",
            control_ledger_path=root / "control.sqlite3",
            synthetic_adapter_path=root / "adapter.sqlite3",
        )
        self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 1)
        self.assertEqual(
            reopened.firewall.observer.observe("WORKSTATION_042")["network_state"],
            "isolated",
        )
        self.assertIsNone(
            reopened.firewall.lookup_request_result(
                raw, credential=reopened.soc_credential
            )
        )
        recovered = reopened.firewall.reconcile_request(
            raw,
            credential=reopened.soc_credential,
            operator_asserted_quiesced=True,
        )
        self.assertIsNotNone(recovered)
        assert recovered is not None
        self.assertEqual(recovered.disposition, "UNKNOWN_EFFECT")
        self.assertFalse(recovered.new_effect)
        self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 1)
        valid, errors = validate_phase3_audit_chain(
            AuditLogger(root / "audit.jsonl").read_all()
        )
        self.assertTrue(valid, errors)
        return recovered

    def test_ambiguous_audit_fsync_never_allows_t3_or_duplicate_effect(self) -> None:
        for failed_record_type, expected_audit_status in (
            ("ACTION_ATTEMPTED", "ORIGINAL_EXECUTION_AUDIT_INCOMPLETE"),
            ("FINAL_STATE_RECORDED", "ORIGINAL_EXECUTION_AUDIT_COMPLETE"),
        ):
            with (
                self.subTest(failed_record_type=failed_record_type),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                harness, raw = self._durable_case(
                    root,
                    request_id=f"P3-STAGE-A-FSYNC-{failed_record_type}",
                )
                original_append = AuditLogger.append
                original_fsync = os.fsync
                current_record: str | None = None
                injected = False

                def tracked_append(logger, record_type, payload):
                    nonlocal current_record
                    current_record = record_type
                    try:
                        return original_append(logger, record_type, payload)
                    finally:
                        current_record = None

                def ambiguous_fsync(descriptor):
                    nonlocal injected
                    if current_record == failed_record_type and not injected:
                        injected = True
                        raise OSError(errno.EIO, "injected audit fsync failure")
                    return original_fsync(descriptor)

                with (
                    patch.object(AuditLogger, "append", new=tracked_append),
                    patch("adf_poc.audit.os.fsync", new=ambiguous_fsync),
                    self.assertRaises(AuditDurabilityError),
                ):
                    harness.firewall.process_json(
                        raw, credential=harness.soc_credential
                    )

                self.assertTrue(injected)
                self.assertEqual(harness.firewall._adapter_store.receipt_count(), 1)
                self.assertEqual(
                    harness.firewall.observer.observe("WORKSTATION_042")[
                        "network_state"
                    ],
                    "isolated",
                )
                continuity = (
                    harness.firewall._control_ledger.audit_continuity_snapshot()
                )
                self.assertEqual(len(continuity), 1)
                self.assertNotEqual(continuity[0]["state"], "TERMINAL")
                recovered = self._reopen_and_reconcile(root, harness, raw)
                self.assertIn(expected_audit_status, recovered.reason_codes)

    def test_persistent_post_effect_enospc_halts_until_explicit_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness, raw = self._durable_case(
                root,
                request_id="P3-STAGE-A-PERSISTENT-ENOSPC",
            )
            original_append = AuditLogger.append
            original_write = os.write
            current_record: str | None = None
            blocked_writes = 0

            def tracked_append(logger, record_type, payload):
                nonlocal current_record
                current_record = record_type
                try:
                    return original_append(logger, record_type, payload)
                finally:
                    current_record = None

            def exhausted_write(descriptor, value):
                nonlocal blocked_writes
                if current_record in {
                    "ACTION_ATTEMPTED",
                    "POST_EFFECT_ACCOUNTING_FAILURE",
                    "FINAL_STATE_RECORDED",
                }:
                    blocked_writes += 1
                    raise OSError(errno.ENOSPC, "injected audit volume exhaustion")
                return original_write(descriptor, value)

            with (
                patch.object(AuditLogger, "append", new=tracked_append),
                patch("adf_poc.audit.os.write", new=exhausted_write),
                self.assertRaises(OSError) as raised,
            ):
                harness.firewall.process_json(raw, credential=harness.soc_credential)

            self.assertEqual(raised.exception.errno, errno.ENOSPC)
            self.assertGreaterEqual(blocked_writes, 2)
            self.assertEqual(harness.firewall._adapter_store.receipt_count(), 1)
            self.assertEqual(
                harness.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "isolated",
            )
            recovered = self._reopen_and_reconcile(root, harness, raw)
            self.assertIn("ORIGINAL_EXECUTION_AUDIT_INCOMPLETE", recovered.reason_codes)


if __name__ == "__main__":
    unittest.main()
