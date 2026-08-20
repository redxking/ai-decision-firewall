from __future__ import annotations

import errno
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from adf_poc.phase3.scenarios import request_json
from adf_poc.stage_a import SQLiteControlLedger
from tests.phase3_support import new_harness, workstation_case


def _fill_volume(path: Path) -> int:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    total = 0
    chunk = b"X" * 65_536
    try:
        while total <= 16 * 1024 * 1024:
            try:
                written = os.write(descriptor, chunk)
            except OSError as exc:
                if exc.errno != errno.ENOSPC:
                    raise
                break
            if written <= 0:
                raise OSError("tmpfs filler made no forward progress")
            total += written
        else:
            raise AssertionError("campaign volume did not reach ENOSPC")
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno != errno.ENOSPC:
                raise
    finally:
        os.close(descriptor)
    return total


@unittest.skipUnless(
    os.environ.get("ADF_CONTAINER_STORAGE_CAMPAIGN") == "1",
    "destructive tmpfs campaign requires an explicit container marker",
)
class StageAContainerStorageFaultTests(unittest.TestCase):
    def test_real_tmpfs_enospc_partial_audit_row_requires_quarantine(self) -> None:
        audit_root = Path("/audit-volume")
        self.assertTrue(audit_root.is_dir())
        with tempfile.TemporaryDirectory() as directory:
            state_root = Path(directory).resolve()
            audit_path = audit_root / "audit.jsonl"
            filler_path = audit_root / "campaign-filler.bin"
            harness = new_harness(
                audit_path=audit_path,
                control_ledger_path=state_root / "control.sqlite3",
                synthetic_adapter_path=state_root / "adapter.sqlite3",
            )
            raw = request_json(
                workstation_case(
                    harness,
                    request_id="P3-STAGE-A-CONTAINER-TMPFS-ENOSPC",
                )
            )
            original_record = SQLiteControlLedger.record_adapter_receipt
            filled = 0

            def exhaust_after_t2(ledger, *args, **kwargs):
                nonlocal filled
                result = original_record(ledger, *args, **kwargs)
                filled = _fill_volume(filler_path)
                return result

            with (
                patch.object(
                    SQLiteControlLedger,
                    "record_adapter_receipt",
                    new=exhaust_after_t2,
                ),
                self.assertRaises(Exception) as raised,
            ):
                harness.firewall.process_json(raw, credential=harness.soc_credential)

            chain: list[BaseException] = []
            current: BaseException | None = raised.exception
            while current is not None and current not in chain:
                chain.append(current)
                current = current.__cause__ or current.__context__
            self.assertTrue(
                any(
                    isinstance(error, OSError) and error.errno == errno.ENOSPC
                    for error in chain
                ),
                [repr(error) for error in chain],
            )
            self.assertGreater(filled, 0)
            self.assertEqual(harness.firewall._adapter_store.receipt_count(), 1)
            self.assertEqual(
                harness.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "isolated",
            )

            filler_path.unlink()
            directory_descriptor = os.open(
                audit_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)

            corrupt_audit = audit_path.read_bytes()
            with self.assertRaises(Exception):
                new_harness(
                    now=harness.clock(),
                    audit_path=audit_path,
                    control_ledger_path=state_root / "control.sqlite3",
                    synthetic_adapter_path=state_root / "adapter.sqlite3",
                )
            self.assertEqual(audit_path.read_bytes(), corrupt_audit)
            self.assertEqual(harness.firewall._adapter_store.receipt_count(), 1)
            self.assertEqual(
                harness.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "isolated",
            )


if __name__ == "__main__":
    unittest.main()
