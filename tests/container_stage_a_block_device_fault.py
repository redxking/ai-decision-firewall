from __future__ import annotations

import errno
import gc
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import time
import unittest
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.phase3.audit import validate_phase3_audit_chain
from adf_poc.phase3.scenarios import request_json
from adf_poc.stage_a import SQLiteControlLedger, SQLiteSyntheticAdapterStore
from tests.phase3_support import new_harness, workstation_case


CAMPAIGN_TIME = datetime.fromisoformat("2026-08-20T15:00:00+00:00")
LAB_ROOT = Path("/lab")
MOUNT_ROOT = Path("/fault-volume")
BOUNDARIES = ("T1", "OBSERVATION", "T2", "AUDIT", "T3")
FAULT_MODES = ("DM_ERROR", "DM_FLAKEY_ERROR_WRITES")


def _run(
    *arguments: str,
    capture: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        arguments,
        check=False,
        capture_output=capture,
        text=True,
        timeout=30,
    )
    if check and completed.returncode != 0:
        raise AssertionError(
            f"{' '.join(arguments)} failed ({completed.returncode}): "
            f"{completed.stderr or completed.stdout}"
        )
    return completed


class _BlockDevice:
    def __init__(self, boundary: str, fault_mode: str) -> None:
        if fault_mode not in FAULT_MODES:
            raise AssertionError("unsupported block-device fault mode")
        suffix = f"{os.getpid()}_{fault_mode.lower()}_{boundary.lower()}"
        self.fault_mode = fault_mode
        self.name = f"adf_stage_a_dm_{suffix}"
        self.image = LAB_ROOT / f"{suffix}.img"
        self.loop = ""
        self.sectors = ""
        self.device = f"/dev/mapper/{self.name}"
        self.mapped = False
        self.mounted = False
        self.fault_active = False
        self.fsck_returncode: int | None = None
        self.artifact_changed_paths: tuple[str, ...] = ()
        self.pre_repair_image_sha256 = ""
        self.post_repair_image_sha256 = ""

    @property
    def linear_table(self) -> str:
        return f"0 {self.sectors} linear {self.loop} 0"

    @property
    def error_table(self) -> str:
        return f"0 {self.sectors} error"

    @property
    def flakey_error_writes_table(self) -> str:
        return f"0 {self.sectors} flakey {self.loop} 0 1 60 1 error_writes"

    def __enter__(self) -> _BlockDevice:
        LAB_ROOT.mkdir(mode=0o700, exist_ok=True)
        MOUNT_ROOT.mkdir(mode=0o700, exist_ok=True)
        descriptor = os.open(
            self.image,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            os.ftruncate(descriptor, 128 * 1024 * 1024)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self.loop = _run(
            "losetup",
            "--find",
            "--show",
            str(self.image),
            capture=True,
        ).stdout.strip()
        self.sectors = _run(
            "blockdev", "--getsz", self.loop, capture=True
        ).stdout.strip()
        _run("dmsetup", "create", self.name, "--table", self.linear_table)
        self.mapped = True
        _run("dmsetup", "mknodes", self.name)
        _run("mkfs.ext4", "-q", self.device)
        self._mount()
        return self

    def _mount(self) -> None:
        _run(
            "mount",
            "-o",
            "data=journal,commit=1,errors=remount-ro",
            self.device,
            str(MOUNT_ROOT),
        )
        self.mounted = True

    def _swap(self, table: str) -> None:
        _run("dmsetup", "suspend", "--noflush", self.name)
        _run("dmsetup", "reload", self.name, "--table", table)
        _run("dmsetup", "resume", self.name)

    def inject_fault(self) -> None:
        if self.fault_active:
            raise AssertionError("block-device fault was injected more than once")
        if self.fault_mode == "DM_ERROR":
            self._swap(self.error_table)
        else:
            self._swap(self.flakey_error_writes_table)
            # The mapping begins with a one-second up interval. Enter the
            # 60-second down interval before returning to application code.
            time.sleep(1.2)
        self.fault_active = True

    def restore_and_repair(self) -> None:
        if not self.fault_active:
            raise AssertionError("block-device fault was not active")
        self._swap(self.linear_table)
        self.fault_active = False
        before = self._artifact_digests()
        _run("umount", str(MOUNT_ROOT))
        self.mounted = False
        self.pre_repair_image_sha256 = self._image_sha256()
        checked = _run("e2fsck", "-fy", self.device, capture=True, check=False)
        if checked.returncode not in {0, 1}:
            raise AssertionError(
                f"e2fsck failed ({checked.returncode}): "
                f"{checked.stderr or checked.stdout}"
            )
        self.fsck_returncode = checked.returncode
        self.post_repair_image_sha256 = self._image_sha256()
        self._mount()
        after = self._artifact_digests()
        self.artifact_changed_paths = tuple(
            sorted(
                path
                for path in set(before) | set(after)
                if before.get(path) != after.get(path)
            )
        )

    @staticmethod
    def _artifact_digests() -> dict[str, str]:
        state_root = MOUNT_ROOT / "state"
        return {
            str(path.relative_to(state_root)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(state_root.rglob("*"))
            if path.is_file() and not path.is_symlink()
        }

    def _image_sha256(self) -> str:
        digest = hashlib.sha256()
        with self.image.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self.fault_active:
            self._swap(self.linear_table)
            self.fault_active = False
        if self.mounted:
            _run("umount", str(MOUNT_ROOT), check=False)
            self.mounted = False
        if self.mapped:
            _run("dmsetup", "remove", "--force", self.name, check=False)
            self.mapped = False
        if self.loop:
            _run("losetup", "--detach", self.loop, check=False)
        if self.image.exists():
            self.image.unlink()


def _harness():
    state_root = MOUNT_ROOT / "state"
    state_root.mkdir(mode=0o700, exist_ok=True)
    return new_harness(
        now=CAMPAIGN_TIME,
        audit_path=state_root / "audit.jsonl",
        control_ledger_path=state_root / "control.sqlite3",
        synthetic_adapter_path=state_root / "adapter.sqlite3",
    )


def _request(harness, boundary: str, fault_mode: str) -> str:
    return request_json(
        workstation_case(
            harness,
            request_id=f"P3-STAGE-A-{fault_mode}-{boundary}",
        )
    )


def _fault_patch(boundary: str, device: _BlockDevice):
    if boundary == "T1":
        target = SQLiteControlLedger
        attribute = "consume_once"
    elif boundary == "OBSERVATION":
        target = SQLiteSyntheticAdapterStore
        attribute = "execute_once"
    elif boundary == "T2":
        target = SQLiteControlLedger
        attribute = "record_adapter_receipt"
    elif boundary == "AUDIT":
        target = AuditLogger
        attribute = "append"
    else:
        target = SQLiteControlLedger
        attribute = "complete_request"
    original = getattr(target, attribute)

    def after_boundary(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if boundary != "AUDIT" or args[0] == "FINAL_STATE_RECORDED":
            device.inject_fault()
        return result

    return patch.object(target, attribute, after_boundary)


@unittest.skipUnless(
    os.environ.get("ADF_CONTAINER_BLOCK_DEVICE_CAMPAIGN") == "1",
    "block-device campaign requires an explicit privileged-lab marker",
)
class StageABlockDeviceFaultTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.previous_sigterm = signal.getsignal(signal.SIGTERM)

        def terminate(_signum, _frame):
            raise KeyboardInterrupt("block-device campaign termination requested")

        signal.signal(signal.SIGTERM, terminate)

    @classmethod
    def tearDownClass(cls) -> None:
        signal.signal(signal.SIGTERM, cls.previous_sigterm)

    def test_device_mapper_ext4_boundaries_never_duplicate_effect(self) -> None:
        if os.geteuid() != 0:
            self.skipTest(
                "block-device campaign requires root inside the disposable lab"
            )
        for tool in ("blockdev", "dmsetup", "e2fsck", "losetup", "mkfs.ext4", "mount"):
            if shutil.which(tool) is None:
                self.skipTest(f"block-device campaign tool is unavailable: {tool}")

        requested_mode = os.environ.get("ADF_BLOCK_DEVICE_FAULT_MODE", "")
        if requested_mode not in FAULT_MODES:
            self.fail("ADF_BLOCK_DEVICE_FAULT_MODE must select one exact fault mode")
        if requested_mode == "DM_FLAKEY_ERROR_WRITES":
            targets = _run("dmsetup", "targets", capture=True).stdout.splitlines()
            available = {line.split()[0] for line in targets if line.split()}
            if "flakey" not in available:
                self.fail(
                    "DM_FLAKEY_ERROR_WRITES requested but the kernel has no "
                    "device-mapper flakey target"
                )

        observations: list[dict[str, object]] = []
        for boundary in BOUNDARIES:
            with (
                self.subTest(fault_mode=requested_mode, boundary=boundary),
                _BlockDevice(boundary, requested_mode) as device,
            ):
                self._run_boundary(observations, requested_mode, boundary, device)
        print(json.dumps(observations, sort_keys=True))

    def _run_boundary(
        self,
        observations: list[dict[str, object]],
        fault_mode: str,
        boundary: str,
        device: _BlockDevice,
    ) -> None:
        first = _harness()
        raw = _request(first, boundary, fault_mode)
        raised: Exception | None = None
        try:
            with _fault_patch(boundary, device):
                first.firewall.process_json(raw, credential=first.soc_credential)
        except Exception as exc:
            raised = exc

        self.assertTrue(device.fault_active)
        if boundary != "T3":
            self.assertIsNotNone(raised)
            chain: list[BaseException] = []
            current = raised
            while current is not None and current not in chain:
                chain.append(current)
                current = current.__cause__ or current.__context__
            self.assertTrue(
                any(
                    (
                        isinstance(error, OSError)
                        and error.errno in {errno.EIO, errno.EROFS}
                    )
                    or (
                        isinstance(error, sqlite3.OperationalError)
                        and str(error)
                        in {
                            "attempt to write a readonly database",
                            "disk I/O error",
                            "unable to open database file",
                        }
                    )
                    for error in chain
                ),
                [repr(error) for error in chain],
            )

        del first
        gc.collect()
        device.restore_and_repair()
        self.assertEqual(64, len(device.pre_repair_image_sha256))
        self.assertEqual(64, len(device.post_repair_image_sha256))
        reopened = _harness()
        expected_receipts = 0 if boundary == "T1" else 1
        expected_state = "connected" if boundary == "T1" else "isolated"
        self.assertEqual(
            expected_receipts,
            reopened.firewall._adapter_store.receipt_count(),
        )
        self.assertEqual(
            expected_state,
            reopened.firewall.observer.observe("WORKSTATION_042")["network_state"],
        )
        lookup = reopened.firewall.lookup_request_result(
            raw, credential=reopened.soc_credential
        )
        if boundary == "T3":
            self.assertIsNotNone(lookup)
            assert lookup is not None
            self.assertEqual("COMPLETED_VERIFIED", lookup.disposition)
            replay = reopened.firewall.process_json(
                raw, credential=reopened.soc_credential
            )
            self.assertIn("DUPLICATE_REQUEST", replay.decision.reason_codes)
            disposition = lookup.disposition
        else:
            self.assertIsNone(lookup)
            recovered = reopened.firewall.reconcile_request(
                raw,
                credential=reopened.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual("UNKNOWN_EFFECT", recovered.disposition)
            self.assertFalse(recovered.new_effect)
            disposition = recovered.disposition
        self.assertEqual(
            expected_receipts,
            reopened.firewall._adapter_store.receipt_count(),
        )
        valid, errors = validate_phase3_audit_chain(
            AuditLogger(MOUNT_ROOT / "state" / "audit.jsonl").read_all()
        )
        self.assertTrue(valid, errors)
        observations.append(
            {
                "artifact_changed_paths": device.artifact_changed_paths,
                "boundary": boundary,
                "disposition": disposition,
                "fault_mode": fault_mode,
                "fsck_returncode": device.fsck_returncode,
                "post_repair_image_sha256": device.post_repair_image_sha256,
                "pre_repair_image_sha256": device.pre_repair_image_sha256,
                "receipt_count": expected_receipts,
            }
        )
        del reopened
        gc.collect()


if __name__ == "__main__":
    unittest.main()
