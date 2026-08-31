from __future__ import annotations

from contextlib import closing
from datetime import datetime
import fcntl
import json
import multiprocessing
import os
import queue
import shutil
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from time import monotonic
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.phase3.audit import (
    validate_phase3_audit_chain,
    validate_phase3_lifecycle,
)
from adf_poc.phase3.contracts import load_decision_request_json
from adf_poc.phase3.scenarios import request_json
from adf_poc.stage_a import (
    ControlLedgerError,
    SQLiteControlLedger,
    SQLiteSyntheticAdapterStore,
    SyntheticAdapterError,
)

from tests.phase3_support import domain_controller_case, new_harness, workstation_case


def _crash_at_adapter_boundary(
    root_text: str,
    raw_request: str,
    now_text: str,
    boundary: str,
    fault_mode: str | None,
) -> None:
    """Child-process kill hook used to test committed T1/T2 restart state."""

    root = Path(root_text)
    faults = {"WORKSTATION_042": fault_mode} if fault_mode is not None else None
    harness = new_harness(
        now=datetime.fromisoformat(now_text),
        fault_modes=faults,
        audit_path=root / "audit.jsonl",
        control_ledger_path=root / "control.sqlite3",
        synthetic_adapter_path=root / "adapter.sqlite3",
    )
    original_execute_once = SQLiteSyntheticAdapterStore.execute_once

    if boundary == "before_adapter":

        def crash_before(self: SQLiteSyntheticAdapterStore, **values: object) -> object:
            os._exit(71)

        replacement = crash_before
        expected_exit = 71
    elif boundary == "after_adapter_commit":

        def crash_after(self: SQLiteSyntheticAdapterStore, **values: object) -> object:
            original_execute_once(self, **values)
            os._exit(72)

        replacement = crash_after
        expected_exit = 72
    else:  # pragma: no cover - parent supplies a closed value
        os._exit(79)

    with patch.object(SQLiteSyntheticAdapterStore, "execute_once", replacement):
        harness.firewall.process_json(raw_request, credential=harness.soc_credential)
    os._exit(expected_exit + 10)


def _hold_audit_file_lock(audit_path: str, ready: object, release: object) -> None:
    descriptor = os.open(audit_path, os.O_RDWR | os.O_APPEND)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        ready.set()
        release.wait(timeout=15)
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _concurrent_request_worker(
    root_text: str,
    raw_request: str,
    now_text: str,
    worker_id: str,
    barrier: object,
    results: object,
) -> None:
    root = Path(root_text)
    try:
        harness = new_harness(
            now=datetime.fromisoformat(now_text),
            audit_path=root / "audit.jsonl",
            control_ledger_path=root / "control.sqlite3",
            control_ledger_busy_timeout_ms=5_000,
            synthetic_adapter_path=root / "adapter.sqlite3",
            synthetic_adapter_busy_timeout_ms=5_000,
        )
        barrier.wait(timeout=15)
        result = harness.firewall.process_json(
            raw_request, credential=harness.soc_credential
        )
        results.put(
            (
                "OK",
                result.decision.outcome,
                result.broker_result is not None,
                (
                    result.verification.status
                    if result.verification is not None
                    else None
                ),
            )
        )
    except Exception as exc:  # pragma: no cover - child diagnostic surface
        results.put(
            (
                "ERROR",
                type(exc).__name__,
                getattr(exc, "reason_code", ""),
                str(exc),
            )
        )


def _crash_after_recovery_audit_record(
    root_text: str,
    raw_request: str,
    now_text: str,
    record_type: str,
    exit_code: int,
) -> None:
    root = Path(root_text)
    harness = new_harness(
        now=datetime.fromisoformat(now_text),
        audit_path=root / "audit.jsonl",
        control_ledger_path=root / "control.sqlite3",
        synthetic_adapter_path=root / "adapter.sqlite3",
    )
    original_append = AuditLogger.append

    def crash_after_append(
        self: AuditLogger,
        appended_type: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        row = original_append(self, appended_type, payload)
        if appended_type == record_type:
            os._exit(exit_code)
        return row

    with patch.object(AuditLogger, "append", crash_after_append):
        harness.firewall.reconcile_request(
            raw_request,
            credential=harness.soc_credential,
            operator_asserted_quiesced=True,
        )
    os._exit(exit_code + 20)


def _crash_after_closed_audit_before_terminal_commit(
    root_text: str,
    raw_request: str,
    now_text: str,
) -> None:
    """Kill after normal JSONL closure but before the control-ledger T3 commit."""

    root = Path(root_text)
    harness = new_harness(
        now=datetime.fromisoformat(now_text),
        audit_path=root / "audit.jsonl",
        control_ledger_path=root / "control.sqlite3",
        synthetic_adapter_path=root / "adapter.sqlite3",
    )

    def crash_before_t3(
        self: SQLiteControlLedger,
        result: object,
        **values: object,
    ) -> None:
        os._exit(84)

    with patch.object(SQLiteControlLedger, "complete_request", crash_before_t3):
        harness.firewall.process_json(raw_request, credential=harness.soc_credential)
    os._exit(104)


def _assert_no_authority_material(test: unittest.TestCase, value: object) -> None:
    denied = {
        "authorization_token",
        "token_id",
        "unsigned_token_sha256",
        "nonce",
        "signature",
        "signatures",
        "audit_records",
        "credential",
        "credentials",
        "secret",
        "signing_key",
        "issuer_instance_id",
        "authorization_key_domain_id",
        "key_domain_id",
    }
    if type(value) is dict:
        for key, child in value.items():
            test.assertNotIn(str(key).lower(), denied)
            _assert_no_authority_material(test, child)
    elif type(value) is list:
        for child in value:
            _assert_no_authority_material(test, child)


class StageAReceiptRecoveryTests(unittest.TestCase):
    def _assert_closed_recovery_audit(
        self,
        audit_path: Path,
        *,
        disposition: str,
        original_lifecycle_valid: bool,
    ) -> None:
        rows = AuditLogger(audit_path).read_all()
        chain_valid, chain_errors = validate_phase3_audit_chain(rows)
        self.assertTrue(chain_valid, chain_errors)
        recovery = rows[-3:]
        self.assertEqual(
            [row["record_type"] for row in recovery],
            [
                "RECOVERY_STARTED",
                "RECOVERY_EVIDENCE_ASSESSED",
                "RECOVERY_FINALIZED",
            ],
        )
        recovery_ids = {row["payload"]["recovery_id"] for row in recovery}
        self.assertEqual(len(recovery_ids), 1)
        self.assertTrue(
            all(
                row["payload"]["operator_asserted_quiesced"] is True
                and row["payload"]["command_invoked"] is False
                and row["payload"]["new_effect"] is False
                and row["payload"]["original_execution_lifecycle_valid"]
                is original_lifecycle_valid
                for row in recovery
            )
        )
        self.assertEqual(recovery[-1]["payload"]["disposition"], disposition)
        self.assertTrue(recovery[-1]["payload"]["control_commit_pending"])

    def _run_crash(
        self,
        root: Path,
        *,
        raw_request: str,
        now: datetime,
        boundary: str,
        fault_mode: str | None = None,
    ) -> None:
        context = multiprocessing.get_context("spawn")
        process = context.Process(
            target=_crash_at_adapter_boundary,
            args=(
                str(root),
                raw_request,
                now.isoformat(),
                boundary,
                fault_mode,
            ),
        )
        process.start()
        process.join(timeout=30)
        if process.is_alive():  # pragma: no cover - bounded hang cleanup
            process.terminate()
            process.join(timeout=5)
            self.fail("Crash-injection child did not terminate within the bound.")
        self.assertEqual(
            process.exitcode,
            71 if boundary == "before_adapter" else 72,
        )

    def _completed_case(self, root: Path, *, request_id: str) -> tuple[object, str]:
        harness = new_harness(
            audit_path=root / "audit.jsonl",
            control_ledger_path=root / "control.sqlite3",
            synthetic_adapter_path=root / "adapter.sqlite3",
        )
        raw = request_json(workstation_case(harness, request_id=request_id))
        result = harness.firewall.process_json(raw, credential=harness.soc_credential)
        self.assertEqual(result.decision.outcome, "ALLOW")
        return harness, raw

    def test_completed_durable_state_requires_existing_nonempty_audit_on_restart(
        self,
    ) -> None:
        for replacement in ("missing", "empty"):
            with (
                self.subTest(replacement=replacement),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                self._completed_case(
                    root, request_id=f"P3-STAGE-A-AUDIT-{replacement.upper()}"
                )
                audit_path = root / "audit.jsonl"
                control_path = root / "control.sqlite3"
                adapter_path = root / "adapter.sqlite3"
                audit_path.unlink()
                if replacement == "empty":
                    audit_path.touch(mode=0o600)
                    audit_path.chmod(0o600)
                before = {
                    control_path: control_path.read_bytes(),
                    adapter_path: adapter_path.read_bytes(),
                }

                with self.assertRaises(ControlLedgerError) as raised:
                    new_harness(
                        audit_path=audit_path,
                        control_ledger_path=control_path,
                        synthetic_adapter_path=adapter_path,
                    )
                self.assertEqual(
                    raised.exception.reason_code, "AUDIT_CONTINUITY_REQUIRED"
                )
                self.assertEqual({path: path.read_bytes() for path in before}, before)
                self.assertEqual(audit_path.exists(), replacement == "empty")
                if audit_path.exists():
                    self.assertEqual(audit_path.read_bytes(), b"")

    def test_truncated_hash_valid_audit_prefix_blocks_restart_and_new_intake(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._completed_case(root, request_id="P3-STAGE-A-AUDIT-PREFIX")
            audit_path = root / "audit.jsonl"
            rows = audit_path.read_bytes().splitlines(keepends=True)
            self.assertGreater(len(rows), 1)
            audit_path.write_bytes(b"".join(rows[:-1]))
            valid, errors = validate_phase3_audit_chain(
                AuditLogger(audit_path).read_all()
            )
            self.assertTrue(valid, errors)
            truncated = audit_path.read_bytes()

            with self.assertRaises(ControlLedgerError) as raised:
                new_harness(
                    audit_path=audit_path,
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
            self.assertEqual(raised.exception.reason_code, "AUDIT_CONTINUITY_REQUIRED")
            self.assertEqual(audit_path.read_bytes(), truncated)

    def test_nonterminal_control_without_matching_audit_suffix_blocks_restart(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = new_harness(
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            harness.firewall.process_json("{}", credential=harness.soc_credential)
            audit_path = root / "audit.jsonl"
            closed_prefix = audit_path.read_bytes()
            now = harness.clock()
            raw = request_json(
                workstation_case(
                    harness, request_id="P3-STAGE-A-MISSING-NONTERMINAL-AUDIT"
                )
            )
            self._run_crash(
                root,
                raw_request=raw,
                now=now,
                boundary="after_adapter_commit",
            )
            audit_path.write_bytes(closed_prefix)
            control_path = root / "control.sqlite3"
            adapter_path = root / "adapter.sqlite3"
            before = {
                path: path.read_bytes()
                for path in (audit_path, control_path, adapter_path)
            }

            with self.assertRaises(ControlLedgerError) as raised:
                new_harness(
                    now=now,
                    audit_path=audit_path,
                    control_ledger_path=control_path,
                    synthetic_adapter_path=adapter_path,
                )
            self.assertEqual(raised.exception.reason_code, "AUDIT_CONTINUITY_REQUIRED")
            self.assertEqual({path: path.read_bytes() for path in before}, before)

    def test_post_construction_audit_delete_or_regular_replacement_fails_before_effect(
        self,
    ) -> None:
        for replacement in ("missing", "empty"):
            with (
                self.subTest(replacement=replacement),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                harness, _raw = self._completed_case(
                    root,
                    request_id=f"P3-STAGE-A-AUDIT-RUNTIME-{replacement.upper()}",
                )
                audit_path = root / "audit.jsonl"
                adapter = harness.firewall._adapter_store
                assert adapter is not None
                before_receipts = adapter.receipt_count()
                before_state = adapter.observe("WORKSTATION_042")
                audit_path.unlink()
                if replacement == "empty":
                    audit_path.touch(mode=0o600)
                    audit_path.chmod(0o600)

                raw = request_json(
                    workstation_case(
                        harness,
                        request_id=f"P3-STAGE-A-AUDIT-NEXT-{replacement.upper()}",
                    )
                )
                with self.assertRaises(RuntimeError):
                    harness.firewall.process_json(
                        raw, credential=harness.soc_credential
                    )
                self.assertEqual(adapter.receipt_count(), before_receipts)
                self.assertEqual(adapter.observe("WORKSTATION_042"), before_state)
                self.assertEqual(audit_path.exists(), replacement == "empty")

    def test_post_construction_main_store_replacement_fails_before_audit_or_effect(
        self,
    ) -> None:
        cases = (
            (
                "control.sqlite3",
                ControlLedgerError,
                "CONTROL_LEDGER_IDENTITY_CHANGED",
            ),
            (
                "adapter.sqlite3",
                SyntheticAdapterError,
                "SYNTHETIC_ADAPTER_IDENTITY_CHANGED",
            ),
        )
        for name, error_type, reason_code in cases:
            with self.subTest(store=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                harness = new_harness(
                    audit_path=root / "audit.jsonl",
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
                audit_path = root / "audit.jsonl"
                audit_before = audit_path.read_bytes()
                target = root / name
                replacement = root / f"replacement-{name}"
                shutil.copyfile(target, replacement)
                replacement.chmod(0o600)
                os.replace(replacement, target)
                target_before = target.read_bytes()
                raw = request_json(
                    workstation_case(
                        harness,
                        request_id=f"P3-STAGE-A-RUNTIME-{name.upper()}",
                    )
                )

                with self.assertRaises(error_type) as raised:
                    harness.firewall.process_json(
                        raw, credential=harness.soc_credential
                    )
                self.assertEqual(raised.exception.reason_code, reason_code)
                self.assertEqual(audit_path.read_bytes(), audit_before)
                self.assertEqual(target.read_bytes(), target_before)

    def test_hash_valid_audit_rejects_same_ledger_historical_control_rollback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            audit_path = root / "audit.jsonl"
            control_path = root / "control.sqlite3"
            adapter_path = root / "adapter.sqlite3"
            harness = new_harness(
                audit_path=audit_path,
                control_ledger_path=control_path,
                synthetic_adapter_path=adapter_path,
            )
            empty_backup = root / "empty-control.sqlite3"
            with (
                closing(sqlite3.connect(control_path)) as source,
                closing(sqlite3.connect(empty_backup)) as destination,
            ):
                source.backup(destination)
            empty_backup.chmod(0o600)

            raw = request_json(
                domain_controller_case(
                    harness,
                    request_id="P3-STAGE-A-SAME-LEDGER-ROLLBACK",
                )
            )
            result = harness.firewall.process_json(
                raw, credential=harness.soc_credential
            )
            self.assertIn(result.decision.outcome, {"DENY", "ESCALATE"})
            audit_before = audit_path.read_bytes()
            self.assertTrue(audit_before)

            os.replace(empty_backup, control_path)
            for suffix in ("-wal", "-shm", "-journal"):
                Path(f"{control_path}{suffix}").unlink(missing_ok=True)
            control_before = control_path.read_bytes()
            adapter_before = adapter_path.read_bytes()

            with self.assertRaises(ControlLedgerError) as raised:
                new_harness(
                    audit_path=audit_path,
                    control_ledger_path=control_path,
                    synthetic_adapter_path=adapter_path,
                )
            self.assertEqual(raised.exception.reason_code, "AUDIT_CONTINUITY_REQUIRED")
            self.assertEqual(audit_path.read_bytes(), audit_before)
            self.assertEqual(control_path.read_bytes(), control_before)
            self.assertEqual(adapter_path.read_bytes(), adapter_before)

    def test_nonempty_audit_cannot_initialize_missing_peer_stores(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.mkdir()
            harness = new_harness(
                audit_path=source / "audit.jsonl",
                control_ledger_path=source / "control.sqlite3",
                synthetic_adapter_path=source / "adapter.sqlite3",
            )
            raw = request_json(
                domain_controller_case(
                    harness,
                    request_id="P3-STAGE-A-ORPHAN-AUDIT",
                )
            )
            harness.firewall.process_json(raw, credential=harness.soc_credential)

            orphan = root / "orphan"
            orphan.mkdir()
            orphan_audit = orphan / "audit.jsonl"
            shutil.copyfile(source / "audit.jsonl", orphan_audit)
            orphan_audit.chmod(0o600)
            with self.assertRaises(ControlLedgerError) as raised:
                new_harness(
                    audit_path=orphan_audit,
                    control_ledger_path=orphan / "control.sqlite3",
                    synthetic_adapter_path=orphan / "adapter.sqlite3",
                )
            self.assertEqual(raised.exception.reason_code, "AUDIT_CONTINUITY_REQUIRED")
            self.assertFalse((orphan / "control.sqlite3").exists())
            self.assertFalse((orphan / "adapter.sqlite3").exists())

    def test_lookup_never_recreates_a_missing_established_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness, raw = self._completed_case(
                root, request_id="P3-STAGE-A-AUDIT-LOOKUP"
            )
            audit_path = root / "audit.jsonl"
            audit_path.unlink()

            with self.assertRaises(RuntimeError):
                harness.firewall.lookup_request_result(
                    raw, credential=harness.soc_credential
                )
            self.assertFalse(audit_path.exists())

    def test_audit_file_lock_timeout_fails_closed_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = new_harness(
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                control_ledger_busy_timeout_ms=100,
                synthetic_adapter_path=root / "adapter.sqlite3",
                synthetic_adapter_busy_timeout_ms=100,
            )
            raw = request_json(
                workstation_case(harness, request_id="P3-STAGE-A-AUDIT-LOCK")
            )
            paths = (
                root / "audit.jsonl",
                root / "control.sqlite3",
                root / "adapter.sqlite3",
            )
            before = {path: path.read_bytes() for path in paths}
            context = multiprocessing.get_context("spawn")
            ready = context.Event()
            release = context.Event()
            holder = context.Process(
                target=_hold_audit_file_lock,
                args=(str(root / "audit.jsonl"), ready, release),
            )
            holder.start()
            self.assertTrue(ready.wait(timeout=10))
            started = monotonic()
            try:
                with self.assertRaises(ControlLedgerError) as raised:
                    harness.firewall.process_json(
                        raw, credential=harness.soc_credential
                    )
                elapsed = monotonic() - started
                self.assertEqual(raised.exception.reason_code, "DURABLE_AUDIT_BUSY")
                self.assertLess(elapsed, 1.0)
                self.assertEqual({path: path.read_bytes() for path in paths}, before)
                self.assertEqual(harness.firewall._adapter_store.receipt_count(), 0)
            finally:
                release.set()
                holder.join(timeout=10)
                if holder.is_alive():  # pragma: no cover - bounded cleanup
                    holder.terminate()
                    holder.join(timeout=5)
            self.assertEqual(holder.exitcode, 0)

    def test_locked_audit_path_swap_is_detected_before_control_or_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = new_harness(
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            audit_path = root / "audit.jsonl"
            detached = root / "detached-audit.jsonl"
            raw = request_json(
                workstation_case(harness, request_id="P3-STAGE-A-AUDIT-SWAP")
            )
            original_append = AuditLogger.append
            swapped = False

            def replace_before_append(
                logger: AuditLogger,
                record_type: str,
                payload: dict[str, object],
            ) -> dict[str, object]:
                nonlocal swapped
                if not swapped:
                    audit_path.rename(detached)
                    audit_path.touch(mode=0o600)
                    audit_path.chmod(0o600)
                    swapped = True
                return original_append(logger, record_type, payload)

            control_before = (root / "control.sqlite3").read_bytes()
            adapter_before = (root / "adapter.sqlite3").read_bytes()
            with patch.object(AuditLogger, "append", replace_before_append):
                with self.assertRaises(RuntimeError):
                    harness.firewall.process_json(
                        raw, credential=harness.soc_credential
                    )
            self.assertTrue(swapped)
            self.assertEqual(audit_path.read_bytes(), b"")
            self.assertEqual(detached.read_bytes(), b"")
            self.assertEqual((root / "control.sqlite3").read_bytes(), control_before)
            self.assertEqual((root / "adapter.sqlite3").read_bytes(), adapter_before)
            self.assertEqual(harness.firewall._adapter_store.receipt_count(), 0)

    def test_brand_new_empty_durable_set_starts_with_bound_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = new_harness(
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            audit_path = root / "audit.jsonl"
            self.assertTrue(audit_path.is_file())
            self.assertEqual(audit_path.read_bytes(), b"")
            self.assertEqual(harness.firewall._control_ledger.pending_outbox(), ())
            self.assertEqual(harness.firewall._adapter_store.receipt_count(), 0)

    def test_unbound_durable_authority_cannot_hide_behind_an_empty_audit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = new_harness(
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            harness.firewall._control_ledger.register(
                "AUTH-UNBOUND-AUDIT",
                verification_id="VERIFY-UNBOUND-AUDIT",
                decision_id="DECISION-UNBOUND-AUDIT",
            )
            self.assertEqual((root / "audit.jsonl").read_bytes(), b"")

            with self.assertRaises(ControlLedgerError) as raised:
                new_harness(
                    audit_path=root / "audit.jsonl",
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
            self.assertEqual(raised.exception.reason_code, "AUDIT_CONTINUITY_REQUIRED")

    def test_permissive_authoritative_artifacts_are_rejected_without_repair(
        self,
    ) -> None:
        names = ("audit.jsonl", "control.sqlite3", "adapter.sqlite3")
        for name in names:
            with self.subTest(path=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                new_harness(
                    audit_path=root / "audit.jsonl",
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
                target = root / name
                target.chmod(0o666)
                before = {
                    path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                    for path in (root / item for item in names)
                }

                with self.assertRaises(ValueError):
                    new_harness(
                        audit_path=root / "audit.jsonl",
                        control_ledger_path=root / "control.sqlite3",
                        synthetic_adapter_path=root / "adapter.sqlite3",
                    )
                after = {
                    path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                    for path in (root / item for item in names)
                }
                self.assertEqual(after, before)

    def test_restart_lookup_is_sanitized_and_duplicate_does_no_new_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            first = new_harness(
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            raw = request_json(
                workstation_case(first, request_id="P3-STAGE-A-RESULT-REPLAY")
            )
            result = first.firewall.process_json(raw, credential=first.soc_credential)
            self.assertEqual(result.decision.outcome, "ALLOW")
            self.assertIsNotNone(result.verification)
            assert result.verification is not None
            self.assertEqual(result.verification.status, "VERIFIED")

            first_lookup = first.firewall.lookup_request_result(
                raw, credential=first.soc_credential
            )
            self.assertIsNotNone(first_lookup)
            assert first_lookup is not None
            self.assertEqual(first_lookup.disposition, "COMPLETED_VERIFIED")
            self.assertTrue(first_lookup.replayed)
            self.assertFalse(first_lookup.execution_attempted_this_call)
            self.assertFalse(first_lookup.new_decision)
            self.assertFalse(first_lookup.new_authorization)
            self.assertFalse(first_lookup.new_effect)
            self.assertIsNone(first_lookup.authorization)
            _assert_no_authority_material(self, first_lookup.to_dict())

            reopened = new_harness(
                now=first.clock(),
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            before_state = reopened.firewall.observer.observe("WORKSTATION_042")
            receipt_count = reopened.firewall._adapter_store.receipt_count()
            outbox_count = len(reopened.firewall._control_ledger.pending_outbox())
            replay = reopened.firewall.lookup_request_result(
                raw, credential=reopened.soc_credential
            )
            self.assertEqual(replay, first_lookup)

            duplicate = reopened.firewall.process_json(
                raw, credential=reopened.soc_credential
            )
            self.assertEqual(duplicate.decision.outcome, "DENY")
            self.assertIn("DUPLICATE_REQUEST", duplicate.decision.reason_codes)
            self.assertIsNone(duplicate.authorization)
            self.assertIsNone(duplicate.broker_result)
            self.assertEqual(
                reopened.firewall._adapter_store.receipt_count(), receipt_count
            )
            self.assertEqual(
                reopened.firewall.observer.observe("WORKSTATION_042"), before_state
            )
            # Duplicate process_json has a JSONL denial lifecycle but no new
            # authority transition or result write in the control outbox.
            self.assertEqual(
                len(reopened.firewall._control_ledger.pending_outbox()), outbox_count
            )

    def test_durable_adapter_requires_all_three_distinct_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            with self.assertRaises(ValueError):
                new_harness(
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
            self.assertFalse((root / "control.sqlite3").exists())
            self.assertFalse((root / "adapter.sqlite3").exists())

    def test_all_artifacts_preflight_before_creation_and_reserve_sqlite_sidecars(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            invalid_adapter = root / "invalid-adapter.sqlite3"
            with closing(sqlite3.connect(invalid_adapter)) as connection:
                connection.execute(
                    "CREATE TABLE metadata(key TEXT PRIMARY KEY, value TEXT)"
                )
                connection.execute(
                    "INSERT INTO metadata(key, value) VALUES('schema_version', '1')"
                )
                connection.commit()
            invalid_adapter.chmod(0o600)

            new_parent = root / "must-not-be-created"
            with self.assertRaises(SyntheticAdapterError) as invalid:
                new_harness(
                    audit_path=new_parent / "audit.jsonl",
                    control_ledger_path=new_parent / "control.sqlite3",
                    synthetic_adapter_path=invalid_adapter,
                )
            self.assertEqual(
                invalid.exception.reason_code,
                "SYNTHETIC_ADAPTER_SCHEMA_UNSUPPORTED",
            )
            self.assertFalse(new_parent.exists())

            existing_control = root / "existing-control.sqlite3"
            existing_audit = root / "existing-audit.jsonl"
            new_harness(
                audit_path=existing_audit,
                control_ledger_path=existing_control,
                synthetic_adapter_path=root / "existing-adapter.sqlite3",
            )
            os.chmod(existing_control, 0o644)
            control_bytes_before = existing_control.read_bytes()
            control_mode_before = existing_control.stat().st_mode & 0o777
            control_mtime_before = existing_control.stat().st_mtime_ns
            control_sidecars = tuple(
                Path(f"{existing_control}{suffix}")
                for suffix in ("-wal", "-shm", "-journal")
            )
            sidecar_presence_before = tuple(
                sidecar.exists() for sidecar in control_sidecars
            )
            directory_entries_before = {child.name for child in root.iterdir()}
            with self.assertRaises(ValueError):
                new_harness(
                    audit_path=existing_audit,
                    control_ledger_path=existing_control,
                    synthetic_adapter_path=invalid_adapter,
                )
            self.assertEqual(existing_control.read_bytes(), control_bytes_before)
            self.assertEqual(
                existing_control.stat().st_mode & 0o777,
                control_mode_before,
            )
            self.assertEqual(
                existing_control.stat().st_mtime_ns,
                control_mtime_before,
            )
            self.assertEqual(
                tuple(sidecar.exists() for sidecar in control_sidecars),
                sidecar_presence_before,
            )
            self.assertEqual(
                {child.name for child in root.iterdir()},
                directory_entries_before,
            )

            control_path = root / "sidecar-control.sqlite3"
            with self.assertRaises(ValueError):
                new_harness(
                    audit_path=Path(f"{control_path}-wal"),
                    control_ledger_path=control_path,
                    synthetic_adapter_path=root / "sidecar-adapter.sqlite3",
                )
            self.assertFalse(control_path.exists())
            self.assertFalse(Path(f"{control_path}-wal").exists())
            self.assertFalse((root / "sidecar-adapter.sqlite3").exists())

            ancestor = root / "state-file"
            with self.assertRaises(ValueError):
                new_harness(
                    audit_path=ancestor / "audit.jsonl",
                    control_ledger_path=ancestor,
                    synthetic_adapter_path=root / "ancestor-adapter.sqlite3",
                )
            self.assertFalse(ancestor.exists())
            self.assertFalse((root / "ancestor-adapter.sqlite3").exists())

    def test_independent_processes_create_one_effect_receipt_and_terminal_result(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            seed = new_harness()
            now = seed.clock()
            raw = request_json(
                workstation_case(seed, request_id="P3-STAGE-A-PROCESS-RACE")
            )
            # Pre-create both shared SQLite contracts so this test isolates the
            # processing race from first-time schema creation.
            new_harness(
                now=now,
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )

            context = multiprocessing.get_context("spawn")
            barrier = context.Barrier(2)
            results = context.Queue()
            processes = [
                context.Process(
                    target=_concurrent_request_worker,
                    args=(
                        str(root),
                        raw,
                        now.isoformat(),
                        str(index),
                        barrier,
                        results,
                    ),
                )
                for index in range(2)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(timeout=30)
                if process.is_alive():  # pragma: no cover - bounded hang cleanup
                    process.terminate()
                    process.join(timeout=5)
                    self.fail("Concurrent Stage A worker exceeded the time bound.")
                self.assertEqual(process.exitcode, 0)
            observed: list[tuple[object, ...]] = []
            for _ in processes:
                try:
                    observed.append(results.get(timeout=5))
                except queue.Empty:
                    self.fail("Concurrent Stage A worker returned no result.")
            results.close()
            results.join_thread()

            self.assertTrue(all(row[0] == "OK" for row in observed), observed)
            self.assertEqual(sorted(row[1] for row in observed), ["ALLOW", "DENY"])
            self.assertEqual(sum(bool(row[2]) for row in observed), 1)
            self.assertEqual(sum(row[3] == "VERIFIED" for row in observed), 1)

            reopened = new_harness(
                now=now,
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            lookup = reopened.firewall.lookup_request_result(
                raw, credential=reopened.soc_credential
            )
            self.assertIsNotNone(lookup)
            assert lookup is not None
            self.assertEqual(lookup.disposition, "COMPLETED_VERIFIED")
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 1)
            self.assertEqual(
                reopened.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "isolated",
            )

    def test_sqlite_sidecar_symlinks_fail_closed_without_touching_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            audit_path = root / "audit.jsonl"
            control_path = root / "control.sqlite3"
            adapter_path = root / "adapter.sqlite3"
            new_harness(
                audit_path=audit_path,
                control_ledger_path=control_path,
                synthetic_adapter_path=adapter_path,
            )
            protected = root / "protected.bin"
            protected.write_bytes(b"must remain unchanged")

            control_wal = Path(f"{control_path}-wal")
            control_wal.symlink_to(protected)
            with self.assertRaises(ControlLedgerError) as control_unsafe:
                new_harness(
                    audit_path=audit_path,
                    control_ledger_path=control_path,
                    synthetic_adapter_path=adapter_path,
                )
            self.assertEqual(
                control_unsafe.exception.reason_code,
                "CONTROL_LEDGER_PATH_UNSAFE",
            )
            self.assertEqual(protected.read_bytes(), b"must remain unchanged")
            control_wal.unlink()

            adapter_wal = Path(f"{adapter_path}-wal")
            adapter_wal.symlink_to(protected)
            with self.assertRaises(SyntheticAdapterError) as adapter_unsafe:
                new_harness(
                    audit_path=audit_path,
                    control_ledger_path=control_path,
                    synthetic_adapter_path=adapter_path,
                )
            self.assertEqual(
                adapter_unsafe.exception.reason_code,
                "SYNTHETIC_ADAPTER_PATH_UNSAFE",
            )
            self.assertEqual(protected.read_bytes(), b"must remain unchanged")

    def test_post_construction_audit_replacement_fails_before_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            audit_path = root / "audit.jsonl"
            harness = new_harness(
                audit_path=audit_path,
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            raw = request_json(
                workstation_case(harness, request_id="P3-STAGE-A-AUDIT-REPLACEMENT")
            )
            protected = root / "protected-audit-target.bin"
            protected.write_bytes(b"must remain unchanged")
            audit_path.unlink()
            audit_path.symlink_to(protected)

            with self.assertRaises(RuntimeError):
                harness.firewall.process_json(raw, credential=harness.soc_credential)
            self.assertEqual(protected.read_bytes(), b"must remain unchanged")
            self.assertEqual(harness.firewall._adapter_store.receipt_count(), 0)
            self.assertEqual(
                harness.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "connected",
            )

    def test_lookup_conflict_and_wrong_principal_disclose_no_prior_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = new_harness(
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            value = workstation_case(
                harness, request_id="P3-STAGE-A-LOOKUP-NONDISCLOSURE"
            )
            raw = request_json(value)
            harness.firewall.process_json(raw, credential=harness.soc_credential)
            receipt_count = harness.firewall._adapter_store.receipt_count()

            changed = json.loads(raw)
            changed["action"]["parameters"]["duration_seconds"] += 1
            with self.assertRaises(ControlLedgerError) as conflict:
                harness.firewall.lookup_request_result(
                    request_json(changed), credential=harness.soc_credential
                )
            self.assertEqual(conflict.exception.reason_code, "REQUEST_ID_CONFLICT")

            with self.assertRaises(ControlLedgerError) as wrong_principal:
                harness.firewall.lookup_request_result(
                    raw, credential=harness.human_credential
                )
            self.assertEqual(
                wrong_principal.exception.reason_code,
                "REQUEST_LOOKUP_AUTHENTICATION_FAILED",
            )
            self.assertEqual(
                harness.firewall._adapter_store.receipt_count(), receipt_count
            )

    def test_process_kill_before_adapter_becomes_terminal_unknown_without_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            seed = new_harness()
            now = seed.clock()
            raw = request_json(
                workstation_case(seed, request_id="P3-STAGE-A-KILL-BEFORE-T2")
            )
            self._run_crash(
                root,
                raw_request=raw,
                now=now,
                boundary="before_adapter",
            )

            reopened = new_harness(
                now=now,
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            self.assertEqual(
                reopened.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "connected",
            )
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 0)
            with self.assertRaises(ControlLedgerError) as not_quiesced:
                reopened.firewall.reconcile_request(
                    raw,
                    credential=reopened.soc_credential,
                    operator_asserted_quiesced=False,
                )
            self.assertEqual(
                not_quiesced.exception.reason_code, "RECOVERY_QUIESCENCE_REQUIRED"
            )

            recovered = reopened.firewall.reconcile_request(
                raw,
                credential=reopened.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered.disposition, "UNKNOWN_EFFECT")
            self.assertTrue(recovered.recovery_required)
            self.assertIsNone(recovered.adapter_receipt_sha256)
            self.assertFalse(recovered.new_effect)
            outbox_count = len(reopened.firewall._control_ledger.pending_outbox())
            repeated = reopened.firewall.reconcile_request(
                raw,
                credential=reopened.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertEqual(repeated, recovered)
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 0)
            self.assertEqual(
                len(reopened.firewall._control_ledger.pending_outbox()), outbox_count
            )

    def test_process_kill_after_applied_receipt_recovers_unknown_without_reinvoke(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            seed = new_harness()
            now = seed.clock()
            raw = request_json(
                workstation_case(seed, request_id="P3-STAGE-A-KILL-AFTER-T2")
            )
            self._run_crash(
                root,
                raw_request=raw,
                now=now,
                boundary="after_adapter_commit",
            )

            reopened = new_harness(
                now=now,
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 1)
            self.assertEqual(
                reopened.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "isolated",
            )
            recovered = reopened.firewall.reconcile_request(
                raw,
                credential=reopened.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered.disposition, "UNKNOWN_EFFECT")
            self.assertTrue(recovered.recovery_required)
            self.assertIsNotNone(recovered.adapter_receipt_sha256)
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 1)
            snapshot = reopened.firewall._control_ledger.attempt_snapshot(
                recovered.attempt_id
            )
            self.assertIsNotNone(snapshot)
            assert snapshot is not None
            self.assertEqual(snapshot["state"], "UNKNOWN_EFFECT")
            self.assertIn(
                "ORIGINAL_EXECUTION_AUDIT_INCOMPLETE",
                recovered.reason_codes,
            )
            self._assert_closed_recovery_audit(
                root / "audit.jsonl",
                disposition="UNKNOWN_EFFECT",
                original_lifecycle_valid=False,
            )

    def test_process_kill_after_affirmative_no_effect_receipt_recovers_failed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            faults = {"WORKSTATION_042": "FAILED"}
            seed = new_harness(fault_modes=faults)
            now = seed.clock()
            raw = request_json(
                workstation_case(seed, request_id="P3-STAGE-A-KILL-NO-EFFECT")
            )
            self._run_crash(
                root,
                raw_request=raw,
                now=now,
                boundary="after_adapter_commit",
                fault_mode="FAILED",
            )

            reopened = new_harness(
                now=now,
                fault_modes=faults,
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            self.assertEqual(
                reopened.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "connected",
            )
            recovered = reopened.firewall.reconcile_request(
                raw,
                credential=reopened.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered.disposition, "FAILED_NO_EFFECT")
            self.assertFalse(recovered.recovery_required)
            self.assertIsNotNone(recovered.adapter_receipt_sha256)
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 1)
            self.assertIn(
                "ORIGINAL_EXECUTION_AUDIT_INCOMPLETE",
                recovered.reason_codes,
            )
            self._assert_closed_recovery_audit(
                root / "audit.jsonl",
                disposition="FAILED_NO_EFFECT",
                original_lifecycle_valid=False,
            )

    def test_recovery_audit_prefix_is_restart_idempotent_at_every_record(self) -> None:
        boundaries = (
            ("RECOVERY_STARTED", 81),
            ("RECOVERY_EVIDENCE_ASSESSED", 82),
            ("RECOVERY_FINALIZED", 83),
        )
        for record_type, exit_code in boundaries:
            with (
                self.subTest(record_type=record_type),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                seed = new_harness()
                now = seed.clock()
                raw = request_json(
                    workstation_case(
                        seed,
                        request_id=f"P3-STAGE-A-RECOVERY-PREFIX-{exit_code}",
                    )
                )
                self._run_crash(
                    root,
                    raw_request=raw,
                    now=now,
                    boundary="before_adapter",
                )

                context = multiprocessing.get_context("spawn")
                process = context.Process(
                    target=_crash_after_recovery_audit_record,
                    args=(
                        str(root),
                        raw,
                        now.isoformat(),
                        record_type,
                        exit_code,
                    ),
                )
                process.start()
                process.join(timeout=30)
                if process.is_alive():  # pragma: no cover - bounded cleanup
                    process.terminate()
                    process.join(timeout=5)
                    self.fail("Recovery-audit crash worker exceeded its bound.")
                self.assertEqual(process.exitcode, exit_code)

                reopened = new_harness(
                    now=now,
                    audit_path=root / "audit.jsonl",
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
                recovered = reopened.firewall.reconcile_request(
                    raw,
                    credential=reopened.soc_credential,
                    operator_asserted_quiesced=True,
                )
                self.assertIsNotNone(recovered)
                assert recovered is not None
                self.assertEqual(recovered.disposition, "UNKNOWN_EFFECT")
                self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 0)
                self.assertEqual(
                    reopened.firewall.observer.observe("WORKSTATION_042")[
                        "network_state"
                    ],
                    "connected",
                )
                rows = AuditLogger(root / "audit.jsonl").read_all()
                for expected_type, _expected_code in boundaries:
                    self.assertEqual(
                        sum(row["record_type"] == expected_type for row in rows),
                        1,
                    )
                self._assert_closed_recovery_audit(
                    root / "audit.jsonl",
                    disposition="UNKNOWN_EFFECT",
                    original_lifecycle_valid=False,
                )

    def test_closed_original_audit_before_lost_t3_recovers_without_reinvocation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            seed = new_harness()
            now = seed.clock()
            raw = request_json(
                workstation_case(
                    seed,
                    request_id="P3-STAGE-A-CLOSED-AUDIT-LOST-T3",
                )
            )
            context = multiprocessing.get_context("spawn")
            process = context.Process(
                target=_crash_after_closed_audit_before_terminal_commit,
                args=(str(root), raw, now.isoformat()),
            )
            process.start()
            process.join(timeout=30)
            if process.is_alive():  # pragma: no cover - bounded cleanup
                process.terminate()
                process.join(timeout=5)
                self.fail("T3 crash worker exceeded its bound.")
            self.assertEqual(process.exitcode, 84)

            audit_path = root / "audit.jsonl"
            original_rows = AuditLogger(audit_path).read_all()
            lifecycle_valid, lifecycle_errors = validate_phase3_lifecycle(original_rows)
            self.assertTrue(lifecycle_valid, lifecycle_errors)

            reopened = new_harness(
                now=now,
                audit_path=audit_path,
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 1)
            audit_before_fence = audit_path.read_bytes()
            with self.assertRaises(ControlLedgerError) as fenced:
                reopened.firewall.process_json("{}", credential=reopened.soc_credential)
            self.assertEqual(fenced.exception.reason_code, "AUDIT_CONTINUITY_REQUIRED")
            self.assertEqual(audit_path.read_bytes(), audit_before_fence)
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 1)
            recovered = reopened.firewall.reconcile_request(
                raw,
                credential=reopened.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered.disposition, "UNKNOWN_EFFECT")
            self.assertTrue(recovered.recovery_required)
            self.assertIn(
                "ORIGINAL_EXECUTION_AUDIT_COMPLETE",
                recovered.reason_codes,
            )
            self.assertNotIn(
                "ORIGINAL_EXECUTION_AUDIT_INCOMPLETE",
                recovered.reason_codes,
            )
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 1)
            self.assertEqual(
                reopened.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "isolated",
            )
            self._assert_closed_recovery_audit(
                audit_path,
                disposition="UNKNOWN_EFFECT",
                original_lifecycle_valid=True,
            )

    def test_pending_recovery_fences_request_and_approval_audit_writers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            audit_path = root / "audit.jsonl"
            control_path = root / "control.sqlite3"
            adapter_path = root / "adapter.sqlite3"
            harness = new_harness(
                audit_path=audit_path,
                control_ledger_path=control_path,
                synthetic_adapter_path=adapter_path,
            )
            approval_result = harness.firewall.process_json(
                request_json(
                    domain_controller_case(
                        harness,
                        request_id="P3-STAGE-A-APPROVAL-BEFORE-RECOVERY",
                    )
                ),
                credential=harness.soc_credential,
            )
            requirement = approval_result.decision.approval_requirement
            self.assertIsNotNone(requirement)
            assert requirement is not None

            now = harness.clock()
            raw = request_json(
                workstation_case(
                    harness,
                    request_id="P3-STAGE-A-PENDING-RECOVERY-FENCE",
                )
            )
            self._run_crash(
                root,
                raw_request=raw,
                now=now,
                boundary="before_adapter",
            )
            context = multiprocessing.get_context("spawn")
            process = context.Process(
                target=_crash_after_recovery_audit_record,
                args=(
                    str(root),
                    raw,
                    now.isoformat(),
                    "RECOVERY_FINALIZED",
                    85,
                ),
            )
            process.start()
            process.join(timeout=30)
            if process.is_alive():  # pragma: no cover - bounded cleanup
                process.terminate()
                process.join(timeout=5)
                self.fail("Recovery fence worker exceeded its bound.")
            self.assertEqual(process.exitcode, 85)

            reopened = new_harness(
                now=now,
                audit_path=audit_path,
                control_ledger_path=control_path,
                synthetic_adapter_path=adapter_path,
            )
            audit_before = audit_path.read_bytes()
            with self.assertRaises(ControlLedgerError) as request_blocked:
                reopened.firewall.process_json("{}", credential=reopened.soc_credential)
            self.assertEqual(
                request_blocked.exception.reason_code,
                "RECOVERY_AUDIT_PENDING",
            )
            with self.assertRaises(ControlLedgerError) as approval_blocked:
                reopened.firewall.approve_for_reevaluation(
                    requirement=requirement,
                    credential=reopened.human_credential,
                    action_type=requirement.action_type,
                    target_id=requirement.target_id,
                    parameters={
                        "duration_seconds": 900,
                        "preserve_management": True,
                    },
                    evidence_sha256=requirement.evidence_sha256,
                )
            self.assertEqual(
                approval_blocked.exception.reason_code,
                "RECOVERY_AUDIT_PENDING",
            )
            self.assertEqual(audit_path.read_bytes(), audit_before)
            self.assertEqual(reopened.firewall._adapter_store.receipt_count(), 0)

            recovered = reopened.firewall.reconcile_request(
                raw,
                credential=reopened.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered.disposition, "UNKNOWN_EFFECT")
            # The exact recovery trio was already durable before the crash;
            # retry commits T3 without duplicating or rewriting audit rows.
            self.assertEqual(audit_path.read_bytes(), audit_before)
            after_commit = reopened.firewall.process_json(
                "{}", credential=reopened.soc_credential
            )
            self.assertEqual(after_commit.decision.outcome, "DENY")
            self.assertNotEqual(audit_path.read_bytes(), audit_before)

    def test_corrupt_receipt_halts_reconciliation_without_state_transition(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            seed = new_harness()
            now = seed.clock()
            raw = request_json(
                workstation_case(seed, request_id="P3-STAGE-A-CORRUPT-RECEIPT")
            )
            self._run_crash(
                root,
                raw_request=raw,
                now=now,
                boundary="after_adapter_commit",
            )
            reopened = new_harness(
                now=now,
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            request_sha256 = load_decision_request_json(raw, now=now).request_sha256()
            principal_id = json.loads(raw)["agent"]["id"]
            control = reopened.firewall._control_ledger
            before = control.request_snapshot(
                principal_id,
                "P3-STAGE-A-CORRUPT-RECEIPT",
                request_sha256,
            )
            self.assertIsNotNone(before)
            assert before is not None
            self.assertEqual(before["state"], "ATTEMPT_RESERVED")
            with closing(sqlite3.connect(root / "adapter.sqlite3")) as connection:
                connection.execute("UPDATE command_receipts SET receipt_json='{}'")
                connection.commit()

            with self.assertRaises(SyntheticAdapterError) as corrupt:
                reopened.firewall.reconcile_request(
                    raw,
                    credential=reopened.soc_credential,
                    operator_asserted_quiesced=True,
                )
            self.assertEqual(corrupt.exception.reason_code, "SYNTHETIC_ADAPTER_CORRUPT")
            after = control.request_snapshot(
                principal_id,
                "P3-STAGE-A-CORRUPT-RECEIPT",
                request_sha256,
            )
            self.assertEqual(after, before)
            with self.assertRaises(SyntheticAdapterError) as lookup_corrupt:
                reopened.firewall.lookup_request_result(
                    raw, credential=reopened.soc_credential
                )
            self.assertEqual(
                lookup_corrupt.exception.reason_code, "SYNTHETIC_ADAPTER_CORRUPT"
            )

    def test_fk_clean_impossible_control_history_fails_closed_on_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            control_path = root / "control.sqlite3"
            adapter_path = root / "adapter.sqlite3"
            audit_path = root / "audit.jsonl"
            harness = new_harness(
                audit_path=audit_path,
                control_ledger_path=control_path,
                synthetic_adapter_path=adapter_path,
            )
            raw = request_json(
                workstation_case(harness, request_id="P3-STAGE-A-IMPOSSIBLE-HISTORY")
            )
            completed = harness.firewall.process_json(
                raw, credential=harness.soc_credential
            )
            self.assertEqual(completed.verification.status, "VERIFIED")
            self.assertEqual(
                harness.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "isolated",
            )

            with closing(sqlite3.connect(control_path)) as connection:
                connection.execute("PRAGMA foreign_keys=ON")
                connection.execute("DELETE FROM request_results")
                connection.execute("DELETE FROM attempts")
                connection.execute("DELETE FROM authorizations")
                connection.execute("UPDATE requests SET state='AUTHORIZED'")
                connection.commit()
                self.assertIsNone(
                    connection.execute("PRAGMA foreign_key_check").fetchone()
                )

            with self.assertRaises(ControlLedgerError) as corrupt:
                new_harness(
                    audit_path=audit_path,
                    control_ledger_path=control_path,
                    synthetic_adapter_path=adapter_path,
                )
            self.assertEqual(
                corrupt.exception.reason_code,
                "CONTROL_LEDGER_CORRUPT",
            )
            self.assertEqual(harness.firewall._adapter_store.receipt_count(), 1)
            self.assertEqual(
                harness.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "isolated",
            )

    def test_adapter_exact_retry_ignores_new_correlation_but_changed_binding_conflicts(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = new_harness(
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            raw = request_json(
                workstation_case(harness, request_id="P3-STAGE-A-ADAPTER-RETRY")
            )
            result = harness.firewall.process_json(
                raw, credential=harness.soc_credential
            )
            self.assertIsNotNone(result.broker_result)
            assert result.broker_result is not None
            adapter = harness.firewall._adapter_store
            with closing(sqlite3.connect(root / "adapter.sqlite3")) as connection:
                row = connection.execute(
                    "SELECT idempotency_key, binding_json FROM command_receipts"
                ).fetchone()
            assert row is not None
            idempotency_key, binding_json = row
            binding = json.loads(binding_json)
            original = adapter.receipt(idempotency_key)
            self.assertIsNotNone(original)
            assert original is not None
            state_before_retry = adapter.observe("WORKSTATION_042")

            repeated = adapter.execute_once(
                idempotency_key=idempotency_key,
                binding=binding,
                attempt_id=original.attempt_id,
                attempted_at=original.attempted_at,
            )
            self.assertEqual(repeated, original)
            self.assertEqual(adapter.receipt_count(), 1)
            self.assertEqual(adapter.observe("WORKSTATION_042"), state_before_retry)

            different_correlation = adapter.execute_once(
                idempotency_key=idempotency_key,
                binding=binding,
                attempt_id="attempt-different-correlation",
                attempted_at=original.attempted_at,
            )
            self.assertEqual(different_correlation, original)
            self.assertEqual(different_correlation.attempt_id, original.attempt_id)
            self.assertEqual(adapter.receipt_count(), 1)
            self.assertEqual(adapter.observe("WORKSTATION_042"), state_before_retry)
            changed_binding = json.loads(binding_json)
            changed_binding["policy_version"] += "-changed"
            with self.assertRaises(SyntheticAdapterError) as changed_command:
                adapter.execute_once(
                    idempotency_key=idempotency_key,
                    binding=changed_binding,
                    attempt_id=original.attempt_id,
                    attempted_at=original.attempted_at,
                )
            self.assertEqual(
                changed_command.exception.reason_code,
                "SYNTHETIC_ADAPTER_IDEMPOTENCY_CONFLICT",
            )
            self.assertEqual(adapter.receipt_count(), 1)
            self.assertEqual(adapter.observe("WORKSTATION_042"), state_before_retry)


if __name__ == "__main__":
    unittest.main()
