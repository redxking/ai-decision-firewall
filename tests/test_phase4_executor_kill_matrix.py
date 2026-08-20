from __future__ import annotations

import json
import os
import select
import signal
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from adf_poc.lab_contracts import COMMAND, lab_message_sha256, sign_lab_message
from adf_poc.lab_services import (
    EXECUTOR_AFTER_COMPLETION,
    EXECUTOR_AFTER_EFFECT,
    EXECUTOR_AFTER_RESERVATION,
    ExecutorReplayJournal,
    LabExecutorService,
    LabMutationResult,
    LabObservedState,
    LabServiceError,
    initialize_executor_journal,
)
from adf_poc.utils import canonical_json


NOW = datetime(2026, 8, 20, 21, 0, tzinfo=timezone.utc)
KEY = b"phase4-kill-matrix-key".ljust(32, b"!")
KEY_ID = "LAB_EXECUTOR_KEY_001"
RULESET = "8" * 64
ISOLATED_RULESET = "7" * 64
EFFECT_MARKER = b"ADF-PHASE4-CODE-OWNED-EFFECT-V1\n"


def _command() -> bytes:
    value = sign_lab_message(
        {
            "schema_version": "0.4.0",
            "message_type": COMMAND,
            "lab_session_id": "lab-kill-matrix-001",
            "request_id": "request-kill-001",
            "decision_id": "decision-kill-001",
            "authorization_id": "authorization-not-integrated",
            "policy_sha256": "1" * 64,
            "adapter_contract_sha256": "2" * 64,
            "target_id": "LAB_ENDPOINT_001",
            "target_boot_id": "boot-kill-001",
            "action": "NETWORK_ISOLATE",
            "parameters": {
                "duration_seconds": 300,
                "preserve_management": True,
                "network_profile": "LAB_BEACON_BLOCK_MANAGEMENT_ALLOW_V1",
            },
            "prestate_sha256": RULESET,
            "idempotency_key": "idempotency-kill-001",
            "sequence": 1,
            "nonce": "9" * 32,
            "issued_at": NOW.isoformat(),
            "expires_at": (NOW + timedelta(seconds=90)).isoformat(),
        },
        message_type=COMMAND,
        key_id=KEY_ID,
        key=KEY,
        now=NOW,
    )
    return canonical_json(value).encode("utf-8")


def _state() -> LabObservedState:
    return LabObservedState(
        target_boot_id="boot-kill-001",
        beacon_reachable=True,
        management_reachable=True,
        ruleset_sha256=RULESET,
    )


@unittest.skipUnless(hasattr(os, "fork"), "requires Unix process-kill semantics")
class Phase4ExecutorKillMatrixTests(unittest.TestCase):
    def _journal_path(self, directory: str) -> Path:
        root = Path(directory) / "state"
        root.mkdir(mode=0o700)
        path = root / "executor-replay.jsonl"
        initialize_executor_journal(path, expect_empty=True)
        return path

    @staticmethod
    def _apply_effect_once(path: Path):
        def apply_effect(_command, _prestate) -> LabMutationResult:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            descriptor = os.open(path, flags, 0o600)
            try:
                os.fchmod(descriptor, 0o600)
                offset = 0
                while offset < len(EFFECT_MARKER):
                    written = os.write(descriptor, EFFECT_MARKER[offset:])
                    if written <= 0:
                        raise OSError("effect marker write was incomplete")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory_fd = os.open(
                path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return LabMutationResult(
                status="APPLIED",
                effect_possible=True,
                reason_code="RULESET_APPLIED",
                poststate_sha256=ISOLATED_RULESET,
            )

        return apply_effect

    def _kill_at(
        self, path: Path, stage: str, *, effect_path: Path | None = None
    ) -> None:
        read_fd, write_fd = os.pipe()
        child = os.fork()
        if child == 0:
            os.close(read_fd)

            def stop_at(observed: str) -> None:
                if observed == stage:
                    os.write(write_fd, b"1")
                    signal.pause()

            service = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=KEY_ID,
                key=KEY,
                read_state=_state,
                apply_action=(
                    self._apply_effect_once(effect_path)
                    if effect_path is not None
                    else None
                ),
                clock=lambda: NOW,
                failure_hook=stop_at,
                effects_enabled=effect_path is not None,
                enabled=True,
            )
            service.handle(_command())
            os._exit(0)
        os.close(write_fd)
        ready, _, _ = select.select([read_fd], [], [], 5.0)
        observed_child = -1
        status = -1
        try:
            self.assertEqual(ready, [read_fd])
            self.assertEqual(os.read(read_fd, 1), b"1")
            os.kill(child, signal.SIGKILL)
            observed_child, status = os.waitpid(child, 0)
        finally:
            os.close(read_fd)
            if observed_child == -1:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                os.waitpid(child, 0)
        self.assertEqual(observed_child, child)
        self.assertTrue(os.WIFSIGNALED(status))
        self.assertEqual(os.WTERMSIG(status), signal.SIGKILL)

    def test_kill_after_reservation_fences_exact_retry_without_target_read(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._journal_path(directory)
            self._kill_at(path, EXECUTOR_AFTER_RESERVATION)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([row["record_type"] for row in rows], ["RESERVATION"])

            reads = 0

            def forbidden_read() -> LabObservedState:
                nonlocal reads
                reads += 1
                return _state()

            reopened = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=KEY_ID,
                key=KEY,
                read_state=forbidden_read,
                clock=lambda: NOW,
                enabled=True,
            )
            with self.assertRaises(LabServiceError) as raised:
                reopened.handle(_command())
            self.assertEqual(
                raised.exception.reason_code, "LAB_EXECUTOR_RECOVERY_REQUIRED"
            )
            self.assertEqual(reads, 0)
            self.assertEqual(len(path.read_text().splitlines()), 1)

    def test_kill_after_completion_replays_exact_no_effect_without_target_read(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._journal_path(directory)
            command = _command()
            self._kill_at(path, EXECUTOR_AFTER_COMPLETION)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(
                [row["record_type"] for row in rows],
                ["RESERVATION", "COMPLETION"],
            )
            completion = rows[-1]["receipt_json"].encode("utf-8")

            reads = 0

            def forbidden_read() -> LabObservedState:
                nonlocal reads
                reads += 1
                return _state()

            reopened = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=KEY_ID,
                key=KEY,
                read_state=forbidden_read,
                clock=lambda: NOW,
                enabled=True,
            )
            self.assertEqual(reopened.handle(command), completion)
            self.assertEqual(reads, 0)
            self.assertEqual(len(path.read_text().splitlines()), 2)
            self.assertEqual(
                rows[0]["command_sha256"],
                lab_message_sha256(json.loads(command)),
            )

    def test_kill_after_effect_fences_retry_and_preserves_exactly_one_effect(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._journal_path(directory)
            effect_path = Path(directory) / "code-owned-effect.marker"
            self._kill_at(path, EXECUTOR_AFTER_EFFECT, effect_path=effect_path)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual([row["record_type"] for row in rows], ["RESERVATION"])
            self.assertEqual(effect_path.read_bytes(), EFFECT_MARKER)
            self.assertEqual(effect_path.stat().st_mode & 0o777, 0o600)

            reads = 0
            effects = 0

            def forbidden_read() -> LabObservedState:
                nonlocal reads
                reads += 1
                return _state()

            def forbidden_effect(*_args) -> LabMutationResult:
                nonlocal effects
                effects += 1
                return LabMutationResult(
                    status="APPLIED",
                    effect_possible=True,
                    reason_code="RULESET_APPLIED",
                    poststate_sha256=ISOLATED_RULESET,
                )

            reopened = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=KEY_ID,
                key=KEY,
                read_state=forbidden_read,
                apply_action=forbidden_effect,
                clock=lambda: NOW,
                effects_enabled=True,
                enabled=True,
            )
            with self.assertRaises(LabServiceError) as raised:
                reopened.handle(_command())
            self.assertEqual(
                raised.exception.reason_code, "LAB_EXECUTOR_RECOVERY_REQUIRED"
            )
            self.assertEqual(reads, 0)
            self.assertEqual(effects, 0)
            self.assertEqual(effect_path.read_bytes(), EFFECT_MARKER)
            self.assertEqual(len(path.read_text().splitlines()), 1)

    def test_kill_after_applied_completion_replays_without_second_effect(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = self._journal_path(directory)
            effect_path = Path(directory) / "code-owned-effect.marker"
            command = _command()
            self._kill_at(path, EXECUTOR_AFTER_COMPLETION, effect_path=effect_path)
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(
                [row["record_type"] for row in rows],
                ["RESERVATION", "COMPLETION"],
            )
            completion = rows[-1]["receipt_json"].encode("utf-8")
            receipt = json.loads(rows[-1]["receipt_json"])
            self.assertEqual(receipt["status"], "APPLIED")
            self.assertTrue(receipt["effect_possible"])
            self.assertEqual(receipt["poststate_sha256"], ISOLATED_RULESET)
            self.assertEqual(effect_path.read_bytes(), EFFECT_MARKER)

            reads = 0
            effects = 0

            def forbidden_read() -> LabObservedState:
                nonlocal reads
                reads += 1
                return _state()

            def forbidden_effect(*_args) -> LabMutationResult:
                nonlocal effects
                effects += 1
                raise AssertionError("durable completion must replay before effect")

            reopened = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=KEY_ID,
                key=KEY,
                read_state=forbidden_read,
                apply_action=forbidden_effect,
                clock=lambda: NOW,
                effects_enabled=True,
                enabled=True,
            )
            self.assertEqual(reopened.handle(command), completion)
            self.assertEqual(reads, 0)
            self.assertEqual(effects, 0)
            self.assertEqual(effect_path.read_bytes(), EFFECT_MARKER)
            self.assertEqual(len(path.read_text().splitlines()), 2)


if __name__ == "__main__":
    unittest.main()
