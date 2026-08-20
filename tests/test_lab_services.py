from __future__ import annotations

import json
import os
import queue
import socket
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from adf_poc.lab_contracts import (
    COMMAND,
    OBSERVATION,
    OBSERVATION_REQUEST,
    RECEIPT,
    LabContractError,
    lab_message_sha256,
    load_authenticated_lab_message,
    sign_lab_message,
    validate_lab_message_correlation,
)
from adf_poc.lab_services import (
    EXECUTOR_AFTER_EFFECT,
    ExecutorReplayJournal,
    LabExecutorService,
    LabMutationResult,
    LabObservedState,
    LabObserverService,
    LabServiceError,
    initialize_executor_journal,
)
from adf_poc.lab_transport import LabSeqpacketServer, lab_seqpacket_exchange
from adf_poc.utils import canonical_json


NOW = datetime(2026, 8, 20, 20, 0, tzinfo=timezone.utc)
EXECUTOR_KEY = b"executor-service-key".ljust(32, b"!")
OBSERVER_KEY = b"observer-service-key".ljust(32, b"!")
EXECUTOR_KEY_ID = "LAB_EXECUTOR_KEY_001"
OBSERVER_KEY_ID = "LAB_OBSERVER_KEY_001"
RULESET = "3" * 64
LINUX_TRANSPORT = (
    sys.platform == "linux"
    and hasattr(socket, "SOCK_SEQPACKET")
    and hasattr(socket, "SO_PEERCRED")
)


def _timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def _command(
    *, request_id: str = "request-001", idempotency_key: str = "idem-001"
) -> dict:
    return sign_lab_message(
        {
            "schema_version": "0.4.0",
            "message_type": COMMAND,
            "lab_session_id": "lab-session-001",
            "request_id": request_id,
            "decision_id": f"decision-{request_id}",
            "authorization_id": f"authorization-{request_id}",
            "policy_sha256": "1" * 64,
            "adapter_contract_sha256": "2" * 64,
            "target_id": "LAB_ENDPOINT_001",
            "target_boot_id": "boot-001",
            "action": "NETWORK_ISOLATE",
            "parameters": {
                "duration_seconds": 300,
                "preserve_management": True,
                "network_profile": "LAB_BEACON_BLOCK_MANAGEMENT_ALLOW_V1",
            },
            "prestate_sha256": RULESET,
            "idempotency_key": idempotency_key,
            "sequence": 1,
            "nonce": "4" * 32,
            "issued_at": _timestamp(NOW),
            "expires_at": _timestamp(NOW + timedelta(seconds=90)),
        },
        message_type=COMMAND,
        key_id=EXECUTOR_KEY_ID,
        key=EXECUTOR_KEY,
        now=NOW,
    )


def _observation_request(command: dict) -> dict:
    return sign_lab_message(
        {
            "schema_version": "0.4.0",
            "message_type": OBSERVATION_REQUEST,
            "lab_session_id": command["lab_session_id"],
            "request_id": command["request_id"],
            "decision_id": command["decision_id"],
            "command_sha256": lab_message_sha256(command),
            "idempotency_key": command["idempotency_key"],
            "target_id": command["target_id"],
            "target_boot_id": command["target_boot_id"],
            "sequence": command["sequence"],
            "nonce": "5" * 32,
            "issued_at": _timestamp(NOW),
            "expires_at": _timestamp(NOW + timedelta(seconds=90)),
        },
        message_type=OBSERVATION_REQUEST,
        key_id=OBSERVER_KEY_ID,
        key=OBSERVER_KEY,
        now=NOW,
    )


def _state() -> LabObservedState:
    return LabObservedState(
        target_boot_id="boot-001",
        beacon_reachable=True,
        management_reachable=True,
        ruleset_sha256=RULESET,
    )


class LabServiceTests(unittest.TestCase):
    def _journal(self, directory: str) -> tuple[Path, ExecutorReplayJournal]:
        root = Path(directory) / "state"
        root.mkdir(mode=0o700)
        path = root / "executor-replay.jsonl"
        initialize_executor_journal(path, expect_empty=True)
        return path, ExecutorReplayJournal(path, require_existing=True)

    def test_journal_requires_explicit_create_once_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "state"
            root.mkdir(mode=0o700)
            path = root / "executor-replay.jsonl"
            with self.assertRaises(LabServiceError) as raised:
                ExecutorReplayJournal(path, require_existing=True)
            self.assertEqual(raised.exception.reason_code, "LAB_JOURNAL_PATH_UNSAFE")

            initialize_executor_journal(path, expect_empty=True)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(LabServiceError) as raised:
                initialize_executor_journal(path, expect_empty=True)
            self.assertEqual(raised.exception.reason_code, "LAB_JOURNAL_ALREADY_EXISTS")

            path.chmod(0o666)
            with self.assertRaises(LabServiceError) as raised:
                ExecutorReplayJournal(path, require_existing=True)
            self.assertEqual(raised.exception.reason_code, "LAB_JOURNAL_PATH_UNSAFE")
            self.assertEqual(path.stat().st_mode & 0o777, 0o666)

    def test_executor_returns_durable_no_effect_and_exact_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            reads = 0

            def read_state() -> LabObservedState:
                nonlocal reads
                reads += 1
                return _state()

            service = LabExecutorService(
                journal=journal,
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=read_state,
                clock=lambda: NOW,
                enabled=True,
            )
            raw = canonical_json(_command()).encode("utf-8")
            first = service.handle(raw)
            reopened = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=read_state,
                clock=lambda: NOW,
                enabled=True,
            )
            second = reopened.handle(raw)
            self.assertEqual(second, first)
            late_reopen = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=read_state,
                clock=lambda: NOW + timedelta(minutes=10),
                enabled=True,
            )
            self.assertEqual(late_reopen.handle(raw), first)
            self.assertEqual(reads, 1)
            receipt = load_authenticated_lab_message(
                first,
                message_type=RECEIPT,
                expected_key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                now=NOW,
            )
            self.assertEqual(receipt["status"], "NO_EFFECT")
            self.assertFalse(receipt["effect_possible"])
            rows = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(
                [row["record_type"] for row in rows], ["RESERVATION", "COMPLETION"]
            )

    def test_unseen_expired_command_is_rejected_before_reservation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            service = LabExecutorService(
                journal=journal,
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                clock=lambda: NOW + timedelta(minutes=10),
                enabled=True,
            )
            with self.assertRaises(LabContractError) as raised:
                service.handle(canonical_json(_command()).encode())
            self.assertEqual(raised.exception.reason_code, "LAB_COMMAND_EXPIRED")
            self.assertEqual(path.read_bytes(), b"")

    def test_conflicting_idempotency_key_and_open_reservation_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, journal = self._journal(directory)
            first = _command()
            journal.reserve_or_replay(
                idempotency_key=first["idempotency_key"],
                command_sha256=lab_message_sha256(first),
                recorded_at=_timestamp(NOW),
            )
            service = LabExecutorService(
                journal=journal,
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                clock=lambda: NOW,
                enabled=True,
            )
            with self.assertRaises(LabServiceError) as raised:
                service.handle(canonical_json(first).encode())
            self.assertEqual(
                raised.exception.reason_code, "LAB_EXECUTOR_RECOVERY_REQUIRED"
            )

            conflict = _command(request_id="request-002")
            with self.assertRaises(LabServiceError) as raised:
                service.handle(canonical_json(conflict).encode())
            self.assertEqual(raised.exception.reason_code, "LAB_IDEMPOTENCY_CONFLICT")

    def test_failure_after_reservation_never_reinvokes_target_reader(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            reads = 0

            def unavailable_state() -> LabObservedState:
                nonlocal reads
                reads += 1
                raise OSError("injected read failure after reservation")

            service = LabExecutorService(
                journal=journal,
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=unavailable_state,
                clock=lambda: NOW,
                enabled=True,
            )
            raw = canonical_json(_command()).encode()
            with self.assertRaises(LabServiceError) as raised:
                service.handle(raw)
            self.assertEqual(raised.exception.reason_code, "LAB_TARGET_READ_FAILED")
            self.assertEqual(reads, 1)
            reopened = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=unavailable_state,
                clock=lambda: NOW,
                enabled=True,
            )
            with self.assertRaises(LabServiceError) as raised:
                reopened.handle(raw)
            self.assertEqual(
                raised.exception.reason_code, "LAB_EXECUTOR_RECOVERY_REQUIRED"
            )
            self.assertEqual(reads, 1)

    def test_journal_corruption_and_replacement_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            path.write_text('{"forged":true}\n')
            path.chmod(0o600)
            with self.assertRaises(LabServiceError) as raised:
                journal.reserve_or_replay(
                    idempotency_key="idem-001",
                    command_sha256="1" * 64,
                    recorded_at=_timestamp(NOW),
                )
            self.assertEqual(raised.exception.reason_code, "LAB_JOURNAL_CORRUPT")

        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            replacement = path.with_suffix(".replacement")
            replacement.write_bytes(b"")
            replacement.chmod(0o600)
            os.replace(replacement, path)
            with self.assertRaises(LabServiceError) as raised:
                journal.reserve_or_replay(
                    idempotency_key="idem-001",
                    command_sha256="1" * 64,
                    recorded_at=_timestamp(NOW),
                )
            self.assertEqual(
                raised.exception.reason_code, "LAB_JOURNAL_IDENTITY_CHANGED"
            )

    def test_effect_boundary_requires_explicit_enablement_and_callable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, journal = self._journal(directory)
            for apply_action, effects_enabled in (
                (lambda *_: None, False),
                (None, True),
            ):
                with self.subTest(effects_enabled=effects_enabled):
                    with self.assertRaises(LabServiceError) as raised:
                        LabExecutorService(
                            journal=journal,
                            key_id=EXECUTOR_KEY_ID,
                            key=EXECUTOR_KEY,
                            read_state=_state,
                            apply_action=apply_action,
                            effects_enabled=effects_enabled,
                            enabled=True,
                        )
                    self.assertEqual(
                        raised.exception.reason_code, "LAB_SERVICE_NOT_ENABLED"
                    )

    def test_prestate_mismatch_closes_no_effect_without_invoking_action(self) -> None:
        mismatches = {
            "boot": LabObservedState("boot-replaced", True, True, RULESET),
            "ruleset": LabObservedState("boot-001", True, True, "9" * 64),
            "beacon": LabObservedState("boot-001", False, True, RULESET),
            "management": LabObservedState("boot-001", True, False, RULESET),
        }
        for label, observed_state in mismatches.items():
            with self.subTest(label=label), tempfile.TemporaryDirectory() as directory:
                _, journal = self._journal(directory)
                calls = 0

                def apply_action(*_args) -> LabMutationResult:
                    nonlocal calls
                    calls += 1
                    raise AssertionError(
                        "precondition failure must not cross effect boundary"
                    )

                receipt_raw = LabExecutorService(
                    journal=journal,
                    key_id=EXECUTOR_KEY_ID,
                    key=EXECUTOR_KEY,
                    read_state=lambda: observed_state,
                    apply_action=apply_action,
                    effects_enabled=True,
                    clock=lambda: NOW,
                    enabled=True,
                ).handle(canonical_json(_command()).encode())
                receipt = load_authenticated_lab_message(
                    receipt_raw,
                    message_type=RECEIPT,
                    expected_key_id=EXECUTOR_KEY_ID,
                    key=EXECUTOR_KEY,
                    now=NOW,
                )
                self.assertEqual(calls, 0)
                self.assertEqual(receipt["status"], "NO_EFFECT")
                self.assertFalse(receipt["effect_possible"])

    def test_applied_effect_is_durable_and_exact_replay_does_not_repeat_it(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            calls = 0

            def apply_action(command, prestate) -> LabMutationResult:
                nonlocal calls
                calls += 1
                self.assertEqual(command["action"], "NETWORK_ISOLATE")
                self.assertEqual(prestate, _state())
                return LabMutationResult(
                    status="APPLIED",
                    effect_possible=True,
                    reason_code="RULESET_APPLIED",
                    poststate_sha256="5" * 64,
                )

            raw = canonical_json(_command()).encode()
            first = LabExecutorService(
                journal=journal,
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                apply_action=apply_action,
                effects_enabled=True,
                clock=lambda: NOW,
                enabled=True,
            ).handle(raw)
            second = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                apply_action=apply_action,
                effects_enabled=True,
                clock=lambda: NOW,
                enabled=True,
            ).handle(raw)
            receipt = load_authenticated_lab_message(
                first,
                message_type=RECEIPT,
                expected_key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                now=NOW,
            )
            self.assertEqual(second, first)
            self.assertEqual(calls, 1)
            self.assertEqual(receipt["status"], "APPLIED")
            self.assertEqual(receipt["poststate_sha256"], "5" * 64)

    def test_action_exception_closes_ambiguous_and_is_never_retried(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            calls = 0

            def apply_action(*_args) -> LabMutationResult:
                nonlocal calls
                calls += 1
                raise OSError("effect state is unknown")

            raw = canonical_json(_command()).encode()
            service = LabExecutorService(
                journal=journal,
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                apply_action=apply_action,
                effects_enabled=True,
                clock=lambda: NOW,
                enabled=True,
            )
            first = service.handle(raw)
            replay = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                apply_action=apply_action,
                effects_enabled=True,
                clock=lambda: NOW,
                enabled=True,
            ).handle(raw)
            receipt = load_authenticated_lab_message(
                first,
                message_type=RECEIPT,
                expected_key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                now=NOW,
            )
            self.assertEqual(replay, first)
            self.assertEqual(calls, 1)
            self.assertEqual(receipt["status"], "AMBIGUOUS")
            self.assertTrue(receipt["effect_possible"])
            self.assertEqual(receipt["poststate_sha256"], "0" * 64)

    def test_loss_after_effect_fences_replay_without_reinvoking_action(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path, journal = self._journal(directory)
            calls = 0

            def apply_action(*_args) -> LabMutationResult:
                nonlocal calls
                calls += 1
                return LabMutationResult(
                    status="APPLIED",
                    effect_possible=True,
                    reason_code="RULESET_APPLIED",
                    poststate_sha256="5" * 64,
                )

            def fail_after_effect(stage: str) -> None:
                if stage == EXECUTOR_AFTER_EFFECT:
                    raise RuntimeError("injected post-effect loss")

            raw = canonical_json(_command()).encode()
            with self.assertRaisesRegex(RuntimeError, "post-effect loss"):
                LabExecutorService(
                    journal=journal,
                    key_id=EXECUTOR_KEY_ID,
                    key=EXECUTOR_KEY,
                    read_state=_state,
                    apply_action=apply_action,
                    effects_enabled=True,
                    failure_hook=fail_after_effect,
                    clock=lambda: NOW,
                    enabled=True,
                ).handle(raw)
            reopened = LabExecutorService(
                journal=ExecutorReplayJournal(path, require_existing=True),
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                apply_action=apply_action,
                effects_enabled=True,
                clock=lambda: NOW,
                enabled=True,
            )
            with self.assertRaises(LabServiceError) as raised:
                reopened.handle(raw)
            self.assertEqual(
                raised.exception.reason_code, "LAB_EXECUTOR_RECOVERY_REQUIRED"
            )
            self.assertEqual(calls, 1)

    def test_observer_uses_separate_request_key_and_fresh_read(self) -> None:
        command = _command()
        request = _observation_request(command)
        reads = 0

        def read_state() -> LabObservedState:
            nonlocal reads
            reads += 1
            return _state()

        service = LabObserverService(
            key_id=OBSERVER_KEY_ID,
            key=OBSERVER_KEY,
            read_state=read_state,
            clock=lambda: NOW,
            enabled=True,
        )
        first = service.handle(canonical_json(request).encode())
        second = service.handle(canonical_json(request).encode())
        self.assertEqual(reads, 2)
        self.assertEqual(first, second)
        observation = load_authenticated_lab_message(
            first,
            message_type=OBSERVATION,
            expected_key_id=OBSERVER_KEY_ID,
            key=OBSERVER_KEY,
            now=NOW,
        )
        self.assertEqual(observation["command_sha256"], lab_message_sha256(command))
        self.assertTrue(observation["beacon_reachable"])

        with self.assertRaises(LabContractError) as raised:
            LabObserverService(
                key_id=OBSERVER_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                clock=lambda: NOW,
                enabled=True,
            ).handle(canonical_json(request).encode())
        self.assertEqual(raised.exception.reason_code, "LAB_AUTHENTICATION_INVALID")

    def test_observer_boot_mismatch_fails_without_fabricating_observation(self) -> None:
        command = _command()
        service = LabObserverService(
            key_id=OBSERVER_KEY_ID,
            key=OBSERVER_KEY,
            read_state=lambda: LabObservedState(
                target_boot_id="boot-replaced",
                beacon_reachable=False,
                management_reachable=True,
                ruleset_sha256=RULESET,
            ),
            clock=lambda: NOW,
            enabled=True,
        )
        with self.assertRaises(LabServiceError) as raised:
            service.handle(canonical_json(_observation_request(command)).encode())
        self.assertEqual(raised.exception.reason_code, "LAB_TARGET_BOOT_ID_MISMATCH")

    def test_no_effect_receipt_and_independent_observation_correlate(self) -> None:
        command = _command()
        with tempfile.TemporaryDirectory() as directory:
            _, journal = self._journal(directory)
            receipt_raw = LabExecutorService(
                journal=journal,
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                clock=lambda: NOW,
                enabled=True,
            ).handle(canonical_json(command).encode())
        observation_raw = LabObserverService(
            key_id=OBSERVER_KEY_ID,
            key=OBSERVER_KEY,
            read_state=_state,
            clock=lambda: NOW,
            enabled=True,
        ).handle(canonical_json(_observation_request(command)).encode())
        receipt = load_authenticated_lab_message(
            receipt_raw,
            message_type=RECEIPT,
            expected_key_id=EXECUTOR_KEY_ID,
            key=EXECUTOR_KEY,
            now=NOW,
        )
        observation = load_authenticated_lab_message(
            observation_raw,
            message_type=OBSERVATION,
            expected_key_id=OBSERVER_KEY_ID,
            key=OBSERVER_KEY,
            now=NOW,
        )
        validate_lab_message_correlation(
            command=command, receipt=receipt, observation=observation
        )


@unittest.skipUnless(LINUX_TRANSPORT, "requires Linux SOCK_SEQPACKET/SO_PEERCRED")
class LabServiceLinuxTransportTests(unittest.TestCase):
    def test_contract_handlers_run_over_real_bounded_peer_checked_sockets(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "private"
            root.mkdir(mode=0o700)
            journal_path = root / "executor-replay.jsonl"
            initialize_executor_journal(journal_path, expect_empty=True)
            command = _command()

            executor = LabExecutorService(
                journal=ExecutorReplayJournal(journal_path, require_existing=True),
                key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                read_state=_state,
                clock=lambda: NOW,
                enabled=True,
            )
            receipt_raw = self._exchange(
                root / "executor.sock",
                canonical_json(command).encode(),
                executor.handle,
            )
            receipt = load_authenticated_lab_message(
                receipt_raw,
                message_type=RECEIPT,
                expected_key_id=EXECUTOR_KEY_ID,
                key=EXECUTOR_KEY,
                now=NOW,
            )

            observer = LabObserverService(
                key_id=OBSERVER_KEY_ID,
                key=OBSERVER_KEY,
                read_state=_state,
                clock=lambda: NOW,
                enabled=True,
            )
            observation_raw = self._exchange(
                root / "observer.sock",
                canonical_json(_observation_request(command)).encode(),
                observer.handle,
            )
            observation = load_authenticated_lab_message(
                observation_raw,
                message_type=OBSERVATION,
                expected_key_id=OBSERVER_KEY_ID,
                key=OBSERVER_KEY,
                now=NOW,
            )
            validate_lab_message_correlation(
                command=command, receipt=receipt, observation=observation
            )

    def _exchange(self, path: Path, request: bytes, handler) -> bytes:
        result: queue.Queue[BaseException | None] = queue.Queue()
        with LabSeqpacketServer(
            path,
            expected_client_uid=os.geteuid(),
            enabled=True,
            timeout_seconds=2,
        ) as server:

            def serve() -> None:
                try:
                    server.serve_once(handler)
                except BaseException as exc:  # captured for exact assertion
                    result.put(exc)
                else:
                    result.put(None)

            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            response = lab_seqpacket_exchange(
                path,
                request,
                expected_server_uid=os.geteuid(),
                enabled=True,
                timeout_seconds=2,
            )
            thread.join(3)
            self.assertFalse(thread.is_alive())
            self.assertIsNone(result.get_nowait())
            return response


if __name__ == "__main__":
    unittest.main()
