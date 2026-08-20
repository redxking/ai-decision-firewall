from __future__ import annotations

from contextlib import closing
from datetime import datetime
import hashlib
import json
import multiprocessing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.phase3.scenarios import request_json
from adf_poc.stage_a import (
    REQUEST_LOOKUP_SCHEMA_VERSION,
    ControlLedgerError,
    RequestLookupResult,
    SQLiteControlLedger,
    SQLiteSyntheticAdapterStore,
    SyntheticAdapterError,
    terminal_attempt_outcome_sha256,
)
from adf_poc.utils import canonical_json, sha256_json

from tests.phase3_support import new_harness, workstation_case


def _outbox_digest(event_type: str, subject_id: str, payload: dict[str, object]) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "event_type": event_type,
                "subject_id": subject_id,
                "payload": payload,
            }
        ).encode("utf-8")
    ).hexdigest()


def _claim_worker(
    ledger_path: str,
    barrier: multiprocessing.synchronize.Barrier,
    results: multiprocessing.queues.Queue,
) -> None:
    try:
        ledger = SQLiteControlLedger(ledger_path, busy_timeout_ms=5000)
        barrier.wait(timeout=10)
        state = ledger.claim_request("SOC_AGENT_001", "STAGE-A-CONCURRENT", "a" * 64)
        results.put(("OK", state))
    except Exception as exc:  # pragma: no cover - child diagnostic surface
        results.put(("ERROR", type(exc).__name__, getattr(exc, "reason_code", "")))


def _consume_worker(
    ledger_path: str,
    attempt_id: str,
    barrier: multiprocessing.synchronize.Barrier,
    results: multiprocessing.queues.Queue,
) -> None:
    try:
        ledger = SQLiteControlLedger(ledger_path, busy_timeout_ms=5000)
        barrier.wait(timeout=10)
        ledger.consume_once(
            "AUTH-CONCURRENT",
            attempt_id=attempt_id,
            attempt_binding_sha256=sha256_json(
                {"token_id": "AUTH-CONCURRENT", "attempt_id": attempt_id}
            ),
            consumed_at="2026-08-15T22:30:00+00:00",
        )
        results.put(("OK", attempt_id))
    except ControlLedgerError as exc:
        results.put(("BLOCKED", exc.reason_code))
    except Exception as exc:  # pragma: no cover - child diagnostic surface
        results.put(("ERROR", type(exc).__name__, getattr(exc, "reason_code", "")))


def _crash_before_adapter_worker(
    root_text: str, raw_request: str, now_text: str
) -> None:
    root = Path(root_text)
    harness = new_harness(
        now=datetime.fromisoformat(now_text),
        audit_path=root / "audit.jsonl",
        control_ledger_path=root / "control.sqlite3",
        synthetic_adapter_path=root / "adapter.sqlite3",
    )

    def crash_before_adapter(*args, **kwargs):
        os._exit(91)

    with patch.object(
        SQLiteSyntheticAdapterStore,
        "execute_once",
        new=crash_before_adapter,
    ):
        harness.firewall.process_json(raw_request, credential=harness.soc_credential)
    os._exit(92)


def _control_first_create_worker(
    path: str,
    barrier: multiprocessing.synchronize.Barrier,
    results: multiprocessing.queues.Queue,
) -> None:
    try:
        barrier.wait(timeout=10)
        ledger = SQLiteControlLedger(path, busy_timeout_ms=5000)
        results.put(("OK", ledger.issuer_instance_id))
    except Exception as exc:  # pragma: no cover - child diagnostic surface
        results.put(("ERROR", type(exc).__name__, getattr(exc, "reason_code", "")))


def _adapter_first_create_worker(
    path: str,
    barrier: multiprocessing.synchronize.Barrier,
    results: multiprocessing.queues.Queue,
) -> None:
    try:
        target_inventory = new_harness().policy.target_inventory
        barrier.wait(timeout=10)
        store = SQLiteSyntheticAdapterStore(
            path,
            target_inventory=target_inventory,
            busy_timeout_ms=5000,
        )
        results.put(("OK", store.adapter_store_id))
    except Exception as exc:  # pragma: no cover - child diagnostic surface
        results.put(("ERROR", type(exc).__name__, getattr(exc, "reason_code", "")))


class StageADurableControlLedgerTests(unittest.TestCase):
    def _completed_durable_case(
        self, root: Path, *, request_id: str
    ) -> tuple[object, str]:
        harness = new_harness(
            audit_path=root / "audit.jsonl",
            control_ledger_path=root / "control.sqlite3",
            synthetic_adapter_path=root / "adapter.sqlite3",
        )
        raw = request_json(workstation_case(harness, request_id=request_id))
        result = harness.firewall.process_json(raw, credential=harness.soc_credential)
        self.assertEqual(result.decision.outcome, "ALLOW")
        self.assertIsNotNone(result.verification)
        return harness, raw

    def _crashed_reserved_case(
        self, root: Path, *, request_id: str
    ) -> tuple[object, str]:
        seed = new_harness()
        now = seed.clock()
        raw = request_json(workstation_case(seed, request_id=request_id))
        context = multiprocessing.get_context("spawn")
        process = context.Process(
            target=_crash_before_adapter_worker,
            args=(str(root), raw, now.isoformat()),
        )
        process.start()
        process.join(timeout=20)
        self.assertEqual(process.exitcode, 91)
        reopened = new_harness(
            now=now,
            audit_path=root / "audit.jsonl",
            control_ledger_path=root / "control.sqlite3",
            synthetic_adapter_path=root / "adapter.sqlite3",
        )
        return reopened, raw

    def test_schema_durability_permissions_and_unknown_version_fail_closed(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            ledger = SQLiteControlLedger(path)

            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(
                    str(
                        connection.execute("PRAGMA journal_mode").fetchone()[0]
                    ).lower(),
                    "wal",
                )
                self.assertEqual(
                    connection.execute("PRAGMA synchronous").fetchone()[0], 2
                )
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                self.assertTrue(
                    {
                        "metadata",
                        "requests",
                        "authorizations",
                        "attempts",
                        "audit_outbox",
                    }
                    <= tables
                )
                connection.execute(
                    "UPDATE metadata SET value='999' WHERE key='schema_version'"
                )
                connection.commit()

            with self.assertRaises(ControlLedgerError) as raised:
                SQLiteControlLedger(path)
            self.assertEqual(
                raised.exception.reason_code, "CONTROL_LEDGER_SCHEMA_UNSUPPORTED"
            )
            self.assertTrue(ledger.issuer_instance_id.startswith("stage-a-ledger-"))

    def test_preexisting_unversioned_database_is_not_adopted_or_modified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "unrelated.sqlite3"
            with closing(sqlite3.connect(path)) as connection:
                connection.execute(
                    "CREATE TABLE unrelated_record(id INTEGER PRIMARY KEY)"
                )
                connection.commit()
            path.chmod(0o600)

            with self.assertRaises(ControlLedgerError) as raised:
                SQLiteControlLedger(path)
            self.assertEqual(
                raised.exception.reason_code, "CONTROL_LEDGER_SCHEMA_UNSUPPORTED"
            )
            with closing(sqlite3.connect(path)) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
            self.assertEqual(tables, {"unrelated_record"})

    def test_restart_replay_is_denied_before_a_second_broker_or_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            audit_path = root / "audit.jsonl"
            ledger_path = root / "control.sqlite3"
            first_harness = new_harness(
                audit_path=audit_path, control_ledger_path=ledger_path
            )
            raw = request_json(
                workstation_case(first_harness, request_id="P3-STAGE-A-RESTART-REPLAY")
            )
            first = first_harness.firewall.process_json(
                raw, credential=first_harness.soc_credential
            )

            second_harness = new_harness(
                now=first_harness.clock(),
                audit_path=audit_path,
                control_ledger_path=ledger_path,
            )
            second = second_harness.firewall.process_json(
                raw, credential=second_harness.soc_credential
            )

            self.assertEqual(first.decision.outcome, "ALLOW")
            self.assertIsNotNone(first.broker_result)
            self.assertEqual(second.decision.outcome, "DENY")
            self.assertIn("DUPLICATE_REQUEST", second.decision.reason_codes)
            self.assertIsNone(second.authorization)
            self.assertIsNone(second.broker_result)
            self.assertEqual(
                second.audit_records[-1]["payload"]["operational_effects"], 0
            )
            self.assertEqual(
                second_harness.firewall.observer.observe("WORKSTATION_042")[
                    "network_state"
                ],
                "connected",
            )

    def test_restart_request_identifier_conflict_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            ledger_path = root / "control.sqlite3"
            first_harness = new_harness(control_ledger_path=ledger_path)
            first_value = workstation_case(
                first_harness, request_id="P3-STAGE-A-RESTART-CONFLICT"
            )
            first = first_harness.firewall.process_json(
                request_json(first_value), credential=first_harness.soc_credential
            )
            self.assertEqual(first.decision.outcome, "ALLOW")

            second_harness = new_harness(
                now=first_harness.clock(), control_ledger_path=ledger_path
            )
            conflicting_value = workstation_case(
                second_harness, request_id="P3-STAGE-A-RESTART-CONFLICT"
            )
            conflicting_value["action"]["parameters"]["duration_seconds"] = 600
            second = second_harness.firewall.process_json(
                request_json(conflicting_value),
                credential=second_harness.soc_credential,
            )

            self.assertEqual(second.decision.outcome, "DENY")
            self.assertIn("REQUEST_ID_CONFLICT", second.decision.reason_codes)
            self.assertIsNone(second.authorization)
            self.assertIsNone(second.broker_result)

    def test_successful_broker_attempt_and_outbox_survive_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            harness = new_harness(control_ledger_path=path)
            result = harness.firewall.process_json(
                request_json(
                    workstation_case(harness, request_id="P3-STAGE-A-DURABLE-ATTEMPT")
                ),
                credential=harness.soc_credential,
            )
            self.assertIsNotNone(result.authorization)
            self.assertIsNotNone(result.broker_result)
            assert result.authorization is not None
            assert result.broker_result is not None

            reopened = SQLiteControlLedger(path)
            attempt = reopened.attempt_snapshot(result.broker_result.attempt_id)
            self.assertIsNotNone(attempt)
            assert attempt is not None
            self.assertEqual(attempt["state"], "VERIFIED_EFFECT")
            self.assertEqual(attempt["token_id"], result.authorization.token_id)
            self.assertEqual(reopened.state(result.authorization.token_id), "CONSUMED")
            event_types = [row["event_type"] for row in reopened.pending_outbox()]
            self.assertEqual(
                event_types,
                [
                    "REQUEST_CLAIMED",
                    "AUTHORIZATION_ISSUED",
                    "ATTEMPT_RESERVED",
                    "AUTHORIZATION_CONSUMED",
                    "ADAPTER_RECEIPT_RECORDED",
                    "ATTEMPT_TERMINAL",
                    "REQUEST_TERMINAL",
                ],
            )
            for row in reopened.pending_outbox():
                self.assertEqual(
                    set(row),
                    {
                        "event_id",
                        "event_type",
                        "subject_id",
                        "payload_sha256",
                        "created_at",
                        "exported_at",
                    },
                )

    def test_outbox_deletion_and_malformed_rows_fail_closed_on_reopen(self) -> None:
        corruptions = {
            "middle deletion": ("DELETE FROM audit_outbox WHERE event_id=4", ()),
            "tail deletion": (
                "DELETE FROM audit_outbox WHERE event_id=(SELECT MAX(event_id) FROM audit_outbox)",
                (),
            ),
            "identifier mutation": (
                "UPDATE audit_outbox SET event_id=99 WHERE event_id=4",
                (),
            ),
            "empty event type": (
                "UPDATE audit_outbox SET event_type='' WHERE event_id=1",
                (),
            ),
            "empty subject": (
                "UPDATE audit_outbox SET subject_id='' WHERE event_id=1",
                (),
            ),
            "invalid payload digest": (
                "UPDATE audit_outbox SET payload_sha256='invalid' WHERE event_id=1",
                (),
            ),
            "invalid creation time": (
                "UPDATE audit_outbox SET created_at='invalid' WHERE event_id=1",
                (),
            ),
            "invalid export time": (
                "UPDATE audit_outbox SET exported_at='invalid' WHERE event_id=1",
                (),
            ),
            "export precedes creation": (
                "UPDATE audit_outbox SET exported_at='2000-01-01T00:00:00+00:00' WHERE event_id=1",
                (),
            ),
        }
        for label, (statement, parameters) in corruptions.items():
            with (
                self.subTest(corruption=label),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                self._completed_durable_case(
                    root, request_id=f"P3-STAGE-A-OUTBOX-{len(label)}"
                )
                path = root / "control.sqlite3"
                with closing(sqlite3.connect(path)) as connection:
                    connection.execute("PRAGMA ignore_check_constraints=ON")
                    connection.execute(statement, parameters)
                    connection.commit()
                before = path.read_bytes()

                with self.assertRaises(ControlLedgerError) as raised:
                    SQLiteControlLedger(path)
                self.assertEqual(raised.exception.reason_code, "CONTROL_LEDGER_CORRUPT")
                self.assertEqual(path.read_bytes(), before)

    def test_valid_looking_outbox_forgery_and_reordering_fail_closed(self) -> None:
        corruptions = {
            "forged event type": (
                "UPDATE audit_outbox SET event_type='FORGED_EVENT' WHERE event_id=1",
            ),
            "forged subject": (
                "UPDATE audit_outbox SET subject_id='FORGED_SUBJECT' WHERE event_id=1",
            ),
            "valid forged digest": (
                f"UPDATE audit_outbox SET payload_sha256='{'0' * 64}' WHERE event_id=1",
            ),
            "valid mismatched time": (
                "UPDATE audit_outbox SET created_at='2035-01-01T00:00:00+00:00' WHERE event_id=1",
            ),
            "advanced sequence": (
                "UPDATE sqlite_sequence SET seq=99 WHERE name='audit_outbox'",
            ),
            "swapped transition order": (
                "UPDATE audit_outbox SET event_id=-1 WHERE event_id=3",
                "UPDATE audit_outbox SET event_id=3 WHERE event_id=4",
                "UPDATE audit_outbox SET event_id=4 WHERE event_id=-1",
            ),
        }
        for label, statements in corruptions.items():
            with (
                self.subTest(corruption=label),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory).resolve()
                self._completed_durable_case(
                    root, request_id=f"P3-STAGE-A-OUTBOX-FORGE-{len(label)}"
                )
                path = root / "control.sqlite3"
                with closing(sqlite3.connect(path)) as connection:
                    for statement in statements:
                        connection.execute(statement)
                    connection.commit()
                before = path.read_bytes()

                with self.assertRaises(ControlLedgerError) as raised:
                    SQLiteControlLedger(path)
                self.assertEqual(raised.exception.reason_code, "CONTROL_LEDGER_CORRUPT")
                self.assertEqual(path.read_bytes(), before)

    def test_attempt_idempotency_binding_is_independent_of_attempt_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            harness = new_harness(control_ledger_path=path)
            result = harness.firewall.process_json(
                request_json(
                    workstation_case(
                        harness, request_id="P3-STAGE-A-STABLE-IDEMPOTENCY"
                    )
                ),
                credential=harness.soc_credential,
            )
            self.assertIsNotNone(result.authorization)
            self.assertIsNotNone(result.broker_result)
            assert result.authorization is not None
            assert result.broker_result is not None

            reopened = SQLiteControlLedger(path)
            attempt = reopened.attempt_snapshot(result.broker_result.attempt_id)
            self.assertIsNotNone(attempt)
            assert attempt is not None
            expected_binding = {
                "token_id": result.authorization.token_id,
                "request_id": result.authorization.request_id,
                "decision_id": result.authorization.decision_id,
                "agent_id": result.authorization.agent_id,
                "command": {
                    "type": result.authorization.action_type,
                    "target": result.authorization.target_id,
                    "parameters": result.authorization.permitted_parameters,
                },
                "policy_id": result.authorization.policy_id,
                "policy_version": result.authorization.policy_version,
                "policy_sha256": result.authorization.policy_sha256,
                "decision_context_sha256": (
                    result.authorization.decision_context_sha256
                ),
                "target_state_sha256": result.broker_result.state_before_sha256,
            }
            self.assertEqual(attempt["binding_sha256"], sha256_json(expected_binding))
            self.assertNotEqual(
                attempt["binding_sha256"],
                sha256_json(
                    {
                        **expected_binding,
                        "attempt_id": result.broker_result.attempt_id,
                    }
                ),
            )

            # A different random attempt identifier cannot bypass the stable
            # idempotency binding, and the losing transaction leaves its token
            # issued and creates no attempt.
            reopened.register(
                "AUTH-STABLE-IDEMPOTENCY-RETRY",
                verification_id="VERIFY-STABLE-IDEMPOTENCY-RETRY",
                decision_id="DECISION-STABLE-IDEMPOTENCY-RETRY",
                issued_at="2026-08-15T22:29:00+00:00",
            )
            with self.assertRaises(ControlLedgerError) as conflict:
                reopened.consume_once(
                    "AUTH-STABLE-IDEMPOTENCY-RETRY",
                    attempt_id="ATTEMPT-DIFFERENT-RANDOM-ID",
                    attempt_binding_sha256=str(attempt["binding_sha256"]),
                    consumed_at="2026-08-15T22:30:00+00:00",
                )
            self.assertEqual(
                conflict.exception.reason_code, "ATTEMPT_IDEMPOTENCY_CONFLICT"
            )
            self.assertEqual(reopened.state("AUTH-STABLE-IDEMPOTENCY-RETRY"), "ISSUED")
            self.assertIsNone(reopened.attempt_snapshot("ATTEMPT-DIFFERENT-RANDOM-ID"))

    def test_no_effect_broker_failure_is_not_recorded_as_completed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            harness = new_harness(
                control_ledger_path=path,
                fault_modes={"WORKSTATION_042": "FAILED"},
            )
            result = harness.firewall.process_json(
                request_json(
                    workstation_case(harness, request_id="P3-STAGE-A-FAILED-NO-EFFECT")
                ),
                credential=harness.soc_credential,
            )
            self.assertIsNotNone(result.authorization)
            self.assertIsNotNone(result.broker_result)
            assert result.broker_result is not None
            self.assertFalse(result.broker_result.reported_success)
            self.assertEqual(
                result.final_state["network_state"],
                "connected",
            )

            attempt = SQLiteControlLedger(path).attempt_snapshot(
                result.broker_result.attempt_id
            )
            self.assertIsNotNone(attempt)
            assert attempt is not None
            self.assertEqual(attempt["state"], "FAILED_NO_EFFECT")

    def test_incomplete_attempt_recovers_to_unknown_and_never_reopens_token(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            ledger = SQLiteControlLedger(path)
            ledger.register(
                "AUTH-RECOVERY",
                verification_id="VERIFY-RECOVERY",
                decision_id="DECISION-RECOVERY",
                issued_at="2026-08-15T22:29:00+00:00",
            )
            ledger.consume_once(
                "AUTH-RECOVERY",
                attempt_id="ATTEMPT-RECOVERY",
                attempt_binding_sha256="b" * 64,
                consumed_at="2026-08-15T22:30:00+00:00",
            )

            reopened = SQLiteControlLedger(path)
            self.assertEqual(
                reopened.recover_incomplete_attempts(operator_asserted_quiesced=True),
                1,
            )
            self.assertEqual(
                reopened.recover_incomplete_attempts(operator_asserted_quiesced=True),
                0,
            )
            attempt = reopened.attempt_snapshot("ATTEMPT-RECOVERY")
            assert attempt is not None
            self.assertEqual(attempt["state"], "UNKNOWN_EFFECT")
            self.assertEqual(reopened.state("AUTH-RECOVERY"), "CONSUMED")
            with self.assertRaises(ControlLedgerError) as replay:
                reopened.consume_once("AUTH-RECOVERY")
            self.assertEqual(replay.exception.reason_code, "AUTHORIZATION_REPLAY")

    def test_post_effect_ledger_failure_is_honest_and_recovers_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "control.sqlite3"
            adapter_path = root / "adapter.sqlite3"
            audit_path = root / "audit.jsonl"
            harness = new_harness(
                control_ledger_path=path,
                synthetic_adapter_path=adapter_path,
                audit_path=audit_path,
            )
            before = harness.firewall.observer.observe("WORKSTATION_042")
            original = SQLiteControlLedger.record_adapter_receipt
            raw = request_json(
                workstation_case(
                    harness, request_id="P3-STAGE-A-POST-EFFECT-LEDGER-FAIL"
                )
            )

            def fail_outcome_commit(*args, **kwargs):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_UNAVAILABLE", "Injected post-effect failure."
                )

            with patch.object(
                SQLiteControlLedger,
                "record_adapter_receipt",
                new=fail_outcome_commit,
            ):
                result = harness.firewall.process_json(
                    raw,
                    credential=harness.soc_credential,
                )

            after = harness.firewall.observer.observe("WORKSTATION_042")
            self.assertNotEqual(after, before)
            self.assertIsNone(result.broker_result)
            self.assertIsNotNone(result.authorization)
            self.assertIsNotNone(result.verification)
            assert result.authorization is not None
            assert result.verification is not None
            self.assertEqual(result.verification.status, "ROLLBACK_REQUIRED")
            self.assertTrue(result.verification.rollback_required)
            self.assertIn("BROKER_INTERNAL_FAILURE", result.verification.reason_codes)

            reopened = SQLiteControlLedger(path)
            attempt = reopened.attempt_snapshot(result.verification.attempt_id)
            self.assertIsNotNone(attempt)
            assert attempt is not None
            self.assertEqual(attempt["state"], "RESERVED")
            self.assertEqual(reopened.state(result.authorization.token_id), "CONSUMED")
            recovery_harness = new_harness(
                now=harness.clock(),
                control_ledger_path=path,
                synthetic_adapter_path=adapter_path,
                audit_path=audit_path,
            )
            recovered = recovery_harness.firewall.reconcile_request(
                raw,
                credential=recovery_harness.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertIsNotNone(recovered)
            assert recovered is not None
            self.assertEqual(recovered.disposition, "UNKNOWN_EFFECT")
            self.assertEqual(
                reopened.attempt_snapshot(result.verification.attempt_id)["state"],
                "UNKNOWN_EFFECT",
            )

            # Restore-call shape remains covered independently by the success path.
            self.assertTrue(callable(original))

    def test_verified_decision_can_issue_only_once_across_restart(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            SQLiteControlLedger(path).register(
                "AUTH-FIRST",
                verification_id="VERIFY-ONE",
                decision_id="DECISION-ONE",
            )
            reopened = SQLiteControlLedger(path)
            with self.assertRaises(ControlLedgerError) as replay:
                reopened.register(
                    "AUTH-SECOND",
                    verification_id="VERIFY-ONE",
                    decision_id="DECISION-ONE",
                )
            self.assertEqual(
                replay.exception.reason_code, "AUTHORIZATION_DECISION_REPLAY"
            )

    def test_database_lock_timeout_denies_without_authorization_or_effect(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            path = root / "control.sqlite3"
            harness = new_harness(
                control_ledger_path=path, control_ledger_busy_timeout_ms=50
            )
            blocker = sqlite3.connect(path, isolation_level=None)
            blocker.execute("BEGIN IMMEDIATE")
            try:
                result = harness.firewall.process_json(
                    request_json(
                        workstation_case(
                            harness, request_id="P3-STAGE-A-LOCKED-DATABASE"
                        )
                    ),
                    credential=harness.soc_credential,
                )
            finally:
                blocker.rollback()
                blocker.close()

            self.assertEqual(result.decision.outcome, "DENY")
            self.assertIn("CONTROL_LEDGER_UNAVAILABLE", result.decision.reason_codes)
            self.assertIsNone(result.authorization)
            self.assertIsNone(result.broker_result)
            self.assertEqual(
                harness.firewall.observer.observe("WORKSTATION_042")["network_state"],
                "connected",
            )

    def test_process_concurrency_yields_one_request_claim(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory).resolve() / "control.sqlite3")
            SQLiteControlLedger(path)
            context = multiprocessing.get_context("spawn")
            worker_count = 5
            barrier = context.Barrier(worker_count)
            results = context.Queue()
            processes = [
                context.Process(target=_claim_worker, args=(path, barrier, results))
                for _ in range(worker_count)
            ]
            for process in processes:
                process.start()
            observed = [results.get(timeout=15) for _ in processes]
            for process in processes:
                process.join(timeout=15)
                self.assertEqual(process.exitcode, 0)

            self.assertEqual(observed.count(("OK", "NEW")), 1)
            self.assertEqual(observed.count(("OK", "DUPLICATE")), worker_count - 1)

    def test_direct_store_first_creation_is_process_serialized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            context = multiprocessing.get_context("spawn")
            cases = (
                (
                    "control",
                    _control_first_create_worker,
                    (str(root / "control-first.sqlite3"),),
                ),
                (
                    "adapter",
                    _adapter_first_create_worker,
                    (str(root / "adapter-first.sqlite3"),),
                ),
            )
            for label, worker, fixed_args in cases:
                with self.subTest(store=label):
                    worker_count = 4
                    barrier = context.Barrier(worker_count)
                    results = context.Queue()
                    processes = [
                        context.Process(
                            target=worker,
                            args=(*fixed_args, barrier, results),
                        )
                        for _index in range(worker_count)
                    ]
                    for process in processes:
                        process.start()
                    observed = [results.get(timeout=15) for _ in processes]
                    for process in processes:
                        process.join(timeout=15)
                        self.assertEqual(process.exitcode, 0)
                    self.assertTrue(all(row[0] == "OK" for row in observed), observed)
                    self.assertEqual(len({row[1] for row in observed}), 1, observed)

    def test_process_concurrency_reserves_one_attempt_and_consumes_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory).resolve() / "control.sqlite3")
            ledger = SQLiteControlLedger(path)
            ledger.register(
                "AUTH-CONCURRENT",
                verification_id="VERIFY-CONCURRENT",
                decision_id="DECISION-CONCURRENT",
                issued_at="2026-08-15T22:29:00+00:00",
            )
            context = multiprocessing.get_context("spawn")
            worker_count = 4
            barrier = context.Barrier(worker_count)
            results = context.Queue()
            processes = [
                context.Process(
                    target=_consume_worker,
                    args=(path, f"ATTEMPT-{index}", barrier, results),
                )
                for index in range(worker_count)
            ]
            for process in processes:
                process.start()
            observed = [results.get(timeout=15) for _ in processes]
            for process in processes:
                process.join(timeout=15)
                self.assertEqual(process.exitcode, 0)

            successes = [row for row in observed if row[0] == "OK"]
            blocked = [row for row in observed if row[0] == "BLOCKED"]
            self.assertEqual(len(successes), 1)
            self.assertEqual(len(blocked), worker_count - 1)
            self.assertTrue(
                all(row[1] == "AUTHORIZATION_REPLAY" for row in blocked), observed
            )
            reopened = SQLiteControlLedger(path)
            self.assertEqual(reopened.state("AUTH-CONCURRENT"), "CONSUMED")
            attempt_rows = [
                reopened.attempt_snapshot(f"ATTEMPT-{index}")
                for index in range(worker_count)
            ]
            self.assertEqual(sum(row is not None for row in attempt_rows), 1)

    def test_symlink_database_path_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real = root / "real.sqlite3"
            SQLiteControlLedger(real)
            alias = root / "alias.sqlite3"
            alias.symlink_to(real)
            with self.assertRaises(ControlLedgerError) as raised:
                SQLiteControlLedger(alias)
            self.assertEqual(raised.exception.reason_code, "CONTROL_LEDGER_PATH_UNSAFE")

    def test_symlink_database_parent_is_rejected_without_creating_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real_parent = root / "real-parent"
            real_parent.mkdir()
            alias_parent = root / "alias-parent"
            alias_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaises(ControlLedgerError) as raised:
                SQLiteControlLedger(alias_parent / "control.sqlite3")
            self.assertEqual(raised.exception.reason_code, "CONTROL_LEDGER_PATH_UNSAFE")
            self.assertFalse((real_parent / "control.sqlite3").exists())

    def test_audit_and_control_ledger_paths_must_not_alias(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            shared = root / "shared-state"
            with self.assertRaises(ValueError) as exact_collision:
                new_harness(audit_path=shared, control_ledger_path=shared)
            self.assertIn("distinct files", str(exact_collision.exception))
            self.assertFalse(shared.exists())

            real_parent = root / "real-state"
            real_parent.mkdir()
            alias_parent = root / "alias-state"
            alias_parent.symlink_to(real_parent, target_is_directory=True)
            audit_path = real_parent / "aliased-state"
            control_path = alias_parent / "aliased-state"
            with self.assertRaises(ValueError) as ancestor_collision:
                new_harness(
                    audit_path=audit_path,
                    control_ledger_path=control_path,
                )
            self.assertIn("symbolic links", str(ancestor_collision.exception))
            self.assertFalse(audit_path.exists())

    def test_cross_store_missing_receipt_blocks_reopen_and_live_terminal_lookup(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness = new_harness(
                audit_path=root / "audit.jsonl",
                control_ledger_path=root / "control.sqlite3",
                synthetic_adapter_path=root / "adapter.sqlite3",
            )
            with closing(sqlite3.connect(root / "adapter.sqlite3")) as connection:
                initial = connection.execute(
                    """
                    SELECT state_json, state_sha256, updated_at
                    FROM target_states WHERE target_id='WORKSTATION_042'
                    """
                ).fetchone()
            raw = request_json(
                workstation_case(harness, request_id="P3-STAGE-A-MISSING-RECEIPT")
            )
            harness.firewall.process_json(raw, credential=harness.soc_credential)
            with closing(sqlite3.connect(root / "adapter.sqlite3")) as connection:
                connection.execute("DELETE FROM command_receipts")
                connection.execute(
                    """
                    UPDATE target_states
                    SET state_json=?, state_sha256=?, updated_at=?
                    WHERE target_id='WORKSTATION_042'
                    """,
                    initial,
                )
                connection.commit()

            with self.assertRaises(ControlLedgerError) as live:
                harness.firewall.lookup_request_result(
                    raw, credential=harness.soc_credential
                )
            self.assertEqual(
                live.exception.reason_code, "DURABLE_STORE_CORRELATION_INVALID"
            )
            with self.assertRaises(ControlLedgerError) as reopened:
                new_harness(
                    audit_path=root / "audit.jsonl",
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
            self.assertEqual(
                reopened.exception.reason_code,
                "DURABLE_STORE_CORRELATION_INVALID",
            )

    def test_cross_store_overlapping_provenance_substitution_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._completed_durable_case(
                root, request_id="P3-STAGE-A-PROVENANCE-SUBSTITUTION"
            )
            replacement = "c" * 64
            with closing(sqlite3.connect(root / "control.sqlite3")) as connection:
                attempt = connection.execute(
                    """
                    SELECT attempt_id, recovery_summary_json, state,
                           adapter_receipt_sha256
                    FROM attempts
                    """
                ).fetchone()
                result_row = connection.execute(
                    "SELECT result_json FROM request_results"
                ).fetchone()
                summary = json.loads(attempt[1])
                summary["decision_context_sha256"] = replacement
                summary_json = canonical_json(summary)
                result_value = json.loads(result_row[0])
                result_value["decision_context_sha256"] = replacement
                result = RequestLookupResult.from_dict(result_value)
                result_json = canonical_json(result.to_dict())
                result_sha256 = hashlib.sha256(result_json.encode()).hexdigest()
                outcome_sha256 = terminal_attempt_outcome_sha256(
                    result, "VERIFIED_EFFECT"
                )
                connection.execute(
                    """
                    UPDATE attempts
                    SET recovery_summary_json=?, recovery_summary_sha256=?,
                        outcome_sha256=?
                    WHERE attempt_id=?
                    """,
                    (
                        summary_json,
                        hashlib.sha256(summary_json.encode()).hexdigest(),
                        outcome_sha256,
                        attempt[0],
                    ),
                )
                connection.execute(
                    """
                    UPDATE request_results SET result_json=?, result_sha256=?
                    """,
                    (result_json, result_sha256),
                )
                connection.execute(
                    """
                    UPDATE audit_outbox SET payload_sha256=?
                    WHERE event_type='ATTEMPT_TERMINAL' AND subject_id=?
                    """,
                    (
                        _outbox_digest(
                            "ATTEMPT_TERMINAL",
                            attempt[0],
                            {
                                "state": attempt[2],
                                "outcome_sha256": outcome_sha256,
                                "adapter_receipt_sha256": attempt[3],
                            },
                        ),
                        attempt[0],
                    ),
                )
                connection.execute(
                    """
                    UPDATE audit_outbox SET payload_sha256=?
                    WHERE event_type='REQUEST_TERMINAL' AND subject_id=?
                    """,
                    (
                        _outbox_digest(
                            "REQUEST_TERMINAL",
                            f"{result.principal_id}:{result.request_id}",
                            {
                                "result_sha256": result_sha256,
                                "disposition": result.disposition,
                            },
                        ),
                        f"{result.principal_id}:{result.request_id}",
                    ),
                )
                connection.commit()
            with self.assertRaises(ControlLedgerError) as raised:
                new_harness(
                    audit_path=root / "audit.jsonl",
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
            self.assertEqual(
                raised.exception.reason_code, "DURABLE_STORE_CORRELATION_INVALID"
            )

    def test_cross_store_terminal_target_substitution_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._completed_durable_case(
                root, request_id="P3-STAGE-A-TARGET-SUBSTITUTION"
            )
            with closing(sqlite3.connect(root / "control.sqlite3")) as connection:
                attempt_id, attempt_state, adapter_receipt_sha256, result_json = (
                    connection.execute(
                        """
                    SELECT a.attempt_id, a.state, a.adapter_receipt_sha256,
                           x.result_json
                    FROM attempts a CROSS JOIN request_results x
                    """
                    ).fetchone()
                )
                result_value = json.loads(result_json)
                result_value["target_state_sha256"] = "d" * 64
                result = RequestLookupResult.from_dict(result_value)
                changed_json = canonical_json(result.to_dict())
                changed_result_sha256 = hashlib.sha256(
                    changed_json.encode()
                ).hexdigest()
                changed_outcome_sha256 = terminal_attempt_outcome_sha256(
                    result, "VERIFIED_EFFECT"
                )
                connection.execute(
                    "UPDATE request_results SET result_json=?, result_sha256=?",
                    (
                        changed_json,
                        changed_result_sha256,
                    ),
                )
                connection.execute(
                    "UPDATE attempts SET outcome_sha256=? WHERE attempt_id=?",
                    (
                        changed_outcome_sha256,
                        attempt_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE audit_outbox SET payload_sha256=?
                    WHERE event_type='ATTEMPT_TERMINAL' AND subject_id=?
                    """,
                    (
                        _outbox_digest(
                            "ATTEMPT_TERMINAL",
                            attempt_id,
                            {
                                "state": attempt_state,
                                "outcome_sha256": changed_outcome_sha256,
                                "adapter_receipt_sha256": adapter_receipt_sha256,
                            },
                        ),
                        attempt_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE audit_outbox SET payload_sha256=?
                    WHERE event_type='REQUEST_TERMINAL' AND subject_id=?
                    """,
                    (
                        _outbox_digest(
                            "REQUEST_TERMINAL",
                            f"{result.principal_id}:{result.request_id}",
                            {
                                "result_sha256": changed_result_sha256,
                                "disposition": result.disposition,
                            },
                        ),
                        f"{result.principal_id}:{result.request_id}",
                    ),
                )
                connection.commit()
            with self.assertRaises(ControlLedgerError) as raised:
                new_harness(
                    audit_path=root / "audit.jsonl",
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
            self.assertEqual(
                raised.exception.reason_code, "DURABLE_STORE_CORRELATION_INVALID"
            )

    def test_cross_store_orphan_receipt_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            self._completed_durable_case(root, request_id="P3-STAGE-A-ORPHAN-RECEIPT")
            with closing(sqlite3.connect(root / "control.sqlite3")) as connection:
                connection.execute("PRAGMA foreign_keys=OFF")
                for table in (
                    "request_results",
                    "attempts",
                    "authorizations",
                    "requests",
                    "audit_outbox",
                ):
                    connection.execute(f"DELETE FROM {table}")
                connection.execute(
                    "DELETE FROM sqlite_sequence WHERE name='audit_outbox'"
                )
                connection.commit()
            with self.assertRaises(ControlLedgerError) as raised:
                new_harness(
                    audit_path=root / "audit.jsonl",
                    control_ledger_path=root / "control.sqlite3",
                    synthetic_adapter_path=root / "adapter.sqlite3",
                )
            self.assertEqual(
                raised.exception.reason_code, "DURABLE_STORE_CORRELATION_INVALID"
            )

    def test_recovery_audit_prewrite_failure_suppresses_t3_until_exact_retry(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness, raw = self._crashed_reserved_case(
                root, request_id="P3-STAGE-A-RECOVERY-PREWRITE"
            )
            audit_path = root / "audit.jsonl"
            before = audit_path.read_bytes()
            original_append = AuditLogger.append

            def fail_before_write(logger, record_type, payload):
                if record_type == "RECOVERY_STARTED":
                    raise RuntimeError("injected recovery prewrite failure")
                return original_append(logger, record_type, payload)

            with patch.object(AuditLogger, "append", new=fail_before_write):
                with self.assertRaises(RuntimeError):
                    harness.firewall.reconcile_request(
                        raw,
                        credential=harness.soc_credential,
                        operator_asserted_quiesced=True,
                    )
            self.assertEqual(audit_path.read_bytes(), before)
            self.assertIsNone(
                harness.firewall.lookup_request_result(
                    raw, credential=harness.soc_credential
                )
            )
            recovered = harness.firewall.reconcile_request(
                raw,
                credential=harness.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertIsNotNone(recovered)

    def test_recovery_audit_readback_failure_leaves_exact_retryable_trio(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness, raw = self._crashed_reserved_case(
                root, request_id="P3-STAGE-A-RECOVERY-READBACK"
            )
            original_append = AuditLogger.append
            original_read = AuditLogger.read_all
            state = {"final_appended": False, "failed": False}

            def observe_final_append(logger, record_type, payload):
                row = original_append(logger, record_type, payload)
                if record_type == "RECOVERY_FINALIZED":
                    state["final_appended"] = True
                return row

            def fail_first_final_readback(logger):
                if state["final_appended"] and not state["failed"]:
                    state["failed"] = True
                    raise RuntimeError("injected recovery readback failure")
                return original_read(logger)

            with (
                patch.object(AuditLogger, "append", new=observe_final_append),
                patch.object(AuditLogger, "read_all", new=fail_first_final_readback),
            ):
                with self.assertRaises(RuntimeError):
                    harness.firewall.reconcile_request(
                        raw,
                        credential=harness.soc_credential,
                        operator_asserted_quiesced=True,
                    )
            with closing(sqlite3.connect(root / "control.sqlite3")) as connection:
                self.assertEqual(
                    connection.execute(
                        "SELECT count(*) FROM request_results"
                    ).fetchone()[0],
                    0,
                )
            audit_path = root / "audit.jsonl"
            before_retry = audit_path.read_bytes()
            recovered = harness.firewall.reconcile_request(
                raw,
                credential=harness.soc_credential,
                operator_asserted_quiesced=True,
            )
            self.assertIsNotNone(recovered)
            self.assertEqual(audit_path.read_bytes(), before_retry)

    def test_unlinked_transition_chronology_rejects_past_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            ledger = SQLiteControlLedger(path)
            ledger.register(
                "AUTH-FUTURE",
                verification_id="VERIFY-FUTURE",
                decision_id="DECISION-FUTURE",
                issued_at="2030-01-01T00:00:00+00:00",
            )
            with self.assertRaises(ControlLedgerError) as consume:
                ledger.consume_once(
                    "AUTH-FUTURE",
                    attempt_id="ATTEMPT-PAST",
                    attempt_binding_sha256="a" * 64,
                    consumed_at="2029-01-01T00:00:00+00:00",
                )
            self.assertEqual(
                consume.exception.reason_code, "AUTHORIZATION_TIME_INVALID"
            )
            self.assertEqual(SQLiteControlLedger(path).state("AUTH-FUTURE"), "ISSUED")

            ledger.consume_once(
                "AUTH-FUTURE",
                attempt_id="ATTEMPT-FUTURE",
                attempt_binding_sha256="b" * 64,
                consumed_at="2031-01-01T00:00:00+00:00",
            )
            with self.assertRaises(ControlLedgerError) as terminal:
                ledger.record_attempt_outcome(
                    "ATTEMPT-FUTURE",
                    outcome_state="UNKNOWN_EFFECT",
                    outcome_sha256="c" * 64,
                    completed_at="2030-06-01T00:00:00+00:00",
                )
            self.assertEqual(terminal.exception.reason_code, "ATTEMPT_TIME_INVALID")
            with self.assertRaises(ControlLedgerError) as recovery:
                ledger.recover_incomplete_attempts(operator_asserted_quiesced=True)
            self.assertEqual(recovery.exception.reason_code, "RECOVERY_TIME_INVALID")
            self.assertEqual(
                SQLiteControlLedger(path).attempt_snapshot("ATTEMPT-FUTURE")["state"],
                "RESERVED",
            )

    def test_active_sqlite_sidecars_must_remain_owner_private(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            SQLiteControlLedger(path)
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("PRAGMA wal_autocheckpoint=0")
                connection.execute(
                    """
                    INSERT INTO audit_outbox(
                        event_type, subject_id, payload_sha256, created_at
                    ) VALUES('TEST_EVENT', 'TEST_SUBJECT', ?, ?)
                    """,
                    ("e" * 64, "2030-01-01T00:00:00+00:00"),
                )
                connection.commit()
                wal = Path(str(path) + "-wal")
                shm = Path(str(path) + "-shm")
                self.assertTrue(wal.exists())
                self.assertTrue(shm.exists())
                wal.chmod(0o644)
                shm.chmod(0o644)
                try:
                    with self.assertRaises(ControlLedgerError) as raised:
                        SQLiteControlLedger.preflight_existing(path)
                    self.assertEqual(
                        raised.exception.reason_code, "CONTROL_LEDGER_PATH_UNSAFE"
                    )
                finally:
                    wal.chmod(0o600)
                    shm.chmod(0o600)

    def test_synthetic_adapter_rejects_backdated_effect_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            harness, _raw = self._completed_durable_case(
                root, request_id="P3-STAGE-A-ADAPTER-TIME"
            )
            store = harness.firewall._adapter_store
            assert store is not None
            with closing(sqlite3.connect(root / "adapter.sqlite3")) as connection:
                binding_json = connection.execute(
                    "SELECT binding_json FROM command_receipts"
                ).fetchone()[0]
            binding = json.loads(binding_json)
            binding["request_id"] = "P3-STAGE-A-ADAPTER-TIME-BACKDATED"
            binding["target_state_sha256"] = sha256_json(
                store.observe("WORKSTATION_042")
            )
            idempotency_key = sha256_json(binding)
            before_count = store.receipt_count()
            before_state = store.observe("WORKSTATION_042")
            with self.assertRaises(SyntheticAdapterError) as raised:
                store.execute_once(
                    idempotency_key=idempotency_key,
                    binding=binding,
                    attempt_id="ATTEMPT-BACKDATED",
                    attempted_at="2020-01-01T00:00:00+00:00",
                )
            self.assertEqual(
                raised.exception.reason_code, "SYNTHETIC_ADAPTER_TIME_INVALID"
            )
            self.assertEqual(store.receipt_count(), before_count)
            self.assertEqual(store.observe("WORKSTATION_042"), before_state)

    def test_revoked_authorization_cannot_be_laundered_as_denied(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ledger = SQLiteControlLedger(Path(directory).resolve() / "control.sqlite3")
            principal_id = "SOC_AGENT_01"
            request_id = "P3-STAGE-A-REVOKED-MATRIX"
            request_sha256 = "1" * 64
            ledger.claim_request(
                principal_id,
                request_id,
                request_sha256,
                claimed_at="2030-01-01T00:00:00+00:00",
            )
            ledger.register(
                "AUTH-REVOKED-MATRIX",
                verification_id="VERIFY-REVOKED-MATRIX",
                decision_id="DECISION-REVOKED-MATRIX",
                principal_id=principal_id,
                request_id=request_id,
                request_sha256=request_sha256,
                unsigned_token_sha256="2" * 64,
                issuer_instance_id="ISSUER-REVOKED-MATRIX",
                key_domain_id="KEY-DOMAIN-REVOKED-MATRIX",
                decision_authorization_sha256="3" * 64,
                issued_at="2030-01-01T00:01:00+00:00",
            )
            ledger.revoke_issued_for_request(
                principal_id,
                request_id,
                request_sha256,
                operator_asserted_quiesced=True,
                revoked_at="2030-01-01T00:02:00+00:00",
            )
            denied = RequestLookupResult(
                schema_version=REQUEST_LOOKUP_SCHEMA_VERSION,
                principal_id=principal_id,
                request_id=request_id,
                request_sha256=request_sha256,
                disposition="DENIED_NO_EFFECT",
                decision_id="DECISION-DENIED-MATRIX",
                decision_outcome="DENY",
                decision_sha256="4" * 64,
                decision_context_sha256="5" * 64,
                policy_sha256="6" * 64,
                verification_status="NOT_APPLICABLE",
                verification_sha256=None,
                attempt_id=None,
                adapter_receipt_sha256=None,
                target_state_sha256=None,
                decided_at="2030-01-01T00:01:00+00:00",
                terminal_at="2030-01-01T00:03:00+00:00",
                recovery_required=False,
                reason_codes=("DENIED",),
                replayed=False,
                execution_attempted_this_call=False,
                new_decision=False,
                new_authorization=False,
                new_effect=False,
                authorization=None,
            )
            with self.assertRaises(ControlLedgerError) as raised:
                ledger.complete_request(denied)
            self.assertEqual(
                raised.exception.reason_code, "REQUEST_RESULT_BINDING_INVALID"
            )


if __name__ == "__main__":
    unittest.main()
