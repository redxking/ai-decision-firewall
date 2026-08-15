from __future__ import annotations

from contextlib import closing
import multiprocessing
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adf_poc.phase3.scenarios import request_json
from adf_poc.stage_a import (
    ControlLedgerError,
    SQLiteControlLedger,
)
from adf_poc.utils import sha256_json

from tests.phase3_support import new_harness, workstation_case


def _claim_worker(
    ledger_path: str,
    barrier: multiprocessing.synchronize.Barrier,
    results: multiprocessing.queues.Queue,
) -> None:
    try:
        ledger = SQLiteControlLedger(ledger_path, busy_timeout_ms=5000)
        barrier.wait(timeout=10)
        state = ledger.claim_request(
            "SOC_AGENT_001", "STAGE-A-CONCURRENT", "a" * 64
        )
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


class StageADurableControlLedgerTests(unittest.TestCase):
    def test_schema_durability_permissions_and_unknown_version_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            ledger = SQLiteControlLedger(path)

            self.assertTrue(path.is_file())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with closing(sqlite3.connect(path)) as connection:
                self.assertEqual(
                    str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower(),
                    "wal",
                )
                self.assertEqual(connection.execute("PRAGMA synchronous").fetchone()[0], 2)
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
                self.assertTrue(
                    {"metadata", "requests", "authorizations", "attempts", "audit_outbox"}
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
                workstation_case(
                    first_harness, request_id="P3-STAGE-A-RESTART-REPLAY"
                )
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
            self.assertEqual(attempt["state"], "COMPLETED")
            self.assertEqual(attempt["token_id"], result.authorization.token_id)
            self.assertEqual(
                reopened.state(result.authorization.token_id), "CONSUMED"
            )
            event_types = [row["event_type"] for row in reopened.pending_outbox()]
            self.assertEqual(
                event_types,
                [
                    "REQUEST_CLAIMED",
                    "AUTHORIZATION_ISSUED",
                    "ATTEMPT_RESERVED",
                    "AUTHORIZATION_CONSUMED",
                    "ATTEMPT_TERMINAL",
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
            self.assertEqual(
                reopened.state("AUTH-STABLE-IDEMPOTENCY-RETRY"), "ISSUED"
            )
            self.assertIsNone(
                reopened.attempt_snapshot("ATTEMPT-DIFFERENT-RANDOM-ID")
            )

    def test_no_effect_broker_failure_is_not_recorded_as_completed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            harness = new_harness(
                control_ledger_path=path,
                fault_modes={"WORKSTATION_042": "FAILED"},
            )
            result = harness.firewall.process_json(
                request_json(
                    workstation_case(
                        harness, request_id="P3-STAGE-A-FAILED-NO-EFFECT"
                    )
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

    def test_incomplete_attempt_recovers_to_unknown_and_never_reopens_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            ledger = SQLiteControlLedger(path)
            ledger.register(
                "AUTH-RECOVERY",
                verification_id="VERIFY-RECOVERY",
                decision_id="DECISION-RECOVERY",
            )
            ledger.consume_once(
                "AUTH-RECOVERY",
                attempt_id="ATTEMPT-RECOVERY",
                attempt_binding_sha256="b" * 64,
                consumed_at="2026-08-15T22:30:00+00:00",
            )

            reopened = SQLiteControlLedger(path)
            self.assertEqual(reopened.recover_incomplete_attempts(), 1)
            self.assertEqual(reopened.recover_incomplete_attempts(), 0)
            attempt = reopened.attempt_snapshot("ATTEMPT-RECOVERY")
            assert attempt is not None
            self.assertEqual(attempt["state"], "UNKNOWN_EFFECT")
            self.assertEqual(reopened.state("AUTH-RECOVERY"), "CONSUMED")
            with self.assertRaises(ControlLedgerError) as replay:
                reopened.consume_once("AUTH-RECOVERY")
            self.assertEqual(replay.exception.reason_code, "AUTHORIZATION_REPLAY")

    def test_post_effect_ledger_failure_is_honest_and_recovers_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "control.sqlite3"
            harness = new_harness(control_ledger_path=path)
            before = harness.firewall.observer.observe("WORKSTATION_042")
            original = SQLiteControlLedger.record_attempt_outcome

            def fail_outcome_commit(*args, **kwargs):
                raise ControlLedgerError(
                    "CONTROL_LEDGER_UNAVAILABLE", "Injected post-effect failure."
                )

            with patch.object(
                SQLiteControlLedger,
                "record_attempt_outcome",
                new=fail_outcome_commit,
            ):
                result = harness.firewall.process_json(
                    request_json(
                        workstation_case(
                            harness, request_id="P3-STAGE-A-POST-EFFECT-LEDGER-FAIL"
                        )
                    ),
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
            self.assertEqual(reopened.recover_incomplete_attempts(), 1)
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

    def test_process_concurrency_reserves_one_attempt_and_consumes_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory).resolve() / "control.sqlite3")
            ledger = SQLiteControlLedger(path)
            ledger.register(
                "AUTH-CONCURRENT",
                verification_id="VERIFY-CONCURRENT",
                decision_id="DECISION-CONCURRENT",
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
            self.assertEqual(
                raised.exception.reason_code, "CONTROL_LEDGER_PATH_UNSAFE"
            )

    def test_symlink_database_parent_is_rejected_without_creating_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            real_parent = root / "real-parent"
            real_parent.mkdir()
            alias_parent = root / "alias-parent"
            alias_parent.symlink_to(real_parent, target_is_directory=True)

            with self.assertRaises(ControlLedgerError) as raised:
                SQLiteControlLedger(alias_parent / "control.sqlite3")
            self.assertEqual(
                raised.exception.reason_code, "CONTROL_LEDGER_PATH_UNSAFE"
            )
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
            self.assertIn("distinct files", str(ancestor_collision.exception))
            self.assertFalse(audit_path.exists())


if __name__ == "__main__":
    unittest.main()
