from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any, Callable
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.phase3.approval import ApprovalError
from adf_poc.phase3.audit import validate_phase3_lifecycle
from adf_poc.phase3.authorization import AuthorizationError
from adf_poc.phase3.config import Phase3PolicyConfig, PolicyValidationError
from adf_poc.phase3.contracts import AuthenticatedPrincipal
from adf_poc.phase3.engine import Phase3DecisionFirewall
from adf_poc.phase3.identity import TrustedPrincipalResolver
from adf_poc.phase3.scenarios import (
    request_json,
    synthetic_invocation_credential,
    trusted_soc_principal,
)
from adf_poc.utils import sha256_json

from tests.phase3_support import (
    INVOCATION_MASTER_KEY,
    POLICY_PATH,
    TEST_SIGNING_KEY,
    DeterministicIdFactory,
    domain_controller_case,
    mint_unconsumed_authorization,
    new_harness,
    resign_evidence,
    workstation_case,
)


class HostileString(str):
    pass


class HostileInteger(int):
    pass


class HostileBytes(bytes):
    pass


class PrefixFailingIdFactory:
    def __init__(self, prefix: str, *, invalid_once: bool = False) -> None:
        self.prefix = prefix
        self.invalid_once = invalid_once
        self.failed = False
        self.counter = 0

    def __call__(self, prefix: str) -> str:
        self.counter += 1
        if prefix == self.prefix and not self.failed:
            self.failed = True
            if self.invalid_once:
                return ""
            raise RuntimeError(f"injected {prefix} allocation failure")
        return f"{prefix}-release-blocker-{self.counter:05d}"


class NthFailingClock:
    def __init__(self, value: datetime, fail_on_call: int) -> None:
        self.value = value.astimezone(timezone.utc).replace(microsecond=0)
        self.fail_on_call = fail_on_call
        self.calls = 0

    def __call__(self) -> datetime:
        self.calls += 1
        if self.calls == self.fail_on_call:
            raise RuntimeError(f"injected clock failure {self.fail_on_call}")
        return self.value


def _new_firewall(
    harness,
    *,
    signing_key: bytes = TEST_SIGNING_KEY,
    source_keys: dict[str, bytes] | None = None,
    resolver: TrustedPrincipalResolver | None = None,
    clock: Callable[[], datetime] | None = None,
    id_factory: Callable[[str], str] | None = None,
) -> Phase3DecisionFirewall:
    return Phase3DecisionFirewall(
        policy=harness.policy,
        signing_key=signing_key,
        evidence_attestation_keys=source_keys or harness.source_keys,
        principal_resolver=resolver or harness.resolver,
        clock=clock or harness.clock,
        id_factory=id_factory or DeterministicIdFactory(),
    )


def _approval_values(harness, requirement) -> dict[str, object]:
    return {
        "requirement": requirement,
        "credential": harness.human_credential,
        "action_type": requirement.action_type,
        "target_id": requirement.target_id,
        "parameters": {
            "duration_seconds": 900,
            "preserve_management": True,
        },
        "evidence_sha256": requirement.evidence_sha256,
    }


def _payload(rows: list[dict[str, Any]], record_type: str) -> dict[str, Any]:
    return next(row["payload"] for row in rows if row["record_type"] == record_type)


def _rehash(rows: list[dict[str, Any]]) -> None:
    previous_hash = "0" * 64
    for sequence, row in enumerate(rows):
        row["sequence"] = sequence
        row["previous_hash"] = previous_hash
        row.pop("record_hash", None)
        row["record_hash"] = sha256_json(row)
        previous_hash = str(row["record_hash"])


class Phase3TrustMaterialReleaseBlockers(unittest.TestCase):
    def test_evidence_keys_require_exact_bytes_values(self) -> None:
        harness = new_harness()
        source_id = next(iter(harness.source_keys))
        for value in (
            bytearray(harness.source_keys[source_id]),
            memoryview(harness.source_keys[source_id]),
            HostileBytes(harness.source_keys[source_id]),
            harness.source_keys[source_id].hex(),
        ):
            with self.subTest(value_type=type(value).__name__):
                keys = dict(harness.source_keys)
                keys[source_id] = value  # type: ignore[assignment]
                with self.assertRaises(TypeError):
                    _new_firewall(harness, source_keys=keys)

    def test_signing_evidence_and_invocation_domains_cannot_reuse_keys(self) -> None:
        harness = new_harness()
        source_id = next(iter(harness.source_keys))

        signing_reused_as_evidence = dict(harness.source_keys)
        signing_reused_as_evidence[source_id] = TEST_SIGNING_KEY
        invocation_reused_as_evidence = dict(harness.source_keys)
        invocation_reused_as_evidence[source_id] = harness.soc_credential

        cases = (
            {
                "signing_key": TEST_SIGNING_KEY,
                "source_keys": signing_reused_as_evidence,
            },
            {
                "signing_key": TEST_SIGNING_KEY,
                "source_keys": invocation_reused_as_evidence,
            },
            {
                "signing_key": harness.soc_credential,
                "source_keys": harness.source_keys,
            },
        )
        for index, values in enumerate(cases, start=1):
            with self.subTest(case=index), self.assertRaises(ValueError):
                _new_firewall(harness, **values)

    def test_resolver_rejects_ambiguous_duplicate_principal_ids(self) -> None:
        principal = trusted_soc_principal()
        downgraded = principal.to_dict()
        downgraded["authority"] = []
        alternate = AuthenticatedPrincipal.from_dict(downgraded)
        alternate_credential = synthetic_invocation_credential(
            INVOCATION_MASTER_KEY + b"-alternate", alternate
        )

        with self.assertRaisesRegex(ValueError, "identifiers"):
            TrustedPrincipalResolver(
                (
                    (b"primary-principal-credential".ljust(32, b"!"), principal),
                    (alternate_credential, alternate),
                )
            )


class Phase3AuditSemanticReleaseBlockers(unittest.TestCase):
    def test_rehashed_executed_lifecycle_rejects_every_semantic_rewrite(
        self,
    ) -> None:
        harness = new_harness()
        state_before = harness.firewall.observer.observe("WORKSTATION_042")
        result = harness.firewall.process_json(
            request_json(
                workstation_case(
                    harness,
                    request_id="P3-REHASHED-SEMANTIC-REWRITES",
                )
            ),
            credential=harness.soc_credential,
        )
        baseline = copy.deepcopy(list(result.audit_records))
        baseline_chain_valid, baseline_chain_errors = AuditLogger.verify_rows(baseline)
        baseline_lifecycle_valid, baseline_lifecycle_errors = validate_phase3_lifecycle(
            baseline
        )
        self.assertTrue(baseline_chain_valid, baseline_chain_errors)
        self.assertTrue(baseline_lifecycle_valid, baseline_lifecycle_errors)

        def rewrite_target(rows: list[dict[str, Any]]) -> None:
            _payload(rows, "BROKER_INVOKED")["target_id"] = "WORKSTATION_999"

        def rewrite_action(rows: list[dict[str, Any]]) -> None:
            _payload(rows, "ACTION_ATTEMPTED")["action_type"] = "HOST_SHUTDOWN"

        def rewrite_parameters(rows: list[dict[str, Any]]) -> None:
            _payload(rows, "ACTION_ATTEMPTED")["parameters"] = {
                "duration_seconds": 901,
                "preserve_management": True,
            }

        def rewrite_policy(rows: list[dict[str, Any]]) -> None:
            _payload(rows, "AUTHORIZATION_PRODUCED")["policy_sha256"] = "a" * 64

        def rewrite_context(rows: list[dict[str, Any]]) -> None:
            _payload(rows, "DECISION_VERIFIED")["decision_context_sha256"] = "b" * 64

        def rewrite_state(rows: list[dict[str, Any]]) -> None:
            _payload(rows, "FINAL_STATE_RECORDED")["target_state_sha256"] = "c" * 64

        def rewrite_observed_target(rows: list[dict[str, Any]]) -> None:
            verification = _payload(rows, "VERIFICATION_PERFORMED")
            observed_state = verification["observed_state"]
            observed_state["target_id"] = "WORKSTATION_999"
            rewritten_state_sha256 = sha256_json(observed_state)
            _payload(rows, "ACTION_ATTEMPTED")[
                "state_after_sha256"
            ] = rewritten_state_sha256
            _payload(rows, "FINAL_STATE_RECORDED")[
                "target_state_sha256"
            ] = rewritten_state_sha256

        def rewrite_verified_as_no_effect(rows: list[dict[str, Any]]) -> None:
            state_before_sha256 = sha256_json(state_before)
            action = _payload(rows, "ACTION_ATTEMPTED")
            action["state_after_sha256"] = state_before_sha256
            verification = _payload(rows, "VERIFICATION_PERFORMED")
            verification["observed_state"] = copy.deepcopy(state_before)
            verification["changed_fields"] = ()
            final = _payload(rows, "FINAL_STATE_RECORDED")
            final["operational_effects"] = 0
            final["target_state_sha256"] = state_before_sha256

        def rewrite_authorization_prestate(rows: list[dict[str, Any]]) -> None:
            _payload(rows, "AUTHORIZATION_PRODUCED")["target_state_sha256"] = "d" * 64

        def expire_authorization_before_action(rows: list[dict[str, Any]]) -> None:
            authorization = _payload(rows, "AUTHORIZATION_PRODUCED")
            action = _payload(rows, "ACTION_ATTEMPTED")
            authorization["expires_at"] = action["executed_at"]

        mutations: tuple[tuple[str, Callable[[list[dict[str, Any]]], None]], ...] = (
            ("target_scope", rewrite_target),
            ("action_scope", rewrite_action),
            ("parameter_scope", rewrite_parameters),
            ("policy_binding", rewrite_policy),
            ("decision_context_binding", rewrite_context),
            ("final_state_binding", rewrite_state),
            ("observed_state_target", rewrite_observed_target),
            ("false_verified_no_effect", rewrite_verified_as_no_effect),
            ("authorization_prestate", rewrite_authorization_prestate),
            ("authorization_expiry", expire_authorization_before_action),
        )

        for label, mutate in mutations:
            with self.subTest(label=label):
                rewritten = copy.deepcopy(baseline)
                mutate(rewritten)
                _rehash(rewritten)

                chain_valid, chain_errors = AuditLogger.verify_rows(rewritten)
                lifecycle_valid, lifecycle_errors = validate_phase3_lifecycle(rewritten)

                self.assertTrue(chain_valid, chain_errors)
                self.assertFalse(lifecycle_valid)
                self.assertTrue(lifecycle_errors)


class Phase3PolymorphicInputReleaseBlockers(unittest.TestCase):
    def test_decision_record_rejects_scalar_subclasses_at_all_depths(self) -> None:
        fixture = mint_unconsumed_authorization(new_harness())
        decision = fixture.decision
        permitted = decision.to_dict()["permitted_action"]
        assert isinstance(permitted, dict)

        mutations = (
            {"decision_id": HostileString(decision.decision_id)},
            {
                "requested_action": {
                    "type": HostileString("NETWORK_ISOLATE"),
                    "target": "WORKSTATION_042",
                    "parameters": {
                        "duration_seconds": 900,
                        "preserve_management": True,
                    },
                }
            },
            {
                "permitted_action": {
                    **permitted,
                    "parameters": {
                        "duration_seconds": HostileInteger(900),
                        "preserve_management": True,
                    },
                }
            },
        )
        for mutation in mutations:
            with self.subTest(field=next(iter(mutation))), self.assertRaises(TypeError):
                replace(decision, **mutation)

    def test_broker_rejects_scalar_subclasses_without_consuming_or_effect(self) -> None:
        fixture = mint_unconsumed_authorization(new_harness())
        before = fixture.observer.observe("WORKSTATION_042")
        commands = []

        hostile_target = copy.deepcopy(fixture.command)
        hostile_target["target"] = HostileString(hostile_target["target"])
        commands.append(hostile_target)

        hostile_duration = copy.deepcopy(fixture.command)
        hostile_duration["parameters"]["duration_seconds"] = HostileInteger(900)
        commands.append(hostile_duration)

        for command in commands:
            arguments = fixture.broker_arguments()
            arguments["command"] = command
            with (
                self.subTest(command=command),
                self.assertRaises(AuthorizationError) as raised,
            ):
                fixture.broker.execute(**arguments)
            self.assertEqual(
                getattr(raised.exception, "reason_code", ""),
                "AUTHORIZATION_COMMAND_SHAPE_INVALID",
            )

        self.assertEqual(fixture.gate.ledger.state(fixture.token.token_id), "ISSUED")
        self.assertEqual(fixture.observer.observe("WORKSTATION_042"), before)

    def test_approval_scope_rejects_scalar_subclasses_and_remains_retryable(
        self,
    ) -> None:
        harness = new_harness()
        before = harness.firewall.observer.observe("DOMAIN_CONTROLLER_01")
        result = harness.firewall.process_json(
            request_json(domain_controller_case(harness)),
            credential=harness.credential,
        )
        requirement = result.decision.approval_requirement
        assert requirement is not None
        baseline_audit = harness.firewall.read_audit()
        valid = _approval_values(harness, requirement)

        hostile_action = dict(valid)
        hostile_action["action_type"] = HostileString(requirement.action_type)
        hostile_parameters = copy.deepcopy(valid)
        hostile_parameters["parameters"]["duration_seconds"] = HostileInteger(900)

        for values, expected in (
            (hostile_action, "APPROVAL_SCOPE_TYPE_INVALID"),
            (hostile_parameters, "APPROVAL_PARAMETERS_INVALID"),
        ):
            with (
                self.subTest(expected=expected),
                self.assertRaises(ApprovalError) as raised,
            ):
                harness.firewall.approve_for_reevaluation(**values)
            self.assertEqual(raised.exception.reason_code, expected)
            self.assertEqual(harness.firewall.read_audit(), baseline_audit)

        receipt = harness.firewall.approve_for_reevaluation(**valid)
        self.assertEqual(receipt.status, "APPROVED_FOR_REEVALUATION")
        self.assertEqual(
            harness.firewall.observer.observe("DOMAIN_CONTROLLER_01"), before
        )


class Phase3InjectedFailureReleaseBlockers(unittest.TestCase):
    def _assert_closed_and_reconciled(self, firewall, result) -> None:
        chain_valid, chain_errors = AuditLogger.verify_rows(result.audit_records)
        lifecycle_valid, lifecycle_errors = validate_phase3_lifecycle(
            result.audit_records
        )
        self.assertTrue(chain_valid, chain_errors)
        self.assertTrue(lifecycle_valid, lifecycle_errors)
        metrics = firewall.metrics_snapshot()
        self.assertEqual(metrics["decisions_total"], 1)
        self.assertEqual(metrics["decision_counts"][result.decision.outcome], 1)
        self.assertEqual(sum(metrics["decision_counts"].values()), 1)

    def test_each_identifier_allocation_failure_closes_without_unauthorized_effect(
        self,
    ) -> None:
        expectations = {
            "decision": ("DENY", "DECISION_IDENTIFIER_FAILURE", False),
            "decision-verification": (
                "DENY",
                "DECISION_VERIFIER_INTERNAL_FAILURE",
                False,
            ),
            "auth": ("DENY", "AUTHORIZATION_PRECONDITION_FAILURE", False),
            "nonce": ("DENY", "AUTHORIZATION_PRECONDITION_FAILURE", False),
            "attempt": ("ALLOW", None, False),
            "verify": ("ALLOW", None, True),
        }
        for prefix, (outcome, reason, expected_effect) in expectations.items():
            with self.subTest(prefix=prefix):
                harness = new_harness()
                firewall = _new_firewall(
                    harness, id_factory=PrefixFailingIdFactory(prefix)
                )
                before = firewall.observer.observe("WORKSTATION_042")
                raw = request_json(
                    workstation_case(
                        harness, request_id=f"P3-ID-FAILURE-{prefix.upper()}"
                    )
                )

                result = firewall.process_json(raw, credential=harness.soc_credential)
                after = firewall.observer.observe("WORKSTATION_042")

                self.assertEqual(result.decision.outcome, outcome)
                if reason is not None:
                    self.assertIn(reason, result.decision.reason_codes)
                self.assertEqual(after != before, expected_effect)
                if after != before:
                    self.assertIsNotNone(result.authorization)
                    self.assertIsNotNone(result.broker_result)
                    self.assertIsNotNone(result.verification)
                    assert result.authorization is not None
                    assert result.broker_result is not None
                    assert result.verification is not None
                    self.assertEqual(
                        result.broker_result.token_id,
                        result.authorization.token_id,
                    )
                    self.assertTrue(result.broker_result.accepted)
                    self.assertTrue(result.verification.rollback_required)
                    self.assertIn(
                        "VERIFIER_INTERNAL_FAILURE",
                        result.verification.reason_codes,
                    )
                else:
                    self.assertEqual(after, before)
                self._assert_closed_and_reconciled(firewall, result)

    def test_first_and_second_clock_failures_close_without_effect(self) -> None:
        expected_reasons = {
            1: "REQUEST_VALIDATION_INTERNAL_FAILURE",
            2: "DECISION_VERIFIER_INTERNAL_FAILURE",
        }
        for fail_on_call, reason in expected_reasons.items():
            with self.subTest(fail_on_call=fail_on_call):
                harness = new_harness()
                fixed_now = harness.clock()
                firewall = _new_firewall(
                    harness,
                    clock=NthFailingClock(fixed_now, fail_on_call),
                )
                before = firewall.observer.observe("WORKSTATION_042")
                raw = request_json(
                    workstation_case(
                        harness,
                        request_id=f"P3-CLOCK-FAILURE-{fail_on_call}",
                    )
                )

                result = firewall.process_json(raw, credential=harness.soc_credential)

                self.assertEqual(result.decision.outcome, "DENY")
                self.assertIn(reason, result.decision.reason_codes)
                self.assertIsNone(result.authorization)
                self.assertEqual(firewall.observer.observe("WORKSTATION_042"), before)
                self._assert_closed_and_reconciled(firewall, result)

    def test_post_effect_audit_append_failures_close_conservatively(self) -> None:
        original_append = AuditLogger.append
        for failed_record_type in (
            "ACTION_ATTEMPTED",
            "VERIFICATION_PERFORMED",
            "FINAL_STATE_RECORDED",
        ):
            with self.subTest(failed_record_type=failed_record_type):
                harness = new_harness()
                firewall = harness.firewall
                state_before = firewall.observer.observe("WORKSTATION_042")
                injected_failures: list[dict[str, Any]] = []

                def fail_once_before_append(
                    logger: AuditLogger,
                    record_type: str,
                    payload: dict[str, Any],
                ) -> dict[str, Any]:
                    if record_type == failed_record_type and not injected_failures:
                        injected_failures.append(copy.deepcopy(payload))
                        raise OSError(f"injected {record_type} append failure")
                    return original_append(logger, record_type, payload)

                with patch.object(
                    AuditLogger,
                    "append",
                    new=fail_once_before_append,
                ):
                    result = firewall.process_json(
                        request_json(
                            workstation_case(
                                harness,
                                request_id=(
                                    "P3-POST-EFFECT-AUDIT-" f"{failed_record_type}"
                                ),
                            )
                        ),
                        credential=harness.soc_credential,
                    )

                state_after = firewall.observer.observe("WORKSTATION_042")
                records = list(result.audit_records)
                record_types = [row["record_type"] for row in records]
                accounting = _payload(records, "POST_EFFECT_ACCOUNTING_FAILURE")
                final = _payload(records, "FINAL_STATE_RECORDED")

                self.assertEqual(len(injected_failures), 1)
                self.assertNotEqual(state_after, state_before)
                self.assertEqual(result.final_state, state_after)
                self.assertIsNotNone(result.authorization)
                self.assertIsNotNone(result.broker_result)
                self.assertIsNotNone(result.verification)
                assert result.broker_result is not None
                assert result.verification is not None
                self.assertTrue(result.broker_result.accepted)
                self.assertEqual(result.verification.status, "ROLLBACK_REQUIRED")
                self.assertTrue(result.verification.rollback_required)
                self.assertIn(
                    "POST_EFFECT_ACCOUNTING_FAILURE",
                    result.verification.reason_codes,
                )
                self.assertIn("ROLLBACK_REQUIRED", result.verification.reason_codes)
                expected_tail = {
                    "ACTION_ATTEMPTED": [
                        "AUTHORIZATION_PRODUCED",
                        "BROKER_INVOKED",
                        "POST_EFFECT_ACCOUNTING_FAILURE",
                        "FINAL_STATE_RECORDED",
                    ],
                    "VERIFICATION_PERFORMED": [
                        "AUTHORIZATION_PRODUCED",
                        "BROKER_INVOKED",
                        "ACTION_ATTEMPTED",
                        "POST_EFFECT_ACCOUNTING_FAILURE",
                        "FINAL_STATE_RECORDED",
                    ],
                    "FINAL_STATE_RECORDED": [
                        "AUTHORIZATION_PRODUCED",
                        "BROKER_INVOKED",
                        "ACTION_ATTEMPTED",
                        "VERIFICATION_PERFORMED",
                        "POST_EFFECT_ACCOUNTING_FAILURE",
                        "FINAL_STATE_RECORDED",
                    ],
                }[failed_record_type]
                self.assertEqual(record_types[-len(expected_tail) :], expected_tail)
                self.assertEqual(
                    record_types.count("POST_EFFECT_ACCOUNTING_FAILURE"), 1
                )
                self.assertEqual(accounting["failed_record_type"], failed_record_type)
                self.assertEqual(accounting["operational_effects"], 1)
                self.assertEqual(
                    accounting["action"]["state_after_sha256"],
                    sha256_json(state_after),
                )
                self.assertEqual(
                    accounting["verification"]["observed_state"], state_after
                )
                self.assertEqual(final["operational_effects"], 1)
                self.assertEqual(final["target_state_sha256"], sha256_json(state_after))
                self.assertEqual(final["verification_status"], "ROLLBACK_REQUIRED")
                metrics = firewall.metrics_snapshot()
                self.assertEqual(metrics["verification_failures"], 1)
                self.assertEqual(metrics["broker_rejections"], 0)
                self.assertEqual(metrics["authorization_failures"], 0)
                self._assert_closed_and_reconciled(firewall, result)


class Phase3ApprovalLifecycleReleaseBlockers(unittest.TestCase):
    def test_receipt_id_failure_is_retryable_without_orphan_audit_or_effect(
        self,
    ) -> None:
        harness = new_harness()
        id_factory = PrefixFailingIdFactory("approval-receipt", invalid_once=True)
        firewall = _new_firewall(harness, id_factory=id_factory)
        before = firewall.observer.observe("DOMAIN_CONTROLLER_01")
        result = firewall.process_json(
            request_json(
                domain_controller_case(
                    harness, request_id="P3-APPROVAL-RECEIPT-ID-FAILURE"
                )
            ),
            credential=harness.soc_credential,
        )
        requirement = result.decision.approval_requirement
        assert requirement is not None
        values = {
            **_approval_values(harness, requirement),
            "credential": harness.human_credential,
        }
        audit_before_failure = firewall.read_audit()

        with self.assertRaises(ApprovalError) as raised:
            firewall.approve_for_reevaluation(**values)
        self.assertEqual(raised.exception.reason_code, "APPROVAL_RECEIPT_ID_INVALID")
        self.assertEqual(firewall.read_audit(), audit_before_failure)
        self.assertEqual(
            [row["record_type"] for row in firewall.read_audit()].count(
                "APPROVAL_RECORDED"
            ),
            0,
        )

        receipt = firewall.approve_for_reevaluation(**values)
        self.assertEqual(receipt.status, "APPROVED_FOR_REEVALUATION")
        full_audit = firewall.read_audit()
        self.assertEqual(full_audit[-1]["record_type"], "APPROVAL_RECORDED")
        self.assertEqual(
            [row["record_type"] for row in full_audit].count("APPROVAL_RECORDED"),
            1,
        )
        chain_valid, chain_errors = AuditLogger.verify_rows(full_audit)
        lifecycle_valid, lifecycle_errors = validate_phase3_lifecycle(full_audit)
        self.assertTrue(chain_valid, chain_errors)
        self.assertTrue(lifecycle_valid, lifecycle_errors)
        record_types = [row["record_type"] for row in full_audit]
        self.assertNotIn("AUTHORIZATION_PRODUCED", record_types)
        self.assertNotIn("BROKER_INVOKED", record_types)
        self.assertNotIn("ACTION_ATTEMPTED", record_types)
        self.assertEqual(firewall.observer.observe("DOMAIN_CONTROLLER_01"), before)
        metrics = firewall.metrics_snapshot()
        self.assertEqual(metrics["decisions_total"], 1)
        self.assertEqual(metrics["decision_counts"]["ESCALATE"], 1)

    def test_durable_approval_append_then_raise_reconciles_without_duplicate(
        self,
    ) -> None:
        harness = new_harness()
        firewall = harness.firewall
        state_before = firewall.observer.observe("DOMAIN_CONTROLLER_01")
        result = firewall.process_json(
            request_json(
                domain_controller_case(
                    harness,
                    request_id="P3-APPROVAL-DURABLE-APPEND-THEN-RAISE",
                )
            ),
            credential=harness.soc_credential,
        )
        requirement = result.decision.approval_requirement
        assert requirement is not None
        values = _approval_values(harness, requirement)
        original_append = AuditLogger.append
        durable_records: list[dict[str, Any]] = []

        def append_then_raise(
            logger: AuditLogger,
            record_type: str,
            payload: dict[str, Any],
        ) -> dict[str, Any]:
            record = original_append(logger, record_type, payload)
            if record_type == "APPROVAL_RECORDED" and not durable_records:
                durable_records.append(copy.deepcopy(record))
                raise OSError("injected failure after durable approval append")
            return record

        with patch.object(AuditLogger, "append", new=append_then_raise):
            receipt = firewall.approve_for_reevaluation(**values)

        self.assertEqual(len(durable_records), 1)
        self.assertEqual(
            durable_records[0]["payload"]["receipt_id"], receipt.receipt_id
        )
        full_audit = list(firewall.read_audit())
        approval_events = [
            row for row in full_audit if row["record_type"] == "APPROVAL_RECORDED"
        ]
        self.assertEqual(len(approval_events), 1)
        self.assertEqual(
            approval_events[0]["payload"]["receipt_id"], receipt.receipt_id
        )
        with self.assertRaises(ApprovalError) as replayed:
            firewall.approve_for_reevaluation(**values)
        self.assertEqual(replayed.exception.reason_code, "APPROVAL_REPLAY")
        self.assertEqual(
            [row["record_type"] for row in firewall.read_audit()].count(
                "APPROVAL_RECORDED"
            ),
            1,
        )
        chain_valid, chain_errors = AuditLogger.verify_rows(full_audit)
        lifecycle_valid, lifecycle_errors = validate_phase3_lifecycle(full_audit)
        self.assertTrue(chain_valid, chain_errors)
        self.assertTrue(lifecycle_valid, lifecycle_errors)
        self.assertEqual(
            firewall.observer.observe("DOMAIN_CONTROLLER_01"), state_before
        )
        metrics = firewall.metrics_snapshot()
        self.assertEqual(metrics["decisions_total"], 1)
        self.assertEqual(metrics["decision_counts"]["ESCALATE"], 1)

    def test_prewrite_approval_failure_reuses_pending_receipt_on_retry(self) -> None:
        harness = new_harness()
        firewall = harness.firewall
        state_before = firewall.observer.observe("DOMAIN_CONTROLLER_01")
        result = firewall.process_json(
            request_json(
                domain_controller_case(
                    harness,
                    request_id="P3-APPROVAL-PREWRITE-FAILURE-RETRY",
                )
            ),
            credential=harness.soc_credential,
        )
        requirement = result.decision.approval_requirement
        assert requirement is not None
        values = _approval_values(harness, requirement)
        audit_before_failure = firewall.read_audit()
        original_append = AuditLogger.append
        pending_payloads: list[dict[str, Any]] = []

        def fail_once_before_append(
            logger: AuditLogger,
            record_type: str,
            payload: dict[str, Any],
        ) -> dict[str, Any]:
            if record_type == "APPROVAL_RECORDED" and not pending_payloads:
                pending_payloads.append(copy.deepcopy(payload))
                raise OSError("injected approval pre-write failure")
            return original_append(logger, record_type, payload)

        with patch.object(
            AuditLogger,
            "append",
            new=fail_once_before_append,
        ):
            with self.assertRaises(OSError):
                firewall.approve_for_reevaluation(**values)
            self.assertEqual(firewall.read_audit(), audit_before_failure)
            receipt = firewall.approve_for_reevaluation(**values)

        self.assertEqual(len(pending_payloads), 1)
        self.assertEqual(pending_payloads[0]["receipt_id"], receipt.receipt_id)
        full_audit = list(firewall.read_audit())
        approval_events = [
            row for row in full_audit if row["record_type"] == "APPROVAL_RECORDED"
        ]
        self.assertEqual(len(approval_events), 1)
        self.assertEqual(
            approval_events[0]["payload"]["receipt_id"], receipt.receipt_id
        )
        chain_valid, chain_errors = AuditLogger.verify_rows(full_audit)
        lifecycle_valid, lifecycle_errors = validate_phase3_lifecycle(full_audit)
        self.assertTrue(chain_valid, chain_errors)
        self.assertTrue(lifecycle_valid, lifecycle_errors)
        self.assertEqual(
            firewall.observer.observe("DOMAIN_CONTROLLER_01"), state_before
        )
        metrics = firewall.metrics_snapshot()
        self.assertEqual(metrics["decisions_total"], 1)
        self.assertEqual(metrics["decision_counts"]["ESCALATE"], 1)


class Phase3ReplayNamespaceReleaseBlockers(unittest.TestCase):
    def test_unknown_target_front_run_cannot_poison_another_principal(self) -> None:
        harness = new_harness()
        principal_one = trusted_soc_principal()
        principal_two = AuthenticatedPrincipal.from_dict(
            {
                "id": "SOC_AGENT_02",
                "type": "SOC_AUTOMATION",
                "authenticated": True,
                "roles": ["SOC_ANALYST"],
                "authority": ["endpoint_containment"],
                "security_status": "TRUSTED",
                "identity_source": "synthetic_second_mtls_fixture",
            }
        )
        credential_one = synthetic_invocation_credential(
            INVOCATION_MASTER_KEY, principal_one
        )
        credential_two = synthetic_invocation_credential(
            INVOCATION_MASTER_KEY, principal_two
        )
        resolver = TrustedPrincipalResolver(
            (
                (credential_one, principal_one),
                (credential_two, principal_two),
            )
        )
        firewall = _new_firewall(harness, resolver=resolver)
        request_id = "P3-NAMESPACED-UNKNOWN-TARGET"

        unknown = workstation_case(harness, request_id=request_id)
        unknown["action"]["target"] = "UNKNOWN_TARGET_01"
        unknown["target"] = {
            "id": "UNKNOWN_TARGET_01",
            "type": "WORKSTATION",
            "criticality": "LOW",
            "classification": "INTERNAL",
            "dependencies": [],
        }
        for item in unknown["evidence"]:
            item["subject_target_id"] = "UNKNOWN_TARGET_01"
            resign_evidence(item, harness.source_keys)
        first = firewall.process_json(request_json(unknown), credential=credential_one)

        valid = workstation_case(harness, request_id=request_id)
        valid["agent"] = {
            key: value
            for key, value in principal_two.to_dict().items()
            if key
            not in {
                "identity_source",
                "human_session",
                "authentication_reason_code",
            }
        }
        second = firewall.process_json(request_json(valid), credential=credential_two)

        self.assertEqual(first.decision.outcome, "DENY")
        self.assertIn("TARGET_OR_ACTION_UNKNOWN", first.decision.reason_codes)
        self.assertEqual(second.decision.outcome, "ALLOW")
        self.assertNotIn("DUPLICATE_REQUEST", second.decision.reason_codes)
        self.assertNotIn("REQUEST_ID_CONFLICT", second.decision.reason_codes)
        self.assertIsNotNone(second.authorization)
        self.assertEqual(second.final_state["network_state"], "isolated")
        metrics = firewall.metrics_snapshot()
        self.assertEqual(metrics["decisions_total"], 2)
        self.assertEqual(metrics["decision_counts"]["DENY"], 1)
        self.assertEqual(metrics["decision_counts"]["ALLOW"], 1)


class Phase3PolicySafetyReleaseBlockers(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.base_policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))

    def test_policy_rejects_every_release_blocking_safety_downgrade(self) -> None:
        variants: list[tuple[str, Callable[[dict], None]]] = []

        def duplicate_permissive_rule(value: dict) -> None:
            value["decision_rules"].append(
                {
                    "id": "P3-ALLOW-SECOND-DEFAULT",
                    "condition": "DEFAULT",
                    "outcome": "ALLOW",
                }
            )

        variants.append(("duplicate_permissive_rule", duplicate_permissive_rule))

        def downgraded_second_domain_controller(value: dict) -> None:
            value["target_inventory"]["DOMAIN_CONTROLLER_02"] = {
                **copy.deepcopy(value["target_inventory"]["DOMAIN_CONTROLLER_01"]),
                "criticality": "LOW",
                "human_approval_required": False,
                "isolation_consequence": "LOW",
                "dependencies": [],
            }

        variants.append(
            ("downgraded_second_domain_controller", downgraded_second_domain_controller)
        )

        def untrusted_source(value: dict) -> None:
            value["evidence"]["trusted_sources"]["CMDB_PRIMARY"][
                "trust_level"
            ] = "UNTRUSTED"

        variants.append(("untrusted_source", untrusted_source))

        def zero_evidence_settings(value: dict) -> None:
            value["evidence"]["minimum_reliability"] = 0.0
            value["evidence"]["minimum_relevance"] = 0.0
            value["evidence"]["minimum_overall_strength_for_allow"] = 0.0
            value["evidence"]["minimum_corroborating_sources"] = 1

        variants.append(("zero_evidence_settings", zero_evidence_settings))

        variants.extend(
            (
                (
                    "conflicts_above_zero",
                    lambda value: value["evidence"].__setitem__(
                        "maximum_conflicts_for_allow", 1
                    ),
                ),
                (
                    "high_level_approval_removed",
                    lambda value: value["consequence"].__setitem__(
                        "approval_levels", ["CRITICAL"]
                    ),
                ),
                (
                    "high_isolation_approval_removed",
                    lambda value: value["consequence"].__setitem__(
                        "approval_isolation_consequences", ["CRITICAL"]
                    ),
                ),
                (
                    "critical_mission_floor_removed",
                    lambda value: value["consequence"].__setitem__(
                        "approval_mission_impacts", ["HIGH"]
                    ),
                ),
                (
                    "high_safety_floor_removed",
                    lambda value: value["consequence"].__setitem__(
                        "approval_safety_impacts", ["MEDIUM"]
                    ),
                ),
                (
                    "critical_availability_floor_removed",
                    lambda value: value["consequence"].__setitem__(
                        "approval_availability_impacts", ["HIGH"]
                    ),
                ),
                (
                    "enterprise_blast_floor_removed",
                    lambda value: value["consequence"].__setitem__(
                        "approval_blast_radii", ["SERVICE"]
                    ),
                ),
                (
                    "downtime_floor_removed",
                    lambda value: value["consequence"].__setitem__(
                        "approval_downtime_minutes", 61
                    ),
                ),
                (
                    "high_target_approval_removed",
                    lambda value: value["action_catalog"][
                        "NETWORK_ISOLATE"
                    ].__setitem__("human_approval_criticalities", ["TIER_0"]),
                ),
            )
        )

        for label, mutate in variants:
            with self.subTest(label=label):
                candidate = copy.deepcopy(self.base_policy)
                mutate(candidate)
                with self.assertRaises(PolicyValidationError) as raised:
                    Phase3PolicyConfig.from_dict(candidate)
                self.assertEqual(
                    raised.exception.reason_code, "POLICY_SAFETY_INVARIANT"
                )


if __name__ == "__main__":
    unittest.main()
