from __future__ import annotations

import copy
import threading
import unittest
from dataclasses import replace

from adf_poc.phase3.approval import ApprovalError
from adf_poc.phase3.authorization import AuthorizationError, AuthorizationGate
from adf_poc.phase3.identity import PrincipalAuthenticationError
from adf_poc.phase3.metrics import Phase3Metrics
from adf_poc.phase3.scenarios import request_json, trusted_soc_principal
from adf_poc.phase3.simulation import (
    ActionBroker,
    SimulatedTargetEnvironment,
    TargetStateObserver,
)

from tests.phase3_support import (
    TEST_SIGNING_KEY,
    VERIFIER_SIGNING_KEY,
    DeterministicIdFactory,
    domain_controller_case,
    mint_unconsumed_authorization,
    new_harness,
    tier_0_human_approver,
)


class Phase3AuthorizationBoundaryTests(unittest.TestCase):
    def test_principal_resolution_attestation_rejects_forgery(self) -> None:
        harness = new_harness()
        resolution = harness.resolver.resolve(harness.soc_credential)
        forged_signature = replace(resolution, signature="0" * 64)
        forged_principal = replace(resolution, principal=tier_0_human_approver())

        for forged in (forged_signature, forged_principal):
            with self.subTest(forged=forged.principal.id):
                with self.assertRaises(PrincipalAuthenticationError) as raised:
                    harness.resolver.verify_resolution(forged)
                self.assertEqual(
                    raised.exception.reason_code, "PRINCIPAL_RESOLUTION_INVALID"
                )

    def test_firewall_public_api_rejects_direct_principal_and_private_capabilities(
        self,
    ) -> None:
        harness = new_harness()
        before = harness.firewall.observer.observe("WORKSTATION_042")
        raw = request_json(
            domain_controller_case(harness, request_id="P3-DIRECT-PRINCIPAL-BYPASS")
        )

        with self.assertRaises(TypeError):
            harness.firewall.process_json(
                raw, principal=trusted_soc_principal()  # type: ignore[call-arg]
            )

        for removed_surface in (
            "_authorization_gate",
            "_broker",
            "_target_verifier",
            "_evidence_attestation_verifier",
        ):
            with self.subTest(removed_surface=removed_surface):
                self.assertFalse(hasattr(harness.firewall, removed_surface))
        self.assertEqual(harness.firewall.observer.observe("WORKSTATION_042"), before)
        self.assertEqual(harness.firewall.read_audit(), ())

    def test_signature_and_every_runtime_binding_fail_closed(self) -> None:
        fixture = mint_unconsumed_authorization(new_harness())
        gate = fixture.gate
        base = fixture.validation_arguments()

        invalid_signature = replace(fixture.token, signature="0" * 64)
        with self.assertRaises(AuthorizationError) as raised:
            gate.validate_and_consume(invalid_signature, **base)
        self.assertEqual(
            raised.exception.reason_code, "AUTHORIZATION_SIGNATURE_INVALID"
        )

        cases = (
            ("request_id", "wrong-request", "AUTHORIZATION_REQUEST_MISMATCH"),
            ("decision_id", "wrong-decision", "AUTHORIZATION_DECISION_MISMATCH"),
            ("agent_id", "wrong-agent", "AUTHORIZATION_AGENT_MISMATCH"),
            ("action_type", "WRONG_ACTION", "AUTHORIZATION_ACTION_MISMATCH"),
            ("target_id", "DOMAIN_CONTROLLER_01", "AUTHORIZATION_TARGET_MISMATCH"),
            (
                "parameters",
                {"duration_seconds": 901, "preserve_management": True},
                "AUTHORIZATION_PARAMETERS_MISMATCH",
            ),
            ("policy_id", "wrong-policy", "AUTHORIZATION_POLICY_ID_MISMATCH"),
            (
                "policy_version",
                "99.0.0",
                "AUTHORIZATION_POLICY_VERSION_MISMATCH",
            ),
            (
                "policy_sha256",
                "a" * 64,
                "AUTHORIZATION_POLICY_DIGEST_MISMATCH",
            ),
            (
                "decision_context_sha256",
                "0" * 64,
                "AUTHORIZATION_DECISION_CONTEXT_MISMATCH",
            ),
            (
                "target_state_sha256",
                "f" * 64,
                "AUTHORIZATION_TARGET_STATE_MISMATCH",
            ),
        )
        for field, mutation, expected in cases:
            with self.subTest(field=field):
                arguments = copy.deepcopy(base)
                arguments[field] = mutation
                with self.assertRaises(AuthorizationError) as raised:
                    gate.validate_and_consume(fixture.token, **arguments)
                self.assertEqual(raised.exception.reason_code, expected)

        altered_scope = replace(
            fixture.token,
            permitted_parameters={
                "duration_seconds": 3600,
                "preserve_management": True,
            },
        )
        with self.assertRaises(AuthorizationError) as raised:
            gate.validate_and_consume(altered_scope, **base)
        self.assertEqual(
            raised.exception.reason_code, "AUTHORIZATION_SIGNATURE_INVALID"
        )
        self.assertEqual(gate.ledger.state(fixture.token.token_id), "ISSUED")

    def test_signed_decision_verification_is_required_and_single_use(self) -> None:
        fixture = mint_unconsumed_authorization(new_harness())
        with self.assertRaises(AuthorizationError) as raised:
            fixture.gate.issue(
                decision=fixture.decision,
                agent_id=fixture.principal.id,
                target_state_sha256=fixture.token.target_state_sha256,
                decision_verification=True,  # type: ignore[arg-type]
            )
        self.assertEqual(
            raised.exception.reason_code,
            "AUTHORIZATION_DECISION_VERIFICATION_INVALID",
        )

        with self.assertRaises(AuthorizationError) as raised:
            fixture.gate.issue(
                decision=fixture.decision,
                agent_id=fixture.principal.id,
                target_state_sha256=fixture.token.target_state_sha256,
                decision_verification=fixture.decision_verification,
            )
        self.assertEqual(raised.exception.reason_code, "AUTHORIZATION_DECISION_REPLAY")

    def test_decision_command_scope_is_deeply_immutable_and_detached(self) -> None:
        fixture = mint_unconsumed_authorization(new_harness())
        assert fixture.decision.permitted_action is not None
        with self.assertRaises(TypeError):
            fixture.decision.permitted_action["parameters"]["duration_seconds"] = 3600

        detached = fixture.decision.to_dict()
        detached["permitted_action"]["parameters"]["duration_seconds"] = 3600
        self.assertEqual(fixture.token.permitted_parameters["duration_seconds"], 900)
        self.assertEqual(
            fixture.decision.permitted_action["parameters"]["duration_seconds"],
            900,
        )

    def test_expiry_boundary_is_valid_before_and_invalid_at_expiration(self) -> None:
        before_fixture = mint_unconsumed_authorization(new_harness())
        before_fixture.harness.clock.advance(
            seconds=before_fixture.harness.policy.authorization_ttl_seconds - 1
        )
        before_fixture.gate.validate_and_consume(
            before_fixture.token, **before_fixture.validation_arguments()
        )
        self.assertEqual(
            before_fixture.gate.ledger.state(before_fixture.token.token_id),
            "CONSUMED",
        )

        expired_fixture = mint_unconsumed_authorization(new_harness())
        expired_fixture.harness.clock.advance(
            seconds=expired_fixture.harness.policy.authorization_ttl_seconds
        )
        with self.assertRaises(AuthorizationError) as raised:
            expired_fixture.gate.validate_and_consume(
                expired_fixture.token, **expired_fixture.validation_arguments()
            )
        self.assertEqual(raised.exception.reason_code, "AUTHORIZATION_EXPIRED")
        self.assertEqual(
            expired_fixture.gate.ledger.state(expired_fixture.token.token_id),
            "ISSUED",
        )

    def test_sequential_and_concurrent_replay_permit_exactly_one_consumption(
        self,
    ) -> None:
        sequential = mint_unconsumed_authorization(new_harness())
        arguments = sequential.validation_arguments()
        sequential.gate.validate_and_consume(sequential.token, **arguments)
        with self.assertRaises(AuthorizationError) as raised:
            sequential.gate.validate_and_consume(sequential.token, **arguments)
        self.assertEqual(raised.exception.reason_code, "AUTHORIZATION_REPLAY")

        concurrent = mint_unconsumed_authorization(new_harness())
        concurrent_arguments = concurrent.validation_arguments()
        barrier = threading.Barrier(8)
        results: list[str] = []
        result_lock = threading.Lock()

        def attempt() -> None:
            barrier.wait()
            try:
                concurrent.gate.validate_and_consume(
                    concurrent.token, **concurrent_arguments
                )
                outcome = "SUCCESS"
            except AuthorizationError as exc:
                outcome = exc.reason_code
            with result_lock:
                results.append(outcome)

        threads = [threading.Thread(target=attempt) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=5)

        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(results.count("SUCCESS"), 1)
        self.assertEqual(results.count("AUTHORIZATION_REPLAY"), 7)

    def test_prior_instance_token_is_rejected_even_with_same_signing_key(self) -> None:
        fixture = mint_unconsumed_authorization(new_harness())
        other_gate = AuthorizationGate(
            signing_key=TEST_SIGNING_KEY,
            decision_verification_key=VERIFIER_SIGNING_KEY,
            verifier_instance_id="different-verifier-instance",
            ttl_seconds=fixture.harness.policy.authorization_ttl_seconds,
            metrics=Phase3Metrics(),
            clock=fixture.harness.clock,
            id_factory=DeterministicIdFactory(),
        )

        with self.assertRaises(AuthorizationError) as raised:
            other_gate.validate_and_consume(
                fixture.token, **fixture.validation_arguments()
            )

        self.assertEqual(raised.exception.reason_code, "AUTHORIZATION_ISSUER_MISMATCH")

    def test_failed_action_consumes_authorization_and_cannot_be_retried(self) -> None:
        fixture = mint_unconsumed_authorization(
            new_harness(fault_modes={"WORKSTATION_042": "FAILED"})
        )

        result = fixture.broker.execute(**fixture.broker_arguments())

        self.assertTrue(result.attempted)
        self.assertTrue(result.accepted)
        self.assertFalse(result.reported_success)
        self.assertEqual(fixture.gate.ledger.state(fixture.token.token_id), "CONSUMED")
        with self.assertRaises(AuthorizationError) as raised:
            fixture.broker.execute(**fixture.broker_arguments())
        self.assertEqual(raised.exception.reason_code, "AUTHORIZATION_REPLAY")

    def test_missing_token_and_public_or_injected_target_bypass_fail(self) -> None:
        fixture = mint_unconsumed_authorization(new_harness())
        broker_arguments = fixture.broker_arguments()
        broker_arguments["token"] = None
        with self.assertRaises(AuthorizationError) as raised:
            fixture.broker.execute(**broker_arguments)
        self.assertEqual(raised.exception.reason_code, "AUTHORIZATION_MISSING")
        self.assertEqual(fixture.metrics.snapshot()["broker_rejections"], 1)

        before = fixture.observer.observe("WORKSTATION_042")
        with self.assertRaises(TypeError):
            SimulatedTargetEnvironment(fixture.harness.policy.target_inventory)
        with self.assertRaises(TypeError):
            ActionBroker(object(), lambda **_: None)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            TargetStateObserver(object(), lambda _: {})
        for exposed_name in ("mutate", "apply", "execute_without_authorization"):
            with self.subTest(exposed_name=exposed_name):
                self.assertFalse(hasattr(fixture.observer, exposed_name))
        for exposed_name in ("environment", "gate", "apply", "mutate"):
            with self.subTest(exposed_name=exposed_name):
                self.assertFalse(hasattr(fixture.broker, exposed_name))
        self.assertEqual(fixture.observer.observe("WORKSTATION_042"), before)


class Phase3HumanApprovalBoundaryTests(unittest.TestCase):
    def _requirement(self):
        harness = new_harness()
        before = harness.firewall.observer.observe("DOMAIN_CONTROLLER_01")
        result = harness.firewall.process_json(
            request_json(domain_controller_case(harness)),
            credential=harness.credential,
        )
        self.assertEqual(result.decision.outcome, "ESCALATE")
        self.assertEqual(result.final_state, before)
        self.assertIsNotNone(result.decision.approval_requirement)
        return harness, result.decision.approval_requirement, before

    @staticmethod
    def _approval_values(harness, requirement):
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

    def test_wrong_human_attestation_authority_scope_and_expiration_are_rejected(
        self,
    ) -> None:
        harness, requirement, before = self._requirement()
        assert requirement is not None
        valid = self._approval_values(harness, requirement)

        wrong_human = dict(valid)
        wrong_human["credential"] = harness.soc_credential
        with self.assertRaises(ApprovalError) as raised:
            harness.firewall.approve_for_reevaluation(**wrong_human)
        self.assertEqual(raised.exception.reason_code, "APPROVER_NOT_HUMAN")

        wrong_authority = dict(valid)
        wrong_authority["credential"] = harness.human_without_authority_credential
        with self.assertRaises(ApprovalError) as raised:
            harness.firewall.approve_for_reevaluation(**wrong_authority)
        self.assertEqual(
            raised.exception.reason_code, "APPROVER_AUTHORITY_INSUFFICIENT"
        )

        invalid_credential = dict(valid)
        invalid_credential["credential"] = harness.invalid_credential
        with self.assertRaises(ApprovalError) as raised:
            harness.firewall.approve_for_reevaluation(**invalid_credential)
        self.assertEqual(raised.exception.reason_code, "APPROVER_CREDENTIAL_REJECTED")

        scope_cases = (
            ("action_type", "WRONG_ACTION", "APPROVAL_ACTION_MISMATCH"),
            ("target_id", "WORKSTATION_042", "APPROVAL_TARGET_MISMATCH"),
            (
                "parameters",
                {"duration_seconds": 901, "preserve_management": True},
                "APPROVAL_PARAMETERS_MISMATCH",
            ),
            ("evidence_sha256", "0" * 64, "APPROVAL_EVIDENCE_MISMATCH"),
        )
        for field, mutation, expected in scope_cases:
            with self.subTest(field=field):
                attempt = copy.deepcopy(valid)
                attempt[field] = mutation
                with self.assertRaises(ApprovalError) as raised:
                    harness.firewall.approve_for_reevaluation(**attempt)
                self.assertEqual(raised.exception.reason_code, expected)

        harness.clock.advance(seconds=harness.policy.approval_ttl_seconds)
        with self.assertRaises(ApprovalError) as raised:
            harness.firewall.approve_for_reevaluation(**valid)
        self.assertEqual(raised.exception.reason_code, "APPROVAL_EXPIRED")
        self.assertEqual(
            harness.firewall.observer.observe("DOMAIN_CONTROLLER_01"), before
        )

    def test_valid_approval_is_scope_bound_single_use_and_never_executes(self) -> None:
        harness, requirement, before = self._requirement()
        assert requirement is not None
        values = self._approval_values(harness, requirement)

        receipt = harness.firewall.approve_for_reevaluation(**values)

        self.assertEqual(receipt.status, "APPROVED_FOR_REEVALUATION")
        self.assertEqual(receipt.approval_id, requirement.approval_id)
        self.assertEqual(receipt.decision_id, requirement.decision_id)
        self.assertEqual(receipt.approver_id, tier_0_human_approver().id)
        with self.assertRaises(ApprovalError) as raised:
            harness.firewall.approve_for_reevaluation(**values)
        self.assertEqual(raised.exception.reason_code, "APPROVAL_REPLAY")
        self.assertEqual(
            harness.firewall.observer.observe("DOMAIN_CONTROLLER_01"), before
        )
        audit_types = [row["record_type"] for row in harness.firewall.read_audit()]
        self.assertEqual(audit_types.count("APPROVAL_RECORDED"), 1)
        self.assertNotIn("AUTHORIZATION_PRODUCED", audit_types)
        self.assertNotIn("BROKER_INVOKED", audit_types)


if __name__ == "__main__":
    unittest.main()
