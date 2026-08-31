from __future__ import annotations

import copy
import unittest
from datetime import timedelta

from adf_poc.phase3.scenarios import (
    anonymous_principal,
    compromised_principal,
    request_json,
    trusted_soc_principal,
)

from tests.phase3_support import (
    audit_record_types,
    domain_controller_case,
    new_harness,
    trusted_principal_without_authority,
    workstation_case,
)


class Phase3DecisionPathTests(unittest.TestCase):
    def test_high_risk_domain_controller_escalates_with_exact_reasons_and_no_effect(
        self,
    ) -> None:
        harness = new_harness()
        before = harness.firewall.observer.observe("DOMAIN_CONTROLLER_01")

        result = harness.firewall.process_json(
            request_json(domain_controller_case(harness)),
            credential=harness.credential,
        )

        self.assertEqual(result.decision.outcome, "ESCALATE")
        self.assertEqual(
            result.decision.reason_codes,
            (
                "PROTECTED_ASSET",
                "INSUFFICIENT_AUTHORITY",
                "STALE_EVIDENCE",
                "CONFLICTING_EVIDENCE",
                "AUTHENTICATION_SERVICE_DEPENDENCY",
                "CASCADING_EFFECT_POSSIBLE",
                "HIGH_OPERATIONAL_CONSEQUENCE",
                "HIGH_ISOLATION_CONSEQUENCE",
                "HUMAN_APPROVAL_REQUIRED",
                "REVERSIBLE_ACTION",
            ),
        )
        approval = result.decision.approval_requirement
        self.assertIsNotNone(approval)
        assert approval is not None
        self.assertEqual(approval.request_id, result.decision.request_id)
        self.assertEqual(approval.decision_id, result.decision.decision_id)
        self.assertEqual(approval.action_type, "NETWORK_ISOLATE")
        self.assertEqual(approval.target_id, "DOMAIN_CONTROLLER_01")
        self.assertEqual(approval.required_approving_authority, "tier_0_containment")
        self.assertIsNone(result.authorization)
        self.assertIsNone(result.broker_result)
        self.assertIsNone(result.verification)
        self.assertEqual(result.final_state, before)
        self.assertEqual(result.final_state["network_state"], "connected")
        self.assertEqual(
            audit_record_types(result)[-5:],
            [
                "AUTHORIZATION_NOT_ISSUED",
                "BROKER_SKIPPED",
                "ACTION_SKIPPED",
                "VERIFICATION_SKIPPED",
                "FINAL_STATE_RECORDED",
            ],
        )

    def test_workstation_allow_executes_once_and_independently_verifies(self) -> None:
        harness = new_harness()
        result = harness.firewall.process_json(
            request_json(workstation_case(harness)),
            credential=harness.credential,
        )

        self.assertEqual(result.decision.outcome, "ALLOW")
        self.assertIsNotNone(result.authorization)
        self.assertIsNotNone(result.broker_result)
        self.assertIsNotNone(result.verification)
        assert result.authorization is not None
        assert result.broker_result is not None
        assert result.verification is not None
        self.assertEqual(result.broker_result.token_id, result.authorization.token_id)
        self.assertTrue(result.broker_result.attempted)
        self.assertTrue(result.broker_result.accepted)
        self.assertTrue(result.broker_result.reported_success)
        self.assertEqual(result.verification.status, "VERIFIED")
        self.assertEqual(result.verification.request_id, result.decision.request_id)
        self.assertEqual(result.verification.decision_id, result.decision.decision_id)
        self.assertEqual(
            result.verification.attempt_id, result.broker_result.attempt_id
        )
        self.assertEqual(result.final_state["network_state"], "isolated")
        self.assertTrue(result.final_state["management_channel"])
        self.assertIsNotNone(result.final_state["isolation_expires_at"])

    def test_allow_constrained_preserves_management_channel(self) -> None:
        harness = new_harness()
        result = harness.firewall.process_json(
            request_json(
                workstation_case(
                    harness,
                    request_id="P3-CONSTRAINED-WORKSTATION",
                    duration_seconds=900,
                    preserve_management=False,
                )
            ),
            credential=harness.credential,
        )

        self.assertEqual(result.decision.outcome, "ALLOW_CONSTRAINED")
        self.assertEqual(
            {row["reason_code"] for row in result.decision.constraints},
            {"MANAGEMENT_ACCESS_CONSTRAINED"},
        )
        permitted = result.decision.permitted_action
        self.assertIsNotNone(permitted)
        assert permitted is not None
        self.assertEqual(
            permitted["parameters"],
            {"duration_seconds": 900, "preserve_management": True},
        )
        self.assertIsNotNone(result.authorization)
        self.assertIsNotNone(result.broker_result)
        self.assertIsNotNone(result.verification)
        assert result.authorization is not None
        assert result.broker_result is not None
        assert result.verification is not None
        self.assertEqual(
            result.authorization.permitted_parameters, permitted["parameters"]
        )
        self.assertEqual(result.broker_result.parameters, permitted["parameters"])
        self.assertEqual(result.verification.status, "VERIFIED")
        self.assertTrue(result.final_state["management_channel"])
        self.assertEqual(
            result.final_state["isolation_expires_at"],
            (harness.clock() + timedelta(seconds=900)).isoformat(),
        )

    def test_long_duration_is_constrained_but_escalates_on_downtime(self) -> None:
        harness = new_harness()
        before = harness.firewall.observer.observe("WORKSTATION_042")
        result = harness.firewall.process_json(
            request_json(
                workstation_case(
                    harness,
                    request_id="P3-LONG-DURATION-ESCALATE",
                    duration_seconds=86400,
                    preserve_management=True,
                )
            ),
            credential=harness.credential,
        )

        self.assertEqual(result.decision.outcome, "ESCALATE")
        self.assertIn("DURATION_CONSTRAINED", result.decision.reason_codes)
        self.assertIn("HUMAN_APPROVAL_REQUIRED", result.decision.reason_codes)
        self.assertIsNone(result.decision.permitted_action)
        self.assertIsNone(result.authorization)
        self.assertEqual(result.final_state, before)

    def test_anonymous_compromised_and_self_asserted_authority_are_denied(self) -> None:
        cases = (
            (
                "anonymous",
                anonymous_principal(),
                {"INVOCATION_CREDENTIAL_REJECTED"},
            ),
            (
                "compromised",
                compromised_principal(),
                {"AGENT_SECURITY_STATUS_INVALID"},
            ),
            (
                "self_asserted_authority",
                trusted_principal_without_authority(),
                {"AGENT_ATTRIBUTE_MISMATCH"},
            ),
        )
        for label, principal, expected_reasons in cases:
            with self.subTest(label=label):
                harness = new_harness(principal=principal)
                before = harness.firewall.observer.observe("WORKSTATION_042")
                result = harness.firewall.process_json(
                    request_json(
                        workstation_case(harness, request_id=f"P3-DENY-{label.upper()}")
                    ),
                    credential=harness.credential,
                )
                self.assertEqual(result.decision.outcome, "DENY")
                self.assertTrue(
                    expected_reasons.issubset(set(result.decision.reason_codes))
                )
                self.assertIsNone(result.authorization)
                self.assertIsNone(result.broker_result)
                self.assertEqual(result.final_state, before)

    def test_ai_confidence_and_recommendation_do_not_change_authority(self) -> None:
        observed = []
        for label, confidence, recommendation in (
            ("low", 0.0, "DO_NOT_ISOLATE"),
            ("high", 1.0, "ISOLATE"),
        ):
            harness = new_harness()
            result = harness.firewall.process_json(
                request_json(
                    workstation_case(
                        harness,
                        request_id=f"P3-CONFIDENCE-{label.upper()}",
                        confidence=confidence,
                        recommendation=recommendation,
                    )
                ),
                credential=harness.credential,
            )
            observed.append(
                (
                    result.decision.outcome,
                    result.decision.reason_codes,
                    result.decision.applicable_rules,
                    result.decision.permitted_action,
                    result.verification.status if result.verification else None,
                )
            )
            self.assertFalse(
                result.decision.explanation["agent_recommendation_is_authoritative"]
            )
            self.assertFalse(
                result.decision.explanation["agent_confidence_is_authoritative"]
            )
        self.assertEqual(observed[0], observed[1])

    def test_spoofed_target_claims_cannot_lower_trusted_tier_zero_facts(self) -> None:
        harness = new_harness()
        source = domain_controller_case(harness, request_id="P3-TARGET-CLAIM-SPOOF")
        source["target"] = {
            "id": "DOMAIN_CONTROLLER_01",
            "type": "WORKSTATION",
            "criticality": "LOW",
            "classification": "INTERNAL",
            "dependencies": [],
        }
        before = harness.firewall.observer.observe("DOMAIN_CONTROLLER_01")

        result = harness.firewall.process_json(
            request_json(source), credential=harness.credential
        )

        self.assertEqual(result.decision.outcome, "ESCALATE")
        self.assertIn("TARGET_CLAIM_MISMATCH", result.decision.reason_codes)
        self.assertIn("PROTECTED_ASSET", result.decision.reason_codes)
        self.assertEqual(result.decision.explanation["target_criticality"], "TIER_0")
        self.assertEqual(result.decision.consequence.level, "CRITICAL")
        self.assertEqual(result.final_state, before)


if __name__ == "__main__":
    unittest.main()
