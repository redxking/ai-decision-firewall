from __future__ import annotations

import json
import random
import tempfile
import unittest
from pathlib import Path

from adf_poc.actions import ActionBroker, AuthorizationError, AuthorizationGate, SimulatedIdentityProvider
from adf_poc.audit import AuditLogger
from adf_poc.evidence import assess_evidence
from adf_poc.model import LogisticRiskModel, ModelAssessment
from adf_poc.policy import DecisionProposal, PolicyConfig, PolicyEngine
from adf_poc.schemas import Disposition
from adf_poc.synthetic import generate_case
from adf_poc.verifier import IndependentVerifier


ROOT = Path(__file__).resolve().parents[1]
POLICY = PolicyConfig.load(ROOT / "config" / "policy.json")


def find_case(scenario_name: str):
    rng = random.Random(77123)
    for index in range(5000):
        case, truth = generate_case(index, rng, "unit")
        if truth.scenario == scenario_name:
            return case, truth
    raise AssertionError(f"Unable to generate scenario {scenario_name}")


class SafetyControlTests(unittest.TestCase):
    def test_poisoned_evidence_forces_abstention(self) -> None:
        case, _ = find_case("prompt_injection_poisoning")
        evidence = assess_evidence(case)
        self.assertTrue(evidence.poisoned_evidence)
        model = ModelAssessment(
            compromise_probability=0.999,
            model_version="test",
            top_positive_factors=[],
            top_negative_factors=[],
            feature_values={"credential_dumping": 1.0, "lateral_movement": 1.0, "token_reuse": 1.0, "oauth_grant": 0.0},
            feature_trace={},
        )
        proposal = PolicyEngine(POLICY).propose(case, model, evidence)
        self.assertEqual(proposal.disposition, Disposition.INVESTIGATE.value)
        self.assertEqual(proposal.executable_actions, [])

    def test_break_glass_never_auto_contains(self) -> None:
        case, _ = find_case("break_glass_drill")
        evidence = assess_evidence(case)
        model = ModelAssessment(
            compromise_probability=0.999,
            model_version="test",
            top_positive_factors=[],
            top_negative_factors=[],
            feature_values={"credential_dumping": 1.0, "lateral_movement": 1.0, "token_reuse": 0.0, "oauth_grant": 0.0},
            feature_trace={},
        )
        proposal = PolicyEngine(POLICY).propose(case, model, evidence)
        self.assertEqual(proposal.disposition, Disposition.ESCALATE_HUMAN.value)
        self.assertFalse(proposal.executable_actions)

    def test_action_broker_rejects_missing_token(self) -> None:
        case, _ = find_case("privileged_token_theft")
        gate = AuthorizationGate(POLICY, signing_key="unit-test-key")
        broker = ActionBroker(gate, SimulatedIdentityProvider())
        with self.assertRaises(AuthorizationError):
            broker.execute(case, "revoke_active_sessions", None)

    def test_verifier_rejects_human_only_action(self) -> None:
        case, _ = find_case("privileged_token_theft")
        evidence = assess_evidence(case)
        model = ModelAssessment(
            compromise_probability=0.999,
            model_version="test",
            top_positive_factors=[],
            top_negative_factors=[],
            feature_values={"credential_dumping": 1.0, "lateral_movement": 1.0, "token_reuse": 1.0, "oauth_grant": 0.0},
            feature_trace={},
        )
        proposal = DecisionProposal(
            disposition=Disposition.CONTAIN_REVERSIBLE.value,
            executable_actions=["disable_account"],
            recommended_human_actions=[],
            investigation_actions=[],
            rationale=["malicious test"],
            policy_rules_applied=["test"],
            evidence_event_ids=[],
            required_authority="test",
            rollback_plan={"disable_account": "enable_account"},
        )
        result = IndependentVerifier(POLICY).verify(case, model, evidence, proposal)
        self.assertFalse(result.passed)
        self.assertTrue(any("NO-HUMAN-ONLY-EXECUTION" in reason for reason in result.blocking_reasons))

    def test_audit_chain_detects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            audit = AuditLogger(path)
            audit.append("ONE", {"value": 1})
            audit.append("TWO", {"value": 2})
            valid, _ = AuditLogger.verify(path)
            self.assertTrue(valid)
            rows = path.read_text(encoding="utf-8").splitlines()
            first = json.loads(rows[0])
            first["payload"]["value"] = 999
            rows[0] = json.dumps(first)
            path.write_text("\n".join(rows) + "\n", encoding="utf-8")
            valid, errors = AuditLogger.verify(path)
            self.assertFalse(valid)
            self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
