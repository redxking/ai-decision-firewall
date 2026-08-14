from __future__ import annotations

import inspect
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.engine import DecisionFirewallEngine, run_engine
from adf_poc.evidence import assess_evidence
from adf_poc.execution import ExecutionMode, SafetyInvariantError
from adf_poc.model import ModelAssessment
from adf_poc.policy import PolicyConfig, PolicyEngine
from adf_poc.schemas import Disposition
from adf_poc.synthetic import generate_case


ROOT = Path(__file__).resolve().parents[1]
POLICY = PolicyConfig.load(ROOT / "config" / "policy.json")


class FixedHighRiskModel:
    version = "phase2-execution-mode-test"

    def assess(self, case):
        return ModelAssessment(
            compromise_probability=0.999,
            model_version=self.version,
            top_positive_factors=[],
            top_negative_factors=[],
            feature_values={
                "credential_dumping": 1.0,
                "lateral_movement": 1.0,
                "token_reuse": 1.0,
                "oauth_grant": 0.0,
            },
            feature_trace={},
        )


def find_automation_eligible_case():
    rng = random.Random(77123)
    model = FixedHighRiskModel()
    for index in range(5000):
        case, truth = generate_case(index, rng, "execution-mode-unit")
        if truth.scenario != "privileged_token_theft":
            continue
        evidence = assess_evidence(case)
        proposal = PolicyEngine(POLICY).propose(case, model.assess(case), evidence)
        if proposal.disposition == Disposition.CONTAIN_REVERSIBLE.value:
            return case
    raise AssertionError("Unable to generate an automation-eligible test case.")


class ExecutionModeTests(unittest.TestCase):
    def test_read_only_modes_never_construct_or_call_execution_components(self) -> None:
        case = find_automation_eligible_case()

        for mode in (ExecutionMode.HISTORICAL_REPLAY, ExecutionMode.SHADOW_READ_ONLY):
            with self.subTest(mode=mode.value), tempfile.TemporaryDirectory() as directory:
                audit_path = Path(directory) / "audit.jsonl"
                with (
                    patch("adf_poc.engine.AuthorizationGate", side_effect=AssertionError("gate constructed")),
                    patch("adf_poc.engine.SimulatedIdentityProvider", side_effect=AssertionError("target constructed")),
                    patch("adf_poc.engine.ActionBroker", side_effect=AssertionError("broker constructed")),
                ):
                    engine = DecisionFirewallEngine(
                        model=FixedHighRiskModel(),
                        policy_config=POLICY,
                        audit_logger=AuditLogger(audit_path),
                        execution_mode=mode,
                    )
                    self.assertIsNone(engine.gate)
                    self.assertIsNone(engine.target)
                    self.assertIsNone(engine.broker)
                    decision = engine.process(case)

                self.assertEqual(decision["final_disposition"], Disposition.CONTAIN_REVERSIBLE.value)
                self.assertTrue(decision["counterfactual_actions"])
                self.assertEqual(decision["proposal"]["executable_actions"], [])
                self.assertFalse(decision["authorization"]["issued"])
                self.assertEqual(decision["authorization"]["permitted_actions"], [])
                self.assertEqual(decision["action_results"], [])
                self.assertEqual(
                    decision["post_action_verification"],
                    {
                        "applicable": False,
                        "status": "NOT_APPLICABLE",
                        "passed": None,
                        "checks": [],
                    },
                )
                self.assertEqual(decision["execution_mode"], mode.value)
                self.assertEqual(decision["execution_control"], {
                    "mode": mode.value,
                    "read_only": True,
                    "status": "SUPPRESSED_READ_ONLY",
                    "authorization_attempted": False,
                    "broker_invocations": 0,
                    "operational_effects": 0,
                })

                audit_rows = AuditLogger(audit_path).read_all()
                record_types = [row["record_type"] for row in audit_rows]
                self.assertIn("EXECUTION_SUPPRESSED", record_types)
                self.assertNotIn("ACTION_EXECUTED", record_types)
                suppression = next(row["payload"] for row in audit_rows if row["record_type"] == "EXECUTION_SUPPRESSED")
                self.assertEqual(suppression["counterfactual_actions"], decision["counterfactual_actions"])
                self.assertFalse(suppression["authorization_attempted"])
                self.assertEqual(suppression["broker_invocations"], 0)
                self.assertEqual(suppression["operational_effects"], 0)

                with self.assertRaises(SafetyInvariantError):
                    engine._require_simulation_wiring()

    def test_default_mode_preserves_v01_synthetic_simulation(self) -> None:
        case = find_automation_eligible_case()
        with tempfile.TemporaryDirectory() as directory:
            engine = DecisionFirewallEngine(
                model=FixedHighRiskModel(),
                policy_config=POLICY,
                audit_logger=AuditLogger(Path(directory) / "audit.jsonl"),
            )
            decision = engine.process(case)

        self.assertEqual(engine.execution_mode, ExecutionMode.SYNTHETIC_SIMULATION)
        self.assertIsNotNone(engine.gate)
        self.assertIsNotNone(engine.target)
        self.assertIsNotNone(engine.broker)
        self.assertTrue(decision["authorization"]["issued"])
        self.assertTrue(decision["action_results"])
        self.assertEqual(decision["counterfactual_actions"], [])
        self.assertFalse(decision["execution_control"]["read_only"])
        self.assertEqual(decision["execution_control"]["status"], "SYNTHETIC_SIMULATION")
        self.assertEqual(
            decision["execution_control"]["operational_effects"],
            sum(1 for result in decision["action_results"] if result["success"]),
        )

    def test_no_live_mode_or_live_enablement_parameter_exists(self) -> None:
        self.assertEqual(
            {mode.value for mode in ExecutionMode},
            {"synthetic_simulation", "historical_replay", "shadow_read_only"},
        )
        self.assertNotIn("LIVE", ExecutionMode.__members__)
        with self.assertRaises(ValueError):
            ExecutionMode("live")
        with self.assertRaises(ValueError):
            ExecutionMode("live_action")

        for callable_object in (DecisionFirewallEngine, run_engine):
            parameter_names = inspect.signature(callable_object).parameters
            self.assertFalse(any("live" in name.lower() for name in parameter_names))


if __name__ == "__main__":
    unittest.main()
