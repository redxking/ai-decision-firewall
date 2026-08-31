from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from adf_poc.audit import AuditLogger
from adf_poc.phase3.engine import Phase3DecisionFirewall
from adf_poc.phase3.scenarios import (
    anonymous_principal,
    request_json,
)
from adf_poc.utils import canonical_json
from run_phase3 import run_demonstration

from tests.phase3_support import (
    POLICY_PATH,
    TEST_SIGNING_KEY,
    domain_controller_case,
    new_harness,
    workstation_case,
)


class Phase3AuditAndMetricsTests(unittest.TestCase):
    def test_allowed_lifecycle_has_complete_correlated_audit_without_secrets(
        self,
    ) -> None:
        harness = new_harness()
        result = harness.firewall.process_json(
            request_json(workstation_case(harness, request_id="P3-AUDIT-WORKSTATION")),
            credential=harness.credential,
        )

        expected_types = [
            "REQUEST_RECEIVED",
            "REQUEST_VALIDATED",
            "IDENTITY_EVALUATED",
            "EVIDENCE_EVALUATED",
            "CONSEQUENCE_EVALUATED",
            "POLICY_EVALUATED",
            "DECISION_VERIFIED",
            "DECISION_PRODUCED",
            "AUTHORIZATION_PRODUCED",
            "BROKER_INVOKED",
            "ACTION_ATTEMPTED",
            "VERIFICATION_PERFORMED",
            "FINAL_STATE_RECORDED",
        ]
        self.assertEqual(
            [row["record_type"] for row in result.audit_records], expected_types
        )
        payloads = [row["payload"] for row in result.audit_records]
        self.assertEqual(len({row["intake_id"] for row in payloads}), 1)
        self.assertEqual(len({row["decision_id"] for row in payloads}), 1)
        self.assertEqual(
            {row["request_id"] for row in payloads[1:]},
            {result.decision.request_id},
        )
        self.assertTrue(all(row["intake_id"] for row in payloads))
        self.assertTrue(all(row["request_id"] for row in payloads))
        self.assertTrue(all(row["decision_id"] for row in payloads))
        valid, errors = AuditLogger.verify_rows(result.audit_records)
        self.assertTrue(valid, errors)

        assert result.authorization is not None
        serialized_audit = json.dumps(result.audit_records, sort_keys=True)
        self.assertNotIn(result.authorization.signature, serialized_audit)
        self.assertNotIn(TEST_SIGNING_KEY.hex(), serialized_audit)
        self.assertNotIn("signature", serialized_audit.lower())
        self.assertNotIn("signing_key", serialized_audit.lower())

        metrics = harness.firewall.metrics_snapshot()
        self.assertEqual(metrics["decisions_total"], 1)
        self.assertEqual(
            metrics["decision_counts"],
            {
                "ALLOW": 1,
                "DENY": 0,
                "ESCALATE": 0,
                "ALLOW_CONSTRAINED": 0,
            },
        )
        self.assertEqual(metrics["policy_rule_matches"], {"P3-ALLOW-REVERSIBLE": 1})
        self.assertEqual(metrics["evidence_conflicts"], 0)
        self.assertEqual(metrics["authorization_failures"], 0)
        self.assertEqual(metrics["broker_rejections"], 0)
        self.assertEqual(metrics["verification_failures"], 0)
        self.assertEqual(metrics["decision_latency_ms"]["count"], 1)
        self.assertGreaterEqual(metrics["decision_latency_ms"]["mean"], 0.0)

    def test_file_audit_with_in_memory_control_appends_across_reopen(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory).resolve() / "phase3-audit-only.jsonl"
            first = new_harness(audit_path=audit_path)
            first.firewall.process_json(
                request_json(
                    domain_controller_case(first, request_id="P3-AUDIT-ONLY-ONE")
                ),
                credential=first.credential,
            )
            first.firewall.process_json(
                request_json(workstation_case(first, request_id="P3-AUDIT-ONLY-TWO")),
                credential=first.credential,
            )
            prefix = audit_path.read_bytes()
            prefix_rows = AuditLogger(audit_path).read_all()
            self.assertEqual(
                prefix,
                b"".join(
                    (canonical_json(row) + "\n").encode("utf-8") for row in prefix_rows
                ),
            )

            reopened = new_harness(audit_path=audit_path)
            self.assertEqual(audit_path.read_bytes(), prefix)
            appended = reopened.firewall.process_json(
                request_json(
                    domain_controller_case(reopened, request_id="P3-AUDIT-ONLY-THREE")
                ),
                credential=reopened.credential,
            )
            expected_suffix = b"".join(
                (canonical_json(row) + "\n").encode("utf-8")
                for row in appended.audit_records
            )
            self.assertEqual(audit_path.read_bytes(), prefix + expected_suffix)
            self.assertEqual(
                AuditLogger(audit_path).read_all(),
                [*prefix_rows, *appended.audit_records],
            )
            valid, errors = AuditLogger.verify(audit_path)
            self.assertTrue(valid, errors)

    def test_metrics_reconcile_one_of_each_decision_outcome(self) -> None:
        escalate_harness = new_harness()
        allow_harness = new_harness()
        constrained_harness = new_harness()
        deny_harness = new_harness(principal=anonymous_principal())
        results = [
            escalate_harness.firewall.process_json(
                request_json(
                    domain_controller_case(
                        escalate_harness, request_id="P3-METRIC-ESCALATE"
                    )
                ),
                credential=escalate_harness.credential,
            ),
            allow_harness.firewall.process_json(
                request_json(
                    workstation_case(allow_harness, request_id="P3-METRIC-ALLOW")
                ),
                credential=allow_harness.credential,
            ),
            constrained_harness.firewall.process_json(
                request_json(
                    workstation_case(
                        constrained_harness,
                        request_id="P3-METRIC-CONSTRAINED",
                        duration_seconds=900,
                        preserve_management=False,
                    )
                ),
                credential=constrained_harness.credential,
            ),
            deny_harness.firewall.process_json(
                request_json(
                    workstation_case(deny_harness, request_id="P3-METRIC-DENY")
                ),
                credential=deny_harness.credential,
            ),
        ]
        self.assertEqual(
            [row.decision.outcome for row in results],
            ["ESCALATE", "ALLOW", "ALLOW_CONSTRAINED", "DENY"],
        )

        snapshots = [
            harness.firewall.metrics_snapshot()
            for harness in (
                escalate_harness,
                allow_harness,
                constrained_harness,
                deny_harness,
            )
        ]
        metrics = {
            "decisions_total": sum(row["decisions_total"] for row in snapshots),
            "decision_counts": {
                outcome: sum(row["decision_counts"][outcome] for row in snapshots)
                for outcome in ("ALLOW", "DENY", "ESCALATE", "ALLOW_CONSTRAINED")
            },
            "evidence_conflicts": sum(row["evidence_conflicts"] for row in snapshots),
            "decision_latency_count": sum(
                row["decision_latency_ms"]["count"] for row in snapshots
            ),
            "policy_rule_matches": {},
            "authorization_failures": sum(
                row["authorization_failures"] for row in snapshots
            ),
            "broker_rejections": sum(row["broker_rejections"] for row in snapshots),
            "verification_failures": sum(
                row["verification_failures"] for row in snapshots
            ),
        }
        for row in snapshots:
            for rule, count in row["policy_rule_matches"].items():
                metrics["policy_rule_matches"][rule] = (
                    metrics["policy_rule_matches"].get(rule, 0) + count
                )
        self.assertEqual(metrics["decisions_total"], 4)
        self.assertEqual(
            metrics["decision_counts"],
            {
                "ALLOW": 1,
                "DENY": 1,
                "ESCALATE": 1,
                "ALLOW_CONSTRAINED": 1,
            },
        )
        self.assertEqual(metrics["evidence_conflicts"], 1)
        self.assertEqual(metrics["decision_latency_count"], 4)
        self.assertEqual(
            metrics["policy_rule_matches"],
            {
                "P3-ALLOW-CONSTRAINED": 1,
                "P3-ALLOW-REVERSIBLE": 1,
                "P3-ESCALATE-PROTECTED-ASSET": 1,
                "P3-FAIL-CLOSED": 1,
            },
        )
        self.assertEqual(metrics["authorization_failures"], 0)
        self.assertEqual(metrics["broker_rejections"], 0)
        self.assertEqual(metrics["verification_failures"], 0)


class Phase3DemonstrationTests(unittest.TestCase):
    def test_demo_runner_writes_reproducible_artifacts_and_valid_audit_chain(
        self,
    ) -> None:
        harness = new_harness()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "phase3-demo"
            result = run_demonstration(
                output_dir=output,
                policy_path=POLICY_PATH,
                evaluated_at=harness.clock(),
            )

            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                [
                    "phase3_audit.jsonl",
                    "phase3_demo_results.json",
                    "phase3_metrics.json",
                ],
            )
            persisted = json.loads(
                (output / "phase3_demo_results.json").read_text(encoding="utf-8")
            )
            persisted_metrics = json.loads(
                (output / "phase3_metrics.json").read_text(encoding="utf-8")
            )
            audit_valid, audit_errors = AuditLogger.verify(
                output / "phase3_audit.jsonl"
            )

        high = result["demo_1_high_risk_domain_controller"]
        low = result["demo_2_authorized_workstation"]
        self.assertEqual(high["decision"]["outcome"], "ESCALATE")
        self.assertIsNone(high["authorization"])
        self.assertIsNone(high["broker_result"])
        self.assertEqual(high["final_state"]["network_state"], "connected")
        self.assertEqual(low["decision"]["outcome"], "ALLOW")
        self.assertEqual(low["verification"]["status"], "VERIFIED")
        self.assertEqual(low["final_state"]["network_state"], "isolated")
        self.assertTrue(result["audit"]["valid"])
        self.assertTrue(audit_valid, audit_errors)
        self.assertEqual(persisted, json.loads(json.dumps(result)))
        self.assertEqual(persisted_metrics, result["metrics"])
        self.assertEqual(
            result["metrics"]["decision_counts"],
            {
                "ALLOW": 1,
                "DENY": 0,
                "ESCALATE": 1,
                "ALLOW_CONSTRAINED": 0,
            },
        )
        self.assertEqual(result["metrics"]["evidence_conflicts"], 1)
        serialized = json.dumps(persisted, sort_keys=True).lower()
        self.assertNotIn("signing_key", serialized)
        self.assertNotIn('"signature"', serialized)
        self.assertFalse(result["scope"]["live_actions_enabled"])
        self.assertEqual(result["scope"]["execution_mode"], "synthetic_simulation")
        self.assertEqual(result["scope"]["operational_validity"], "not established")

    def test_phase3_rejects_non_simulated_environment_injection(self) -> None:
        harness = new_harness()
        for injected_name in (
            "environment",
            "broker",
            "target_verifier",
            "authorization_gate",
            "audit_logger",
            "metrics",
        ):
            with self.subTest(injected_name=injected_name):
                arguments = {
                    "policy": harness.policy,
                    "signing_key": TEST_SIGNING_KEY,
                    "evidence_attestation_keys": harness.source_keys,
                    "principal_resolver": harness.resolver,
                    injected_name: object(),
                }
                with self.assertRaises(TypeError):
                    Phase3DecisionFirewall(**arguments)


if __name__ == "__main__":
    unittest.main()
