from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.replay.adapters import CanonicalJSONLAdapter
from adf_poc.replay.contracts import (
    ContractValidationError,
    ManifestValidationError,
    sha256_file,
)
from adf_poc.replay.harness import ReplayHarness, ReplaySafetyViolation
from adf_poc.utils import read_jsonl, sha256_json, write_jsonl


ROOT = Path(__file__).resolve().parents[1]


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def make_repository(root: Path, *, mode: str = "HISTORICAL_REPLAY") -> Path:
    shutil.copytree(ROOT / "data" / "phase2_starter", root / "data" / "phase2_starter")
    (root / "config").mkdir(parents=True)
    (root / "outputs" / "baseline").mkdir(parents=True)
    shutil.copyfile(ROOT / "config" / "policy.json", root / "config" / "policy.json")
    shutil.copyfile(
        ROOT / "outputs" / "baseline" / "model.json",
        root / "outputs" / "baseline" / "model.json",
    )
    manifest_path = root / "data" / "phase2_starter" / "manifest.json"
    if mode == "SHADOW_READ_ONLY":
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["intended_mode"] = mode
        write_json(manifest_path, manifest)
    config = {
        "schema_version": "0.2.0",
        "execution_mode": mode,
        "live_actions_enabled": False,
        "dataset_manifest": "data/phase2_starter/manifest.json",
        "model_path": "outputs/baseline/model.json",
        "policy_path": "config/policy.json",
        "output_dir": "outputs/replay/test",
        "contract_adapter": "canonical_jsonl_v0.2",
        "deterministic_outputs": True,
        "zero_effects_required": True,
    }
    config_path = root / "config" / "phase2_replay.json"
    write_json(config_path, config)
    return config_path


def safe_fake_decision(case_id: str, execution_mode: str) -> dict:
    decision = {
        "decision_id": f"test-decision-{case_id}",
        "case_id": case_id,
        "execution_mode": execution_mode,
        "final_disposition": "NO_ACTION",
        "compromise_probability": 0.1,
        "counterfactual_actions": [],
        "evidence_assessment": {"evidence_quality": 0.9},
        "proposal": {
            "executable_actions": [],
            "policy_rules_applied": ["TEST-READ-ONLY"],
            "evidence_event_ids": [],
        },
        "authorization": {
            "issued": False,
            "token_id": "",
            "decision_hash": "",
            "permitted_actions": [],
            "error": "",
        },
        "action_results": [],
        "post_action_verification": {
            "applicable": False,
            "status": "NOT_APPLICABLE",
            "passed": None,
            "checks": [],
        },
        "execution_control": {
            "mode": execution_mode,
            "read_only": True,
            "status": "SUPPRESSED_READ_ONLY",
            "authorization_attempted": False,
            "broker_invocations": 0,
            "operational_effects": 0,
        },
    }
    decision["decision_record_hash"] = sha256_json(decision)
    return decision


def rehash_decision(decision: dict) -> None:
    decision.pop("decision_record_hash", None)
    decision["decision_record_hash"] = sha256_json(decision)


def write_safe_read_only_audit(
    path: str | Path,
    decisions: list[dict],
    *,
    include_finalization: bool = True,
) -> None:
    audit = AuditLogger(path)
    for decision in decisions:
        audit.append(
            "EXECUTION_SUPPRESSED",
            {
                "case_id": decision["case_id"],
                "execution_mode": decision["execution_mode"],
                "reason": "Test runner read-only suppression.",
                "counterfactual_actions": decision["counterfactual_actions"],
                "authorization_attempted": False,
                "broker_invocations": 0,
                "operational_effects": 0,
            },
        )
        audit.append(
            "AUTHORIZATION_EVALUATED",
            {
                "case_id": decision["case_id"],
                "execution_mode": decision["execution_mode"],
                "attempted": False,
                "issued": False,
                "token_id": "",
                "permitted_actions": [],
                "error": "",
            },
        )
        if include_finalization:
            audit.append(
                "DECISION_FINALIZED",
                {
                    "case_id": decision["case_id"],
                    "decision_id": decision["decision_id"],
                    "final_disposition": decision["final_disposition"],
                    "decision_record_hash": decision["decision_record_hash"],
                },
            )


def run_with_runner(harness: ReplayHarness, runner):
    with patch.object(harness, "_default_engine_runner", return_value=runner):
        return harness.run()


class TrackingAdapter(CanonicalJSONLAdapter):
    def __init__(self, events: list[str], decision_path: Path) -> None:
        self.events = events
        self.decision_path = decision_path

    def load_cases(
        self,
        entry,
        *,
        record_failure_policy="FAIL_DATASET",
        dataset_id=None,
    ):
        self.events.append("cases_loaded")
        return super().load_cases(
            entry,
            record_failure_policy=record_failure_policy,
            dataset_id=dataset_id,
        )

    def load_adjudications(self, entry, *, known_case_ids):
        self.assert_decisions_exist()
        self.events.append("adjudications_loaded")
        return super().load_adjudications(entry, known_case_ids=known_case_ids)

    def assert_decisions_exist(self) -> None:
        if not self.decision_path.exists():
            raise AssertionError("Adjudications were loaded before engine decisions existed.")


class ReplayHarnessTests(unittest.TestCase):
    def test_synthetic_fixture_replay_has_zero_authorization_broker_or_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            result = ReplayHarness.from_config(
                config_path, repository_root=root
            ).run()
            assurance = result.metrics["read_only_assurance"]
            self.assertEqual(assurance["authorization_tokens_issued"], 0)
            self.assertEqual(assurance["broker_invocations"], 0)
            self.assertEqual(assurance["operational_effects"], 0)
            self.assertEqual(assurance["action_results"], 0)
            self.assertTrue(assurance["audit_chain_valid"])
            self.assertEqual(assurance["execution_suppression_records"], 3)
            self.assertEqual(assurance["authorization_evaluated_records"], 3)
            self.assertEqual(assurance["decision_finalized_records"], 3)
            self.assertEqual(assurance["action_executed_audit_records"], 0)
            self.assertEqual(result.metrics["scope"]["cases_evaluated"], 3)
            self.assertEqual(result.data_origin, "SYNTHETIC_FIXTURE")
            self.assertEqual(result.historical_case_count, 0)
            decisions = read_jsonl(result.raw_decisions_path)
            self.assertTrue(any(row["counterfactual_actions"] for row in decisions))
            for row in decisions:
                self.assertEqual(row["proposal"]["executable_actions"], [])
                self.assertFalse(row["authorization"]["issued"])
                self.assertEqual(row["action_results"], [])
                self.assertEqual(
                    row["post_action_verification"]["status"], "NOT_APPLICABLE"
                )
            run_manifest = json.loads(
                result.run_manifest_path.read_text(encoding="utf-8")
            )
            volatile = run_manifest["volatile_engine_artifacts"]
            self.assertEqual(
                volatile["engine_decisions"]["sha256"],
                sha256_file(result.raw_decisions_path),
            )
            self.assertEqual(
                volatile["audit_log"]["sha256"], sha256_file(result.audit_path)
            )
            self.assertEqual(
                volatile["audit_log"]["record_count"], assurance["audit_record_count"]
            )
            inputs = run_manifest["inputs"]
            self.assertTrue(
                inputs["snapshot_integrity_verified_before_and_after_execution"]
            )
            for name in ("configuration", "dataset_manifest", "model", "policy"):
                snapshot_path = result.output_dir / inputs[name]["path"]
                self.assertEqual(inputs[name]["sha256"], sha256_file(snapshot_path))

    def test_shadow_read_only_mode_is_supported_without_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root, mode="SHADOW_READ_ONLY")
            result = ReplayHarness.from_config(
                config_path, repository_root=root
            ).run()
            self.assertEqual(result.execution_mode, "shadow_read_only")
            self.assertEqual(
                result.metrics["read_only_assurance"]["operational_effects"], 0
            )

    def test_shadow_mode_requires_explicit_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root, mode="SHADOW_READ_ONLY")
            manifest_path = root / "data" / "phase2_starter" / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["attestations"]["approved_for_replay"] = False
            write_json(manifest_path, manifest)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with self.assertRaises(ManifestValidationError):
                harness.run()

    def test_non_empty_output_directory_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            output = root / "outputs" / "replay" / "test"
            output.mkdir(parents=True)
            (output / "prior-evidence.json").write_text("{}", encoding="utf-8")
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with self.assertRaises(ReplaySafetyViolation):
                harness.run()

    def test_adjudications_are_loaded_only_after_decisions_and_never_passed_to_engine(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            output = root / "outputs" / "replay" / "test"
            decision_path = output / "engine_decisions.jsonl"
            events: list[str] = []

            def fake_runner(**kwargs):
                events.append("engine_started")
                cases = read_jsonl(kwargs["cases_path"])
                serialized = json.dumps(cases)
                for forbidden in (
                    '"compromised"',
                    '"expected_disposition"',
                    '"scenario"',
                    '"adjudicated_disposition"',
                ):
                    self.assertNotIn(forbidden, serialized)
                mode = kwargs["execution_mode"].value
                decisions = [safe_fake_decision(row["case_id"], mode) for row in cases]
                write_jsonl(kwargs["decisions_path"], decisions)
                write_safe_read_only_audit(kwargs["audit_path"], decisions)
                events.append("decisions_written")
                return decisions

            adapter = TrackingAdapter(events, decision_path)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            harness._adapter = adapter
            result = run_with_runner(harness, fake_runner)
            self.assertEqual(
                events,
                [
                    "cases_loaded",
                    "engine_started",
                    "decisions_written",
                    "adjudications_loaded",
                ],
            )
            self.assertEqual(result.metrics["scope"]["adjudicated_cases"], 3)
            self.assertTrue(
                result.metrics["read_only_assurance"]
                ["adjudications_loaded_after_decisions"]
            )
            self.assertFalse(
                result.metrics["read_only_assurance"]
                ["runtime_label_file_passed_to_engine"]
            )

    def test_adjudication_json_is_not_decoded_until_after_engine_decisions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            adjudications_path = (
                root / "data" / "phase2_starter" / "adjudications.jsonl"
            )
            adjudications_path.write_text('{"malformed":\n', encoding="utf-8")
            manifest_path = root / "data" / "phase2_starter" / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            entry = next(
                value for value in manifest["files"] if value["role"] == "adjudications"
            )
            entry["sha256"] = sha256_file(adjudications_path)
            entry["record_count"] = 1
            write_json(manifest_path, manifest)
            engine_started = False

            def fake_runner(**kwargs):
                nonlocal engine_started
                engine_started = True
                cases = read_jsonl(kwargs["cases_path"])
                mode = kwargs["execution_mode"].value
                decisions = [safe_fake_decision(row["case_id"], mode) for row in cases]
                write_jsonl(kwargs["decisions_path"], decisions)
                write_safe_read_only_audit(kwargs["audit_path"], decisions)
                return decisions

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with self.assertRaises(ContractValidationError):
                run_with_runner(harness, fake_runner)
            self.assertTrue(engine_started)

    def test_engine_uses_frozen_inputs_when_sources_change_mid_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            adjudications_path = (
                root / "data" / "phase2_starter" / "adjudications.jsonl"
            )
            model_path = root / "outputs" / "baseline" / "model.json"
            original_adjudications = read_jsonl(adjudications_path)
            original_model_digest = sha256_file(model_path)

            def source_mutating_runner(**kwargs):
                cases = read_jsonl(kwargs["cases_path"])
                mode = kwargs["execution_mode"].value
                decisions = [safe_fake_decision(row["case_id"], mode) for row in cases]
                write_jsonl(kwargs["decisions_path"], decisions)
                write_safe_read_only_audit(kwargs["audit_path"], decisions)
                mutated = [dict(row) for row in original_adjudications]
                mutated[0]["adjudicated_disposition"] = "ESCALATE_HUMAN"
                write_jsonl(adjudications_path, mutated)
                model_path.write_text("{}", encoding="utf-8")
                return decisions

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            result = run_with_runner(harness, source_mutating_runner)
            comparisons = read_jsonl(result.comparisons_path)
            benign = next(
                row
                for row in comparisons
                if row["case_id"] == "phase2-synthetic-benign-001"
            )
            self.assertEqual(benign["adjudicated_disposition"], "NO_ACTION")
            run_manifest = json.loads(
                result.run_manifest_path.read_text(encoding="utf-8")
            )
            self.assertEqual(
                run_manifest["inputs"]["model"]["sha256"], original_model_digest
            )
            self.assertNotEqual(
                run_manifest["inputs"]["declared_files"]["adjudications"][
                    "sha256"
                ],
                sha256_file(adjudications_path),
            )

    def test_custom_runner_cannot_bypass_audit_boundary_validation(self) -> None:
        for audit_contents in ("", "{not-json}\n"):
            with self.subTest(audit_contents=audit_contents), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config_path = make_repository(root)

                def runner_without_boundary_audit(**kwargs):
                    cases = read_jsonl(kwargs["cases_path"])
                    mode = kwargs["execution_mode"].value
                    decisions = [
                        safe_fake_decision(row["case_id"], mode) for row in cases
                    ]
                    write_jsonl(kwargs["decisions_path"], decisions)
                    Path(kwargs["audit_path"]).write_text(
                        audit_contents, encoding="utf-8"
                    )
                    return decisions

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                with self.assertRaises(ReplaySafetyViolation):
                    run_with_runner(harness, runner_without_boundary_audit)

    def test_audit_must_bind_every_finalized_decision(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)

            def runner_without_finalization(**kwargs):
                cases = read_jsonl(kwargs["cases_path"])
                mode = kwargs["execution_mode"].value
                decisions = [safe_fake_decision(row["case_id"], mode) for row in cases]
                write_jsonl(kwargs["decisions_path"], decisions)
                write_safe_read_only_audit(
                    kwargs["audit_path"], decisions, include_finalization=False
                )
                return decisions

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with self.assertRaises(ReplaySafetyViolation):
                run_with_runner(harness, runner_without_finalization)

    def test_harness_rejects_any_reported_authorization_or_effect(self) -> None:
        unsafe_fields = (
            "authorization",
            "token_id",
            "decision_hash",
            "broker_invocations",
            "operational_effects",
        )
        for unsafe_field in unsafe_fields:
            with self.subTest(unsafe_field=unsafe_field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config_path = make_repository(root)

                def unsafe_runner(**kwargs):
                    cases = read_jsonl(kwargs["cases_path"])
                    mode = kwargs["execution_mode"].value
                    decisions = [safe_fake_decision(row["case_id"], mode) for row in cases]
                    if unsafe_field == "authorization":
                        decisions[0]["authorization"]["issued"] = True
                    elif unsafe_field in {"token_id", "decision_hash"}:
                        decisions[0]["authorization"][unsafe_field] = "residual-state"
                    else:
                        decisions[0]["execution_control"][unsafe_field] = 1
                    rehash_decision(decisions[0])
                    write_jsonl(kwargs["decisions_path"], decisions)
                    Path(kwargs["audit_path"]).write_text("", encoding="utf-8")
                    return decisions

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                with self.assertRaises(ReplaySafetyViolation):
                    run_with_runner(harness, unsafe_runner)

    def test_deterministic_projection_metrics_and_diagnostics_repeat(self) -> None:
        snapshots = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config_path = make_repository(root)
                result = ReplayHarness.from_config(
                    config_path, repository_root=root
                ).run()
                snapshots.append(
                    (
                        result.deterministic_decisions_path.read_bytes(),
                        result.metrics_path.read_bytes(),
                        result.comparisons_path.read_bytes(),
                        result.normalization_diagnostics_path.read_bytes(),
                    )
                )
        self.assertEqual(snapshots[0], snapshots[1])


if __name__ == "__main__":
    unittest.main()
