from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from adf_poc.audit import AuditLogger
from adf_poc.features import extract_features
from adf_poc.replay.adapters import CanonicalJSONLAdapter
from adf_poc.replay.contracts import (
    ContractValidationError,
    ManifestValidationError,
    sha256_file,
)
from adf_poc.replay.harness import ReplayHarness, ReplaySafetyViolation
from adf_poc.replay.reference_decision import ReferenceDecisionAssuranceError
from adf_poc.schemas import IdentityCase
from adf_poc.utils import read_jsonl, sha256_json, write_jsonl


ROOT = Path(__file__).resolve().parents[1]
BOUND_AUTONOMOUS_ACTIONS = [
    "revoke_active_sessions",
    "force_step_up_auth",
    "increase_monitoring",
]
CONTAINMENT_ROLLBACK_PLAN = {
    "revoke_active_sessions": (
        "restore only through normal reauthentication; no session token is reinstated"
    ),
    "force_step_up_auth": ("remove temporary step-up requirement after analyst review"),
    "increase_monitoring": "return telemetry policy to baseline after closure",
}
VERIFIER_DOWNGRADE_REASON = (
    "Independent verification failed; the action proposal was downgraded to "
    "investigation."
)


def write_json(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")


def make_repository(root: Path, *, mode: str = "HISTORICAL_REPLAY") -> Path:
    shutil.copytree(ROOT / "data" / "phase2_starter", root / "data" / "phase2_starter")
    shutil.copytree(ROOT / "contracts", root / "contracts")
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


def safe_fake_decision(case: str | dict, execution_mode: str) -> dict:
    case_id = case if isinstance(case, str) else str(case["case_id"])
    decision = {
        "decision_id": f"test-decision-{case_id}",
        "case_id": case_id,
        "subject_id": f"test-subject-{case_id}",
        "execution_mode": execution_mode,
        "original_disposition": "NO_ACTION",
        "final_disposition": "NO_ACTION",
        "compromise_probability": 0.1,
        "counterfactual_actions": [],
        "evidence_assessment": {
            "evidence_quality": 0.9,
            "provenance_valid_ratio": 1.0,
            "integrity_verified_ratio": 1.0,
            "freshness_score": 1.0,
            "source_diversity_score": 1.0,
            "mean_source_trust": 0.9,
            "independent_supporting_sources": 0,
            "positive_event_ids": [],
            "benign_event_ids": [],
            "missing_expected_sources": [],
            "conflict_count": 0,
            "poisoned_evidence": False,
            "poisoned_event_ids": [],
            "reasons": ["Test runner evidence assessment."],
        },
        "model_assessment": {
            "model_version": "test-model-v1",
            "compromise_probability": 0.1,
            "feature_values": {},
            "feature_trace": {},
            "top_positive_factors": [],
            "top_negative_factors": [],
        },
        "proposal": {
            "disposition": "NO_ACTION",
            "executable_actions": [],
            "recommended_human_actions": [],
            "investigation_actions": [],
            "rationale": ["Test runner read-only proposal."],
            "policy_rules_applied": ["TEST-READ-ONLY"],
            "evidence_event_ids": [],
            "required_authority": "read_only_observation",
            "rollback_plan": {},
        },
        "independent_verification": {
            "passed": True,
            "checks": [],
            "blocking_reasons": [],
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
        "traceability": {
            "input_event_ids": [],
            "cited_evidence_event_ids": [],
            "feature_trace": {},
        },
    }
    if isinstance(case, dict):
        typed_case = IdentityCase.from_dict(case)
        feature_values, feature_trace = extract_features(typed_case)
        decision["model_assessment"]["feature_values"] = {
            name: round(float(value), 6) for name, value in feature_values.items()
        }
        decision["model_assessment"]["feature_trace"] = feature_trace
        decision["traceability"]["input_event_ids"] = [
            event.event_id for event in typed_case.events
        ]
        decision["traceability"]["feature_trace"] = feature_trace
    decision["decision_record_hash"] = sha256_json(decision)
    return decision


def rehash_decision(decision: dict) -> None:
    decision.pop("decision_record_hash", None)
    decision["decision_record_hash"] = sha256_json(decision)


def make_containment_decision(
    case: str | dict,
    execution_mode: str,
    *,
    verifier_downgrade: bool,
) -> dict:
    decision = safe_fake_decision(case, execution_mode)
    decision["original_disposition"] = "CONTAIN_REVERSIBLE"
    decision["proposal"].update(
        {
            "policy_rules_applied": [
                "RISK-AUTO-CONTAIN-THRESHOLD",
                "AUTH-REVERSIBLE-ACTIONS-ONLY",
            ],
            "rationale": ["Test runner reversible containment proposal."],
        }
    )
    if verifier_downgrade:
        decision["final_disposition"] = "INVESTIGATE"
        decision["counterfactual_actions"] = []
        decision["proposal"].update(
            {
                "disposition": "INVESTIGATE",
                "investigation_actions": [
                    "resolve_independent_verifier_failure",
                    "collect_additional_evidence",
                ],
                "rationale": decision["proposal"]["rationale"]
                + [VERIFIER_DOWNGRADE_REASON],
                "policy_rules_applied": decision["proposal"]["policy_rules_applied"]
                + ["FAIL-SAFE-VERIFIER-DOWNGRADE"],
            }
        )
        decision["independent_verification"] = {
            "passed": False,
            "checks": [
                {
                    "check": "TEST-FORCED-FAILURE",
                    "passed": False,
                    "detail": "Exercise the deterministic downgrade contract.",
                }
            ],
            "blocking_reasons": ["TEST-FORCED-FAILURE"],
        }
    else:
        decision["final_disposition"] = "CONTAIN_REVERSIBLE"
        decision["counterfactual_actions"] = list(BOUND_AUTONOMOUS_ACTIONS)
        decision["proposal"]["disposition"] = "CONTAIN_REVERSIBLE"
    rehash_decision(decision)
    return decision


def write_safe_read_only_audit(
    path: str | Path,
    decisions: list[dict],
) -> None:
    audit = AuditLogger(path)
    for decision in decisions:
        original_disposition = decision["original_disposition"]
        policy_payload = dict(decision["proposal"])
        if original_disposition == "CONTAIN_REVERSIBLE":
            policy_payload["required_authority"] = "deterministic_policy_gate"
            policy_payload["rollback_plan"] = dict(CONTAINMENT_ROLLBACK_PLAN)
        elif original_disposition == "INVESTIGATE":
            policy_payload["required_authority"] = "read_only_automation"
        elif original_disposition == "ESCALATE_HUMAN":
            policy_payload["required_authority"] = "soc_shift_lead_or_identity_owner"
        else:
            policy_payload["required_authority"] = "none"
        if original_disposition != decision["final_disposition"]:
            policy_payload.update(
                {
                    "disposition": original_disposition,
                    "investigation_actions": [],
                    "rationale": policy_payload["rationale"][:-1],
                    "policy_rules_applied": policy_payload["policy_rules_applied"][:-1],
                }
            )
        policy_payload["counterfactual_actions"] = (
            list(BOUND_AUTONOMOUS_ACTIONS)
            if original_disposition == "CONTAIN_REVERSIBLE"
            else []
        )
        audit.append(
            "CASE_RECEIVED",
            {
                "case_id": decision["case_id"],
                "subject_id": decision["subject_id"],
                "event_ids": decision["traceability"]["input_event_ids"],
            },
        )
        audit.append(
            "EVIDENCE_ASSESSED",
            {
                "case_id": decision["case_id"],
                **decision["evidence_assessment"],
            },
        )
        audit.append(
            "MODEL_ASSESSED",
            {
                "case_id": decision["case_id"],
                **decision["model_assessment"],
            },
        )
        audit.append(
            "POLICY_PROPOSED",
            {
                "case_id": decision["case_id"],
                **policy_payload,
            },
        )
        audit.append(
            "INDEPENDENTLY_VERIFIED",
            {
                "case_id": decision["case_id"],
                **decision["independent_verification"],
            },
        )
        audit.append(
            "EXECUTION_SUPPRESSED",
            {
                "case_id": decision["case_id"],
                "execution_mode": decision["execution_mode"],
                "reason": "Historical replay and shadow modes are observation-only.",
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
        audit.append(
            "DECISION_FINALIZED",
            {
                "case_id": decision["case_id"],
                "decision_id": decision["decision_id"],
                "final_disposition": decision["final_disposition"],
                "decision_record_hash": decision["decision_record_hash"],
            },
        )


def rewrite_rechained_audit(
    path: str | Path,
    rows: list[dict],
    *,
    preserve_sequence: bool = False,
    preserve_recorded_at: bool = False,
) -> None:
    target = Path(path)
    previous_hash = "0" * 64
    rechained = []
    for index, row in enumerate(rows):
        body = dict(row)
        body.pop("record_hash", None)
        body["previous_hash"] = previous_hash
        if not preserve_sequence:
            body["sequence"] = index
        if not preserve_recorded_at:
            body["recorded_at"] = "2026-01-01T00:00:00+00:00"
        body["record_hash"] = sha256_json(body)
        previous_hash = body["record_hash"]
        rechained.append(body)
    write_jsonl(target, rechained)
    valid, errors = AuditLogger.verify(target)
    if not valid:
        raise AssertionError(
            f"Test audit mutation was not correctly rechained: {errors}"
        )


def run_with_runner(harness: ReplayHarness, runner):
    def isolated_source_to_decision_receipts(**kwargs):
        cases = [
            json.loads(line)
            for line in kwargs["cases_jsonl"].decode("utf-8").splitlines()
            if line.strip()
        ]
        model_digest = hashlib.sha256(kwargs["model_json"]).hexdigest()
        policy_digest = hashlib.sha256(kwargs["policy_json"]).hexdigest()
        records = []
        for case in sorted(cases, key=lambda row: row["case_id"]):
            stage_digest = sha256_json(
                {"case_id": case["case_id"], "test_boundary": "isolated"}
            )
            records.append(
                {
                    "schema_version": "0.2.0",
                    "assurance_kind": "SEPARATE_SOURCE_TO_DECISION_RECOMPUTATION",
                    "recomputation_scope": (
                        "EVIDENCE_MODEL_POLICY_VERIFIER_READ_ONLY_FINAL"
                    ),
                    "case_id": case["case_id"],
                    "normalized_case_sha256": sha256_json(case),
                    "model_source_sha256": model_digest,
                    "policy_source_sha256": policy_digest,
                    "expected_evidence_sha256": stage_digest,
                    "observed_evidence_sha256": stage_digest,
                    "expected_model_sha256": stage_digest,
                    "observed_model_sha256": stage_digest,
                    "expected_policy_sha256": stage_digest,
                    "observed_policy_sha256": stage_digest,
                    "expected_verifier_sha256": stage_digest,
                    "observed_verifier_sha256": stage_digest,
                    "expected_final_surface_sha256": stage_digest,
                    "observed_final_surface_sha256": stage_digest,
                    "expected_source_to_decision_sha256": stage_digest,
                    "observed_source_to_decision_sha256": stage_digest,
                    "execution_mode": kwargs["expected_execution_mode"],
                    "read_only": True,
                    "matched": True,
                }
            )
        return records

    # Custom runners in these tests isolate earlier harness and audit controls.
    # The real source-to-decision path is exercised by the default-run and
    # dedicated fail-closed integration tests below.
    with (
        patch.object(harness, "_default_engine_runner", return_value=runner),
        patch(
            "adf_poc.replay.harness.verify_reference_decision_path",
            side_effect=isolated_source_to_decision_receipts,
        ),
    ):
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
            raise AssertionError(
                "Adjudications were loaded before engine decisions existed."
            )


class ReplayHarnessTests(unittest.TestCase):
    def test_synthetic_fixture_replay_has_zero_authorization_broker_or_effects(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            result = ReplayHarness.from_config(config_path, repository_root=root).run()
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
            reference_assurance = result.metrics["reference_feature_assurance"]
            self.assertEqual(reference_assurance["cases_checked"], 3)
            self.assertEqual(reference_assurance["matched_cases"], 3)
            self.assertEqual(reference_assurance["mismatched_cases"], 0)
            self.assertTrue(reference_assurance["complete"])
            reference_records = read_jsonl(result.reference_feature_assurance_path)
            self.assertEqual(len(reference_records), 3)
            self.assertTrue(all(row["matched"] is True for row in reference_records))
            source_assurance = result.metrics["source_to_decision_assurance"]
            self.assertEqual(source_assurance["cases_checked"], 3)
            self.assertEqual(source_assurance["matched_cases"], 3)
            self.assertEqual(source_assurance["mismatched_cases"], 0)
            self.assertTrue(source_assurance["complete"])
            source_records = read_jsonl(result.source_to_decision_assurance_path)
            self.assertEqual(len(source_records), 3)
            self.assertEqual(
                [row["case_id"] for row in source_records],
                sorted(row["case_id"] for row in source_records),
            )
            for row in source_records:
                self.assertEqual(
                    row["assurance_kind"],
                    "SEPARATE_SOURCE_TO_DECISION_RECOMPUTATION",
                )
                self.assertEqual(
                    row["recomputation_scope"],
                    "EVIDENCE_MODEL_POLICY_VERIFIER_READ_ONLY_FINAL",
                )
                self.assertTrue(row["read_only"])
                self.assertTrue(row["matched"])
                for stage in (
                    "evidence",
                    "model",
                    "policy",
                    "verifier",
                    "final_surface",
                    "source_to_decision",
                ):
                    self.assertEqual(
                        row[f"expected_{stage}_sha256"],
                        row[f"observed_{stage}_sha256"],
                    )
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
            reference_artifact = run_manifest["deterministic_artifacts"][
                "reference_feature_assurance"
            ]
            self.assertEqual(reference_artifact["record_count"], 3)
            self.assertEqual(
                reference_artifact["sha256"],
                sha256_file(result.reference_feature_assurance_path),
            )
            source_artifact = run_manifest["deterministic_artifacts"][
                "source_to_decision_assurance"
            ]
            self.assertEqual(source_artifact["record_count"], 3)
            self.assertEqual(
                source_artifact["sha256"],
                sha256_file(result.source_to_decision_assurance_path),
            )
            inputs = run_manifest["inputs"]
            self.assertTrue(
                inputs["snapshot_integrity_verified_before_and_after_execution"]
            )
            for name in ("configuration", "dataset_manifest", "model", "policy"):
                snapshot_path = result.output_dir / inputs[name]["path"]
                self.assertEqual(inputs[name]["sha256"], sha256_file(snapshot_path))
            for row in source_records:
                self.assertEqual(row["model_source_sha256"], inputs["model"]["sha256"])
                self.assertEqual(
                    row["policy_source_sha256"], inputs["policy"]["sha256"]
                )

    def test_shadow_read_only_mode_is_supported_without_effects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root, mode="SHADOW_READ_ONLY")
            result = ReplayHarness.from_config(config_path, repository_root=root).run()
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

    def test_adjudications_are_loaded_only_after_decisions_and_never_passed_to_engine(
        self,
    ) -> None:
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
                decisions = [safe_fake_decision(row, mode) for row in cases]
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
                result.metrics["read_only_assurance"][
                    "adjudications_loaded_after_decisions"
                ]
            )
            self.assertFalse(
                result.metrics["read_only_assurance"][
                    "runtime_label_file_passed_to_engine"
                ]
            )

    def test_adjudication_json_is_not_decoded_until_after_engine_decisions(
        self,
    ) -> None:
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
                decisions = [safe_fake_decision(row, mode) for row in cases]
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
                decisions = [safe_fake_decision(row, mode) for row in cases]
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
                run_manifest["inputs"]["declared_files"]["adjudications"]["sha256"],
                sha256_file(adjudications_path),
            )

    def test_custom_runner_cannot_bypass_audit_boundary_validation(self) -> None:
        for audit_contents in ("", "{not-json}\n"):
            with (
                self.subTest(audit_contents=audit_contents),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)

                def runner_without_boundary_audit(**kwargs):
                    cases = read_jsonl(kwargs["cases_path"])
                    mode = kwargs["execution_mode"].value
                    decisions = [safe_fake_decision(row, mode) for row in cases]
                    write_jsonl(kwargs["decisions_path"], decisions)
                    Path(kwargs["audit_path"]).write_text(
                        audit_contents, encoding="utf-8"
                    )
                    return decisions

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                with self.assertRaises(ReplaySafetyViolation):
                    run_with_runner(harness, runner_without_boundary_audit)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)

            def runner_with_unknown_audit_type(**kwargs):
                cases = read_jsonl(kwargs["cases_path"])
                mode = kwargs["execution_mode"].value
                decisions = [safe_fake_decision(row, mode) for row in cases]
                write_jsonl(kwargs["decisions_path"], decisions)
                write_safe_read_only_audit(kwargs["audit_path"], decisions)
                AuditLogger(kwargs["audit_path"]).append(
                    "UNREVIEWED_AUDIT_TYPE",
                    {"case_id": decisions[0]["case_id"]},
                )
                return decisions

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with self.assertRaises(ReplaySafetyViolation):
                run_with_runner(harness, runner_with_unknown_audit_type)

    def test_coherent_feature_and_audit_forgery_is_blocked_before_finalization(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)

            def runner_with_coherent_feature_forgery(**kwargs):
                cases = read_jsonl(kwargs["cases_path"])
                mode = kwargs["execution_mode"].value
                decisions = [safe_fake_decision(row, mode) for row in cases]
                forged = decisions[0]
                original = forged["model_assessment"]["feature_values"]["new_device"]
                forged["model_assessment"]["feature_values"]["new_device"] = (
                    0.0 if original == 1.0 else 1.0
                )
                rehash_decision(forged)
                write_jsonl(kwargs["decisions_path"], decisions)
                write_safe_read_only_audit(kwargs["audit_path"], decisions)
                return decisions

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with self.assertRaisesRegex(
                ReplaySafetyViolation,
                "Reference feature assurance rejected",
            ):
                run_with_runner(harness, runner_with_coherent_feature_forgery)
            self.assertFalse(
                (root / "outputs/replay/test/replay_run_manifest.json").exists()
            )

    def test_source_to_decision_mismatch_blocks_all_assurance_and_evaluation_outputs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with (
                patch(
                    "adf_poc.replay.harness.verify_reference_decision_path",
                    side_effect=ReferenceDecisionAssuranceError(
                        "REFERENCE_DECISION_POLICY_MISMATCH"
                    ),
                ),
                self.assertRaisesRegex(
                    ReplaySafetyViolation,
                    "Source-to-decision assurance rejected",
                ),
            ):
                harness.run()

            output = root / "outputs/replay/test"
            for relative in (
                "reference_feature_assurance.jsonl",
                "source_to_decision_assurance.jsonl",
                "qualification_accounting.jsonl",
                "rejections.jsonl",
                "input_snapshot/adjudications.jsonl",
                "adjudication_comparison.jsonl",
                "replay_metrics.json",
                "replay_run_manifest.json",
            ):
                with self.subTest(relative=relative):
                    self.assertFalse((output / relative).exists())
            for relative in (
                "normalized_cases.jsonl",
                "engine_decisions.jsonl",
                "replay_decisions.jsonl",
                "replay_audit.jsonl",
            ):
                with self.subTest(incomplete_artifact=relative):
                    self.assertTrue((output / relative).exists())

    def test_source_to_decision_artifact_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)

            def tampering_write_jsonl(path, rows):
                count = write_jsonl(path, rows)
                if Path(path).name == "source_to_decision_assurance.jsonl":
                    mutated = read_jsonl(path)
                    mutated[0]["unexpected_payload"] = "blocked"
                    write_jsonl(path, mutated)
                return count

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with (
                patch(
                    "adf_poc.replay.harness.write_jsonl",
                    side_effect=tampering_write_jsonl,
                ),
                self.assertRaisesRegex(
                    ReplaySafetyViolation,
                    "artifact changed after validation",
                ),
            ):
                harness.run()
            self.assertFalse(
                (root / "outputs/replay/test/adjudication_comparison.jsonl").exists()
            )
            self.assertFalse(
                (root / "outputs/replay/test/replay_metrics.json").exists()
            )
            self.assertFalse(
                (root / "outputs/replay/test/replay_run_manifest.json").exists()
            )

    def test_duplicate_source_to_decision_artifact_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)

            def duplicate_member_write(path, rows):
                count = write_jsonl(path, rows)
                if Path(path).name == "source_to_decision_assurance.jsonl":
                    lines = Path(path).read_text(encoding="utf-8").splitlines()
                    lines[0] = lines[0].replace(
                        '"matched":true',
                        '"matched":false,"matched":true',
                        1,
                    )
                    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
                return count

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with (
                patch(
                    "adf_poc.replay.harness.write_jsonl",
                    side_effect=duplicate_member_write,
                ),
                self.assertRaisesRegex(ReplaySafetyViolation, "artifact is invalid"),
            ):
                harness.run()
            self.assertFalse(
                (root / "outputs/replay/test/adjudication_comparison.jsonl").exists()
            )
            self.assertFalse(
                (root / "outputs/replay/test/replay_metrics.json").exists()
            )
            self.assertFalse(
                (root / "outputs/replay/test/replay_run_manifest.json").exists()
            )

    def test_nonfinite_source_to_decision_artifact_value_is_rejected(self) -> None:
        for spelling in ("NaN", "1e400"):
            with (
                self.subTest(spelling=spelling),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)

                def nonfinite_write(path, rows):
                    count = write_jsonl(path, rows)
                    if Path(path).name == "source_to_decision_assurance.jsonl":
                        content = Path(path).read_text(encoding="utf-8")
                        content = content.replace(
                            '"matched":true', f'"matched":{spelling}', 1
                        )
                        Path(path).write_text(content, encoding="utf-8")
                    return count

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                with (
                    patch(
                        "adf_poc.replay.harness.write_jsonl",
                        side_effect=nonfinite_write,
                    ),
                    self.assertRaisesRegex(
                        ReplaySafetyViolation, "artifact is invalid"
                    ),
                ):
                    harness.run()
                self.assertFalse(
                    (root / "outputs/replay/test/replay_metrics.json").exists()
                )
                self.assertFalse(
                    (root / "outputs/replay/test/replay_run_manifest.json").exists()
                )

    def test_reference_feature_artifact_mutation_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)

            def tampering_write_jsonl(path, rows):
                count = write_jsonl(path, rows)
                if Path(path).name == "reference_feature_assurance.jsonl":
                    mutated = read_jsonl(path)
                    mutated[0]["unexpected_payload"] = "blocked"
                    write_jsonl(path, mutated)
                return count

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with (
                patch(
                    "adf_poc.replay.harness.write_jsonl",
                    side_effect=tampering_write_jsonl,
                ),
                self.assertRaisesRegex(
                    ReplaySafetyViolation,
                    "artifact changed after validation",
                ),
            ):
                harness.run()
            self.assertFalse(
                (root / "outputs/replay/test/replay_run_manifest.json").exists()
            )

    def test_duplicate_reference_artifact_member_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)

            def duplicate_member_write(path, rows):
                count = write_jsonl(path, rows)
                if Path(path).name == "reference_feature_assurance.jsonl":
                    lines = Path(path).read_text(encoding="utf-8").splitlines()
                    lines[0] = lines[0].replace(
                        '"matched":true',
                        '"matched":false,"matched":true',
                        1,
                    )
                    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
                return count

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with (
                patch(
                    "adf_poc.replay.harness.write_jsonl",
                    side_effect=duplicate_member_write,
                ),
                self.assertRaisesRegex(ReplaySafetyViolation, "artifact is invalid"),
            ):
                harness.run()
            self.assertFalse(
                (root / "outputs/replay/test/replay_run_manifest.json").exists()
            )

    def test_runner_cannot_mutate_normalized_cases_after_deciding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            builtin = harness._default_engine_runner()

            def mutating_runner(**kwargs):
                result = builtin(**kwargs)
                cases = read_jsonl(kwargs["cases_path"])
                cases[0]["events"][0]["attributes"]["runner_added_context"] = True
                write_jsonl(kwargs["cases_path"], cases)
                return result

            with self.assertRaisesRegex(
                ReplaySafetyViolation,
                "Normalized cases artifact changed after validation",
            ):
                run_with_runner(harness, mutating_runner)
            self.assertFalse(
                (root / "outputs/replay/test/replay_run_manifest.json").exists()
            )

    def test_manifest_construction_rejects_late_reference_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            original = harness._build_run_manifest

            def mutate_before_manifest(**kwargs):
                records = read_jsonl(kwargs["reference_features_path"])
                records[0]["expected_projection_sha256"] = "0" * 64
                write_jsonl(kwargs["reference_features_path"], records)
                return original(**kwargs)

            with (
                patch.object(
                    harness,
                    "_build_run_manifest",
                    side_effect=mutate_before_manifest,
                ),
                self.assertRaisesRegex(
                    ReplaySafetyViolation,
                    "bound replay artifact changed",
                ),
            ):
                harness.run()
            self.assertFalse(
                (root / "outputs/replay/test/replay_run_manifest.json").exists()
            )

    def test_manifest_construction_rejects_late_source_to_decision_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            original = harness._build_run_manifest

            def mutate_before_manifest(**kwargs):
                records = read_jsonl(kwargs["source_to_decision_path"])
                records[0]["expected_source_to_decision_sha256"] = "0" * 64
                write_jsonl(kwargs["source_to_decision_path"], records)
                return original(**kwargs)

            with (
                patch.object(
                    harness,
                    "_build_run_manifest",
                    side_effect=mutate_before_manifest,
                ),
                self.assertRaisesRegex(
                    ReplaySafetyViolation,
                    "bound replay artifact changed",
                ),
            ):
                harness.run()
            self.assertFalse(
                (root / "outputs/replay/test/replay_run_manifest.json").exists()
            )

    def test_manifest_cannot_bind_decision_or_audit_bytes_not_previously_checked(
        self,
    ) -> None:
        for argument in (
            "raw_decisions_path",
            "deterministic_path",
            "audit_path",
        ):
            with (
                self.subTest(argument=argument),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)
                harness = ReplayHarness.from_config(config_path, repository_root=root)
                original = harness._build_run_manifest

                def mutate_before_manifest(**kwargs):
                    records = read_jsonl(kwargs[argument])
                    records[0]["late_unvalidated_mutation"] = argument
                    write_jsonl(kwargs[argument], records)
                    return original(**kwargs)

                with (
                    patch.object(
                        harness,
                        "_build_run_manifest",
                        side_effect=mutate_before_manifest,
                    ),
                    self.assertRaisesRegex(
                        ReplaySafetyViolation,
                        "bound replay artifact changed",
                    ),
                ):
                    harness.run()
                self.assertFalse(
                    (root / "outputs/replay/test/replay_run_manifest.json").exists()
                )

    def test_manifest_rejects_late_mutation_of_every_deterministic_artifact(
        self,
    ) -> None:
        artifacts = (
            ("normalized_path", "jsonl"),
            ("diagnostics_path", "json"),
            ("deterministic_path", "jsonl"),
            ("reference_features_path", "jsonl"),
            ("source_to_decision_path", "jsonl"),
            ("qualification_path", "jsonl"),
            ("rejections_path", "jsonl"),
            ("comparisons_path", "jsonl"),
            ("metrics_path", "json"),
        )
        for argument, artifact_type in artifacts:
            with (
                self.subTest(argument=argument),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)
                config = json.loads(config_path.read_text(encoding="utf-8"))
                config["record_failure_policy"] = "QUARANTINE_RECORD"
                write_json(config_path, config)
                harness = ReplayHarness.from_config(config_path, repository_root=root)
                original = harness._build_run_manifest

                def mutate_before_manifest(**kwargs):
                    target = kwargs[argument]
                    if artifact_type == "json":
                        value = json.loads(target.read_text(encoding="utf-8"))
                        value["late_unvalidated_mutation"] = argument
                        write_json(target, value)
                    else:
                        rows = read_jsonl(target)
                        if rows:
                            rows[0]["late_unvalidated_mutation"] = argument
                        else:
                            rows.append({"late_unvalidated_mutation": argument})
                        write_jsonl(target, rows)
                    return original(**kwargs)

                with (
                    patch.object(
                        harness,
                        "_build_run_manifest",
                        side_effect=mutate_before_manifest,
                    ),
                    self.assertRaisesRegex(
                        ReplaySafetyViolation,
                        "bound replay artifact changed",
                    ),
                ):
                    harness.run()
                self.assertFalse(
                    (root / "outputs/replay/test/replay_run_manifest.json").exists()
                )

    def test_nonfinite_case_json_is_rejected_before_engine_invocation(self) -> None:
        for spelling in ("NaN", "1e400"):
            with (
                self.subTest(spelling=spelling),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)
                cases_path = root / "data" / "phase2_starter" / "cases.jsonl"
                content = cases_path.read_text(encoding="utf-8")
                content = content.replace(
                    '"travel_record_id":""',
                    f'"opaque_overflow":{spelling},"travel_record_id":""',
                    1,
                )
                cases_path.write_text(content, encoding="utf-8")
                manifest_path = root / "data" / "phase2_starter" / "manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                cases_entry = next(
                    entry for entry in manifest["files"] if entry["role"] == "cases"
                )
                cases_entry["sha256"] = sha256_file(cases_path)
                write_json(manifest_path, manifest)

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                with (
                    patch.object(
                        harness,
                        "_default_engine_runner",
                        side_effect=AssertionError("engine must not be reached"),
                    ),
                    self.assertRaises(ContractValidationError),
                ):
                    harness.run()
                self.assertFalse(
                    (root / "outputs/replay/test/engine_decisions.jsonl").exists()
                )
                self.assertFalse(
                    (root / "outputs/replay/test/replay_run_manifest.json").exists()
                )

    def test_audit_must_bind_every_finalized_decision(self) -> None:
        for mutation in ("missing", "decision_id", "decision_record_hash"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)

                def runner_with_invalid_finalization(**kwargs):
                    cases = read_jsonl(kwargs["cases_path"])
                    mode = kwargs["execution_mode"].value
                    decisions = [safe_fake_decision(row, mode) for row in cases]
                    write_jsonl(kwargs["decisions_path"], decisions)
                    audit_path = kwargs["audit_path"]
                    write_safe_read_only_audit(audit_path, decisions)
                    rows = AuditLogger(audit_path).read_all()
                    finalization_index = next(
                        index
                        for index, row in enumerate(rows)
                        if row["record_type"] == "DECISION_FINALIZED"
                        and row["payload"]["case_id"] == decisions[0]["case_id"]
                    )
                    if mutation == "missing":
                        del rows[finalization_index]
                    else:
                        rows[finalization_index]["payload"][mutation] = "0" * 64
                    rewrite_rechained_audit(audit_path, rows)
                    return decisions

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                with self.assertRaises(ReplaySafetyViolation):
                    run_with_runner(harness, runner_with_invalid_finalization)

    def test_audit_requires_each_intermediate_stage_once_and_in_order(self) -> None:
        for mutation in ("missing", "duplicate", "out_of_order", "payload_mismatch"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)

                def runner_with_invalid_stage_sequence(**kwargs):
                    cases = read_jsonl(kwargs["cases_path"])
                    mode = kwargs["execution_mode"].value
                    decisions = [safe_fake_decision(row, mode) for row in cases]
                    write_jsonl(kwargs["decisions_path"], decisions)
                    audit_path = kwargs["audit_path"]
                    write_safe_read_only_audit(audit_path, decisions)
                    rows = AuditLogger(audit_path).read_all()
                    first_case_id = decisions[0]["case_id"]
                    received_index = next(
                        index
                        for index, row in enumerate(rows)
                        if row["record_type"] == "CASE_RECEIVED"
                        and row["payload"]["case_id"] == first_case_id
                    )
                    if mutation == "missing":
                        del rows[received_index]
                    elif mutation == "duplicate":
                        rows.insert(received_index + 1, dict(rows[received_index]))
                    elif mutation == "out_of_order":
                        rows[received_index], rows[received_index + 1] = (
                            rows[received_index + 1],
                            rows[received_index],
                        )
                    else:
                        evidence_row = rows[received_index + 1]
                        evidence_row["payload"]["evidence_quality"] = 0.1
                    rewrite_rechained_audit(audit_path, rows)
                    return decisions

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                with self.assertRaises(ReplaySafetyViolation):
                    run_with_runner(harness, runner_with_invalid_stage_sequence)

    def test_audit_metadata_shapes_and_code_owned_payloads_fail_closed(self) -> None:
        mutations = (
            "sequence",
            "invalid_recorded_at",
            "naive_recorded_at",
            "decreasing_recorded_at",
            "extra_row_member",
            "extra_payload_member",
            "duplicate_json_member",
            "suppression_reason",
            "policy_rationale",
            "policy_required_authority",
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)

                def runner_with_invalid_audit_contract(**kwargs):
                    cases = read_jsonl(kwargs["cases_path"])
                    mode = kwargs["execution_mode"].value
                    decisions = [safe_fake_decision(row, mode) for row in cases]
                    write_jsonl(kwargs["decisions_path"], decisions)
                    audit_path = kwargs["audit_path"]
                    write_safe_read_only_audit(audit_path, decisions)
                    rows = AuditLogger(audit_path).read_all()
                    preserve_sequence = False
                    preserve_recorded_at = False
                    if mutation == "sequence":
                        rows[0]["sequence"] = 999
                        preserve_sequence = True
                    elif mutation == "invalid_recorded_at":
                        rows[0]["recorded_at"] = "not-an-iso-timestamp"
                        preserve_recorded_at = True
                    elif mutation == "naive_recorded_at":
                        rows[0]["recorded_at"] = "2026-01-01T00:00:00"
                        preserve_recorded_at = True
                    elif mutation == "decreasing_recorded_at":
                        rows[0]["recorded_at"] = "2026-01-02T00:00:00+00:00"
                        rows[1]["recorded_at"] = "2026-01-01T00:00:00+00:00"
                        preserve_recorded_at = True
                    elif mutation == "extra_row_member":
                        rows[0]["unexpected"] = "forged"
                    elif mutation == "extra_payload_member":
                        rows[0]["payload"]["unexpected"] = "forged"
                    elif mutation == "duplicate_json_member":
                        pass
                    elif mutation == "suppression_reason":
                        suppression = next(
                            row
                            for row in rows
                            if row["record_type"] == "EXECUTION_SUPPRESSED"
                        )
                        suppression["payload"]["reason"] = "forged"
                    else:
                        policy = next(
                            row
                            for row in rows
                            if row["record_type"] == "POLICY_PROPOSED"
                        )
                        field = (
                            "rationale"
                            if mutation == "policy_rationale"
                            else "required_authority"
                        )
                        policy["payload"][field] = (
                            ["forged"] if field == "rationale" else "forged"
                        )
                    rewrite_rechained_audit(
                        audit_path,
                        rows,
                        preserve_sequence=preserve_sequence,
                        preserve_recorded_at=preserve_recorded_at,
                    )
                    if mutation == "duplicate_json_member":
                        serialized = Path(audit_path).read_text(encoding="utf-8")
                        serialized = serialized.replace(
                            '"sequence":0}',
                            '"sequence":999,"sequence":0}',
                            1,
                        )
                        Path(audit_path).write_text(serialized, encoding="utf-8")
                        collapsed_rows = [
                            json.loads(line)
                            for line in serialized.splitlines()
                            if line.strip()
                        ]
                        self.assertEqual(
                            AuditLogger.verify_rows(collapsed_rows), (True, [])
                        )
                    return decisions

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                with self.assertRaises(ReplaySafetyViolation):
                    run_with_runner(harness, runner_with_invalid_audit_contract)

    def test_bound_policy_actions_accept_only_engine_consistent_traces(self) -> None:
        for scenario in ("noncontain", "contain", "verifier_downgrade"):
            with (
                self.subTest(scenario=scenario),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)

                def runner_with_bound_policy_trace(**kwargs):
                    cases = read_jsonl(kwargs["cases_path"])
                    mode = kwargs["execution_mode"].value
                    decisions = [safe_fake_decision(row, mode) for row in cases]
                    if scenario != "noncontain":
                        decisions[0] = make_containment_decision(
                            cases[0],
                            mode,
                            verifier_downgrade=scenario == "verifier_downgrade",
                        )
                    write_jsonl(kwargs["decisions_path"], decisions)
                    write_safe_read_only_audit(kwargs["audit_path"], decisions)
                    return decisions

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                result = run_with_runner(harness, runner_with_bound_policy_trace)
                self.assertEqual(result.metrics["scope"]["cases_evaluated"], 3)

    def test_bound_policy_actions_reject_rechained_action_list_forgery(self) -> None:
        action_mutations = ("omit", "duplicate", "reorder", "substitute")
        scenarios = ("contain", "verifier_downgrade")
        for scenario in scenarios:
            for mutation in action_mutations:
                with (
                    self.subTest(scenario=scenario, mutation=mutation),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    config_path = make_repository(root)

                    def runner_with_forged_policy_actions(**kwargs):
                        cases = read_jsonl(kwargs["cases_path"])
                        mode = kwargs["execution_mode"].value
                        decisions = [safe_fake_decision(row, mode) for row in cases]
                        decisions[0] = make_containment_decision(
                            cases[0],
                            mode,
                            verifier_downgrade=scenario == "verifier_downgrade",
                        )
                        write_jsonl(kwargs["decisions_path"], decisions)
                        audit_path = kwargs["audit_path"]
                        write_safe_read_only_audit(audit_path, decisions)
                        rows = AuditLogger(audit_path).read_all()
                        policy = next(
                            row
                            for row in rows
                            if row["record_type"] == "POLICY_PROPOSED"
                            and row["payload"]["case_id"] == decisions[0]["case_id"]
                        )
                        forged = list(BOUND_AUTONOMOUS_ACTIONS)
                        if mutation == "omit":
                            forged.pop()
                        elif mutation == "duplicate":
                            forged.append(forged[0])
                        elif mutation == "reorder":
                            forged.reverse()
                        else:
                            forged[0] = "disable_account"
                        policy["payload"]["counterfactual_actions"] = forged
                        rewrite_rechained_audit(audit_path, rows)
                        return decisions

                    harness = ReplayHarness.from_config(
                        config_path, repository_root=root
                    )
                    with self.assertRaises(ReplaySafetyViolation):
                        run_with_runner(harness, runner_with_forged_policy_actions)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path = make_repository(root)

            def runner_with_noncontain_human_action(**kwargs):
                cases = read_jsonl(kwargs["cases_path"])
                mode = kwargs["execution_mode"].value
                decisions = [safe_fake_decision(row, mode) for row in cases]
                decisions[0]["counterfactual_actions"] = ["disable_account"]
                rehash_decision(decisions[0])
                write_jsonl(kwargs["decisions_path"], decisions)
                audit_path = kwargs["audit_path"]
                write_safe_read_only_audit(audit_path, decisions)
                rows = AuditLogger(audit_path).read_all()
                for row in rows:
                    if row["payload"]["case_id"] != decisions[0]["case_id"]:
                        continue
                    if row["record_type"] in {
                        "POLICY_PROPOSED",
                        "EXECUTION_SUPPRESSED",
                    }:
                        row["payload"]["counterfactual_actions"] = ["disable_account"]
                rewrite_rechained_audit(audit_path, rows)
                return decisions

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with self.assertRaises(ReplaySafetyViolation):
                run_with_runner(harness, runner_with_noncontain_human_action)

    def test_harness_rejects_any_reported_authorization_or_effect(self) -> None:
        unsafe_fields = (
            "authorization",
            "token_id",
            "decision_hash",
            "broker_invocations",
            "operational_effects",
        )
        for unsafe_field in unsafe_fields:
            with (
                self.subTest(unsafe_field=unsafe_field),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path = make_repository(root)

                def unsafe_runner(**kwargs):
                    cases = read_jsonl(kwargs["cases_path"])
                    mode = kwargs["execution_mode"].value
                    decisions = [safe_fake_decision(row, mode) for row in cases]
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
