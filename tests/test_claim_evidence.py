from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from jsonschema import Draft202012Validator

from adf_poc.replay import ReplayHarness
from adf_poc.utils import sha256_json
from scripts.validate_claim_evidence import (
    EvidenceValidationError,
    validate_evidence_record,
)
from scripts.generate_gate_b_ce2_campaign import (
    CAMPAIGN_SCHEMA,
    SENSITIVE_CANARY,
    build_campaign_artifacts,
    check_artifacts,
    generate_artifacts,
    load_and_validate_plan,
)


ROOT = Path(__file__).resolve().parents[1]
BASELINE_RECORD = ROOT / "contracts/v0.2.0/examples/phase2-starter-evidence-record.json"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def _copy_qualification_run_inputs(repository_root: Path) -> None:
    files = (
        "config/phase2_qualification.json",
        "config/policy.json",
        "outputs/baseline/model.json",
        "contracts/v0.2.0/replay-qualification.schema.json",
        "data/phase2_qualification/manifest.json",
        "data/phase2_qualification/cases.jsonl",
        "data/phase2_qualification/adjudications.jsonl",
        "data/phase2_qualification/expected_qualification.json",
    )
    for relative in files:
        source = ROOT / relative
        target = repository_root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)


def _artifact_record(
    repository_root: Path,
    *,
    role: str,
    path: Path,
    deterministic: bool,
    record_count: int | None = None,
) -> dict:
    value = {
        "artifact_role": role,
        "path": str(path.resolve().relative_to(repository_root.resolve())),
        "sha256": _sha256(path),
        "deterministic": deterministic,
        "committed": True,
        "custody_notes": "Test-only temporary evidence with no external custody.",
    }
    if record_count is not None:
        value["record_count"] = record_count
    return value


def _build_qualification_evidence(repository_root: Path) -> tuple[Path, dict]:
    repository_root = repository_root.resolve()
    _copy_qualification_run_inputs(repository_root)
    config_path = repository_root / "config/phase2_qualification.json"
    run = ReplayHarness.from_config(
        config_path,
        repository_root=repository_root,
    ).run()
    bundle_root = run.run_manifest_path.parent
    expected_path = bundle_root / "expected_qualification.json"
    shutil.copyfile(
        repository_root / "data/phase2_qualification/expected_qualification.json",
        expected_path,
    )
    manifest = json.loads(run.run_manifest_path.read_text(encoding="utf-8"))

    artifacts = [
        _artifact_record(
            repository_root,
            role="run_manifest",
            path=run.run_manifest_path,
            deterministic=False,
        )
    ]
    inputs = manifest["inputs"]
    for role in ("configuration", "dataset_manifest", "model", "policy"):
        entry = inputs[role]
        artifacts.append(
            _artifact_record(
                repository_root,
                role=role,
                path=bundle_root / entry["path"],
                deterministic=True,
                record_count=entry.get("record_count"),
            )
        )
    for role, entry in inputs["declared_files"].items():
        artifacts.append(
            _artifact_record(
                repository_root,
                role=role,
                path=bundle_root / entry["path"],
                deterministic=True,
                record_count=entry.get("record_count"),
            )
        )
    for role, entry in manifest["deterministic_artifacts"].items():
        public_role = "deterministic_decisions" if role == "replay_decisions" else role
        artifacts.append(
            _artifact_record(
                repository_root,
                role=public_role,
                path=bundle_root / entry["path"],
                deterministic=True,
                record_count=entry.get("record_count"),
            )
        )
    for role, entry in manifest["volatile_engine_artifacts"].items():
        if role == "reproducibility_note":
            continue
        artifacts.append(
            _artifact_record(
                repository_root,
                role=role,
                path=bundle_root / entry["path"],
                deterministic=False,
                record_count=entry.get("record_count"),
            )
        )
    artifacts.append(
        _artifact_record(
            repository_root,
            role="expected_qualification",
            path=expected_path,
            deterministic=True,
        )
    )

    record = json.loads(BASELINE_RECORD.read_text(encoding="utf-8"))
    record["evidence_record_id"] = "EV-P2-QUALIFICATION-TEST-002"
    record["claim_id"] = "P2-CE-002"
    record["claim_text"] = (
        "The fixed seven-record qualification fixture produced the seven "
        "predeclared outcomes: three accepted and four quarantined."
    )
    record["system_under_test"][
        "source_reference"
    ] = "Test-only temporary source identity; not a publishable evidence record."
    record["system_under_test"]["model"] = {
        "path": str(
            run.output_dir.joinpath("input_snapshot/model.json").relative_to(
                repository_root
            )
        ),
        "sha256": _sha256(run.output_dir / "input_snapshot/model.json"),
    }
    record["system_under_test"]["policy"] = {
        "path": str(
            run.output_dir.joinpath("input_snapshot/policy.json").relative_to(
                repository_root
            )
        ),
        "sha256": _sha256(run.output_dir / "input_snapshot/policy.json"),
    }
    record["evaluation_scope"]["case_count"] = 7
    record["evaluation_scope"]["adjudicated_case_count"] = 3
    record["evaluation_scope"][
        "sample_selection_method"
    ] = "Complete inclusion of a fixed project-controlled seven-record qualification fixture."
    record["budget"]["case_evaluations"] = 7
    record["results"] = {
        "denominator": 7,
        "passed": 7,
        "failed": 0,
        "excluded": 0,
        "metrics": {
            "authorization_attempts": 0,
            "authorization_tokens_issued": 0,
            "broker_invocations": 0,
            "action_results": 0,
            "operational_effects": 0,
            "historical_case_count": 0,
            "qualification_input_records": 7,
            "qualification_accepted_records": 3,
            "qualification_rejected_records": 4,
            "qualification_fatal_count": 0,
            "qualification_outcome_matches": 7,
            "decision_records": 3,
        },
        "strata": [
            {
                "name": "FIXED_QUALIFICATION_FIXTURE",
                "denominator": 7,
                "passed": 7,
                "failed": 0,
                "excluded": 0,
            }
        ],
        "uncertainty": (
            "Seven fixed synthetic outcomes are a regression observation, not an "
            "estimate of operational data quality or performance."
        ),
        "deviations_from_plan": [],
    }
    record["evidence_artifacts"] = artifacts
    record["supported_wording"] = (
        "In one fixed synthetic run, all seven qualification outcomes matched the "
        "predeclared expected outcomes: three accepted and four quarantined."
    )
    record["limitations"] = list(record["limitations"]) + [
        "This test-only record does not provide an implementation commit identity."
    ]
    record_path = repository_root / "qualification-evidence-test.json"
    _write_json(record_path, record)
    return record_path, record


def _artifact_by_role(record: dict, role: str) -> dict:
    return next(
        artifact
        for artifact in record["evidence_artifacts"]
        if artifact["artifact_role"] == role
    )


def _refresh_manifest_artifact_binding(
    repository_root: Path,
    record: dict,
    role: str,
) -> None:
    artifact = _artifact_by_role(record, role)
    artifact_path = repository_root / artifact["path"]
    artifact["sha256"] = _sha256(artifact_path)
    run_manifest_artifact = _artifact_by_role(record, "run_manifest")
    run_manifest_path = repository_root / run_manifest_artifact["path"]
    run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
    manifest_role = "replay_decisions" if role == "deterministic_decisions" else role
    for section in ("deterministic_artifacts", "volatile_engine_artifacts"):
        if manifest_role in run_manifest[section]:
            run_manifest[section][manifest_role]["sha256"] = artifact["sha256"]
            break
    else:
        raise AssertionError(f"Run manifest does not declare artifact role {role!r}.")
    _write_json(run_manifest_path, run_manifest)
    run_manifest_artifact["sha256"] = _sha256(run_manifest_path)


def _build_gate_b_campaign_evidence(
    temporary_root: Path,
) -> tuple[Path, Path, Path]:
    output_dir = temporary_root / "evidence/phase2_gate_b_ce2"
    record_path = temporary_root / "phase2-gate-b-ce2-evidence-record.json"
    generate_artifacts(
        output_dir,
        implementation_commit="1" * 40,
        evaluated_at="2026-08-15T00:00:00Z",
        record_path=record_path,
    )
    return record_path, output_dir, temporary_root


def _refresh_gate_b_campaign_record(
    record_path: Path,
    output_dir: Path,
    *,
    results_role: str = "campaign_results_run1",
    update_results_binding: bool = True,
) -> None:
    record = json.loads(record_path.read_text(encoding="utf-8"))
    if results_role not in {"campaign_results_run1", "campaign_results_run2"}:
        raise ValueError("Unsupported Gate B result role.")
    results_path = output_dir / f"{results_role}.jsonl"
    summary_path = output_dir / "campaign_summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    if update_results_binding:
        summary["artifact_bindings"][f"{results_role}_sha256"] = _sha256(results_path)
        _write_json(summary_path, summary)
    for role, path in (
        (results_role, results_path),
        ("campaign_summary", summary_path),
    ):
        artifact = _artifact_by_role(record, role)
        artifact["sha256"] = _sha256(path)
        if role == results_role:
            artifact["record_count"] = sum(
                bool(line.strip())
                for line in results_path.read_text(encoding="utf-8").splitlines()
            )
    _write_json(record_path, record)


def _validate_gate_b_test_record(record_path: Path) -> dict:
    def committed_digest(
        repository_root: Path,
        *,
        commit: str,
        relative_path: str,
    ) -> str:
        del repository_root, commit
        return _sha256(ROOT / relative_path)

    with (
        patch(
            "scripts.validate_claim_evidence._git_blob_digest",
            side_effect=committed_digest,
        ),
        patch(
            "scripts.validate_claim_evidence._git_commit_timestamp",
            return_value=datetime(2026, 8, 14, tzinfo=timezone.utc),
        ),
    ):
        return validate_evidence_record(
            record_path,
            repository_root=ROOT,
            profile_id="P2-CE-003",
        )


class ClaimEvidenceContractTests(unittest.TestCase):
    def test_starter_record_preserves_narrow_synthetic_claim_boundary(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/v0.2.0/evaluation-evidence.schema.json").read_text(
                encoding="utf-8"
            )
        )
        record = json.loads(
            (
                ROOT / "contracts/v0.2.0/examples/phase2-starter-evidence-record.json"
            ).read_text(encoding="utf-8")
        )
        validated = validate_evidence_record()

        self.assertEqual(validated["status"], "VALID")
        self.assertEqual(validated["profile_id"], "P2-CE-001")
        self.assertEqual(validated["artifact_count"], 14)
        self.assertEqual(validated["audit_record_count"], 24)
        self.assertEqual(schema["properties"]["schema_version"]["const"], "0.2.0")
        self.assertEqual(record["schema_version"], "0.2.0")
        self.assertEqual(record["claim_class"], "CONTROLLED_BEHAVIOR")
        self.assertEqual(record["claim_status"], "OBSERVED")
        self.assertEqual(record["research_basis"]["reviewed_through"], "2026-08-14")
        self.assertTrue(record["research_basis"]["not_yet_evaluated"])
        self.assertEqual(record["evaluation_scope"]["data_origin"], "SYNTHETIC_FIXTURE")
        self.assertEqual(record["evaluation_scope"]["historical_case_count"], 0)
        self.assertEqual(record["results"]["denominator"], 3)
        self.assertEqual(record["results"]["passed"], 3)
        self.assertEqual(record["results"]["failed"], 0)
        self.assertEqual(record["results"]["excluded"], 0)

        metrics = record["results"]["metrics"]
        for key in (
            "authorization_attempts",
            "authorization_tokens_issued",
            "broker_invocations",
            "action_results",
            "operational_effects",
            "historical_case_count",
        ):
            self.assertEqual(metrics[key], 0, key)

        prohibited = " ".join(record["prohibited_inferences"]).lower()
        for phrase in (
            "historical",
            "aligned",
            "production ready",
            "zero risk",
            "monitor",
        ):
            self.assertIn(phrase, prohibited)

        roles = set()
        for artifact in record["evidence_artifacts"]:
            self.assertRegex(artifact["sha256"], re.compile(r"^[0-9a-f]{64}$"))
            self.assertTrue(artifact["committed"])
            roles.add(artifact["artifact_role"])
        self.assertEqual(len(roles), 14)

        with tempfile.TemporaryDirectory() as directory:
            invalid_path = Path(directory) / "invalid-evidence.json"
            invalid = json.loads(json.dumps(record))
            invalid["evidence_artifacts"][0]["sha256"] = "0" * 64
            invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                validate_evidence_record(invalid_path)

            invalid = json.loads(json.dumps(record))
            del invalid["budget"]
            invalid_path.write_text(json.dumps(invalid), encoding="utf-8")
            with self.assertRaises(EvidenceValidationError):
                validate_evidence_record(invalid_path)

        with self.assertRaises(EvidenceValidationError):
            validate_evidence_record(profile_id="P2-CE-002")

    def test_qualification_profile_validates_7_equals_3_plus_4_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            record_path, _ = _build_qualification_evidence(repository_root)
            validated = validate_evidence_record(
                record_path,
                repository_root=repository_root,
            )

        self.assertEqual(validated["status"], "VALID")
        self.assertEqual(validated["profile_id"], "P2-CE-002")
        self.assertEqual(validated["artifact_count"], 17)
        self.assertEqual(validated["audit_record_count"], 24)
        self.assertEqual(
            validated["record_qualification"],
            {
                "input_records": 7,
                "accepted_records": 3,
                "rejected_records": 4,
            },
        )
        committed = validate_evidence_record(
            ROOT
            / "contracts/v0.2.0/examples/phase2-qualification-evidence-record.json",
            profile_id="P2-CE-002",
        )
        self.assertEqual(committed["status"], "VALID")
        self.assertEqual(committed["artifact_count"], 17)

    def test_profile_rejects_live_executable_or_stale_hash_decisions(self) -> None:
        for mutation in ("live-mode", "executable-action", "stale-hash"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                repository_root = Path(directory)
                record_path, record = _build_qualification_evidence(repository_root)
                engine_artifact = _artifact_by_role(record, "engine_decisions")
                engine_path = repository_root / engine_artifact["path"]
                decisions = [
                    json.loads(line)
                    for line in engine_path.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                decision = decisions[0]
                if mutation == "live-mode":
                    decision["execution_mode"] = "LIVE"
                    decision["execution_control"].update(
                        {
                            "mode": "LIVE",
                            "read_only": False,
                            "status": "EXECUTION_READY",
                        }
                    )
                elif mutation == "executable-action":
                    decision["proposal"]["executable_actions"] = ["disable_account"]
                else:
                    decision["latency_ms"] = float(decision["latency_ms"]) + 1.0

                if mutation != "stale-hash":
                    hash_input = dict(decision)
                    hash_input.pop("decision_record_hash", None)
                    decision["decision_record_hash"] = sha256_json(hash_input)
                _write_jsonl(engine_path, decisions)
                _refresh_manifest_artifact_binding(
                    repository_root,
                    record,
                    "engine_decisions",
                )
                _write_json(record_path, record)

                with self.assertRaises(EvidenceValidationError):
                    validate_evidence_record(
                        record_path,
                        repository_root=repository_root,
                    )

    def test_profile_rejects_deterministic_decision_drift_from_raw_decisions(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            record_path, record = _build_qualification_evidence(repository_root)
            deterministic_artifact = _artifact_by_role(
                record,
                "deterministic_decisions",
            )
            deterministic_path = repository_root / deterministic_artifact["path"]
            rows = [
                json.loads(line)
                for line in deterministic_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            rows[0]["final_disposition"] = "ESCALATE_HUMAN"
            _write_jsonl(deterministic_path, rows)
            _refresh_manifest_artifact_binding(
                repository_root,
                record,
                "deterministic_decisions",
            )
            _write_json(record_path, record)

            with self.assertRaises(EvidenceValidationError):
                validate_evidence_record(
                    record_path,
                    repository_root=repository_root,
                )

    def test_qualification_profile_rejects_expected_outcome_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            record_path, record = _build_qualification_evidence(repository_root)
            expected_artifact = _artifact_by_role(record, "expected_qualification")
            expected_path = repository_root / expected_artifact["path"]
            expected = json.loads(expected_path.read_text(encoding="utf-8"))
            expected["records"][3]["error_code"] = "MISSING_REQUIRED_FIELD"
            _write_json(expected_path, expected)
            expected_artifact["sha256"] = _sha256(expected_path)
            _write_json(record_path, record)

            with self.assertRaises(EvidenceValidationError):
                validate_evidence_record(
                    record_path,
                    repository_root=repository_root,
                )

    def test_expected_qualification_schema_rejects_extra_payload_fields(self) -> None:
        mutations = (
            lambda expected: expected.__setitem__(
                "raw_payload",
                "prohibited-root-payload",
            ),
            lambda expected: expected["records"][0].__setitem__(
                "payload_excerpt",
                "prohibited-nested-payload",
            ),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                repository_root = Path(directory)
                record_path, record = _build_qualification_evidence(repository_root)
                expected_artifact = _artifact_by_role(
                    record,
                    "expected_qualification",
                )
                expected_path = repository_root / expected_artifact["path"]
                expected = json.loads(expected_path.read_text(encoding="utf-8"))
                mutate(expected)
                _write_json(expected_path, expected)
                expected_artifact["sha256"] = _sha256(expected_path)
                _write_json(record_path, record)

                with self.assertRaises(EvidenceValidationError):
                    validate_evidence_record(
                        record_path,
                        repository_root=repository_root,
                    )

    def test_qualification_profile_rejects_nonexact_rejection_projection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            record_path, record = _build_qualification_evidence(repository_root)
            rejection_artifact = _artifact_by_role(record, "rejections")
            rejection_path = repository_root / rejection_artifact["path"]
            rows = [
                json.loads(line)
                for line in rejection_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            rejection_path.write_text(
                "".join(
                    json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n"
                    for row in reversed(rows)
                ),
                encoding="utf-8",
            )
            _refresh_manifest_artifact_binding(
                repository_root,
                record,
                "rejections",
            )
            _write_json(record_path, record)

            with self.assertRaises(EvidenceValidationError):
                validate_evidence_record(
                    record_path,
                    repository_root=repository_root,
                )

    def test_qualification_profile_rejects_nonexact_accounting_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            record_path, record = _build_qualification_evidence(repository_root)
            accounting_artifact = _artifact_by_role(
                record,
                "qualification_accounting",
            )
            accounting_path = repository_root / accounting_artifact["path"]
            rows = [
                json.loads(line)
                for line in accounting_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            accounting_path.write_text(
                "".join(
                    json.dumps(row, separators=(",", ":"), sort_keys=True) + "\n"
                    for row in reversed(rows)
                ),
                encoding="utf-8",
            )
            _refresh_manifest_artifact_binding(
                repository_root,
                record,
                "qualification_accounting",
            )
            _write_json(record_path, record)

            with self.assertRaises(EvidenceValidationError):
                validate_evidence_record(
                    record_path,
                    repository_root=repository_root,
                )

    def test_qualification_profile_rejects_nonzero_effect_claim_metric(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            record_path, record = _build_qualification_evidence(repository_root)
            record["results"]["metrics"]["operational_effects"] = 1
            _write_json(record_path, record)

            with self.assertRaises(EvidenceValidationError):
                validate_evidence_record(
                    record_path,
                    repository_root=repository_root,
                )

    def test_run_manifest_artifact_roles_are_discovered_dynamically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository_root = Path(directory)
            record_path, record = _build_qualification_evidence(repository_root)
            run_manifest_artifact = _artifact_by_role(record, "run_manifest")
            run_manifest_path = repository_root / run_manifest_artifact["path"]
            bundle_root = run_manifest_path.parent
            note_path = bundle_root / "profile_attestation.json"
            _write_json(note_path, {"status": "TEST_ONLY"})
            run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
            run_manifest["deterministic_artifacts"]["profile_attestation"] = {
                "path": note_path.name,
                "sha256": _sha256(note_path),
            }
            _write_json(run_manifest_path, run_manifest)
            run_manifest_artifact["sha256"] = _sha256(run_manifest_path)
            record["evidence_artifacts"].append(
                _artifact_record(
                    repository_root,
                    role="profile_attestation",
                    path=note_path,
                    deterministic=True,
                )
            )
            _write_json(record_path, record)
            validated = validate_evidence_record(
                record_path,
                repository_root=repository_root,
            )

        self.assertEqual(validated["artifact_count"], 18)

    def test_gate_b_campaign_plan_and_core_outputs_are_closed_and_sanitized(
        self,
    ) -> None:
        plan = load_and_validate_plan()
        self.assertEqual(plan["campaign_seed"], 20260814)
        self.assertEqual(plan["budget"]["evaluation_runs"], 2)
        self.assertEqual(plan["budget"]["attempts_per_run"], 16)
        self.assertEqual(plan["budget"]["total_attempt_executions"], 32)
        self.assertEqual(plan["budget"]["retries"], 0)
        self.assertEqual(plan["budget"]["engine_call_budget"], 0)
        self.assertEqual(plan["design"]["data_origin"], "SYNTHETIC_FIXTURE")
        self.assertEqual(
            plan["design"]["simulated_runtime_origin"],
            "HISTORICAL_DEIDENTIFIED",
        )
        self.assertEqual(plan["design"]["actual_historical_records"], 0)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            (
                profile_bytes,
                results_run1_bytes,
                results_run2_bytes,
                summary_bytes,
            ) = build_campaign_artifacts(
                "1" * 40,
                "2026-08-15T00:00:00Z",
            )
        combined = (
            profile_bytes + results_run1_bytes + results_run2_bytes + summary_bytes
        )
        self.assertNotIn(SENSITIVE_CANARY.encode("utf-8"), combined)
        self.assertNotIn(SENSITIVE_CANARY, stdout.getvalue())
        self.assertNotIn(SENSITIVE_CANARY, stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")

        schema = json.loads(CAMPAIGN_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        profile = json.loads(profile_bytes)
        summary = json.loads(summary_bytes)
        rows_run1 = [json.loads(line) for line in results_run1_bytes.splitlines()]
        rows_run2 = [json.loads(line) for line in results_run2_bytes.splitlines()]
        validator.validate(profile)
        validator.validate(summary)
        for row in rows_run1 + rows_run2:
            validator.validate(row)
        self.assertEqual(len(rows_run1), 16)
        self.assertEqual(len(rows_run2), 16)
        self.assertEqual(results_run1_bytes, results_run2_bytes)
        self.assertEqual(rows_run1, rows_run2)
        self.assertEqual(
            summary["raw_outcomes"],
            {
                "denominator": 32,
                "matched": 32,
                "mismatched": 0,
                "excluded": 0,
                "observed_pass_test_only": 2,
                "observed_blocked": 30,
            },
        )
        self.assertEqual(
            summary["repeatability"],
            {
                "evaluation_runs": 2,
                "attempts_per_run": 16,
                "total_attempt_executions": 32,
                "byte_identical_result_ledgers": True,
            },
        )
        rows = rows_run1 + rows_run2
        self.assertTrue(all(row["matched"] for row in rows))
        self.assertEqual(
            [row["observed_outcome"] for row in rows].count("PASS_TEST_ONLY"),
            2,
        )
        self.assertEqual(
            [row["observed_outcome"] for row in rows].count("BLOCKED_PREPAYLOAD"),
            28,
        )
        self.assertEqual(
            [row["observed_outcome"] for row in rows].count(
                "BLOCKED_POSTQUALIFICATION_PREENGINE"
            ),
            2,
        )
        safe_result_fields = {
            "artifact_kind",
            "schema_version",
            "campaign_id",
            "sequence",
            "attempt_id",
            "fixture",
            "operation",
            "mutation_id",
            "expected_outcome",
            "observed_outcome",
            "matched",
            "error_class",
            "accessed_payload_roles",
            "engine_calls",
            "authorization_attempts",
            "authorization_tokens_issued",
            "broker_invocations",
            "target_effect_calls",
            "action_results",
            "operational_effects",
            "completed_run_manifests",
            "decision_artifacts",
            "audit_artifacts",
        }
        for row in rows:
            self.assertEqual(set(row), safe_result_fields)
            for field in (
                "engine_calls",
                "authorization_attempts",
                "authorization_tokens_issued",
                "broker_invocations",
                "target_effect_calls",
                "action_results",
                "operational_effects",
                "completed_run_manifests",
                "decision_artifacts",
                "audit_artifacts",
            ):
                self.assertEqual(row[field], 0, (row["attempt_id"], field))

    def test_gate_b_campaign_profile_validates_exact_commit_frozen_result(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".gate-b-ce2-test-",
            dir=ROOT,
        ) as directory:
            record_path, output_dir, _ = _build_gate_b_campaign_evidence(
                Path(directory)
            )
            validated = _validate_gate_b_test_record(record_path)
            public_bundle = record_path.read_bytes() + b"".join(
                path.read_bytes() for path in sorted(output_dir.iterdir())
            )

        self.assertEqual(validated["status"], "VALID")
        self.assertNotIn(SENSITIVE_CANARY.encode("utf-8"), public_bundle)
        self.assertEqual(validated["profile_id"], "P2-CE-003")
        self.assertEqual(validated["artifact_count"], 6)
        self.assertEqual(validated["historical_case_count"], 0)
        self.assertEqual(
            validated["campaign_outcomes"],
            {
                "unique_scenarios": 16,
                "evaluation_runs": 2,
                "denominator": 32,
                "pass_test_only": 2,
                "blocked_prepayload": 28,
                "blocked_postqualification_preengine": 2,
                "byte_identical_result_ledgers": True,
            },
        )

    def test_gate_b_campaign_check_preserves_recorded_runtime_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".gate-b-ce2-runtime-check-",
            dir=ROOT,
        ) as directory:
            root = Path(directory)
            record_path, output_dir, _ = _build_gate_b_campaign_evidence(root)
            with patch(
                "scripts.generate_gate_b_ce2_campaign._runtime_fingerprint",
                return_value={
                    "python_implementation": "DifferentPython",
                    "python_version": "0.0.0",
                    "jsonschema_version": "0.0.0",
                    "numpy_version": "0.0.0",
                    "platform_system": "DifferentOS",
                    "platform_release": "different",
                    "platform_machine": "different",
                },
            ):
                check_artifacts(
                    output_dir,
                    implementation_commit="1" * 40,
                    evaluated_at="2026-08-15T00:00:00Z",
                    record_path=record_path,
                )

    def test_gate_b_campaign_validator_rejects_drift_leakage_and_ambiguity(
        self,
    ) -> None:
        mutations = (
            "extra_payload_field",
            "outcome_drift",
            "reordered_attempts",
            "missing_attempt",
            "nonzero_engine_counter",
            "nonzero_effect_counter",
            "payload_role_drift",
            "source_reference_mismatch",
            "duplicate_json_member",
            "authorization_canary",
            "run2_only_outcome_drift",
            "both_ledgers_identical_outcome_drift",
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(
                    prefix=".gate-b-ce2-negative-",
                    dir=ROOT,
                ) as directory,
            ):
                record_path, output_dir, _ = _build_gate_b_campaign_evidence(
                    Path(directory)
                )
                results_path = output_dir / "campaign_results_run1.jsonl"
                if mutation in {
                    "extra_payload_field",
                    "outcome_drift",
                    "reordered_attempts",
                    "missing_attempt",
                    "nonzero_engine_counter",
                    "nonzero_effect_counter",
                    "payload_role_drift",
                    "run2_only_outcome_drift",
                    "both_ledgers_identical_outcome_drift",
                }:
                    selected_role = (
                        "campaign_results_run2"
                        if mutation == "run2_only_outcome_drift"
                        else "campaign_results_run1"
                    )
                    results_path = output_dir / f"{selected_role}.jsonl"
                    rows = [
                        json.loads(line)
                        for line in results_path.read_text(
                            encoding="utf-8"
                        ).splitlines()
                    ]
                    if mutation == "extra_payload_field":
                        rows[0]["raw_payload"] = "prohibited"
                    elif mutation == "outcome_drift":
                        rows[1]["observed_outcome"] = "PASS_TEST_ONLY"
                    elif mutation == "reordered_attempts":
                        rows.reverse()
                    elif mutation == "missing_attempt":
                        rows.pop()
                    elif mutation == "nonzero_engine_counter":
                        rows[0]["engine_calls"] = 1
                    elif mutation == "nonzero_effect_counter":
                        rows[0]["target_effect_calls"] = 1
                    elif mutation in {
                        "run2_only_outcome_drift",
                        "both_ledgers_identical_outcome_drift",
                    }:
                        rows[1]["observed_outcome"] = "PASS_TEST_ONLY"
                    else:
                        rows[1]["accessed_payload_roles"] = ["cases"]
                    _write_jsonl(results_path, rows)
                    _refresh_gate_b_campaign_record(
                        record_path,
                        output_dir,
                        results_role=selected_role,
                    )
                    if mutation == "both_ledgers_identical_outcome_drift":
                        second_path = output_dir / "campaign_results_run2.jsonl"
                        _write_jsonl(second_path, rows)
                        _refresh_gate_b_campaign_record(
                            record_path,
                            output_dir,
                            results_role="campaign_results_run2",
                        )
                elif mutation == "duplicate_json_member":
                    lines = results_path.read_text(encoding="utf-8").splitlines()
                    lines[0] = lines[0][:-1] + ',"matched":true}'
                    results_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    _refresh_gate_b_campaign_record(record_path, output_dir)
                else:
                    record = json.loads(record_path.read_text(encoding="utf-8"))
                    if mutation == "source_reference_mismatch":
                        record["system_under_test"]["source_reference"] = (
                            "Git commit "
                            + "2" * 40
                            + " (https://github.com/redxking/ai-decision-firewall/commit/"
                            + "2" * 40
                            + ")"
                        )
                    else:
                        record["limitations"].append(SENSITIVE_CANARY)
                    _write_json(record_path, record)

                with self.assertRaises(EvidenceValidationError):
                    _validate_gate_b_test_record(record_path)

    def test_standard_cites_primary_research_and_states_nonclaim(self) -> None:
        standard = (ROOT / "docs/phase2/CLAIM_EVIDENCE_STANDARD.md").read_text(
            encoding="utf-8"
        )
        for url in (
            "https://www.anthropic.com/research/agentic-misalignment",
            "https://www.anthropic.com/research/sabotage-evaluations",
            "https://www.anthropic.com/research/auditing-hidden-objectives",
            "https://openai.com/index/trustworthy-third-party-evaluations-foundations/",
            "https://openai.com/index/how-we-monitor-internal-coding-agents-misalignment/",
        ):
            self.assertIn(url, standard)
        self.assertIn(
            "does **not** contain an autonomous generative-language-model agent",
            standard,
        )
        self.assertIn("A repository test may block a release", standard)

        coverage = (ROOT / "docs/phase2/RESEARCH_COVERAGE_REGISTER.md").read_text(
            encoding="utf-8"
        )
        for url in (
            "https://openai.com/research/index/",
            "https://openai.com/index/unlocking-self-improvement-gpt-red/",
            "https://openai.com/index/separating-signal-from-noise-coding-evaluations/",
            "https://openai.com/index/why-language-models-hallucinate/",
            "https://openai.com/index/strengthening-safety-with-external-testing/",
        ):
            self.assertIn(url, coverage)
        self.assertIn("Not applicable to the present decision-control claim", coverage)
        self.assertIn("Rescreen the OpenAI Research Index", coverage)


if __name__ == "__main__":
    unittest.main()
