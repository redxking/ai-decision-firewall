from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import Draft202012Validator

from adf_poc.actions import (
    ActionBroker,
    AuthorizationGate,
    SimulatedIdentityProvider,
)
from adf_poc.policy import PolicyConfig
import scripts.generate_source_to_decision_ce2_campaign as campaign_module
from scripts.generate_source_to_decision_ce2_campaign import (
    CAMPAIGN_PLAN,
    CAMPAIGN_SCHEMA,
    CAMPAIGN_SOURCE_PATHS,
    EXPECTED_ATTEMPTS,
    PROHIBITED_PUBLIC_FIELDS,
    CampaignGenerationError,
    MODEL_PATH,
    POLICY_PATH,
    _production_baseline,
    _run_attempt,
    build_seeded_case,
    _jsonl_bytes,
    _prepare_cli_destinations,
    _strict_json_bytes,
    build_campaign_artifacts,
    build_evidence_record,
    build_profile,
    check_artifacts,
    generate_artifacts,
    load_and_validate_plan,
    run_campaign,
)
from scripts.validate_claim_evidence import (
    EvidenceValidationError,
    validate_evidence_record,
)


ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def _copy_campaign_cli_fixture(destination: Path, *, initialize_git: bool) -> Path:
    """Create an isolated repository-shaped CLI fixture without evidence reuse."""

    repository = destination / "repository"
    source_paths = set(CAMPAIGN_SOURCE_PATHS.values())
    source_paths.add(".gitignore")
    for relative_path in sorted(source_paths):
        source = ROOT / relative_path
        if not source.is_file():
            continue
        target = repository / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    if initialize_git:
        subprocess.run(
            ["git", "init", "-q", "-b", "main"],
            cwd=repository,
            check=True,
            timeout=20,
        )
        subprocess.run(
            ["git", "add", "."],
            cwd=repository,
            check=True,
            timeout=20,
        )
        subprocess.run(
            [
                "git",
                "-c",
                "user.name=ADF Test",
                "-c",
                "user.email=adf-test@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "commit",
                "-q",
                "--no-verify",
                "-m",
                "isolated campaign CLI fixture",
            ],
            cwd=repository,
            check=True,
            timeout=20,
        )
    return repository


def _run_campaign_cli(
    repository: Path,
    arguments: list[str],
    *,
    cwd: Path,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [
            sys.executable,
            str(repository / "scripts/generate_source_to_decision_ce2_campaign.py"),
            *arguments,
        ],
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _validate_test_record(record_path: Path) -> dict:
    frozen_package_paths = {
        role: path
        for role, path in CAMPAIGN_SOURCE_PATHS.items()
        if role.startswith("ADF_")
    }

    def committed_digest(
        repository_root: Path, *, commit: str, relative_path: str
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
        patch(
            "scripts.validate_claim_evidence._git_package_source_paths",
            return_value=frozen_package_paths,
        ),
    ):
        return validate_evidence_record(
            record_path,
            repository_root=ROOT,
            profile_id="P2-CE-005",
        )


class SourceToDecisionCampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.commit = "1" * 40
        cls.evaluated_at = "2026-08-15T00:00:00Z"
        cls.profile = build_profile(cls.commit, cls.evaluated_at)
        cls.rows = run_campaign(cls.profile)

    def test_plan_and_closed_schema_are_valid(self) -> None:
        plan = load_and_validate_plan()
        schema = json.loads(CAMPAIGN_SCHEMA.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(plan)
        self.assertEqual(plan["expected_attempts"], list(EXPECTED_ATTEMPTS))
        self.assertEqual(len(self.rows), 20)

    def test_exact_fixed_matrix_and_stage_denominators(self) -> None:
        observed = {
            row["attempt_id"]: (row["observed_outcome"], row["observed_error_code"])
            for row in self.rows
        }
        expected = {
            row["attempt_id"]: (row["expected_outcome"], row["expected_error_code"])
            for row in EXPECTED_ATTEMPTS
        }
        self.assertEqual(observed, expected)
        self.assertEqual(
            sum(
                row["observed_outcome"] == "ACCEPTED_REFERENCE_PATH_MATCH"
                for row in self.rows
            ),
            10,
        )
        for code in (
            "REFERENCE_DECISION_EVIDENCE_MISMATCH",
            "REFERENCE_DECISION_MODEL_MISMATCH",
            "REFERENCE_DECISION_POLICY_MISMATCH",
            "REFERENCE_DECISION_VERIFIER_MISMATCH",
            "REFERENCE_DECISION_FINAL_SURFACE_MISMATCH",
        ):
            self.assertEqual(
                sum(row["observed_error_code"] == code for row in self.rows),
                2,
            )

    def test_clean_mutant_twins_share_input_and_production_baseline(self) -> None:
        for pair_index in range(1, 11):
            pair_id = f"P{pair_index:02d}"
            twins = [row for row in self.rows if row["pair_id"] == pair_id]
            self.assertEqual(len(twins), 2)
            self.assertEqual(len({row["synthetic_input_sha256"] for row in twins}), 1)
            self.assertEqual(
                len({row["pre_mutation_decision_sha256"] for row in twins}), 1
            )
            self.assertTrue(all(row["twin_input_binding_preserved"] for row in twins))
            self.assertTrue(
                all(row["pre_mutation_baseline_preserved"] for row in twins)
            )

    def test_every_mutant_passes_all_legacy_controls_before_reference_block(
        self,
    ) -> None:
        mutants = [row for row in self.rows if row["control_kind"] == "MUTANT"]
        self.assertEqual(len(mutants), 10)
        for row in mutants:
            self.assertTrue(row["legacy_decision_validation_passed"])
            self.assertTrue(row["legacy_audit_assurance_passed"])
            self.assertTrue(row["legacy_feature_assurance_passed"])
            self.assertTrue(row["reference_path_attempted"])
            self.assertFalse(row["reference_path_passed"])
            self.assertEqual(row["mutation_applications"], 1)
            self.assertEqual(row["decision_record_rehashes"], 1)
            self.assertEqual(row["audit_chain_rechains"], 1)

    def test_verifier_downgrade_bypass_localizes_at_verifier(self) -> None:
        row = next(
            row
            for row in self.rows
            if row["mutation_id"] == "VERIFIER_FALSE_BLOCKER_WITHOUT_DOWNGRADE_REHASH"
        )
        self.assertEqual(row["base_disposition"], "CONTAIN_REVERSIBLE")
        self.assertEqual(row["observed_stage"], "VERIFIER")
        self.assertEqual(
            row["observed_error_code"], "REFERENCE_DECISION_VERIFIER_MISMATCH"
        )

    def test_two_complete_runs_are_byte_identical_and_summary_is_complete(self) -> None:
        profile, run1, run2, summary_bytes = build_campaign_artifacts(
            self.commit, self.evaluated_at
        )
        self.assertTrue(profile)
        self.assertEqual(run1, run2)
        self.assertEqual(len([line for line in run1.splitlines() if line]), 20)
        summary = json.loads(summary_bytes)
        self.assertEqual(
            summary["raw_outcomes"],
            {"denominator": 40, "matched": 40, "mismatched": 0, "excluded": 0},
        )
        self.assertEqual(
            summary["stage_outcomes"],
            {
                "accepted_reference_path_match": 20,
                "blocked_evidence": 4,
                "blocked_model": 4,
                "blocked_policy": 4,
                "blocked_verifier": 4,
                "blocked_final_surface": 4,
            },
        )
        self.assertEqual(
            summary["legacy_control_assurance"],
            {
                "decision_validation_passes": 40,
                "audit_assurance_passes": 40,
                "feature_assurance_passes": 40,
            },
        )
        self.assertEqual(
            summary["call_accounting"],
            {
                "production_baseline_generation_calls": 20,
                "engine_calls": 20,
                "evidence_calls": 20,
                "model_calls": 20,
                "policy_calls": 20,
                "verifier_calls": 20,
                "audit_record_appends": 160,
                "reference_path_calls": 40,
                "authorization_gate_instantiations": 0,
                "broker_instantiations": 0,
                "target_instantiations": 0,
                "authorization_attempts": 0,
                "broker_invocations": 0,
                "target_effect_calls": 0,
                "decision_artifact_write_calls": 0,
                "audit_artifact_write_calls": 0,
                "run_manifest_write_calls": 0,
                "scoped_filesystem_write_calls": 0,
            },
        )
        self.assertEqual(
            summary["derived_output_accounting"],
            {
                "authorization_attempted_reported": 0,
                "authorization_tokens": 0,
                "broker_invocations_reported": 0,
                "action_results_observed": 0,
                "operational_effects": 0,
            },
        )
        self.assertTrue(summary["repeatability"]["byte_identical_result_ledgers"])

    def test_doubled_shared_baseline_call_accounting_is_rejected(self) -> None:
        schema = json.loads(CAMPAIGN_SCHEMA.read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        forged_mutant = copy.deepcopy(
            next(row for row in self.rows if row["control_kind"] == "MUTANT")
        )
        forged_mutant["production_baseline_generation_calls"] = 1
        forged_mutant["audit_record_appends"] = 8
        for field in (
            "engine_calls",
            "evidence_calls",
            "model_calls",
            "policy_calls",
            "verifier_calls",
        ):
            forged_mutant[field] = 1
        self.assertTrue(list(validator.iter_errors(forged_mutant)))

        _, _, _, summary_bytes = build_campaign_artifacts(
            self.commit, self.evaluated_at
        )
        forged_summary = json.loads(summary_bytes)
        forged_summary["call_accounting"]["production_baseline_generation_calls"] = 40
        forged_summary["call_accounting"]["engine_calls"] = 40
        self.assertTrue(list(validator.iter_errors(forged_summary)))

    def test_reference_scope_constructor_instrumentation_is_sensitive(self) -> None:
        case = build_seeded_case("P01")
        decision, audit_rows, measurements = _production_baseline(case, "P01")
        policy = PolicyConfig.load(POLICY_PATH)
        original_reference = campaign_module.verify_reference_decision_path

        def constructing_reference(*args: object, **kwargs: object) -> object:
            gate = AuthorizationGate(policy)
            target = SimulatedIdentityProvider()
            ActionBroker(gate, target)
            return original_reference(*args, **kwargs)

        with (
            patch.object(
                campaign_module,
                "verify_reference_decision_path",
                side_effect=constructing_reference,
            ),
            patch.object(
                campaign_module,
                "_validate_campaign_artifact",
            ) as artifact_validator,
        ):
            result = _run_attempt(
                EXPECTED_ATTEMPTS[0],
                case=copy.deepcopy(case),
                baseline_decision=copy.deepcopy(decision),
                baseline_audit=copy.deepcopy(audit_rows),
                baseline_measurements=copy.deepcopy(measurements),
                policy=policy,
                model_bytes=MODEL_PATH.read_bytes(),
                policy_bytes=POLICY_PATH.read_bytes(),
            )

        self.assertEqual(result["authorization_gate_instantiations"], 1)
        self.assertEqual(result["broker_instantiations"], 1)
        self.assertEqual(result["target_instantiations"], 1)
        self.assertFalse(result["matched"])
        artifact_validator.assert_called_once_with(result)
        with self.assertRaises(CampaignGenerationError):
            campaign_module._validate_campaign_artifact(result)

    def test_public_artifacts_are_metadata_only(self) -> None:
        payloads = build_campaign_artifacts(self.commit, self.evaluated_at)
        public = b"\n".join(payloads)
        for token in PROHIBITED_PUBLIC_FIELDS:
            self.assertNotIn(token, public)

    def test_strict_parser_rejects_duplicate_and_nonfinite_numbers(self) -> None:
        for raw in (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":1e400}',
        ):
            with self.subTest(raw=raw):
                with self.assertRaises(CampaignGenerationError):
                    _strict_json_bytes(raw, label="negative-control.json")

    def test_profile_source_or_plan_drift_fails_closed(self) -> None:
        for mutation in ("source", "attempt"):
            drifted = copy.deepcopy(self.profile)
            if mutation == "source":
                drifted["source_bindings"][0]["sha256"] = "0" * 64
            else:
                drifted["expected_attempts"][0]["expected_stage"] = "EVIDENCE"
            with self.subTest(mutation=mutation):
                with self.assertRaises(CampaignGenerationError):
                    run_campaign(drifted)

    def test_temp_generation_and_check_are_exact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_dir = Path(directory) / "campaign"
            paths = generate_artifacts(
                output_dir,
                implementation_commit=self.commit,
                evaluated_at=self.evaluated_at,
            )
            self.assertEqual(len(paths), 4)
            check_artifacts(
                output_dir,
                implementation_commit=self.commit,
                evaluated_at=self.evaluated_at,
            )
            rows = [
                json.loads(line)
                for line in paths[1].read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(paths[1].read_bytes(), _jsonl_bytes(rows))

    def test_check_rejects_unsafe_leaf_aliases_before_read_or_rebuild(self) -> None:
        artifact_names = (
            "campaign_profile.json",
            "campaign_results_run1.jsonl",
            "campaign_results_run2.jsonl",
            "campaign_summary.json",
        )
        for mutation in ("symlink", "directory", "hardlink", "record_symlink"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                temporary_root = Path(root)
                output_dir = temporary_root / "campaign"
                output_dir.mkdir()
                for name in artifact_names:
                    (output_dir / name).write_bytes(b"placeholder")
                record_path = temporary_root / "record.json"
                record_path.write_bytes(b"placeholder")
                outside = temporary_root / "outside.bin"
                outside.write_bytes(b"must-not-be-read")
                target = output_dir / artifact_names[0]

                if mutation == "record_symlink":
                    record_path.unlink()
                    record_path.symlink_to(outside)
                else:
                    target.unlink()
                    if mutation == "symlink":
                        target.symlink_to(outside)
                    elif mutation == "directory":
                        target.mkdir()
                    else:
                        os.link(outside, target)

                read_targets: list[Path] = []
                original_read_bytes = Path.read_bytes

                def monitored_read_bytes(path: Path) -> bytes:
                    read_targets.append(path)
                    return original_read_bytes(path)

                with (
                    patch.object(Path, "read_bytes", new=monitored_read_bytes),
                    patch.object(
                        campaign_module,
                        "build_campaign_artifacts",
                    ) as build_spy,
                    self.assertRaisesRegex(
                        CampaignGenerationError,
                        "singly linked regular file",
                    ),
                ):
                    check_artifacts(
                        output_dir,
                        implementation_commit=self.commit,
                        evaluated_at=self.evaluated_at,
                        record_path=record_path,
                    )

                build_spy.assert_not_called()
                self.assertEqual(read_targets, [])

    def test_cli_destination_preflight_accepts_only_repo_confined_fresh_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".source-to-decision-cli-paths-", dir=ROOT
        ) as directory:
            temporary_root = Path(directory)
            output_dir = temporary_root / "campaign"
            record_path = temporary_root / "record.json"
            relative_output = output_dir.relative_to(ROOT)
            relative_record = record_path.relative_to(ROOT)

            normalized_output, normalized_record, display_paths = (
                _prepare_cli_destinations(
                    relative_output,
                    relative_record,
                    for_generation=True,
                )
            )
            self.assertEqual(normalized_output, output_dir.resolve())
            self.assertEqual(normalized_record, record_path.resolve())
            self.assertEqual(len(display_paths), 5)
            self.assertTrue(
                all(not Path(path).is_absolute() for path in display_paths)
            )

            output_dir.mkdir()
            existing_output = output_dir / "existing.txt"
            existing_output.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(
                CampaignGenerationError,
                "must be absent or empty",
            ):
                _prepare_cli_destinations(
                    relative_output,
                    relative_record,
                    for_generation=True,
                )
            self.assertEqual(existing_output.read_text(encoding="utf-8"), "preserve")

            existing_output.unlink()
            record_path.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(
                CampaignGenerationError,
                "must not already exist",
            ):
                _prepare_cli_destinations(
                    relative_output,
                    relative_record,
                    for_generation=True,
                )
            self.assertEqual(record_path.read_text(encoding="utf-8"), "preserve")

    def test_cli_destination_preflight_rejects_escape_symlink_and_overlap(
        self,
    ) -> None:
        with (
            tempfile.TemporaryDirectory(
                prefix=".source-to-decision-cli-negative-", dir=ROOT
            ) as directory,
            tempfile.TemporaryDirectory(
                prefix="source-to-decision-outside-"
            ) as outside_directory,
        ):
            temporary_root = Path(directory)
            outside_root = Path(outside_directory)
            relative_root = temporary_root.relative_to(ROOT)
            linked = temporary_root / "linked"
            linked.symlink_to(outside_root, target_is_directory=True)

            invalid_pairs = (
                (ROOT, None, "non-root path"),
                (Path(".git/campaign"), None, "control metadata"),
                (Path(".GIT/campaign"), None, "control metadata"),
                (outside_root / "campaign", None, "confined to the repository"),
                (Path("../campaign-outside"), None, "confined to the repository"),
                (relative_root / "linked/campaign", None, "symbolic link"),
                (
                    relative_root / "overlap",
                    relative_root / "overlap/record.json",
                    "must not overlap",
                ),
                (
                    relative_root / "record-parent/campaign",
                    relative_root / "record-parent",
                    "must not overlap",
                ),
            )
            for output_dir, record_path, message in invalid_pairs:
                with self.subTest(
                    output_dir=output_dir,
                    record_path=record_path,
                ):
                    with self.assertRaisesRegex(CampaignGenerationError, message):
                        _prepare_cli_destinations(
                            output_dir,
                            record_path,
                            for_generation=True,
                        )
            self.assertEqual(list(outside_root.iterdir()), [])

            with self.assertRaisesRegex(
                CampaignGenerationError,
                "unavailable for verification",
            ):
                _prepare_cli_destinations(
                    relative_root / "missing",
                    None,
                    for_generation=False,
                )

    def test_cli_rejects_outside_destination_before_campaign_execution(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="source-to-decision-cli-process-"
        ) as directory:
            temporary_root = Path(directory)
            repository = _copy_campaign_cli_fixture(
                temporary_root,
                initialize_git=False,
            )
            outside_destination = temporary_root / "outside-campaign"
            completed = _run_campaign_cli(
                repository,
                [
                    "--check",
                    "--output-dir",
                    str(outside_destination),
                    "--implementation-commit",
                    "0" * 40,
                    "--evaluated-at",
                    "2026-08-15T00:00:00Z",
                ],
                cwd=temporary_root,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("confined to the repository", completed.stderr)
            self.assertFalse(outside_destination.exists())

    def test_evidence_profile_validates_exact_ce2_boundary(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".source-to-decision-ce2-test-", dir=ROOT
        ) as directory:
            temporary_root = Path(directory)
            output_dir = temporary_root / "evidence"
            record_path = temporary_root / "record.json"
            paths = generate_artifacts(
                output_dir,
                implementation_commit=self.commit,
                evaluated_at=self.evaluated_at,
                record_path=record_path,
            )
            self.assertEqual(len(paths), 5)
            self.assertEqual(
                json.loads(record_path.read_text(encoding="utf-8")),
                build_evidence_record(
                    implementation_commit=self.commit,
                    evaluated_at=self.evaluated_at,
                    output_dir=output_dir,
                ),
            )
            validated = _validate_test_record(record_path)
        self.assertEqual(validated["status"], "VALID")
        self.assertEqual(validated["profile_id"], "P2-CE-005")
        self.assertEqual(validated["artifact_count"], 6)
        self.assertEqual(
            validated["campaign_outcomes"],
            {
                "unique_scenarios": 20,
                "evaluation_runs": 2,
                "denominator": 40,
                "clean_reference_matches": 20,
                "evidence_blocks": 4,
                "model_blocks": 4,
                "policy_blocks": 4,
                "verifier_blocks": 4,
                "final_surface_blocks": 4,
                "byte_identical_result_ledgers": True,
            },
        )

    def test_source_campaign_registry_does_not_consult_later_worktree_modules(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".source-to-decision-ce2-frozen-registry-", dir=ROOT
        ) as directory:
            temporary_root = Path(directory)
            output_dir = temporary_root / "evidence"
            record_path = temporary_root / "record.json"
            generate_artifacts(
                output_dir,
                implementation_commit=self.commit,
                evaluated_at=self.evaluated_at,
                record_path=record_path,
            )
            with (
                patch.object(
                    Path,
                    "rglob",
                    side_effect=AssertionError(
                        "current worktree must not define a frozen evidence registry"
                    ),
                ),
                patch(
                    "scripts.generate_source_to_decision_ce2_campaign._source_bindings",
                    side_effect=AssertionError(
                        "fresh evaluation must not widen a commit-frozen registry"
                    ),
                ),
            ):
                validated = _validate_test_record(record_path)
        self.assertEqual(validated["status"], "VALID")

    def test_fresh_evaluator_rejects_coherent_dual_ledger_rewrite(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".source-to-decision-ce2-forgery-", dir=ROOT
        ) as directory:
            temporary_root = Path(directory)
            output_dir = temporary_root / "evidence"
            record_path = temporary_root / "record.json"
            generate_artifacts(
                output_dir,
                implementation_commit=self.commit,
                evaluated_at=self.evaluated_at,
                record_path=record_path,
            )
            rows = [
                json.loads(line)
                for line in (output_dir / "campaign_results_run1.jsonl")
                .read_text(encoding="utf-8")
                .splitlines()
                if line.strip()
            ]
            rows[0]["presented_decision_sha256"] = "0" * 64
            forged = _jsonl_bytes(rows)
            for run_name in (
                "campaign_results_run1.jsonl",
                "campaign_results_run2.jsonl",
            ):
                (output_dir / run_name).write_bytes(forged)
            summary_path = output_dir / "campaign_summary.json"
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            forged_sha256 = hashlib.sha256(forged).hexdigest()
            summary["artifact_bindings"]["campaign_results_run1_sha256"] = forged_sha256
            summary["artifact_bindings"]["campaign_results_run2_sha256"] = forged_sha256
            for receipt in summary["run_receipts"]:
                receipt["result_ledger_sha256"] = forged_sha256
            _write_json(summary_path, summary)
            record = json.loads(record_path.read_text(encoding="utf-8"))
            for artifact in record["evidence_artifacts"]:
                if artifact["artifact_role"] in {
                    "campaign_results_run1",
                    "campaign_results_run2",
                }:
                    artifact["sha256"] = forged_sha256
                elif artifact["artifact_role"] == "campaign_summary":
                    artifact["sha256"] = _sha256(summary_path)
            _write_json(record_path, record)
            with self.assertRaisesRegex(
                EvidenceValidationError,
                "ledgers do not match fresh frozen-plan execution",
            ):
                _validate_test_record(record_path)

    def test_validator_rejects_source_binding_and_claim_boundary_drift(self) -> None:
        for mutation in (
            "source_binding_missing",
            "source_binding_extra",
            "source_binding_path",
            "source_binding_digest",
            "supported_wording",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory(
                    prefix=".source-to-decision-ce2-drift-", dir=ROOT
                ) as directory,
            ):
                temporary_root = Path(directory)
                output_dir = temporary_root / "evidence"
                record_path = temporary_root / "record.json"
                generate_artifacts(
                    output_dir,
                    implementation_commit=self.commit,
                    evaluated_at=self.evaluated_at,
                    record_path=record_path,
                )
                record = json.loads(record_path.read_text(encoding="utf-8"))
                if mutation.startswith("source_binding"):
                    profile_path = output_dir / "campaign_profile.json"
                    profile = json.loads(profile_path.read_text(encoding="utf-8"))
                    if mutation == "source_binding_missing":
                        profile["source_bindings"].pop()
                        expected_message = "source-binding count is invalid"
                    elif mutation == "source_binding_extra":
                        profile["source_bindings"].append(
                            {
                                "role": "ADF_SRC_ADF_POC_FUTURE_MODULE_PY",
                                "path": "src/adf_poc/future_module.py",
                                "sha256": "0" * 64,
                            }
                        )
                        expected_message = "source-binding count is invalid"
                    elif mutation == "source_binding_path":
                        profile["source_bindings"][0][
                            "path"
                        ] = "src/adf_poc/changed_binding.py"
                        expected_message = "source-binding path is not canonical"
                    else:
                        profile["source_bindings"][0]["sha256"] = "0" * 64
                        expected_message = (
                            "sources do not match the implementation commit"
                        )
                    _write_json(profile_path, profile)
                    next(
                        artifact
                        for artifact in record["evidence_artifacts"]
                        if artifact["artifact_role"] == "campaign_profile"
                    )["sha256"] = _sha256(profile_path)
                else:
                    record["supported_wording"] += " Unsupported expansion."
                    expected_message = "does not preserve its exact CE-2 boundary"
                _write_json(record_path, record)
                with self.assertRaisesRegex(
                    EvidenceValidationError,
                    expected_message,
                ):
                    _validate_test_record(record_path)

    def test_plan_path_is_repository_owned(self) -> None:
        self.assertTrue(CAMPAIGN_PLAN.is_file())
        self.assertEqual(
            CAMPAIGN_PLAN.name, "source_to_decision_ce2_campaign_plan.json"
        )


if __name__ == "__main__":
    unittest.main()
