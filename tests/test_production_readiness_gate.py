from __future__ import annotations

import io
import hashlib
import json
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
from pathlib import Path

from scripts.validate_production_readiness import (
    ALLOWED_EVIDENCE_STATES,
    DOMAIN_NAMES,
    EXPECTED_REQUIREMENT_IDS,
    ReadinessValidationError,
    SCHEMA_VERSION,
    _validate_release_carrier,
    load_readiness_document,
    main,
    validate_readiness_document,
    validate_readiness_file,
)


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "config" / "production_readiness_requirements.json"


class ProductionReadinessGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = load_readiness_document(MATRIX)

    def assert_invalid(self, document: dict, pattern: str) -> None:
        with self.assertRaisesRegex(ReadinessValidationError, pattern):
            validate_readiness_document(document, repo_root=ROOT)

    def current_candidate_document(self) -> dict:
        candidate = deepcopy(self.document)
        if candidate["schema_version"] == SCHEMA_VERSION:
            return candidate
        commit = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        manifest = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{commit}:MANIFEST.sha256"],
            check=True,
            capture_output=True,
        ).stdout
        candidate["schema_version"] = SCHEMA_VERSION
        candidate["candidate_commit"] = commit
        candidate["candidate_manifest_sha256"] = hashlib.sha256(manifest).hexdigest()
        return candidate

    def test_current_matrix_is_structurally_valid_and_derived_blocked(self) -> None:
        report = validate_readiness_file(MATRIX, repo_root=ROOT)
        self.assertEqual(report.derived_status, "BLOCKED")
        self.assertEqual(report.domain_count, 18)
        self.assertEqual(report.requirement_count, 36)
        self.assertEqual(
            report.blocking_requirement_ids,
            EXPECTED_REQUIREMENT_IDS,
        )

    def test_cli_returns_release_blocking_exit_for_valid_blocked_matrix(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            return_code = main(["--config", str(MATRIX), "--repo-root", str(ROOT)])
        self.assertEqual(return_code, 2)
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(json.loads(stdout.getvalue())["derived_status"], "BLOCKED")

    def test_current_schema_binds_exact_candidate_commit_and_manifest(self) -> None:
        candidate = self.current_candidate_document()
        report = validate_readiness_document(candidate, repo_root=ROOT)
        self.assertTrue(report.candidate_manifest_verified)
        self.assertEqual(report.candidate_commit, candidate["candidate_commit"])

        wrong_digest = deepcopy(candidate)
        wrong_digest["candidate_manifest_sha256"] = "0" * 64
        self.assert_invalid(wrong_digest, "does not match its declared digest")

        unknown_commit = deepcopy(candidate)
        unknown_commit["candidate_commit"] = "0" * 40
        self.assert_invalid(unknown_commit, "Git evidence is unavailable")

    def test_release_carrier_allows_only_descriptor_and_manifest_changes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "config",
                    "user.email",
                    "test@example.invalid",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(root), "config", "user.name", "Test"],
                check=True,
            )
            (root / "config").mkdir()
            (root / "config/production_readiness_requirements.json").write_text(
                "candidate\n", encoding="utf-8"
            )
            (root / "source.py").write_text("candidate\n", encoding="utf-8")
            (root / "MANIFEST.sha256").write_text("candidate\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "candidate"],
                check=True,
            )
            candidate_commit = subprocess.run(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            (root / "config/production_readiness_requirements.json").write_text(
                "carrier\n", encoding="utf-8"
            )
            (root / "MANIFEST.sha256").write_text("carrier\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "."], check=True)
            subprocess.run(
                ["git", "-C", str(root), "commit", "-q", "-m", "carrier"],
                check=True,
            )
            _validate_release_carrier(root, candidate_commit)

            (root / "source.py").write_text("dirty\n", encoding="utf-8")
            with self.assertRaisesRegex(
                ReadinessValidationError, "requires a clean Git worktree"
            ):
                _validate_release_carrier(root, candidate_commit)

    def test_relabeling_blocked_matrix_ready_is_rejected(self) -> None:
        mutation = deepcopy(self.document)
        mutation["declared_status"] = "READY"
        mutation["candidate_label"] = "PRODUCTION_READY_CANDIDATE"
        self.assert_invalid(mutation, "does not match derived status BLOCKED")

    def test_ready_requires_every_frozen_row_to_be_owner_accepted_and_effective(
        self,
    ) -> None:
        ready = deepcopy(self.document)
        for row in ready["requirements"]:
            row["owner_acceptance"] = "ACCEPTED"
            row["current_state"] = "OPERATIONALLY_EFFECTIVE"
            row["evidence_artifacts"] = ["README.md"]
            row["remaining_gate"] = "NONE"
        ready["declared_status"] = "READY"
        ready["candidate_label"] = "PRODUCTION_READY_CANDIDATE"
        report = validate_readiness_document(ready, repo_root=ROOT)
        self.assertEqual(report.derived_status, "READY")
        self.assertEqual(report.blocking_requirement_ids, ())

        downgraded = deepcopy(ready)
        downgraded["requirements"][0]["current_state"] = "INTEGRATION_TESTED"
        downgraded["declared_status"] = "BLOCKED"
        downgraded["candidate_label"] = "PRODUCTION_DEVELOPMENT_CANDIDATE"
        report = validate_readiness_document(downgraded, repo_root=ROOT)
        self.assertEqual(report.derived_status, "BLOCKED")
        self.assertEqual(report.blocking_requirement_ids, ("PR-01-001",))

        for field, value, pattern in (
            (
                "owner_acceptance",
                "NOT_RECORDED",
                "cannot claim OPERATIONALLY_EFFECTIVE",
            ),
            (
                "remaining_gate",
                "UNRESOLVED_PRODUCTION_GATE",
                "remaining_gate must be NONE",
            ),
        ):
            inconsistent = deepcopy(ready)
            inconsistent["requirements"][0][field] = value
            with self.subTest(field=field):
                self.assert_invalid(inconsistent, pattern)

    def test_requirement_omission_is_rejected_even_when_domain_remains(self) -> None:
        mutation = deepcopy(self.document)
        del mutation["requirements"][1]
        self.assert_invalid(mutation, "missing frozen requirements.*PR-01-002")

    def test_domain_omission_is_rejected(self) -> None:
        mutation = deepcopy(self.document)
        mutation["requirements"] = [
            row for row in mutation["requirements"] if row["domain_id"] != "18"
        ]
        self.assert_invalid(mutation, "missing frozen requirements.*PR-18-001")

    def test_exact_domain_names_and_requirement_order_are_enforced(self) -> None:
        renamed = deepcopy(self.document)
        renamed["requirements"][0]["domain"] = "Mission"
        self.assert_invalid(renamed, "controlled name for domain 01")

        reordered = deepcopy(self.document)
        reordered["requirements"][0], reordered["requirements"][1] = (
            reordered["requirements"][1],
            reordered["requirements"][0],
        )
        self.assert_invalid(reordered, "controlled requirement order")
        self.assertEqual(
            DOMAIN_NAMES,
            {
                "01": "Mission and operational requirements",
                "02": "Supported and prohibited use cases",
                "03": "Identity authentication authorization and human authority",
                "04": "Evidence provenance freshness integrity and source independence",
                "05": "Model performance calibration abstention drift and promotion governance",
                "06": "Policy correctness and policy-change control",
                "07": "Durable replay prevention and idempotency",
                "08": "Broker and target-adapter isolation",
                "09": "Independent post-action observation",
                "10": "Failure handling reconciliation rollback and recovery",
                "11": "Audit durability authenticity retention and external custody",
                "12": "Availability concurrency scaling and disaster recovery",
                "13": "Security architecture and threat-model closure",
                "14": "Privacy data governance records management and legal constraints",
                "15": "Deployment configuration secrets key management and supply-chain controls",
                "16": "Monitoring alerting incident response and operational runbooks",
                "17": "Verification validation red teaming and operational acceptance",
                "18": "Release rollback upgrade and decommissioning procedures",
            },
        )

    def test_duplicate_and_unknown_requirement_ids_are_rejected(self) -> None:
        duplicate = deepcopy(self.document)
        duplicate["requirements"][1]["requirement_id"] = "PR-01-001"
        self.assert_invalid(duplicate, "duplicate requirement_id")

        unknown = deepcopy(self.document)
        unknown["requirements"][1]["requirement_id"] = "PR-01-003"
        self.assert_invalid(unknown, "missing frozen requirements.*PR-01-002")

    def test_mandatory_flag_cannot_be_weakened(self) -> None:
        mutation = deepcopy(self.document)
        mutation["requirements"][0]["mandatory"] = False
        self.assert_invalid(mutation, "mandatory must be true")

    def test_row_shape_and_required_owner_acceptance_evidence_gate_fields(self) -> None:
        fields = (
            "accountable_owner",
            "owner_acceptance",
            "acceptance_criteria",
            "evidence_artifacts",
            "remaining_gate",
            "release_gate",
        )
        for field in fields:
            mutation = deepcopy(self.document)
            del mutation["requirements"][0][field]
            with self.subTest(field=field):
                self.assert_invalid(mutation, f"missing fields.*{field}")

        extra = deepcopy(self.document)
        extra["requirements"][0]["waiver"] = True
        self.assert_invalid(extra, "unknown fields.*waiver")

    def test_empty_control_fields_and_placeholder_owner_are_rejected(self) -> None:
        for field in (
            "requirement",
            "acceptance_criteria",
            "accountable_owner",
            "remaining_gate",
            "release_gate",
            "prohibited_inference",
        ):
            mutation = deepcopy(self.document)
            mutation["requirements"][0][field] = ""
            with self.subTest(field=field):
                self.assert_invalid(mutation, f"{field} must be a nonempty string")

        placeholder = deepcopy(self.document)
        placeholder["requirements"][0]["accountable_owner"] = "TBD"
        self.assert_invalid(placeholder, "not a valid accountable role identifier")

    def test_only_controlled_evidence_and_owner_acceptance_states_are_allowed(
        self,
    ) -> None:
        mutation = deepcopy(self.document)
        mutation["requirements"][0]["current_state"] = "READY"
        self.assert_invalid(mutation, "current_state must be one of")

        mutation = deepcopy(self.document)
        mutation["requirements"][0]["owner_acceptance"] = "SELF_APPROVED"
        self.assert_invalid(mutation, "owner_acceptance must be one of")

        self.assertEqual(
            ALLOWED_EVIDENCE_STATES,
            {
                "NOT_IMPLEMENTED",
                "IMPLEMENTED",
                "UNIT_TESTED",
                "INTEGRATION_TESTED",
                "SYNTHETIC_MECHANISM_EVALUATED",
                "HISTORICALLY_EVALUATED",
                "NON_PRODUCTION_VALIDATED",
                "PILOT_ACCEPTED",
                "PRODUCTION_AUTHORIZED",
                "OPERATIONALLY_EFFECTIVE",
                "EXTERNAL_APPROVAL_REQUIRED",
            },
        )

        combined = deepcopy(self.document)
        combined["requirements"][0]["current_state"] = "PRODUCTION_AUTHORIZED_EFFECTIVE"
        self.assert_invalid(combined, "current_state must be one of")

    def test_production_authorization_is_distinct_from_operational_effectiveness(
        self,
    ) -> None:
        mutation = deepcopy(self.document)
        for row in mutation["requirements"]:
            row["owner_acceptance"] = "ACCEPTED"
            row["current_state"] = "OPERATIONALLY_EFFECTIVE"
            row["evidence_artifacts"] = ["README.md"]
            row["remaining_gate"] = "NONE"
        mutation["requirements"][0]["current_state"] = "PRODUCTION_AUTHORIZED"
        mutation["declared_status"] = "BLOCKED"
        mutation["candidate_label"] = "PRODUCTION_DEVELOPMENT_CANDIDATE"
        report = validate_readiness_document(mutation, repo_root=ROOT)
        self.assertEqual(report.derived_status, "BLOCKED")
        self.assertEqual(report.blocking_requirement_ids, ("PR-01-001",))

    def test_nonempty_evidence_is_required_for_claimed_implementation(self) -> None:
        mutation = deepcopy(self.document)
        mutation["requirements"][2]["evidence_artifacts"] = []
        self.assert_invalid(mutation, "must not be empty for state INTEGRATION_TESTED")

    def test_evidence_paths_must_exist_inside_repository_without_symlinks(self) -> None:
        mutations = []
        for artifact in (
            "does/not/exist.txt",
            "/etc/passwd",
            "../outside.txt",
        ):
            mutation = deepcopy(self.document)
            mutation["requirements"][0]["evidence_artifacts"] = [artifact]
            mutations.append((artifact, mutation))
        for artifact, mutation in mutations:
            with self.subTest(artifact=artifact):
                self.assert_invalid(
                    mutation, "repository-relative path|does not resolve"
                )

        with tempfile.TemporaryDirectory(dir=ROOT) as directory:
            temporary_root = Path(directory)
            target = temporary_root / "target.txt"
            target.write_text("evidence\n", encoding="utf-8")
            link = temporary_root / "link.txt"
            link.symlink_to(target)
            mutation = deepcopy(self.document)
            mutation["requirements"][0]["evidence_artifacts"] = [
                str(link.relative_to(ROOT))
            ]
            self.assert_invalid(mutation, "must not traverse a symbolic link")

    def test_strict_json_rejects_duplicate_members_and_nonfinite_numbers(self) -> None:
        fixtures = (
            '{"schema_version":"first","schema_version":"second"}',
            '{"schema_version":NaN}',
        )
        with tempfile.TemporaryDirectory() as directory:
            for index, payload in enumerate(fixtures):
                path = Path(directory) / f"invalid-{index}.json"
                path.write_text(payload, encoding="utf-8")
                with self.subTest(index=index):
                    with self.assertRaises(ReadinessValidationError):
                        load_readiness_document(path)

    def test_top_level_shape_and_control_values_are_strict(self) -> None:
        missing = deepcopy(self.document)
        del missing["baseline_commit"]
        self.assert_invalid(missing, "missing fields.*baseline_commit")

        extra = deepcopy(self.document)
        extra["override"] = "READY"
        self.assert_invalid(extra, "unknown fields.*override")

        bad_commit = deepcopy(self.document)
        bad_commit["baseline_commit"] = "bb6b8f"
        self.assert_invalid(bad_commit, "40-character lowercase Git SHA")

    def test_json_serialized_mutant_cannot_bypass_validation(self) -> None:
        mutation = deepcopy(self.document)
        mutation["declared_status"] = "READY"
        mutation["candidate_label"] = "PRODUCTION_READY_CANDIDATE"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mutation.json"
            path.write_text(json.dumps(mutation), encoding="utf-8")
            decoded = load_readiness_document(path)
            self.assert_invalid(decoded, "does not match derived status BLOCKED")


if __name__ == "__main__":
    unittest.main()
