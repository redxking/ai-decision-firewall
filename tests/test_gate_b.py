from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

from jsonschema import Draft202012Validator, FormatChecker

from adf_poc.replay import ReplayHarness, ReplaySafetyViolation
from adf_poc.replay import contracts as replay_contracts
from adf_poc.replay import gate_b as gate_b_module
from adf_poc.replay import harness as replay_harness_module
from adf_poc.replay.gate_b import (
    GateBStopConditionViolation,
    GateBValidationError,
    MAX_GATE_B_ARTIFACT_BYTES,
    evaluate_qualification_stop_conditions,
    load_gate_b_authorization,
    load_manifest_control,
    validate_accepted_case_window,
    validate_gate_b_current,
)
from adf_poc.replay.contracts import (
    MAX_CONTROL_DOCUMENT_BYTES,
    ReplayConfig,
    ReplayConfigurationError,
    sha256_file,
)
from adf_poc.replay.secure_output import (
    HistoricalOutputError,
    HistoricalOutputGuard,
)


ROOT = Path(__file__).resolve().parents[1]


@contextmanager
def prohibit_payload_access(cases_path: Path, adjudications_path: Path):
    """Fail if a structural-preflight test touches either governed payload."""

    source_paths = {cases_path.resolve(), adjudications_path.resolve()}
    accesses: list[Path] = []
    original_path_open = Path.open
    original_read_text = Path.read_text
    original_read_bytes = Path.read_bytes
    original_os_open = os.open

    def resolved_source(value) -> Path | None:
        try:
            return Path(value).resolve()
        except (TypeError, ValueError, OSError):
            return None

    def reject_if_source(value) -> None:
        resolved = resolved_source(value)
        if resolved in source_paths:
            accesses.append(resolved)
            raise AssertionError("Historical payload was accessed before Gate B.")

    def guarded_path_open(path, *args, **kwargs):
        reject_if_source(path)
        return original_path_open(path, *args, **kwargs)

    def guarded_read_text(path, *args, **kwargs):
        reject_if_source(path)
        return original_read_text(path, *args, **kwargs)

    def guarded_read_bytes(path, *args, **kwargs):
        reject_if_source(path)
        return original_read_bytes(path, *args, **kwargs)

    def guarded_os_open(path, flags, *args, **kwargs):
        reject_if_source(path)
        return original_os_open(path, flags, *args, **kwargs)

    with (
        patch.object(Path, "open", new=guarded_path_open),
        patch.object(Path, "read_text", new=guarded_read_text),
        patch.object(Path, "read_bytes", new=guarded_read_bytes),
        patch.object(
            replay_harness_module.os,
            "open",
            side_effect=guarded_os_open,
        ),
        patch.object(
            HistoricalOutputGuard,
            "_require_platform_support",
            return_value=None,
        ),
    ):
        yield accesses
    if accesses:
        raise AssertionError("Historical payload access was observed before Gate B.")


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def approved_authorization(root: Path, manifest_path: Path) -> dict:
    model_path = root / "outputs" / "baseline" / "model.json"
    policy_path = root / "config" / "policy.json"
    artifact_paths = {
        "SOURCE_MAPPING": root / "local" / "gate_b" / "source_mapping.csv",
        "ADJUDICATION_PROTOCOL": root / "local" / "gate_b" / "adjudication_protocol.md",
        "PILOT_PROTOCOL": root / "local" / "gate_b" / "pilot_protocol.md",
    }
    return {
        "schema_version": "0.2.0",
        "authorization_id": "SYNTHETIC-TEST-ONLY-GATE-B",
        "status": "APPROVED",
        "dataset_id": "adf-phase2-starter-synthetic",
        "dataset_manifest_sha256": sha256_file(manifest_path),
        "approved_purpose": "Synthetic structural preflight test only.",
        "population_scope": "Three synthetic fixture cases; no organizational data.",
        "window_start": "2026-08-01T00:00:00Z",
        "window_end": "2026-08-02T00:00:00Z",
        "valid_from": "2026-08-10T00:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "approvals": [
            {
                "role": role,
                "status": "APPROVED",
                "approver_id": f"synthetic-test-{role.lower()}",
                "approval_reference": f"synthetic-test-reference-{role.lower()}",
                "approved_at": "2026-08-09T00:00:00Z",
            }
            for role in (
                "DATA_OWNER",
                "MISSION_OWNER",
                "SECURITY",
                "PRIVACY_LEGAL",
                "RECORDS_MANAGEMENT",
            )
        ],
        "artifact_bindings": {
            "contract_version": "0.2.0",
            "contract_adapter": "canonical_jsonl_v0.2",
            "model_sha256": sha256_file(model_path),
            "policy_sha256": sha256_file(policy_path),
            "artifacts": [
                {
                    "role": role,
                    "path": str(path.relative_to(root)),
                    "sha256": sha256_file(path),
                }
                for role, path in artifact_paths.items()
            ],
        },
        "controls": {
            "deidentification_assessment_reference": "synthetic-test-assessment",
            "direct_identifiers_removed": True,
            "reidentification_risk_reviewed": True,
            "offline_only": True,
            "live_feed_connected": False,
            "action_credentials_present": False,
            "write_capable_connectors_present": False,
            "network_egress_disabled": True,
            "runtime_labels_separated": True,
            "complete_intake_reporting": True,
            "restricted_hash_handling": True,
            "retention_deletion_reference": "synthetic-test-retention",
            "incident_response_reference": "synthetic-test-incident",
            "isolation_reference": "synthetic-test-isolation",
            "kill_switch_reference": "synthetic-test-kill-switch",
        },
        "custody": {
            "snapshot_reference": "synthetic-test-snapshot",
            "custody_record_reference": "synthetic-test-custody",
            "external_manifest_digest_reference": "synthetic-test-external-digest",
            "frozen_at": "2026-08-09T00:00:00Z",
            "custodian_id": "synthetic-test-custodian",
        },
        "sampling": {
            "protocol_reference": "synthetic-test-sampling",
            "predeclared_at": "2026-08-09T00:00:00Z",
            "temporal_holdout_start": "2026-08-01T00:00:00Z",
            "temporal_holdout_end": "2026-08-01T23:59:59Z",
            "full_intake_count": 3,
            "sample_count": 3,
            "selection_method": "All three fixed synthetic fixture cases.",
            "selection_frozen": True,
        },
        "stop_conditions": {
            "max_overall_quarantine_rate": 0,
            "max_category_quarantine_rates": [
                {"category": "SYNTAX", "max_rate": 0},
                {"category": "STRUCTURE", "max_rate": 0},
                {"category": "SEMANTICS", "max_rate": 0},
                {"category": "RESOURCE_LIMIT", "max_rate": 0},
            ],
            "stop_on_any_fatal": True,
            "stop_on_unknown_failure": True,
            "thresholds_frozen": True,
            "escalation_owner_id": "synthetic-test-escalation-owner",
        },
        "adjudication": {
            "protocol_reference": "synthetic-test-adjudication",
            "minimum_reviewers": 2,
            "runtime_separated": True,
            "labels_hidden_until_decision": True,
            "indeterminate_allowed": True,
            "disagreement_resolution": "Synthetic test-only majority rule.",
        },
        "independent_review": {
            "status": "APPROVED",
            "reviewer_id": "synthetic-test-reviewer",
            "review_reference": "synthetic-test-review",
            "reviewed_at": "2026-08-09T00:00:00Z",
        },
        "claim_control": {
            "claim_owner_id": "synthetic-test-claim-owner",
            "pause_authority_id": "synthetic-test-pause-owner",
            "revocation_authority_id": "synthetic-test-revocation-owner",
            "expires_at": "2099-01-01T00:00:00Z",
            "revalidation_triggers": [
                "Any source, mapping, model, policy, or protocol change",
                "Any incident or discovered validation gap",
            ],
        },
    }


def make_gate_b_repository(root: Path) -> tuple[Path, Path, Path, Path]:
    shutil.copytree(ROOT / "data" / "phase2_starter", root / "data" / "historical")
    shutil.copytree(ROOT / "contracts", root / "contracts")
    (root / "config").mkdir(parents=True)
    (root / "outputs" / "baseline").mkdir(parents=True)
    shutil.copyfile(ROOT / "config" / "policy.json", root / "config" / "policy.json")
    shutil.copyfile(
        ROOT / "outputs" / "baseline" / "model.json",
        root / "outputs" / "baseline" / "model.json",
    )
    controls = root / "local" / "gate_b"
    controls.mkdir(parents=True)
    (controls / "source_mapping.csv").write_text(
        "source_field,canonical_field\nsynthetic,synthetic\n", encoding="utf-8"
    )
    (controls / "adjudication_protocol.md").write_text(
        "# Synthetic test-only adjudication protocol\n", encoding="utf-8"
    )
    (controls / "pilot_protocol.md").write_text(
        "# Synthetic test-only pilot protocol\n", encoding="utf-8"
    )
    manifest_path = root / "data" / "historical" / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["data_origin"] = "HISTORICAL_DEIDENTIFIED"
    manifest["historical_case_count"] = 3
    write_json(manifest_path, manifest)

    authorization_path = controls / "gate_b_authorization.json"
    write_json(authorization_path, approved_authorization(root, manifest_path))
    config = {
        "schema_version": "0.2.0",
        "execution_mode": "HISTORICAL_REPLAY",
        "live_actions_enabled": False,
        "dataset_manifest": "data/historical/manifest.json",
        "model_path": "outputs/baseline/model.json",
        "policy_path": "config/policy.json",
        "output_dir": "outputs/replay/gate-b-test",
        "contract_adapter": "canonical_jsonl_v0.2",
        "deterministic_outputs": True,
        "zero_effects_required": True,
        "record_failure_policy": "QUARANTINE_RECORD",
        "gate_b_authorization": "local/gate_b/gate_b_authorization.json",
    }
    config_path = root / "config" / "phase2_historical.json"
    write_json(config_path, config)
    return (
        config_path,
        authorization_path,
        root / "data" / "historical" / "cases.jsonl",
        root / "data" / "historical" / "adjudications.jsonl",
    )


class GateBContractTests(unittest.TestCase):
    def test_schema_accepts_only_the_non_authorizing_draft_example(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/v0.2.0/gate-b-authorization.schema.json").read_text(
                encoding="utf-8"
            )
        )
        draft = json.loads(
            (
                ROOT / "contracts/v0.2.0/examples/gate-b-authorization-draft.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        self.assertEqual(list(validator.iter_errors(draft)), [])
        self.assertEqual(draft["status"], "DRAFT")
        self.assertTrue(all(row["status"] == "PENDING" for row in draft["approvals"]))

    def test_missing_draft_and_expired_authorization_precede_source_access(
        self,
    ) -> None:
        mutations = (
            "missing",
            "draft",
            "expired",
            "malformed",
            "binding_failed",
            "placeholder_payload_digest",
            "duplicate_payload_path",
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path, authorization_path, cases_path, adjudications_path = (
                    make_gate_b_repository(root)
                )
                if mutation == "missing":
                    config = json.loads(config_path.read_text(encoding="utf-8"))
                    config.pop("gate_b_authorization")
                    write_json(config_path, config)
                elif mutation == "malformed":
                    authorization_path.write_text("{not-json\n", encoding="utf-8")
                elif mutation in {
                    "placeholder_payload_digest",
                    "duplicate_payload_path",
                }:
                    manifest_path = root / "data" / "historical" / "manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    cases_entry = next(
                        row for row in manifest["files"] if row["role"] == "cases"
                    )
                    adjudication_entry = next(
                        row
                        for row in manifest["files"]
                        if row["role"] == "adjudications"
                    )
                    if mutation == "placeholder_payload_digest":
                        cases_entry["sha256"] = "0" * 64
                    else:
                        adjudication_entry["path"] = cases_entry["path"]
                        adjudication_entry["sha256"] = cases_entry["sha256"]
                        adjudication_entry["record_count"] = cases_entry["record_count"]
                    write_json(manifest_path, manifest)
                    authorization = json.loads(
                        authorization_path.read_text(encoding="utf-8")
                    )
                    authorization["dataset_manifest_sha256"] = sha256_file(
                        manifest_path
                    )
                    write_json(authorization_path, authorization)
                else:
                    authorization = json.loads(
                        authorization_path.read_text(encoding="utf-8")
                    )
                    if mutation == "draft":
                        authorization["status"] = "DRAFT"
                    elif mutation == "expired":
                        authorization["expires_at"] = "2026-08-11T00:00:00Z"
                        authorization["claim_control"][
                            "expires_at"
                        ] = "2026-08-11T00:00:00Z"
                    else:
                        authorization["artifact_bindings"]["model_sha256"] = "1" * 64
                    write_json(authorization_path, authorization)

                source_paths = {cases_path.resolve(), adjudications_path.resolve()}
                source_reads: list[Path] = []
                original_sha256 = replay_contracts.sha256_file
                original_open = Path.open
                original_os_open = os.open

                def guarded_sha256(path):
                    resolved = Path(path).resolve()
                    if resolved in source_paths:
                        source_reads.append(resolved)
                    return original_sha256(path)

                def guarded_open(path, *args, **kwargs):
                    resolved = Path(path).resolve()
                    if resolved in source_paths:
                        source_reads.append(resolved)
                        raise AssertionError(
                            "Historical source was opened before Gate B."
                        )
                    return original_open(path, *args, **kwargs)

                def guarded_os_open(path, flags, *args, **kwargs):
                    try:
                        resolved = Path(path).resolve()
                    except TypeError:
                        resolved = None
                    if resolved in source_paths:
                        source_reads.append(resolved)
                        raise AssertionError(
                            "Historical source descriptor was opened before Gate B."
                        )
                    return original_os_open(path, flags, *args, **kwargs)

                for operation in ("validate", "run"):
                    with self.subTest(mutation=mutation, operation=operation):
                        harness = ReplayHarness.from_config(
                            config_path, repository_root=root
                        )
                        with (
                            patch.object(
                                replay_contracts,
                                "sha256_file",
                                side_effect=guarded_sha256,
                            ),
                            patch.object(Path, "open", new=guarded_open),
                            patch.object(
                                replay_harness_module.os,
                                "open",
                                side_effect=guarded_os_open,
                            ),
                        ):
                            with self.assertRaises(GateBValidationError):
                                if operation == "validate":
                                    harness.validate_inputs()
                                else:
                                    harness.run()
                        self.assertEqual(source_reads, [])

    def test_closed_runtime_mutations_fail(self) -> None:
        mutations: dict[str, Callable[[dict[str, Any]], None]] = {
            "revoked": lambda value: value.__setitem__("status", "REVOKED"),
            "missing_role": lambda value: value["approvals"].pop(),
            "duplicate_role": lambda value: value["approvals"][-1].__setitem__(
                "role", "DATA_OWNER"
            ),
            "missing_artifact_role": lambda value: value["artifact_bindings"][
                "artifacts"
            ].pop(),
            "duplicate_artifact_role": lambda value: value["artifact_bindings"][
                "artifacts"
            ][-1].__setitem__("role", "SOURCE_MAPPING"),
            "unapproved_role": lambda value: value["approvals"][0].__setitem__(
                "status", "PENDING"
            ),
            "unsafe_action_credentials": lambda value: value["controls"].__setitem__(
                "action_credentials_present", True
            ),
            "model_digest": lambda value: value["artifact_bindings"].__setitem__(
                "model_sha256", "1" * 64
            ),
            "policy_digest": lambda value: value["artifact_bindings"].__setitem__(
                "policy_sha256", "1" * 64
            ),
            "manifest_digest": lambda value: value.__setitem__(
                "dataset_manifest_sha256", "1" * 64
            ),
            "source_mapping_digest": lambda value: value["artifact_bindings"][
                "artifacts"
            ][0].__setitem__("sha256", "1" * 64),
            "adjudication_protocol_digest": lambda value: value["artifact_bindings"][
                "artifacts"
            ][1].__setitem__("sha256", "1" * 64),
            "pilot_protocol_digest": lambda value: value["artifact_bindings"][
                "artifacts"
            ][2].__setitem__("sha256", "1" * 64),
            "contract_version": lambda value: value["artifact_bindings"].__setitem__(
                "contract_version", "0.2.1"
            ),
            "adapter": lambda value: value["artifact_bindings"].__setitem__(
                "contract_adapter", "unknown_adapter"
            ),
            "sample_count": lambda value: value["sampling"].__setitem__(
                "sample_count", 2
            ),
            "review_pending": lambda value: value["independent_review"].__setitem__(
                "status", "PENDING"
            ),
            "reviewer_is_approver": lambda value: value[
                "independent_review"
            ].__setitem__("reviewer_id", value["approvals"][0]["approver_id"]),
            "custody_before_window_end": lambda value: value["custody"].__setitem__(
                "frozen_at", "2026-08-01T00:00:00Z"
            ),
        }
        required_true = (
            "direct_identifiers_removed",
            "reidentification_risk_reviewed",
            "offline_only",
            "network_egress_disabled",
            "runtime_labels_separated",
            "complete_intake_reporting",
            "restricted_hash_handling",
        )
        required_false = (
            "live_feed_connected",
            "action_credentials_present",
            "write_capable_connectors_present",
        )

        def set_control(field: str, expected: bool) -> Callable[[dict[str, Any]], None]:
            def mutate(value: dict[str, Any]) -> None:
                value["controls"][field] = expected

            return mutate

        for field in required_true:
            mutations[f"unsafe_{field}"] = set_control(field, False)
        for field in required_false:
            mutations[f"unsafe_{field}"] = set_control(field, True)
        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                config_path, authorization_path, cases_path, adjudications_path = (
                    make_gate_b_repository(root)
                )
                value = json.loads(authorization_path.read_text(encoding="utf-8"))
                mutate(value)
                write_json(authorization_path, value)
                for operation in ("validate", "run"):
                    with self.subTest(name=name, operation=operation):
                        harness = ReplayHarness.from_config(
                            config_path, repository_root=root
                        )
                        with prohibit_payload_access(
                            cases_path, adjudications_path
                        ) as accesses:
                            with self.assertRaises(GateBValidationError):
                                if operation == "validate":
                                    harness.validate_inputs()
                                else:
                                    harness.run()
                        self.assertEqual(accesses, [])

    def test_protocol_and_manifest_path_escapes_are_rejected(self) -> None:
        for mutation in (
            "artifact_traversal",
            "artifact_symlink",
            "artifact_hardlink",
            "manifest_traversal",
            "payload_hardlink",
            "payload_hardlink_during_read",
        ):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path, authorization_path, cases_path, adjudications_path = (
                    make_gate_b_repository(root)
                )
                if mutation == "manifest_traversal":
                    config = ReplayConfig.load(config_path)
                    manifest_path = config.resolve_paths(root)["dataset_manifest"]
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["files"][0]["path"] = "../outside/cases.jsonl"
                    write_json(manifest_path, manifest)
                    with self.assertRaises(GateBValidationError):
                        ReplayHarness.from_config(
                            config_path, repository_root=root
                        ).validate_inputs()
                    continue
                if mutation == "payload_hardlink":
                    adjudications_path.unlink()
                    adjudications_path.hardlink_to(cases_path)
                    manifest_path = root / "data" / "historical" / "manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    for entry in manifest["files"]:
                        if entry["role"] == "adjudications":
                            entry["sha256"] = sha256_file(adjudications_path)
                            entry["record_count"] = 3
                    write_json(manifest_path, manifest)
                    authorization = json.loads(
                        authorization_path.read_text(encoding="utf-8")
                    )
                    authorization["dataset_manifest_sha256"] = sha256_file(
                        manifest_path
                    )
                    write_json(authorization_path, authorization)
                    with self.assertRaises(GateBValidationError):
                        ReplayHarness.from_config(
                            config_path, repository_root=root
                        ).validate_inputs()
                    continue
                if mutation == "payload_hardlink_during_read":
                    cases_identity = (
                        cases_path.stat().st_dev,
                        cases_path.stat().st_ino,
                    )
                    outside_link = root / "outside-case-hardlink.jsonl"
                    original_read = os.read
                    linked = False
                    engine_called = False

                    def hardlink_then_read(descriptor, size):
                        nonlocal linked
                        metadata = os.fstat(descriptor)
                        if (
                            not linked
                            and (metadata.st_dev, metadata.st_ino) == cases_identity
                        ):
                            outside_link.hardlink_to(cases_path)
                            linked = True
                        return original_read(descriptor, size)

                    def forbidden_runner(**kwargs):
                        nonlocal engine_called
                        engine_called = True
                        raise AssertionError(
                            "Engine must not run after a source custody change."
                        )

                    harness = ReplayHarness.from_config(
                        config_path, repository_root=root
                    )
                    with (
                        patch.object(
                            replay_harness_module.os,
                            "read",
                            side_effect=hardlink_then_read,
                        ),
                        patch.object(
                            harness,
                            "_default_record_engine_runner",
                            return_value=forbidden_runner,
                        ),
                    ):
                        with self.assertRaises(ReplaySafetyViolation):
                            harness.run()
                    self.assertTrue(linked)
                    self.assertTrue(outside_link.exists())
                    self.assertFalse(engine_called)
                    continue
                value = json.loads(authorization_path.read_text(encoding="utf-8"))
                artifact = value["artifact_bindings"]["artifacts"][0]
                if mutation == "artifact_traversal":
                    artifact["path"] = "../outside/source_mapping.csv"
                elif mutation == "artifact_symlink":
                    target = root / "local" / "gate_b" / "source_mapping.csv"
                    link = root / "local" / "gate_b" / "source_mapping_link.csv"
                    link.symlink_to(target)
                    self.assertTrue(link.is_symlink())
                    artifact["path"] = "local/gate_b/source_mapping_link.csv"
                    artifact["sha256"] = sha256_file(target)
                else:
                    target = root / "local" / "gate_b" / "source_mapping.csv"
                    link = root / "local" / "gate_b" / "source_mapping_hardlink.csv"
                    link.hardlink_to(target)
                    self.assertGreater(target.stat().st_nlink, 1)
                    artifact["path"] = "local/gate_b/source_mapping_hardlink.csv"
                    artifact["sha256"] = sha256_file(target)
                write_json(authorization_path, value)
                with self.assertRaises(GateBValidationError):
                    ReplayHarness.from_config(
                        config_path, repository_root=root
                    ).validate_inputs()

    def test_bound_artifact_swap_to_symlink_is_rejected_at_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            target = root / "local" / "gate_b" / "source_mapping.csv"
            outside = root / "outside-source-mapping.csv"
            outside.write_bytes(target.read_bytes())
            original_resolve = gate_b_module._resolve_bound_artifact
            swapped = False

            def resolve_then_swap(**kwargs):
                nonlocal swapped
                resolved = original_resolve(**kwargs)
                if kwargs["role"] == "SOURCE_MAPPING" and not swapped:
                    target.unlink()
                    target.symlink_to(outside)
                    swapped = True
                return resolved

            with patch.object(
                gate_b_module,
                "_resolve_bound_artifact",
                side_effect=resolve_then_swap,
            ):
                with self.assertRaises(GateBValidationError):
                    ReplayHarness.from_config(
                        config_path, repository_root=root
                    ).validate_inputs()
            self.assertTrue(swapped)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            target = root / "local" / "gate_b" / "source_mapping.csv"
            target_identity = (target.stat().st_dev, target.stat().st_ino)
            outside_link = root / "outside-source-mapping-hardlink.csv"
            original_read = os.read
            linked = False

            def hardlink_then_read(descriptor, size):
                nonlocal linked
                metadata = os.fstat(descriptor)
                if not linked and (metadata.st_dev, metadata.st_ino) == target_identity:
                    outside_link.hardlink_to(target)
                    linked = True
                return original_read(descriptor, size)

            with patch.object(
                gate_b_module.os,
                "read",
                side_effect=hardlink_then_read,
            ):
                with self.assertRaises(GateBValidationError):
                    ReplayHarness.from_config(
                        config_path, repository_root=root
                    ).validate_inputs()
            self.assertTrue(linked)

    def test_schema_and_runtime_share_approved_value_boundaries(self) -> None:
        schema = json.loads(
            (ROOT / "contracts/v0.2.0/gate-b-authorization.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, authorization_path, _, _ = make_gate_b_repository(root)
            config = ReplayConfig.load(config_path)
            paths = config.resolve_paths(root)
            manifest = load_manifest_control(paths["dataset_manifest"])
            value = json.loads(authorization_path.read_text(encoding="utf-8"))
            value["sampling"]["full_intake_count"] = 100001
            value["adjudication"]["minimum_reviewers"] = 2.0
            self.assertEqual(list(validator.iter_errors(value)), [])
            write_json(authorization_path, value)
            load_gate_b_authorization(
                authorization_path,
                repository_root=root,
                manifest=manifest,
                config=config,
                model_path=paths["model_path"],
                policy_path=paths["policy_path"],
            )

            for mutation in (
                "whitespace",
                "space_path",
                "long_path",
                "repeated_separator",
                "trailing_separator",
            ):
                candidate = json.loads(json.dumps(value))
                if mutation == "whitespace":
                    candidate["approved_purpose"] = "   "
                elif mutation == "space_path":
                    candidate["artifact_bindings"]["artifacts"][0][
                        "path"
                    ] = "local/gate_b/source mapping.csv"
                elif mutation == "long_path":
                    candidate["artifact_bindings"]["artifacts"][0]["path"] = (
                        "local/gate_b/" + "/".join(["a" * 100] * 6)
                    )
                elif mutation == "repeated_separator":
                    candidate["artifact_bindings"]["artifacts"][0][
                        "path"
                    ] = "local//gate_b/source_mapping.csv"
                else:
                    candidate["artifact_bindings"]["artifacts"][0][
                        "path"
                    ] = "local/gate_b/source_mapping.csv/"
                self.assertTrue(list(validator.iter_errors(candidate)))
                write_json(authorization_path, candidate)
                with self.assertRaises(GateBValidationError):
                    load_gate_b_authorization(
                        authorization_path,
                        repository_root=root,
                        manifest=manifest,
                        config=config,
                        model_path=paths["model_path"],
                        policy_path=paths["policy_path"],
                    )

    def test_sensitive_control_values_are_not_echoed(self) -> None:
        marker = "SENSITIVE-CANARY-DO-NOT-ECHO"
        for mutation in ("value", "top_level_key", "nested_key"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path, authorization_path, _, _ = make_gate_b_repository(root)
                value = json.loads(authorization_path.read_text(encoding="utf-8"))
                if mutation == "value":
                    value["status"] = "REVOKED"
                    value["approved_purpose"] = marker
                    value["population_scope"] = marker
                    value["approvals"][0]["approver_id"] = marker
                    value["approvals"][0]["approval_reference"] = marker
                elif mutation == "top_level_key":
                    value[marker] = True
                else:
                    value["controls"][marker] = True
                write_json(authorization_path, value)
                with self.assertRaises(GateBValidationError) as caught:
                    ReplayHarness.from_config(
                        config_path, repository_root=root
                    ).validate_inputs()
                self.assertNotIn(marker, str(caught.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, authorization_path, _, _ = make_gate_b_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            harness.validate_inputs()
            returned_summary = harness.gate_b_preflight_summary
            assert returned_summary is not None
            returned_summary["category_quarantine_rates"]["INJECTED"] = 1.0
            cached_summary = harness.gate_b_preflight_summary
            assert cached_summary is not None
            self.assertNotIn(
                "INJECTED",
                cached_summary["category_quarantine_rates"],
            )

            authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
            authorization["status"] = "REVOKED"
            write_json(authorization_path, authorization)
            with self.assertRaises(GateBValidationError):
                harness.validate_inputs()
            self.assertIsNone(harness.gate_b_preflight_summary)

    def test_missing_private_path_and_snapshot_faults_do_not_leak_paths(self) -> None:
        marker = "SENSITIVE-CANARY-PATH"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            config = json.loads(config_path.read_text(encoding="utf-8"))
            config["gate_b_authorization"] = f"local/gate_b/{marker}.json"
            write_json(config_path, config)
            with self.assertRaises(ReplayConfigurationError) as caught:
                ReplayHarness.from_config(
                    config_path, repository_root=root
                ).validate_inputs()
            self.assertNotIn(marker, str(caught.exception))
            self.assertNotIn(str(root), str(caught.exception))

        for bad_path in (
            "local//gate_b/authorization.json",
            "local/gate_b/authorization.json/",
        ):
            with (
                self.subTest(gate_b_authorization=bad_path),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path, _, _, _ = make_gate_b_repository(root)
                config = json.loads(config_path.read_text(encoding="utf-8"))
                config["gate_b_authorization"] = bad_path
                write_json(config_path, config)
                with self.assertRaises(ReplayConfigurationError):
                    ReplayHarness.from_config(config_path, repository_root=root)

        for field in ("dataset_manifest", "model_path", "policy_path"):
            for operation in ("validate", "run"):
                with (
                    self.subTest(field=field, operation=operation),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    root = Path(directory)
                    config_path, _, _, _ = make_gate_b_repository(root)
                    config = json.loads(config_path.read_text(encoding="utf-8"))
                    config[field] = f"private/{marker}-{field}.json"
                    write_json(config_path, config)
                    harness = ReplayHarness.from_config(
                        config_path, repository_root=root
                    )
                    with self.assertRaises(GateBValidationError) as caught:
                        if operation == "validate":
                            harness.validate_inputs()
                        else:
                            harness.run()
                    self.assertNotIn(marker, str(caught.exception))
                    self.assertNotIn(str(root), str(caught.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            schema_path = (
                root / "contracts" / "v0.2.0" / "replay-qualification.schema.json"
            )
            schema_path.unlink()
            with self.assertRaises(GateBValidationError) as caught:
                ReplayHarness.from_config(
                    config_path, repository_root=root
                ).validate_inputs()
            self.assertNotIn(str(root), str(caught.exception))
            self.assertNotIn("replay-qualification.schema.json", str(caught.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            original_write_bytes = HistoricalOutputGuard.write_bytes

            def failing_write_bytes(instance, relative_path, content, **kwargs):
                if Path(relative_path).name == "gate_b_source_mapping.artifact":
                    raise HistoricalOutputError(f"raw {marker} should not escape")
                return original_write_bytes(
                    instance,
                    relative_path,
                    content,
                    **kwargs,
                )

            with patch.object(
                HistoricalOutputGuard,
                "write_bytes",
                new=failing_write_bytes,
            ):
                with self.assertRaises(ReplaySafetyViolation) as caught:
                    harness.run()
            self.assertNotIn(marker, str(caught.exception))
            self.assertNotIn(str(root), str(caught.exception))

    def test_nonhistorical_misuse_and_public_output_paths_fail_before_sources(
        self,
    ) -> None:
        for mutation in ("nonhistorical", "public_output", "noncanonical_output"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path, _, cases_path, adjudications_path = make_gate_b_repository(
                    root
                )
                if mutation == "nonhistorical":
                    manifest_path = root / "data" / "historical" / "manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["data_origin"] = "SYNTHETIC_FIXTURE"
                    manifest["historical_case_count"] = 0
                    write_json(manifest_path, manifest)
                elif mutation == "public_output":
                    config = json.loads(config_path.read_text(encoding="utf-8"))
                    config["output_dir"] = "docs/pilot-output"
                    write_json(config_path, config)
                else:
                    config = json.loads(config_path.read_text(encoding="utf-8"))
                    config["output_dir"] = "outputs//replay/gate-b-test"
                    write_json(config_path, config)
                for operation in ("validate", "run"):
                    with self.subTest(mutation=mutation, operation=operation):
                        harness = ReplayHarness.from_config(
                            config_path, repository_root=root
                        )
                        with prohibit_payload_access(
                            cases_path, adjudications_path
                        ) as accesses:
                            with self.assertRaises(GateBValidationError):
                                if operation == "validate":
                                    harness.validate_inputs()
                                else:
                                    harness.run()
                        self.assertEqual(accesses, [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            original_preflight = harness._preflight_control_documents
            outside = root / "outside-output"
            outside.mkdir(mode=0o700)

            def preflight_then_substitute_output(paths):
                result = original_preflight(paths)
                output_dir = paths["output_dir"]
                output_dir.parent.mkdir(parents=True, exist_ok=True)
                output_dir.symlink_to(outside, target_is_directory=True)
                return result

            with patch.object(
                harness,
                "_preflight_control_documents",
                side_effect=preflight_then_substitute_output,
            ):
                with self.assertRaises((GateBValidationError, ReplaySafetyViolation)):
                    harness.run()
            self.assertEqual(list(outside.iterdir()), [])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            original_write_jsonl = HistoricalOutputGuard.write_jsonl
            attacker_target = root / "attacker-selected-output"
            attacker_target.mkdir(mode=0o700)
            relocated = root / "relocated-replay"
            swapped = False

            def relocate_before_payload_write(instance, relative_path, rows, **kwargs):
                nonlocal swapped
                if relative_path == "normalized_cases.jsonl" and not swapped:
                    replay_root = root / "outputs" / "replay"
                    replay_root.rename(relocated)
                    replay_root.symlink_to(attacker_target, target_is_directory=True)
                    swapped = True
                return original_write_jsonl(
                    instance,
                    relative_path,
                    rows,
                    **kwargs,
                )

            with patch.object(
                HistoricalOutputGuard,
                "write_jsonl",
                new=relocate_before_payload_write,
            ):
                with self.assertRaises(ReplaySafetyViolation):
                    harness.run()
            self.assertTrue(swapped)
            self.assertEqual(list(attacker_target.iterdir()), [])
            self.assertFalse(
                (relocated / "gate-b-test" / "normalized_cases.jsonl").exists()
            )

    def test_control_json_nesting_and_bound_artifact_size_fail_safely(self) -> None:
        for target_name in ("authorization", "manifest"):
            with (
                self.subTest(target=target_name),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path, authorization_path, _, _ = make_gate_b_repository(root)
                target = (
                    authorization_path
                    if target_name == "authorization"
                    else root / "data" / "historical" / "manifest.json"
                )
                raw = target.read_text(encoding="utf-8").rstrip()
                raw = raw[:-1] + ',"extra":' + "[" * 129 + "0" + "]" * 129 + "}\n"
                target.write_text(raw, encoding="utf-8")
                with self.assertRaises(GateBValidationError) as caught:
                    ReplayHarness.from_config(
                        config_path, repository_root=root
                    ).validate_inputs()
                self.assertIn("nesting limit", str(caught.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, authorization_path, _, _ = make_gate_b_repository(root)
            authorization_path.write_bytes(b" " * (MAX_CONTROL_DOCUMENT_BYTES + 1))
            with self.assertRaises(GateBValidationError) as caught:
                ReplayHarness.from_config(
                    config_path, repository_root=root
                ).validate_inputs()
            self.assertIn("size limit", str(caught.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            model_path = root / "outputs" / "baseline" / "model.json"
            policy_path = root / "config" / "policy.json"
            exact_limit = max(model_path.stat().st_size, policy_path.stat().st_size)
            with patch.object(
                gate_b_module,
                "MAX_GATE_B_MODEL_POLICY_BYTES",
                exact_limit,
            ):
                ReplayHarness.from_config(
                    config_path, repository_root=root
                ).validate_inputs()
            with patch.object(
                gate_b_module,
                "MAX_GATE_B_MODEL_POLICY_BYTES",
                exact_limit - 1,
            ):
                with self.assertRaises(GateBValidationError) as caught:
                    ReplayHarness.from_config(
                        config_path, repository_root=root
                    ).validate_inputs()
                self.assertIn("size limit", str(caught.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, authorization_path, _, _ = make_gate_b_repository(root)
            mapping_path = root / "local" / "gate_b" / "source_mapping.csv"
            mapping_path.write_bytes(b"x" * MAX_GATE_B_ARTIFACT_BYTES)
            value = json.loads(authorization_path.read_text(encoding="utf-8"))
            value["artifact_bindings"]["artifacts"][0]["sha256"] = sha256_file(
                mapping_path
            )
            write_json(authorization_path, value)
            ReplayHarness.from_config(
                config_path, repository_root=root
            ).validate_inputs()

            mapping_path.write_bytes(b"x" * (MAX_GATE_B_ARTIFACT_BYTES + 1))
            value["artifact_bindings"]["artifacts"][0]["sha256"] = sha256_file(
                mapping_path
            )
            write_json(authorization_path, value)
            with self.assertRaises(GateBValidationError) as caught:
                ReplayHarness.from_config(
                    config_path, repository_root=root
                ).validate_inputs()
            self.assertIn("size limit", str(caught.exception))

    def test_manifest_mutation_after_preflight_fails_before_source_access(self) -> None:
        for operation in ("validate", "run"):
            with (
                self.subTest(operation=operation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path, _, cases_path, adjudications_path = make_gate_b_repository(
                    root
                )
                harness = ReplayHarness.from_config(config_path, repository_root=root)
                original_preflight = harness._preflight_control_documents

                def preflight_then_mutate(paths):
                    result = original_preflight(paths)
                    manifest_path = paths["dataset_manifest"]
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    manifest["created_at"] = "2026-08-14T12:34:56Z"
                    write_json(manifest_path, manifest)
                    return result

                with (
                    patch.object(
                        harness,
                        "_preflight_control_documents",
                        side_effect=preflight_then_mutate,
                    ),
                    prohibit_payload_access(cases_path, adjudications_path) as accesses,
                ):
                    with self.assertRaises(GateBValidationError):
                        if operation == "validate":
                            harness.validate_inputs()
                        else:
                            harness.run()
                self.assertEqual(accesses, [])

    def test_historical_integrity_errors_do_not_publish_paths_or_digests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, cases_path, _ = make_gate_b_repository(root)
            manifest_path = root / "data" / "historical" / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            declared_digest = next(
                row["sha256"] for row in manifest["files"] if row["role"] == "cases"
            )
            cases_path.write_text(
                cases_path.read_text(encoding="utf-8") + "SENSITIVE-CANARY-ROW\n",
                encoding="utf-8",
            )
            actual_digest = sha256_file(cases_path)
            with self.assertRaises(GateBValidationError) as caught:
                ReplayHarness.from_config(
                    config_path, repository_root=root
                ).validate_inputs()
            message = str(caught.exception)
            self.assertNotIn(str(root), message)
            self.assertNotIn("cases.jsonl", message)
            self.assertNotIn(declared_digest, message)
            self.assertNotIn(actual_digest, message)

        source_marker = "SENSITIVE-RAW-SOURCE-CANARY"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, cases_path, _ = make_gate_b_repository(root)
            original_sha256 = replay_contracts.sha256_file

            def failing_source_digest(path):
                if Path(path).resolve() == cases_path.resolve():
                    raise OSError(source_marker)
                return original_sha256(path)

            with patch.object(
                replay_contracts,
                "sha256_file",
                side_effect=failing_source_digest,
            ):
                with self.assertRaises(GateBValidationError) as caught:
                    ReplayHarness.from_config(
                        config_path, repository_root=root
                    ).validate_inputs()
            self.assertNotIn(source_marker, str(caught.exception))
            self.assertNotIn(str(root), str(caught.exception))

        label_marker = "SENSITIVE-LABEL-CANARY"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, authorization_path, _, adjudications_path = (
                make_gate_b_repository(root)
            )
            rows = [
                json.loads(line)
                for line in adjudications_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            rows[0]["case_id"] = label_marker
            adjudications_path.write_text(
                "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                encoding="utf-8",
            )
            manifest_path = root / "data" / "historical" / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for entry in manifest["files"]:
                if entry["role"] == "adjudications":
                    entry["sha256"] = sha256_file(adjudications_path)
            write_json(manifest_path, manifest)
            authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
            authorization["dataset_manifest_sha256"] = sha256_file(manifest_path)
            write_json(authorization_path, authorization)
            with self.assertRaises(GateBValidationError) as caught:
                ReplayHarness.from_config(config_path, repository_root=root).run()
            self.assertNotIn(label_marker, str(caught.exception))
            self.assertNotIn(str(root), str(caught.exception))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, authorization_path, _, adjudications_path = (
                make_gate_b_repository(root)
            )
            lines = adjudications_path.read_text(encoding="utf-8").splitlines()
            lines[0] = lines[0][:-1] + ',"adjudicated_disposition":"ESCALATE_HUMAN"}'
            adjudications_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            manifest_path = root / "data" / "historical" / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for entry in manifest["files"]:
                if entry["role"] == "adjudications":
                    entry["sha256"] = sha256_file(adjudications_path)
            write_json(manifest_path, manifest)
            authorization = json.loads(authorization_path.read_text(encoding="utf-8"))
            authorization["dataset_manifest_sha256"] = sha256_file(manifest_path)
            write_json(authorization_path, authorization)
            with self.assertRaises(GateBValidationError):
                ReplayHarness.from_config(config_path, repository_root=root).run()
            self.assertFalse(
                (
                    root
                    / "outputs"
                    / "replay"
                    / "gate-b-test"
                    / "replay_run_manifest.json"
                ).exists()
            )

    def test_threshold_decimal_boundary_and_window_scope(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, authorization_path, _, _ = make_gate_b_repository(root)
            config = ReplayConfig.load(config_path)
            paths = config.resolve_paths(root)
            manifest = load_manifest_control(paths["dataset_manifest"])
            authorization = load_gate_b_authorization(
                authorization_path,
                repository_root=root,
                manifest=manifest,
                config=config,
                model_path=paths["model_path"],
                policy_path=paths["policy_path"],
            )
            authorization = replace(
                authorization,
                full_intake_count=4,
                sample_count=4,
                max_overall_quarantine_rate=Decimal("0.25"),
                max_category_quarantine_rates=(("SYNTAX", Decimal("0.25")),),
            )
            rows = [
                {"status": "ACCEPTED", "error_category": ""},
                {"status": "ACCEPTED", "error_category": ""},
                {"status": "ACCEPTED", "error_category": ""},
                {"status": "QUARANTINED", "error_category": "SYNTAX"},
            ]
            summary = evaluate_qualification_stop_conditions(authorization, rows)
            self.assertEqual(summary["overall_quarantine_rate"], 0.25)
            too_strict = replace(
                authorization,
                max_overall_quarantine_rate=Decimal("0.249"),
            )
            with self.assertRaises(GateBStopConditionViolation):
                evaluate_qualification_stop_conditions(too_strict, rows)
            unlisted = replace(
                authorization,
                max_category_quarantine_rates=(("STRUCTURE", Decimal("1")),),
            )
            with self.assertRaises(GateBStopConditionViolation):
                evaluate_qualification_stop_conditions(unlisted, rows)

            validate_accepted_case_window(
                authorization, [{"opened_at": "2026-08-01T00:00:00Z"}]
            )
            validate_gate_b_current(authorization, now=authorization.valid_from)
            with self.assertRaises(GateBValidationError):
                validate_gate_b_current(authorization, now=authorization.expires_at)
            with self.assertRaises(GateBStopConditionViolation):
                validate_accepted_case_window(
                    authorization, [{"opened_at": "2026-08-02T00:00:00Z"}]
                )


class GateBIntegrationTests(unittest.TestCase):
    def test_valid_test_only_package_runs_read_only_and_binds_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            manifest, batch = harness.validate_inputs()
            self.assertEqual(manifest.data_origin, "HISTORICAL_DEIDENTIFIED")
            self.assertEqual(len(batch.records), 3)
            self.assertIsNotNone(harness.gate_b_preflight_summary)

            built_in_runner = harness._default_record_engine_runner()

            def label_separation_runner(**kwargs):
                self.assertEqual(
                    set(kwargs),
                    {
                        "cases",
                        "model_bytes",
                        "policy_bytes",
                        "execution_mode",
                    },
                )
                self.assertIsInstance(kwargs["cases"], list)
                self.assertIsInstance(kwargs["model_bytes"], bytes)
                self.assertIsInstance(kwargs["policy_bytes"], bytes)
                self.assertFalse(
                    (
                        root
                        / "outputs"
                        / "replay"
                        / "gate-b-test"
                        / "input_snapshot"
                        / "adjudications.jsonl"
                    ).exists()
                )
                return built_in_runner(**kwargs)

            with patch.object(
                harness,
                "_default_record_engine_runner",
                return_value=label_separation_runner,
            ):
                result = harness.run()
            self.assertIsNotNone(result.gate_b_preflight)
            assurance = result.metrics["read_only_assurance"]
            self.assertEqual(assurance["authorization_tokens_issued"], 0)
            self.assertEqual(assurance["broker_invocations"], 0)
            self.assertEqual(assurance["operational_effects"], 0)
            self.assertEqual(assurance["action_results"], 0)
            run_manifest = json.loads(
                result.run_manifest_path.read_text(encoding="utf-8")
            )
            self.assertIn("gate_b_preflight", run_manifest)
            for role in (
                "gate_b_authorization",
                "gate_b_source_mapping",
                "gate_b_adjudication_protocol",
                "gate_b_pilot_protocol",
            ):
                self.assertIn(role, run_manifest["inputs"])
            serialized = json.dumps(run_manifest, sort_keys=True)
            self.assertNotIn("synthetic-test-data_owner", serialized)
            self.assertNotIn("local/gate_b/source_mapping.csv", serialized)
            self.assertEqual(result.output_dir.stat().st_mode & 0o077, 0)
            snapshot_dir = result.output_dir / "input_snapshot"
            self.assertEqual(snapshot_dir.stat().st_mode & 0o077, 0)
            for path in snapshot_dir.iterdir():
                self.assertEqual(path.stat().st_mode & 0o077, 0)

    def test_post_qualification_scope_gates_stop_before_engine(self) -> None:
        for mutation in ("quarantine_threshold", "case_window"):
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                config_path, authorization_path, cases_path, _ = make_gate_b_repository(
                    root
                )
                if mutation == "quarantine_threshold":
                    rows = [
                        json.loads(line) for line in cases_path.read_text().splitlines()
                    ]
                    rows[0].pop("subject_id")
                    cases_path.write_text(
                        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
                        encoding="utf-8",
                    )
                    manifest_path = root / "data" / "historical" / "manifest.json"
                    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                    for entry in manifest["files"]:
                        if entry["role"] == "cases":
                            entry["sha256"] = sha256_file(cases_path)
                    write_json(manifest_path, manifest)
                    authorization = json.loads(
                        authorization_path.read_text(encoding="utf-8")
                    )
                    authorization["dataset_manifest_sha256"] = sha256_file(
                        manifest_path
                    )
                    write_json(authorization_path, authorization)
                else:
                    authorization = json.loads(
                        authorization_path.read_text(encoding="utf-8")
                    )
                    authorization["window_start"] = "2026-08-01T12:30:00Z"
                    authorization["sampling"][
                        "temporal_holdout_start"
                    ] = "2026-08-01T12:30:00Z"
                    write_json(authorization_path, authorization)

                engine_called = False

                def forbidden_runner(**kwargs):
                    nonlocal engine_called
                    engine_called = True
                    raise AssertionError(
                        "Engine must not run after a Gate B stop condition."
                    )

                harness = ReplayHarness.from_config(config_path, repository_root=root)
                with patch.object(
                    harness,
                    "_default_record_engine_runner",
                    return_value=forbidden_runner,
                ):
                    with self.assertRaises(GateBStopConditionViolation):
                        harness.run()
                self.assertFalse(engine_called)

    def test_control_bytes_are_frozen_before_payload_processing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            mapping_path = root / "local" / "gate_b" / "source_mapping.csv"
            original_bytes = mapping_path.read_bytes()
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            original_preflight = harness._preflight_control_documents

            def preflight_then_mutate(paths):
                result = original_preflight(paths)
                mapping_path.write_text("changed,after-preflight\n", encoding="utf-8")
                return result

            with patch.object(
                harness,
                "_preflight_control_documents",
                side_effect=preflight_then_mutate,
            ):
                result = harness.run()
            frozen_path = (
                result.output_dir / "input_snapshot" / "gate_b_source_mapping.artifact"
            )
            self.assertEqual(frozen_path.read_bytes(), original_bytes)
            self.assertNotEqual(mapping_path.read_bytes(), original_bytes)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            config_identity = (config_path.stat().st_dev, config_path.stat().st_ino)
            outside_link = root / "outside-config-hardlink.json"
            original_read = os.read
            linked = False
            engine_called = False

            def hardlink_then_read(descriptor, size):
                nonlocal linked
                metadata = os.fstat(descriptor)
                if not linked and (metadata.st_dev, metadata.st_ino) == config_identity:
                    outside_link.hardlink_to(config_path)
                    linked = True
                return original_read(descriptor, size)

            def forbidden_runner(**kwargs):
                nonlocal engine_called
                engine_called = True
                raise AssertionError(
                    "Engine must not run after a control custody change."
                )

            harness = ReplayHarness.from_config(config_path, repository_root=root)
            with (
                patch.object(
                    replay_harness_module.os,
                    "read",
                    side_effect=hardlink_then_read,
                ),
                patch.object(
                    harness,
                    "_default_record_engine_runner",
                    return_value=forbidden_runner,
                ),
            ):
                with self.assertRaises(ReplaySafetyViolation):
                    harness.run()
            self.assertTrue(linked)
            self.assertTrue(outside_link.exists())
            self.assertFalse(engine_called)

    def test_runner_tampering_with_gate_b_snapshot_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            built_in_runner = harness._default_record_engine_runner()

            def tampering_runner(**kwargs):
                authorization_path = (
                    root
                    / "outputs"
                    / "replay"
                    / "gate-b-test"
                    / "input_snapshot"
                    / "gate_b_authorization.json"
                )
                decisions, audit_rows = built_in_runner(**kwargs)
                authorization = json.loads(
                    authorization_path.read_text(encoding="utf-8")
                )
                authorization["status"] = "REVOKED"
                write_json(authorization_path, authorization)
                return decisions, audit_rows

            with patch.object(
                harness,
                "_default_record_engine_runner",
                return_value=tampering_runner,
            ):
                with self.assertRaises(ReplaySafetyViolation):
                    harness.run()

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_path, _, _, _ = make_gate_b_repository(root)
            harness = ReplayHarness.from_config(config_path, repository_root=root)
            built_in_runner = harness._default_record_engine_runner()
            validity_checks = 0
            engine_called = False

            def staged_validity(authorization, **kwargs):
                nonlocal validity_checks
                validity_checks += 1
                if validity_checks >= 3:
                    raise GateBValidationError(
                        "Gate B authorization is not currently valid."
                    )

            def observed_runner(**kwargs):
                nonlocal engine_called
                engine_called = True
                return built_in_runner(**kwargs)

            with (
                patch.object(
                    replay_harness_module,
                    "validate_gate_b_current",
                    side_effect=staged_validity,
                ),
                patch.object(
                    harness,
                    "_default_record_engine_runner",
                    return_value=observed_runner,
                ),
            ):
                with self.assertRaises(GateBValidationError):
                    harness.run()
            self.assertTrue(engine_called)
            self.assertEqual(validity_checks, 3)
            self.assertFalse(
                (
                    root
                    / "outputs"
                    / "replay"
                    / "gate-b-test"
                    / "replay_run_manifest.json"
                ).exists()
            )


if __name__ == "__main__":
    unittest.main()
