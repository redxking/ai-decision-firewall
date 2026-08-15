from __future__ import annotations

import hashlib
import io
import json
import os
import stat
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator

from adf_poc.audit import AuditLogger
from adf_poc.execution import ExecutionMode
from adf_poc.utils import read_jsonl, sha256_json, write_json, write_jsonl

from .adapters import AdapterCaseBatch, get_adapter
from .contracts import (
    ALLOWED_DISPOSITIONS,
    ContractValidationError,
    MAX_DECLARED_FILE_BYTES,
    MAX_JSONL_LINE_BYTES,
    ManifestFile,
    ReplayConfig,
    ReplayConfigurationError,
    ReplayManifest,
    count_jsonl_records,
    load_jsonl_bytes,
    load_and_validate_manifest,
    sha256_file,
    validate_adjudication_records,
)
from .gate_b import (
    GATE_B_SNAPSHOT_ROLE_BY_ARTIFACT,
    GateBAuthorization,
    GateBValidationError,
    ManifestControl,
    evaluate_qualification_stop_conditions,
    load_gate_b_authorization,
    load_manifest_control,
    validate_accepted_case_window,
    validate_gate_b_current,
)
from .metrics import build_comparisons, compute_replay_metrics
from .normalizer import normalize_cases_with_diagnostics
from .qualification import (
    QUALIFICATION_TAXONOMY_VERSION,
    qualify_case_bytes,
    qualify_case_file,
)
from .secure_output import HistoricalOutputError, HistoricalOutputGuard


class ReplaySafetyViolation(RuntimeError):
    """Raised when a replay/shadow run attempts or reports an operational effect."""


EngineRunner = Callable[..., list[dict[str, Any]]]
RecordEngineRunner = Callable[
    ...,
    tuple[list[dict[str, Any]], list[dict[str, Any]]],
]


@dataclass(frozen=True, slots=True)
class ReplayRunResult:
    dataset_id: str
    data_origin: str
    historical_case_count: int
    execution_mode: str
    output_dir: Path
    normalized_cases_path: Path
    normalization_diagnostics_path: Path
    raw_decisions_path: Path
    deterministic_decisions_path: Path
    comparisons_path: Path
    metrics_path: Path
    audit_path: Path
    run_manifest_path: Path
    metrics: dict[str, Any]
    qualification_accounting_path: Path | None = None
    rejections_path: Path | None = None
    gate_b_preflight: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class RunInputSnapshots:
    paths: dict[str, Path]
    sha256: dict[str, str]
    record_counts: dict[str, int]


@dataclass(frozen=True, slots=True, repr=False)
class FrozenManifestInput:
    role: str
    content: bytes
    sha256: str
    record_count: int
    device: int
    inode: int


class ReplayHarness:
    def __init__(
        self,
        *,
        repository_root: str | Path,
        config: ReplayConfig,
    ) -> None:
        self.repository_root = Path(repository_root).resolve()
        self.config = config
        self._adapter = get_adapter(config.contract_adapter)
        self._gate_b_preflight_summary: dict[str, Any] | None = None

    @classmethod
    def from_config(
        cls,
        config_path: str | Path,
        *,
        repository_root: str | Path,
    ) -> "ReplayHarness":
        return cls(
            repository_root=repository_root,
            config=ReplayConfig.load(config_path),
        )

    @property
    def gate_b_preflight_summary(self) -> dict[str, Any] | None:
        if self._gate_b_preflight_summary is None:
            return None
        return deepcopy(self._gate_b_preflight_summary)

    def validate_inputs(self) -> tuple[ReplayManifest, AdapterCaseBatch]:
        self._gate_b_preflight_summary = None
        paths, manifest_control, gate_b = self._resolve_and_preflight_controls()
        try:
            return self._validate_inputs_after_preflight(
                paths=paths,
                manifest_control=manifest_control,
                gate_b=gate_b,
            )
        except GateBValidationError:
            raise
        except Exception:
            if gate_b is not None:
                raise GateBValidationError(
                    "Historical replay input validation failed."
                ) from None
            raise

    def _validate_inputs_after_preflight(
        self,
        *,
        paths: dict[str, Path],
        manifest_control: ManifestControl,
        gate_b: GateBAuthorization | None,
    ) -> tuple[ReplayManifest, AdapterCaseBatch]:
        if gate_b is not None:
            validate_gate_b_current(gate_b)
        try:
            manifest = self._load_manifest(
                paths["dataset_manifest"],
                expected_source_sha256=manifest_control.source_sha256,
                defer_adjudication_content_validation=gate_b is not None,
            )
        except Exception:
            if gate_b is not None:
                raise GateBValidationError(
                    "Historical manifest or source integrity validation failed."
                ) from None
            raise
        if gate_b is not None:
            self._validate_historical_manifest_file_identities(manifest)
        cases_entry = manifest.file_for_role("cases")
        assert cases_entry is not None
        case_batch = self._load_cases(
            cases_entry,
            dataset_id=manifest.dataset_id,
        )
        if self.config.record_failure_policy == "QUARANTINE_RECORD":
            self._validate_qualification_batch(
                case_batch,
                cases_entry=cases_entry,
                dataset_id=manifest.dataset_id,
            )
            if not case_batch.records:
                raise ReplaySafetyViolation(
                    "Record qualification accepted no cases; refusing an empty replay."
                )
        if gate_b is not None:
            validate_gate_b_current(gate_b)
            self._gate_b_preflight_summary = deepcopy(
                self._evaluate_gate_b_scope(gate_b, case_batch)
            )
        else:
            self._gate_b_preflight_summary = None
        return manifest, case_batch

    def _resolve_and_preflight_controls(
        self,
    ) -> tuple[dict[str, Path], ManifestControl, GateBAuthorization | None]:
        governed_historical = self.config.gate_b_authorization is not None
        try:
            paths = self.config.resolve_paths(self.repository_root)
            manifest_control, gate_b = self._preflight_control_documents(paths)
            return paths, manifest_control, gate_b
        except (ReplayConfigurationError, GateBValidationError):
            raise
        except Exception:
            if governed_historical:
                raise GateBValidationError(
                    "Historical replay control preflight failed."
                ) from None
            raise

    @staticmethod
    def _validate_historical_manifest_file_identities(
        manifest: ReplayManifest,
    ) -> None:
        """Reject linked or aliased payload files before accepted cases are used."""

        identities: set[tuple[int, int]] = set()
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            for entry in manifest.files:
                descriptor = os.open(entry.resolved_path, flags)
                try:
                    metadata = os.fstat(descriptor)
                finally:
                    os.close(descriptor)
                identity = (metadata.st_dev, metadata.st_ino)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_nlink != 1
                    or identity in identities
                ):
                    raise GateBValidationError(
                        "Historical cases and adjudications require distinct regular source files."
                    )
                identities.add(identity)
        except GateBValidationError:
            raise
        except OSError:
            raise GateBValidationError(
                "Historical manifest or source integrity validation failed."
            ) from None

    def _load_manifest(
        self,
        manifest_path: Path,
        *,
        expected_source_sha256: str | None = None,
        defer_adjudication_content_validation: bool = False,
    ) -> ReplayManifest:
        manifest = load_and_validate_manifest(
            manifest_path,
            expected_source_sha256=expected_source_sha256,
            defer_adjudication_content_validation=defer_adjudication_content_validation,
        )
        if manifest.intended_mode != self.config.execution_mode:
            raise ContractValidationError(
                "Configuration execution_mode does not match the dataset manifest intended_mode."
            )
        return manifest

    def _preflight_control_documents(
        self, paths: dict[str, Path]
    ) -> tuple[ManifestControl, GateBAuthorization | None]:
        manifest_control = load_manifest_control(paths["dataset_manifest"])
        if manifest_control.intended_mode != self.config.execution_mode:
            raise ContractValidationError(
                "Configuration execution_mode does not match the dataset manifest intended_mode."
            )
        if manifest_control.data_origin == "HISTORICAL_DEIDENTIFIED":
            self._validate_historical_output_boundary(paths["output_dir"])
            authorization_path = paths.get("gate_b_authorization")
            if authorization_path is None or self.config.gate_b_authorization is None:
                raise GateBValidationError(
                    "Historical input requires an approved Gate B authorization package."
                )
            gate_b = load_gate_b_authorization(
                authorization_path,
                repository_root=self.repository_root,
                manifest=manifest_control,
                config=self.config,
                model_path=paths["model_path"],
                policy_path=paths["policy_path"],
            )
            return manifest_control, gate_b
        if self.config.gate_b_authorization is not None:
            raise GateBValidationError(
                "Gate B authorization cannot be attached to a non-historical input."
            )
        return manifest_control, None

    def _validate_historical_output_boundary(self, output_dir: Path) -> None:
        configured = self.config.output_dir
        configured_path = Path(configured)
        if (
            configured != configured_path.as_posix()
            or configured_path.parts[:2] != ("outputs", "replay")
            or len(configured_path.parts) != 3
        ):
            raise GateBValidationError(
                "Historical replay output must use a canonical run-specific outputs/replay path."
            )
        allowed_root = (self.repository_root / "outputs" / "replay").resolve()
        resolved_output = output_dir.resolve()
        try:
            relative = resolved_output.relative_to(allowed_root)
        except ValueError:
            raise GateBValidationError(
                "Historical replay output must use the ignored outputs/replay root."
            ) from None
        if not relative.parts:
            raise GateBValidationError(
                "Historical replay output must be a run-specific directory."
            )
        current = self.repository_root
        for part in Path(self.config.output_dir).parts:
            current = current / part
            if current.is_symlink():
                raise GateBValidationError(
                    "Historical replay output cannot use symlink components."
                )

    @staticmethod
    def _assert_historical_output_identity(
        output_dir: Path,
        expected: None,
    ) -> None:
        """Compatibility no-op for the nonhistorical path-only output flow."""

        del output_dir
        if expected is not None:
            raise ReplaySafetyViolation(
                "Historical output must use the descriptor-bound run path."
            )

    @staticmethod
    def _evaluate_gate_b_scope(
        authorization: GateBAuthorization,
        case_batch: AdapterCaseBatch,
    ) -> dict[str, Any]:
        validate_accepted_case_window(authorization, case_batch.records)
        return evaluate_qualification_stop_conditions(
            authorization,
            case_batch.qualification_records,
        )

    def _load_cases(
        self,
        cases_entry: ManifestFile,
        *,
        dataset_id: str,
    ) -> AdapterCaseBatch:
        if cases_entry.adapter != self.config.contract_adapter:
            raise ContractValidationError(
                "Case-file adapter does not match the configured contract adapter."
            )
        return self._adapter.load_cases(
            cases_entry,
            record_failure_policy=self.config.record_failure_policy,
            dataset_id=dataset_id,
        )

    def run(self) -> ReplayRunResult:
        self._gate_b_preflight_summary = None
        paths, manifest_control, original_gate_b = (
            self._resolve_and_preflight_controls()
        )
        if original_gate_b is not None:
            return self._run_historical(
                paths=paths,
                manifest_control=manifest_control,
                gate_b=original_gate_b,
            )
        output_dir = paths["output_dir"]
        output_identity = None
        if output_dir.exists():
            if not output_dir.is_dir():
                raise ReplaySafetyViolation(
                    "Configured output_dir exists and is not a directory."
                )
            if any(output_dir.iterdir()):
                raise ReplaySafetyViolation(
                    "Configured output_dir is non-empty; refusing to overwrite prior replay evidence."
                )
        output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._assert_historical_output_identity(output_dir, output_identity)
        input_snapshots = self._snapshot_control_inputs(
            output_dir=output_dir,
            manifest_control=manifest_control,
            paths=paths,
            gate_b=original_gate_b,
        )
        self._assert_historical_output_identity(output_dir, output_identity)
        gate_b = self._revalidate_gate_b_snapshot(
            input_snapshots,
            expected=original_gate_b,
        )
        try:
            manifest = self._load_manifest(
                paths["dataset_manifest"],
                expected_source_sha256=manifest_control.source_sha256,
                defer_adjudication_content_validation=gate_b is not None,
            )
        except Exception:
            if gate_b is not None:
                raise GateBValidationError(
                    "Historical manifest or source integrity validation failed."
                ) from None
            raise
        input_snapshots = self._snapshot_manifest_roles(
            snapshots=input_snapshots,
            manifest=manifest,
            roles={"cases"},
            owner_only=gate_b is not None,
        )
        self._assert_historical_output_identity(output_dir, output_identity)
        cases_entry = manifest.file_for_role("cases")
        assert cases_entry is not None
        adjudication_entry = manifest.file_for_role("adjudications", required=False)
        frozen_adjudications: FrozenManifestInput | None = None
        if adjudication_entry is not None:
            if adjudication_entry.resolved_path == cases_entry.resolved_path:
                raise ReplaySafetyViolation(
                    "Cases and adjudications must be stored in physically separate files."
                )
            frozen_adjudications = self._freeze_manifest_input(adjudication_entry)
        snapshotted_cases_entry = replace(
            cases_entry, resolved_path=input_snapshots.paths["cases"]
        )
        case_batch = self._load_cases(
            snapshotted_cases_entry,
            dataset_id=manifest.dataset_id,
        )
        qualification_enabled = self.config.record_failure_policy == "QUARANTINE_RECORD"
        if qualification_enabled:
            self._validate_qualification_batch(
                case_batch,
                cases_entry=snapshotted_cases_entry,
                dataset_id=manifest.dataset_id,
            )
            if not case_batch.records:
                raise ReplaySafetyViolation(
                    "Record qualification accepted no cases; refusing an empty replay."
                )
        gate_b_summary: dict[str, Any] | None = None
        if gate_b is not None:
            gate_b_summary = self._evaluate_gate_b_scope(gate_b, case_batch)
            self._gate_b_preflight_summary = deepcopy(gate_b_summary)
        else:
            self._gate_b_preflight_summary = None
        normalized_cases, normalization_diagnostics = normalize_cases_with_diagnostics(
            case_batch.records, mapping_warnings=case_batch.mapping_warnings
        )
        if qualification_enabled:
            normalization_diagnostics["record_qualification"] = {
                "failure_policy": self.config.record_failure_policy,
                "input_records": len(case_batch.qualification_records),
                "accepted_records": len(case_batch.records),
                "rejected_records": len(case_batch.rejection_records),
            }
        expected_case_ids = {row["case_id"] for row in normalized_cases}

        normalized_path = output_dir / "normalized_cases.jsonl"
        diagnostics_path = output_dir / "normalization_diagnostics.json"
        raw_decisions_path = output_dir / "engine_decisions.jsonl"
        deterministic_path = output_dir / "replay_decisions.jsonl"
        comparisons_path = output_dir / "adjudication_comparison.jsonl"
        metrics_path = output_dir / "replay_metrics.json"
        audit_path = output_dir / "replay_audit.jsonl"
        run_manifest_path = output_dir / "replay_run_manifest.json"
        qualification_path = output_dir / "qualification_accounting.jsonl"
        rejections_path = output_dir / "rejections.jsonl"
        self._assert_historical_output_identity(output_dir, output_identity)
        write_jsonl(normalized_path, normalized_cases)
        write_json(diagnostics_path, normalization_diagnostics)
        self._assert_historical_output_identity(output_dir, output_identity)

        execution_mode = ExecutionMode[self.config.execution_mode]
        self._verify_snapshot_integrity(input_snapshots)
        self._revalidate_gate_b_snapshot(input_snapshots, expected=gate_b)
        self._assert_historical_output_identity(output_dir, output_identity)
        runner = self._default_engine_runner()
        runner(
            cases_path=normalized_path,
            model_path=input_snapshots.paths["model"],
            policy_path=input_snapshots.paths["policy"],
            decisions_path=raw_decisions_path,
            audit_path=audit_path,
            execution_mode=execution_mode,
        )
        self._assert_historical_output_identity(output_dir, output_identity)
        self._verify_snapshot_integrity(input_snapshots)
        self._revalidate_gate_b_snapshot(input_snapshots, expected=gate_b)
        if not raw_decisions_path.exists():
            raise ReplaySafetyViolation(
                "The decision engine did not produce its declared output."
            )
        decisions = read_jsonl(raw_decisions_path)
        self._validate_read_only_decisions(
            decisions,
            expected_case_ids=expected_case_ids,
            execution_mode=execution_mode,
        )
        deterministic_decisions = [
            self._deterministic_projection(row)
            for row in sorted(decisions, key=lambda value: value["case_id"])
        ]
        self._assert_historical_output_identity(output_dir, output_identity)
        write_jsonl(deterministic_path, deterministic_decisions)
        self._assert_historical_output_identity(output_dir, output_identity)
        audit_assurance = self._validate_audit_assurance(
            audit_path,
            decisions=decisions,
        )
        if qualification_enabled:
            # The engine never receives qualification artifact paths. Emit the
            # metadata-only artifacts only after engine and audit closure so a
            # runner cannot replace them with payload-bearing output.
            self._assert_historical_output_identity(output_dir, output_identity)
            write_jsonl(qualification_path, list(case_batch.qualification_records))
            write_jsonl(rejections_path, list(case_batch.rejection_records))
            self._assert_historical_output_identity(output_dir, output_identity)
            self._verify_qualification_artifacts(
                qualification_path=qualification_path,
                rejections_path=rejections_path,
                expected_accounting=case_batch.qualification_records,
                expected_rejections=case_batch.rejection_records,
            )

        # Deliberately load evaluator-only adjudications only after decision execution
        # and read-only safety validation have completed.
        adjudications: list[dict[str, Any]] = []
        if adjudication_entry is not None and frozen_adjudications is not None:
            self._assert_historical_output_identity(output_dir, output_identity)
            input_snapshots = self._snapshot_frozen_manifest_input(
                snapshots=input_snapshots,
                frozen=frozen_adjudications,
                owner_only=gate_b is not None,
            )
            self._verify_snapshot_integrity(input_snapshots)
            self._revalidate_gate_b_snapshot(input_snapshots, expected=gate_b)
            snapshotted_adjudication_entry = replace(
                adjudication_entry,
                resolved_path=input_snapshots.paths["adjudications"],
            )
            try:
                adjudications = self._adapter.load_adjudications(
                    snapshotted_adjudication_entry,
                    known_case_ids=expected_case_ids,
                )
            except Exception:
                if gate_b is not None:
                    raise GateBValidationError(
                        "Historical adjudication validation failed."
                    ) from None
                raise
        comparisons = build_comparisons(decisions, adjudications)
        self._assert_historical_output_identity(output_dir, output_identity)
        write_jsonl(comparisons_path, comparisons)
        self._assert_historical_output_identity(output_dir, output_identity)

        metrics = compute_replay_metrics(
            dataset_id=manifest.dataset_id,
            data_origin=manifest.data_origin,
            historical_case_count=manifest.historical_case_count,
            execution_mode=execution_mode.value,
            decisions=decisions,
            adjudications=adjudications,
            audit_assurance=audit_assurance,
            qualification_records=(
                list(case_batch.qualification_records)
                if qualification_enabled
                else None
            ),
        )
        if gate_b_summary is not None:
            metrics["gate_b_preflight"] = deepcopy(gate_b_summary)
        assurance = metrics["read_only_assurance"]
        if any(
            assurance[name] != 0
            for name in (
                "authorization_tokens_issued",
                "broker_invocations",
                "operational_effects",
                "action_results",
            )
        ):
            raise ReplaySafetyViolation(
                "Replay metrics report a non-zero execution effect."
            )
        self._assert_historical_output_identity(output_dir, output_identity)
        write_json(metrics_path, metrics)
        self._assert_historical_output_identity(output_dir, output_identity)
        self._verify_snapshot_integrity(input_snapshots)
        self._revalidate_gate_b_snapshot(input_snapshots, expected=gate_b)
        if qualification_enabled:
            self._verify_qualification_artifacts(
                qualification_path=qualification_path,
                rejections_path=rejections_path,
                expected_accounting=case_batch.qualification_records,
                expected_rejections=case_batch.rejection_records,
            )

        artifact_manifest = self._build_run_manifest(
            manifest=manifest,
            execution_mode=execution_mode,
            paths=paths,
            normalized_path=normalized_path,
            diagnostics_path=diagnostics_path,
            deterministic_path=deterministic_path,
            comparisons_path=comparisons_path,
            metrics_path=metrics_path,
            raw_decisions_path=raw_decisions_path,
            audit_path=audit_path,
            normalized_count=len(normalized_cases),
            decision_count=len(deterministic_decisions),
            comparison_count=len(comparisons),
            audit_assurance=audit_assurance,
            input_snapshots=input_snapshots,
            qualification_path=(qualification_path if qualification_enabled else None),
            rejections_path=(rejections_path if qualification_enabled else None),
            qualification_count=len(case_batch.qualification_records),
            rejection_count=len(case_batch.rejection_records),
            gate_b_summary=gate_b_summary,
        )
        self._assert_historical_output_identity(output_dir, output_identity)
        write_json(run_manifest_path, artifact_manifest)
        self._assert_historical_output_identity(output_dir, output_identity)
        return ReplayRunResult(
            dataset_id=manifest.dataset_id,
            data_origin=manifest.data_origin,
            historical_case_count=manifest.historical_case_count,
            execution_mode=execution_mode.value,
            output_dir=output_dir,
            normalized_cases_path=normalized_path,
            normalization_diagnostics_path=diagnostics_path,
            raw_decisions_path=raw_decisions_path,
            deterministic_decisions_path=deterministic_path,
            comparisons_path=comparisons_path,
            metrics_path=metrics_path,
            audit_path=audit_path,
            run_manifest_path=run_manifest_path,
            metrics=deepcopy(metrics),
            qualification_accounting_path=(
                qualification_path if qualification_enabled else None
            ),
            rejections_path=(rejections_path if qualification_enabled else None),
            gate_b_preflight=deepcopy(gate_b_summary),
        )

    def _run_historical(
        self,
        *,
        paths: dict[str, Path],
        manifest_control: ManifestControl,
        gate_b: GateBAuthorization,
    ) -> ReplayRunResult:
        """Run the historical path without granting the runner filesystem paths.

        Historical artifacts are persisted only through retained directory
        descriptors. Cases, model, policy, decisions, and audit records cross the
        decision boundary as in-memory values; adjudication bytes remain private to
        the harness until decision and audit closure.
        """

        output_dir = paths["output_dir"]
        try:
            guard = HistoricalOutputGuard.create(
                self.repository_root,
                self.config.output_dir,
            )
        except HistoricalOutputError:
            raise ReplaySafetyViolation(
                "Historical output custody could not be established."
            ) from None

        try:
            snapshots = self._secure_snapshot_control_inputs(
                guard=guard,
                output_dir=output_dir,
                manifest_control=manifest_control,
                gate_b=gate_b,
            )
            self._verify_secure_snapshot_integrity(
                guard=guard,
                output_dir=output_dir,
                snapshots=snapshots,
            )
            self._verify_gate_b_snapshot_identity(
                snapshots=snapshots,
                expected=gate_b,
            )
            validate_gate_b_current(gate_b)
            try:
                manifest = self._load_manifest(
                    paths["dataset_manifest"],
                    expected_source_sha256=manifest_control.source_sha256,
                    defer_adjudication_content_validation=True,
                )
                self._validate_historical_manifest_file_identities(manifest)
            except Exception:
                raise GateBValidationError(
                    "Historical manifest or source integrity validation failed."
                ) from None

            cases_entry = manifest.file_for_role("cases")
            adjudication_entry = manifest.file_for_role("adjudications")
            assert cases_entry is not None
            assert adjudication_entry is not None
            frozen_cases = self._freeze_manifest_input(cases_entry)
            frozen_adjudications = self._freeze_manifest_input(adjudication_entry)
            if (frozen_cases.device, frozen_cases.inode) == (
                frozen_adjudications.device,
                frozen_adjudications.inode,
            ):
                raise GateBValidationError(
                    "Historical cases and adjudications require distinct regular source files."
                )
            snapshots = self._secure_snapshot_frozen_input(
                guard=guard,
                output_dir=output_dir,
                snapshots=snapshots,
                frozen=frozen_cases,
            )

            if self.config.record_failure_policy != "QUARANTINE_RECORD":
                raise GateBValidationError(
                    "Historical replay requires the governed qualification policy."
                )
            qualification = qualify_case_bytes(
                frozen_cases.content,
                frozen_cases.sha256,
                dataset_id=manifest.dataset_id,
            )
            case_batch = AdapterCaseBatch(
                records=qualification.accepted_records,
                qualification_records=qualification.accounting_records,
                rejection_records=qualification.rejection_records,
            )
            self._validate_qualification_batch(
                case_batch,
                cases_entry=cases_entry,
                dataset_id=manifest.dataset_id,
                source_content=frozen_cases.content,
            )
            if not case_batch.records:
                raise ReplaySafetyViolation(
                    "Record qualification accepted no cases; refusing an empty replay."
                )

            gate_b_summary = self._evaluate_gate_b_scope(gate_b, case_batch)
            self._gate_b_preflight_summary = deepcopy(gate_b_summary)
            normalized_cases, normalization_diagnostics = (
                normalize_cases_with_diagnostics(
                    case_batch.records,
                    mapping_warnings=case_batch.mapping_warnings,
                )
            )
            normalization_diagnostics["record_qualification"] = {
                "failure_policy": self.config.record_failure_policy,
                "input_records": len(case_batch.qualification_records),
                "accepted_records": len(case_batch.records),
                "rejected_records": len(case_batch.rejection_records),
            }
            expected_case_ids = {row["case_id"] for row in normalized_cases}

            normalized_path = guard.display_path_for("normalized_cases.jsonl")
            diagnostics_path = guard.display_path_for("normalization_diagnostics.json")
            raw_decisions_path = guard.display_path_for("engine_decisions.jsonl")
            deterministic_path = guard.display_path_for("replay_decisions.jsonl")
            comparisons_path = guard.display_path_for("adjudication_comparison.jsonl")
            metrics_path = guard.display_path_for("replay_metrics.json")
            audit_path = guard.display_path_for("replay_audit.jsonl")
            run_manifest_path = guard.display_path_for("replay_run_manifest.json")
            qualification_path = guard.display_path_for(
                "qualification_accounting.jsonl"
            )
            rejections_path = guard.display_path_for("rejections.jsonl")

            guard.write_jsonl("normalized_cases.jsonl", normalized_cases)
            guard.write_json(
                "normalization_diagnostics.json", normalization_diagnostics
            )
            execution_mode = ExecutionMode[self.config.execution_mode]
            self._verify_secure_snapshot_integrity(
                guard=guard,
                output_dir=output_dir,
                snapshots=snapshots,
            )
            self._verify_gate_b_snapshot_identity(
                snapshots=snapshots,
                expected=gate_b,
            )
            validate_gate_b_current(gate_b)

            runner = self._default_record_engine_runner()
            try:
                decisions, audit_rows = runner(
                    cases=deepcopy(normalized_cases),
                    model_bytes=bytes(gate_b.model_bytes),
                    policy_bytes=bytes(gate_b.policy_bytes),
                    execution_mode=execution_mode,
                )
            except Exception:
                raise ReplaySafetyViolation(
                    "Historical decision processing failed."
                ) from None
            validate_gate_b_current(gate_b)
            guard.write_jsonl("engine_decisions.jsonl", decisions)
            guard.write_jsonl("replay_audit.jsonl", audit_rows)
            decisions = guard.read_jsonl("engine_decisions.jsonl")
            audit_rows = guard.read_jsonl("replay_audit.jsonl")
            self._validate_read_only_decisions(
                decisions,
                expected_case_ids=expected_case_ids,
                execution_mode=execution_mode,
            )
            deterministic_decisions = [
                self._deterministic_projection(row)
                for row in sorted(decisions, key=lambda value: value["case_id"])
            ]
            guard.write_jsonl("replay_decisions.jsonl", deterministic_decisions)
            audit_assurance = self._validate_audit_assurance(
                audit_path,
                decisions=decisions,
                audit_rows=audit_rows,
            )

            guard.write_jsonl(
                "qualification_accounting.jsonl",
                list(case_batch.qualification_records),
            )
            guard.write_jsonl(
                "rejections.jsonl",
                list(case_batch.rejection_records),
            )
            self._verify_secure_qualification_artifacts(
                guard=guard,
                expected_accounting=case_batch.qualification_records,
                expected_rejections=case_batch.rejection_records,
            )

            # Only now may evaluator labels be snapshotted and semantically decoded.
            snapshots = self._secure_snapshot_frozen_input(
                guard=guard,
                output_dir=output_dir,
                snapshots=snapshots,
                frozen=frozen_adjudications,
            )
            self._verify_secure_snapshot_integrity(
                guard=guard,
                output_dir=output_dir,
                snapshots=snapshots,
            )
            self._verify_gate_b_snapshot_identity(
                snapshots=snapshots,
                expected=gate_b,
            )
            try:
                adjudications = validate_adjudication_records(
                    load_jsonl_bytes(
                        frozen_adjudications.content,
                        label="replay adjudications",
                    ),
                    known_case_ids=expected_case_ids,
                )
            except Exception:
                raise GateBValidationError(
                    "Historical adjudication validation failed."
                ) from None
            comparisons = build_comparisons(decisions, adjudications)
            guard.write_jsonl("adjudication_comparison.jsonl", comparisons)

            metrics = compute_replay_metrics(
                dataset_id=manifest.dataset_id,
                data_origin=manifest.data_origin,
                historical_case_count=manifest.historical_case_count,
                execution_mode=execution_mode.value,
                decisions=decisions,
                adjudications=adjudications,
                audit_assurance=audit_assurance,
                qualification_records=list(case_batch.qualification_records),
            )
            metrics["gate_b_preflight"] = deepcopy(gate_b_summary)
            assurance = metrics["read_only_assurance"]
            if any(
                assurance[name] != 0
                for name in (
                    "authorization_tokens_issued",
                    "broker_invocations",
                    "operational_effects",
                    "action_results",
                )
            ):
                raise ReplaySafetyViolation(
                    "Replay metrics report a non-zero execution effect."
                )
            guard.write_json("replay_metrics.json", metrics)
            self._verify_secure_snapshot_integrity(
                guard=guard,
                output_dir=output_dir,
                snapshots=snapshots,
            )
            self._verify_gate_b_snapshot_identity(
                snapshots=snapshots,
                expected=gate_b,
            )
            self._verify_secure_qualification_artifacts(
                guard=guard,
                expected_accounting=case_batch.qualification_records,
                expected_rejections=case_batch.rejection_records,
            )
            validate_gate_b_current(gate_b)

            artifact_manifest = self._build_run_manifest(
                manifest=manifest,
                execution_mode=execution_mode,
                paths=paths,
                normalized_path=normalized_path,
                diagnostics_path=diagnostics_path,
                deterministic_path=deterministic_path,
                comparisons_path=comparisons_path,
                metrics_path=metrics_path,
                raw_decisions_path=raw_decisions_path,
                audit_path=audit_path,
                normalized_count=len(normalized_cases),
                decision_count=len(deterministic_decisions),
                comparison_count=len(comparisons),
                audit_assurance=audit_assurance,
                input_snapshots=snapshots,
                qualification_path=qualification_path,
                rejections_path=rejections_path,
                qualification_count=len(case_batch.qualification_records),
                rejection_count=len(case_batch.rejection_records),
                gate_b_summary=gate_b_summary,
                output_guard=guard,
            )
            validate_gate_b_current(gate_b)
            guard.write_json("replay_run_manifest.json", artifact_manifest)
            guard.verify_bindings()
            return ReplayRunResult(
                dataset_id=manifest.dataset_id,
                data_origin=manifest.data_origin,
                historical_case_count=manifest.historical_case_count,
                execution_mode=execution_mode.value,
                output_dir=output_dir,
                normalized_cases_path=normalized_path,
                normalization_diagnostics_path=diagnostics_path,
                raw_decisions_path=raw_decisions_path,
                deterministic_decisions_path=deterministic_path,
                comparisons_path=comparisons_path,
                metrics_path=metrics_path,
                audit_path=audit_path,
                run_manifest_path=run_manifest_path,
                metrics=deepcopy(metrics),
                qualification_accounting_path=qualification_path,
                rejections_path=rejections_path,
                gate_b_preflight=deepcopy(gate_b_summary),
            )
        except GateBValidationError:
            raise
        except HistoricalOutputError:
            raise ReplaySafetyViolation(
                "Historical output custody could not be preserved."
            ) from None
        except ReplaySafetyViolation:
            raise ReplaySafetyViolation(
                "Historical replay safety validation failed."
            ) from None
        except Exception:
            raise ReplaySafetyViolation(
                "Historical replay failed inside the restricted processing boundary."
            ) from None
        finally:
            guard.close()

    @staticmethod
    def _read_bounded_snapshot_source(
        source: Path,
        *,
        expected_sha256: str,
    ) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            descriptor = os.open(source, flags)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_DECLARED_FILE_BYTES
            ):
                raise OSError
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DECLARED_FILE_BYTES:
                    raise OSError
                chunks.append(chunk)
            final_metadata = os.fstat(descriptor)
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
                "st_nlink",
            )
            if final_metadata.st_nlink != 1 or any(
                getattr(metadata, field) != getattr(final_metadata, field)
                for field in stable_fields
            ):
                raise OSError
            content = b"".join(chunks)
            if hashlib.sha256(content).hexdigest() != expected_sha256:
                raise OSError
            return content
        except OSError:
            raise ReplaySafetyViolation(
                "A governed replay control input could not be frozen safely."
            ) from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _secure_snapshot_control_inputs(
        self,
        *,
        guard: HistoricalOutputGuard,
        output_dir: Path,
        manifest_control: ManifestControl,
        gate_b: GateBAuthorization,
    ) -> RunInputSnapshots:
        configuration_bytes = self._read_bounded_snapshot_source(
            self.config.path,
            expected_sha256=self.config.source_sha256,
        )
        artifact_by_snapshot_role = {
            GATE_B_SNAPSHOT_ROLE_BY_ARTIFACT[artifact.role]: artifact
            for artifact in gate_b.artifacts
        }
        sources: dict[str, tuple[bytes, str, str]] = {
            "configuration": (
                configuration_bytes,
                "input_snapshot/configuration.json",
                self.config.source_sha256,
            ),
            "dataset_manifest": (
                manifest_control.source_bytes,
                "input_snapshot/dataset_manifest.json",
                manifest_control.source_sha256,
            ),
            "model": (
                gate_b.model_bytes,
                "input_snapshot/model.json",
                hashlib.sha256(gate_b.model_bytes).hexdigest(),
            ),
            "policy": (
                gate_b.policy_bytes,
                "input_snapshot/policy.json",
                hashlib.sha256(gate_b.policy_bytes).hexdigest(),
            ),
            "gate_b_authorization": (
                gate_b.source_bytes,
                "input_snapshot/gate_b_authorization.json",
                gate_b.source_sha256,
            ),
        }
        for snapshot_role, artifact in artifact_by_snapshot_role.items():
            sources[snapshot_role] = (
                artifact.content,
                f"input_snapshot/{snapshot_role}.artifact",
                artifact.sha256,
            )

        snapshot_paths: dict[str, Path] = {}
        snapshot_hashes: dict[str, str] = {}
        for role, (content, relative_path, expected_digest) in sources.items():
            if hashlib.sha256(content).hexdigest() != expected_digest:
                raise ReplaySafetyViolation(
                    "A frozen Gate B input no longer matches its approved binding."
                )
            guard.write_bytes(relative_path, content)
            snapshot_paths[role] = output_dir / relative_path
            snapshot_hashes[role] = expected_digest
        return RunInputSnapshots(
            paths=snapshot_paths,
            sha256=snapshot_hashes,
            record_counts={},
        )

    @staticmethod
    def _secure_snapshot_frozen_input(
        *,
        guard: HistoricalOutputGuard,
        output_dir: Path,
        snapshots: RunInputSnapshots,
        frozen: FrozenManifestInput,
    ) -> RunInputSnapshots:
        relative_path = f"input_snapshot/{frozen.role}.jsonl"
        guard.write_bytes(relative_path, frozen.content)
        paths = dict(snapshots.paths)
        hashes = dict(snapshots.sha256)
        counts = dict(snapshots.record_counts)
        paths[frozen.role] = output_dir / relative_path
        hashes[frozen.role] = frozen.sha256
        counts[frozen.role] = frozen.record_count
        return RunInputSnapshots(paths=paths, sha256=hashes, record_counts=counts)

    @staticmethod
    def _verify_secure_snapshot_integrity(
        *,
        guard: HistoricalOutputGuard,
        output_dir: Path,
        snapshots: RunInputSnapshots,
    ) -> None:
        for role, display_path in snapshots.paths.items():
            try:
                relative_path = display_path.relative_to(output_dir).as_posix()
                digest = guard.sha256(relative_path)
                if digest != snapshots.sha256[role]:
                    raise ReplaySafetyViolation(
                        "A historical replay input snapshot changed during the run."
                    )
                if role in snapshots.record_counts:
                    count = guard.count_nonblank_lines(relative_path)
                    if count != snapshots.record_counts[role]:
                        raise ReplaySafetyViolation(
                            "A historical replay input snapshot changed record count."
                        )
            except ReplaySafetyViolation:
                raise
            except (HistoricalOutputError, ValueError, KeyError):
                raise ReplaySafetyViolation(
                    "A historical replay input snapshot is unavailable or invalid."
                ) from None

    @staticmethod
    def _verify_gate_b_snapshot_identity(
        *,
        snapshots: RunInputSnapshots,
        expected: GateBAuthorization,
    ) -> None:
        expected_hashes = {
            "gate_b_authorization": expected.source_sha256,
            "dataset_manifest": expected.dataset_manifest_sha256,
            "model": hashlib.sha256(expected.model_bytes).hexdigest(),
            "policy": hashlib.sha256(expected.policy_bytes).hexdigest(),
        }
        expected_hashes.update(
            {
                GATE_B_SNAPSHOT_ROLE_BY_ARTIFACT[artifact.role]: artifact.sha256
                for artifact in expected.artifacts
            }
        )
        if any(
            snapshots.sha256.get(role) != digest
            for role, digest in expected_hashes.items()
        ):
            raise ReplaySafetyViolation(
                "Gate B snapshots do not match the approved preflight bytes."
            )

    @staticmethod
    def _verify_secure_qualification_artifacts(
        *,
        guard: HistoricalOutputGuard,
        expected_accounting: tuple[dict, ...],
        expected_rejections: tuple[dict, ...],
    ) -> None:
        try:
            accounting = guard.read_jsonl("qualification_accounting.jsonl")
            rejections = guard.read_jsonl("rejections.jsonl")
        except HistoricalOutputError:
            raise ReplaySafetyViolation(
                "Historical qualification artifacts could not be verified."
            ) from None
        if accounting != list(expected_accounting) or rejections != list(
            expected_rejections
        ):
            raise ReplaySafetyViolation(
                "Historical qualification artifacts do not match verified accounting."
            )

    def _validate_qualification_batch(
        self,
        batch: AdapterCaseBatch,
        *,
        cases_entry: ManifestFile,
        dataset_id: str,
        source_content: bytes | None = None,
    ) -> None:
        """Independently verify qualifier output before any accepted case reaches the engine."""

        accounting = list(batch.qualification_records)
        rejections = list(batch.rejection_records)
        if len(accounting) != cases_entry.record_count:
            raise ReplaySafetyViolation(
                "Qualification ledger count does not match the governed source count."
            )
        if len(accounting) != len(batch.records) + len(rejections):
            raise ReplaySafetyViolation(
                "Qualification accounting must equal accepted plus rejected records."
            )
        projected_rejections = [
            row for row in accounting if row.get("status") == "QUARANTINED"
        ]
        if projected_rejections != rejections:
            raise ReplaySafetyViolation(
                "Rejection artifact is not the exact quarantined ledger projection."
            )
        if sum(row.get("status") == "ACCEPTED" for row in accounting) != len(
            batch.records
        ):
            raise ReplaySafetyViolation(
                "Accepted qualification rows do not match accepted case records."
            )

        schema_path = (
            self.repository_root
            / "contracts"
            / "v0.2.0"
            / "replay-qualification.schema.json"
        )
        try:
            schema = json.loads(schema_path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            validator = Draft202012Validator(schema)
        except Exception as exc:
            raise ReplaySafetyViolation(
                f"Qualification schema could not be loaded or validated: {exc}"
            ) from exc

        expected_occurrences: list[tuple[int, int, str]] = []
        try:
            source_handle = (
                io.BytesIO(source_content)
                if source_content is not None
                else cases_entry.resolved_path.open("rb")
            )
            with source_handle as handle:
                physical_line_number = 0
                nonblank_record_number = 0
                while True:
                    raw = handle.readline(MAX_JSONL_LINE_BYTES + 3)
                    if not raw:
                        break
                    physical_line_number += 1
                    if raw.endswith(b"\r\n"):
                        payload = raw[:-2]
                    elif raw.endswith(b"\n"):
                        payload = raw[:-1]
                    else:
                        payload = raw
                    if len(payload) > MAX_JSONL_LINE_BYTES:
                        raise ReplaySafetyViolation(
                            "Qualification source contains an oversized line after qualification."
                        )
                    if not payload.strip():
                        continue
                    nonblank_record_number += 1
                    expected_occurrences.append(
                        (
                            physical_line_number,
                            nonblank_record_number,
                            hashlib.sha256(payload).hexdigest(),
                        )
                    )
        except ReplaySafetyViolation:
            raise
        except OSError as exc:
            raise ReplaySafetyViolation(
                f"Qualification source could not be reread for accounting: {exc}"
            ) from exc

        if len(expected_occurrences) != cases_entry.record_count:
            raise ReplaySafetyViolation(
                "Qualification source occurrence count changed during verification."
            )
        run_ids: set[str] = set()
        for row, expected in zip(accounting, expected_occurrences, strict=True):
            errors = sorted(
                validator.iter_errors(row), key=lambda error: list(error.path)
            )
            if errors:
                raise ReplaySafetyViolation(
                    "Qualification ledger record violates the closed metadata schema."
                )
            if (
                row.get("dataset_id") != dataset_id
                or row.get("source_role") != "cases"
                or row.get("source_file_sha256") != cases_entry.sha256
                or (
                    row.get("physical_line_number"),
                    row.get("nonblank_record_number"),
                    row.get("raw_line_sha256"),
                )
                != expected
            ):
                raise ReplaySafetyViolation(
                    "Qualification ledger does not bind the governed source occurrence."
                )
            run_ids.add(str(row.get("qualification_run_id", "")))
        if len(run_ids) != 1:
            raise ReplaySafetyViolation(
                "Qualification ledger must contain one deterministic run identifier."
            )

        # Bind the adapter's accepted objects to the exact governed source bytes.
        # This second bounded pass prevents an adapter defect from substituting,
        # omitting, or admitting a record while presenting a well-formed ledger.
        if source_content is None:
            independently_qualified = qualify_case_file(
                cases_entry.resolved_path,
                cases_entry.sha256,
                dataset_id=dataset_id,
            )
        else:
            independently_qualified = qualify_case_bytes(
                source_content,
                cases_entry.sha256,
                dataset_id=dataset_id,
            )
        if (
            independently_qualified.accounting_records != batch.qualification_records
            or independently_qualified.rejection_records != batch.rejection_records
            or independently_qualified.accepted_records != batch.records
        ):
            raise ReplaySafetyViolation(
                "Qualification output does not match independent source requalification."
            )

    @staticmethod
    def _verify_qualification_artifacts(
        *,
        qualification_path: Path,
        rejections_path: Path,
        expected_accounting: tuple[dict, ...],
        expected_rejections: tuple[dict, ...],
    ) -> None:
        """Reject any on-disk qualification mutation before run finalization."""

        try:
            accounting = read_jsonl(qualification_path)
            rejections = read_jsonl(rejections_path)
        except (OSError, UnicodeError, ValueError, TypeError) as exc:
            raise ReplaySafetyViolation(
                f"Qualification artifacts could not be decoded: {exc}"
            ) from exc
        if accounting != list(expected_accounting):
            raise ReplaySafetyViolation(
                "On-disk qualification accounting does not match verified in-memory records."
            )
        if rejections != list(expected_rejections):
            raise ReplaySafetyViolation(
                "On-disk rejection accounting does not match verified in-memory records."
            )

    @staticmethod
    def _write_snapshot_bytes(
        *,
        name: str,
        destination: Path,
        content: bytes,
        expected_sha256: str,
        owner_only: bool,
    ) -> str:
        actual_digest = hashlib.sha256(content).hexdigest()
        if actual_digest != expected_sha256:
            raise ReplaySafetyViolation(
                f"Replay input {name!r} changed before it could be snapshotted."
            )
        try:
            with destination.open("xb") as handle:
                handle.write(content)
            if owner_only:
                os.chmod(destination, 0o600)
        except OSError:
            raise ReplaySafetyViolation(
                f"Unable to write replay input snapshot {name!r}."
            ) from None
        return actual_digest

    @staticmethod
    def _copy_snapshot_file(
        *,
        name: str,
        source: Path,
        destination: Path,
        expected_sha256: str | None,
        owner_only: bool,
    ) -> str:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(source, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                raise OSError
            if metadata.st_size > MAX_DECLARED_FILE_BYTES:
                raise ReplaySafetyViolation(
                    f"Replay input {name!r} exceeds its size limit."
                )
            with os.fdopen(descriptor, "rb") as source_handle:
                descriptor = -1
                with destination.open("xb") as destination_handle:
                    copied = 0
                    while True:
                        chunk = source_handle.read(1024 * 1024)
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > MAX_DECLARED_FILE_BYTES:
                            raise ReplaySafetyViolation(
                                f"Replay input {name!r} exceeds its size limit."
                            )
                        destination_handle.write(chunk)
            if owner_only:
                os.chmod(destination, 0o600)
            destination_digest = sha256_file(destination)
        except ReplaySafetyViolation:
            raise
        except OSError:
            raise ReplaySafetyViolation(
                f"Unable to snapshot replay input {name!r}."
            ) from None
        finally:
            if "descriptor" in locals() and descriptor >= 0:
                os.close(descriptor)
        if expected_sha256 is not None and destination_digest != expected_sha256:
            raise ReplaySafetyViolation(
                f"Replay input {name!r} changed while it was being snapshotted."
            )
        return destination_digest

    def _snapshot_control_inputs(
        self,
        *,
        output_dir: Path,
        manifest_control: ManifestControl,
        paths: dict[str, Path],
        gate_b: GateBAuthorization | None,
    ) -> RunInputSnapshots:
        snapshot_dir = output_dir / "input_snapshot"
        snapshot_dir.mkdir(parents=True, exist_ok=False, mode=0o700)
        if gate_b is not None:
            os.chmod(snapshot_dir, 0o700)
        snapshot_paths: dict[str, Path] = {}
        snapshot_hashes: dict[str, str] = {}
        owner_only = gate_b is not None

        def copy_source(
            name: str,
            source: Path,
            destination_name: str,
            *,
            expected_sha256: str | None = None,
        ) -> None:
            destination = snapshot_dir / destination_name
            destination_digest = self._copy_snapshot_file(
                name=name,
                source=source,
                destination=destination,
                expected_sha256=expected_sha256,
                owner_only=owner_only,
            )
            snapshot_paths[name] = destination
            snapshot_hashes[name] = destination_digest

        def copy_bytes(
            name: str,
            content: bytes,
            destination_name: str,
            expected_sha256: str,
        ) -> None:
            destination = snapshot_dir / destination_name
            snapshot_hashes[name] = self._write_snapshot_bytes(
                name=name,
                destination=destination,
                content=content,
                expected_sha256=expected_sha256,
                owner_only=owner_only,
            )
            snapshot_paths[name] = destination

        copy_source(
            "configuration",
            self.config.path,
            "configuration.json",
            expected_sha256=self.config.source_sha256,
        )
        copy_bytes(
            "dataset_manifest",
            manifest_control.source_bytes,
            "dataset_manifest.json",
            manifest_control.source_sha256,
        )
        if gate_b is not None:
            model_digest = hashlib.sha256(gate_b.model_bytes).hexdigest()
            policy_digest = hashlib.sha256(gate_b.policy_bytes).hexdigest()
            copy_bytes("model", gate_b.model_bytes, "model.json", model_digest)
            copy_bytes("policy", gate_b.policy_bytes, "policy.json", policy_digest)
            copy_bytes(
                "gate_b_authorization",
                gate_b.source_bytes,
                "gate_b_authorization.json",
                gate_b.source_sha256,
            )
            for artifact in gate_b.artifacts:
                snapshot_role = GATE_B_SNAPSHOT_ROLE_BY_ARTIFACT[artifact.role]
                copy_bytes(
                    snapshot_role,
                    artifact.content,
                    f"{snapshot_role}.artifact",
                    artifact.sha256,
                )
        else:
            copy_source("model", paths["model_path"], "model.json")
            copy_source("policy", paths["policy_path"], "policy.json")
        snapshots = RunInputSnapshots(
            paths=snapshot_paths,
            sha256=snapshot_hashes,
            record_counts={},
        )
        self._verify_snapshot_integrity(snapshots)
        return snapshots

    def _snapshot_manifest_roles(
        self,
        *,
        snapshots: RunInputSnapshots,
        manifest: ReplayManifest,
        roles: set[str],
        owner_only: bool,
    ) -> RunInputSnapshots:
        snapshot_dir = next(iter(snapshots.paths.values())).parent
        paths = dict(snapshots.paths)
        hashes = dict(snapshots.sha256)
        counts = dict(snapshots.record_counts)
        matched: set[str] = set()
        for entry in manifest.files:
            if entry.role not in roles:
                continue
            destination = snapshot_dir / f"{entry.role}.jsonl"
            digest = self._copy_snapshot_file(
                name=entry.role,
                source=entry.resolved_path,
                destination=destination,
                expected_sha256=entry.sha256,
                owner_only=owner_only,
            )
            try:
                actual_count = count_jsonl_records(destination)
            except ContractValidationError:
                raise ReplaySafetyViolation(
                    f"Replay input snapshot {entry.role!r} cannot be counted safely."
                ) from None
            if actual_count != entry.record_count:
                raise ReplaySafetyViolation(
                    f"Replay input snapshot {entry.role!r} has an unexpected record count."
                )
            paths[entry.role] = destination
            hashes[entry.role] = digest
            counts[entry.role] = entry.record_count
            matched.add(entry.role)
        if matched != roles:
            raise ReplaySafetyViolation("Required replay input roles are unavailable.")
        result = RunInputSnapshots(paths=paths, sha256=hashes, record_counts=counts)
        self._verify_snapshot_integrity(result)
        return result

    @staticmethod
    def _freeze_manifest_input(entry: ManifestFile) -> FrozenManifestInput:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(entry.resolved_path, flags)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_size > MAX_DECLARED_FILE_BYTES
            ):
                raise OSError
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > MAX_DECLARED_FILE_BYTES:
                    raise OSError
            final_metadata = os.fstat(descriptor)
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
                "st_nlink",
            )
            if final_metadata.st_nlink != 1 or any(
                getattr(metadata, field) != getattr(final_metadata, field)
                for field in stable_fields
            ):
                raise OSError
            metadata = final_metadata
        except OSError:
            raise ReplaySafetyViolation(
                f"Unable to freeze replay input {entry.role!r}."
            ) from None
        finally:
            if "descriptor" in locals():
                os.close(descriptor)
        content = b"".join(chunks)
        if hashlib.sha256(content).hexdigest() != entry.sha256:
            raise ReplaySafetyViolation(
                f"Replay input {entry.role!r} changed before decision closure."
            )
        count = 0
        for line in content.splitlines(keepends=True):
            if len(line) > MAX_JSONL_LINE_BYTES:
                raise ReplaySafetyViolation(
                    f"Replay input {entry.role!r} contains an oversized line."
                )
            if line.strip():
                count += 1
        if count != entry.record_count:
            raise ReplaySafetyViolation(
                f"Replay input {entry.role!r} has an unexpected record count."
            )
        return FrozenManifestInput(
            role=entry.role,
            content=content,
            sha256=entry.sha256,
            record_count=entry.record_count,
            device=metadata.st_dev,
            inode=metadata.st_ino,
        )

    def _snapshot_frozen_manifest_input(
        self,
        *,
        snapshots: RunInputSnapshots,
        frozen: FrozenManifestInput,
        owner_only: bool,
    ) -> RunInputSnapshots:
        snapshot_dir = next(iter(snapshots.paths.values())).parent
        destination = snapshot_dir / f"{frozen.role}.jsonl"
        self._write_snapshot_bytes(
            name=frozen.role,
            destination=destination,
            content=frozen.content,
            expected_sha256=frozen.sha256,
            owner_only=owner_only,
        )
        paths = dict(snapshots.paths)
        hashes = dict(snapshots.sha256)
        counts = dict(snapshots.record_counts)
        paths[frozen.role] = destination
        hashes[frozen.role] = frozen.sha256
        counts[frozen.role] = frozen.record_count
        result = RunInputSnapshots(paths=paths, sha256=hashes, record_counts=counts)
        self._verify_snapshot_integrity(result)
        return result

    def _revalidate_gate_b_snapshot(
        self,
        snapshots: RunInputSnapshots,
        *,
        expected: GateBAuthorization | None,
    ) -> GateBAuthorization | None:
        if expected is None:
            return None
        required_snapshot_roles = {
            "gate_b_authorization",
            "dataset_manifest",
            "model",
            "policy",
            *GATE_B_SNAPSHOT_ROLE_BY_ARTIFACT.values(),
        }
        if not required_snapshot_roles.issubset(snapshots.paths):
            raise ReplaySafetyViolation("Gate B input snapshots are incomplete.")
        manifest_control = load_manifest_control(snapshots.paths["dataset_manifest"])
        artifact_overrides = {
            role: snapshots.paths[snapshot_role]
            for role, snapshot_role in GATE_B_SNAPSHOT_ROLE_BY_ARTIFACT.items()
        }
        revalidated = load_gate_b_authorization(
            snapshots.paths["gate_b_authorization"],
            repository_root=self.repository_root,
            manifest=manifest_control,
            config=self.config,
            model_path=snapshots.paths["model"],
            policy_path=snapshots.paths["policy"],
            artifact_path_overrides=artifact_overrides,
        )
        if (
            revalidated.source_sha256 != expected.source_sha256
            or revalidated.authorization_id != expected.authorization_id
            or revalidated.dataset_manifest_sha256 != expected.dataset_manifest_sha256
        ):
            raise ReplaySafetyViolation(
                "Gate B authorization snapshot does not match the approved preflight."
            )
        return revalidated

    @staticmethod
    def _verify_snapshot_integrity(snapshots: RunInputSnapshots) -> None:
        for name, path in snapshots.paths.items():
            try:
                actual_digest = sha256_file(path)
            except OSError:
                raise ReplaySafetyViolation(
                    f"Snapshotted replay input {name!r} is unavailable."
                ) from None
            if actual_digest != snapshots.sha256[name]:
                raise ReplaySafetyViolation(
                    f"Snapshotted replay input {name!r} changed during the run."
                )
            if name in snapshots.record_counts:
                try:
                    actual_count = count_jsonl_records(path)
                except ContractValidationError:
                    raise ReplaySafetyViolation(
                        f"Snapshotted replay input {name!r} cannot be counted safely."
                    ) from None
                if actual_count != snapshots.record_counts[name]:
                    raise ReplaySafetyViolation(
                        f"Snapshotted replay input {name!r} changed record count during the run."
                    )

    @staticmethod
    def _default_engine_runner() -> EngineRunner:
        from adf_poc.engine import run_engine

        return run_engine

    @staticmethod
    def _default_record_engine_runner() -> RecordEngineRunner:
        from adf_poc.engine import DecisionFirewallEngine
        from adf_poc.model import LogisticRiskModel
        from adf_poc.policy import PolicyConfig
        from adf_poc.schemas import IdentityCase

        def run_records(
            *,
            cases: list[dict[str, Any]],
            model_bytes: bytes,
            policy_bytes: bytes,
            execution_mode: ExecutionMode,
        ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
            model_value = json.loads(model_bytes.decode("utf-8"))
            policy_value = json.loads(policy_bytes.decode("utf-8"))
            if not isinstance(model_value, dict) or not isinstance(policy_value, dict):
                raise ValueError("Model and policy inputs must be JSON objects.")
            audit = AuditLogger(None)
            engine = DecisionFirewallEngine(
                model=LogisticRiskModel.from_dict(model_value),
                policy_config=PolicyConfig(**policy_value),
                audit_logger=audit,
                execution_mode=execution_mode,
            )
            decisions = [engine.process(IdentityCase.from_dict(row)) for row in cases]
            return decisions, audit.read_all()

        return run_records

    @staticmethod
    def _validate_read_only_decisions(
        decisions: list[dict[str, Any]],
        *,
        expected_case_ids: set[str],
        execution_mode: ExecutionMode,
    ) -> None:
        if len(decisions) != len(expected_case_ids):
            raise ReplaySafetyViolation(
                "The engine must emit exactly one decision for every normalized case."
            )
        decision_case_ids: set[str] = set()
        for index, decision in enumerate(decisions):
            if not isinstance(decision, dict):
                raise ReplaySafetyViolation(f"Decision {index} is not a JSON object.")
            case_id = decision.get("case_id")
            if case_id not in expected_case_ids or case_id in decision_case_ids:
                raise ReplaySafetyViolation(
                    f"Decision {index} has an unknown or duplicate case_id {case_id!r}."
                )
            decision_case_ids.add(str(case_id))
            if decision.get("execution_mode") != execution_mode.value:
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} does not declare {execution_mode.value!r}."
                )
            if decision.get("final_disposition") not in ALLOWED_DISPOSITIONS:
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} contains an unsupported disposition."
                )
            probability = decision.get("compromise_probability")
            if (
                isinstance(probability, bool)
                or not isinstance(probability, (int, float))
                or not 0.0 <= float(probability) <= 1.0
            ):
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} has an invalid compromise probability."
                )
            proposal = decision.get("proposal")
            if (
                not isinstance(proposal, dict)
                or proposal.get("executable_actions") != []
            ):
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} retained executable actions in read-only mode."
                )
            authorization = decision.get("authorization")
            expected_authorization = {
                "issued": False,
                "token_id": "",
                "decision_hash": "",
                "permitted_actions": [],
                "error": "",
            }
            if authorization != expected_authorization:
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} retained authorization state in read-only mode."
                )
            if decision.get("action_results") != []:
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} contains action execution results."
                )
            counterfactual = decision.get("counterfactual_actions")
            if not isinstance(counterfactual, list) or not all(
                isinstance(action, str) for action in counterfactual
            ):
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} has invalid counterfactual actions."
                )
            control = decision.get("execution_control")
            expected_control = {
                "mode": execution_mode.value,
                "read_only": True,
                "status": "SUPPRESSED_READ_ONLY",
                "authorization_attempted": False,
                "broker_invocations": 0,
                "operational_effects": 0,
            }
            if control != expected_control:
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} violates the read-only execution-control contract."
                )
            expected_post_action = {
                "applicable": False,
                "status": "NOT_APPLICABLE",
                "passed": None,
                "checks": [],
            }
            if decision.get("post_action_verification") != expected_post_action:
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} misrepresents read-only post-action verification."
                )
            decision_id = decision.get("decision_id")
            stored_hash = decision.get("decision_record_hash")
            if not isinstance(decision_id, str) or not decision_id:
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} has no stable decision identifier."
                )
            if not isinstance(stored_hash, str) or len(stored_hash) != 64:
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} has no valid decision-record hash."
                )
            hash_input = dict(decision)
            hash_input.pop("decision_record_hash", None)
            if sha256_json(hash_input) != stored_hash:
                raise ReplaySafetyViolation(
                    f"Decision {case_id!r} does not match its decision-record hash."
                )
        if decision_case_ids != expected_case_ids:
            raise ReplaySafetyViolation(
                "Decision case IDs do not match normalized input case IDs."
            )

    @staticmethod
    def _deterministic_projection(decision: dict[str, Any]) -> dict[str, Any]:
        value = {
            "schema_version": "0.2.0",
            "case_id": decision["case_id"],
            "execution_mode": decision["execution_mode"],
            "final_disposition": decision["final_disposition"],
            "compromise_probability": float(decision["compromise_probability"]),
            "evidence_quality": float(
                decision.get("evidence_assessment", {}).get("evidence_quality", 0.0)
            ),
            "policy_rules_applied": list(
                decision.get("proposal", {}).get("policy_rules_applied", [])
            ),
            "cited_evidence_event_ids": sorted(
                decision.get("proposal", {}).get("evidence_event_ids", [])
            ),
            "counterfactual_actions": list(decision.get("counterfactual_actions", [])),
            "authorization_issued": False,
            "broker_invocations": 0,
            "operational_effects": 0,
        }
        return value

    @staticmethod
    def _validate_audit_assurance(
        audit_path: Path,
        *,
        decisions: list[dict[str, Any]],
        audit_rows: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        try:
            valid, errors = (
                AuditLogger.verify_rows(audit_rows)
                if audit_rows is not None
                else AuditLogger.verify(audit_path)
            )
        except (
            OSError,
            UnicodeError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
        ) as exc:
            raise ReplaySafetyViolation(
                f"Replay audit evidence could not be decoded or verified: {exc}"
            ) from exc
        if not valid:
            raise ReplaySafetyViolation(
                "Replay audit chain is invalid: " + "; ".join(errors)
            )
        if audit_rows is None:
            try:
                rows = AuditLogger(audit_path).read_all()
            except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
                raise ReplaySafetyViolation(
                    f"Replay audit evidence could not be read after verification: {exc}"
                ) from exc
        else:
            rows = deepcopy(audit_rows)
        allowed_record_types = {
            "CASE_RECEIVED",
            "EVIDENCE_ASSESSED",
            "MODEL_ASSESSED",
            "POLICY_PROPOSED",
            "INDEPENDENTLY_VERIFIED",
            "EXECUTION_SUPPRESSED",
            "AUTHORIZATION_EVALUATED",
            "DECISION_FINALIZED",
        }
        if any(row.get("record_type") not in allowed_record_types for row in rows):
            raise ReplaySafetyViolation(
                "Replay audit evidence contains a record type outside the read-only contract."
            )
        suppression_rows = [
            row for row in rows if row.get("record_type") == "EXECUTION_SUPPRESSED"
        ]
        authorization_rows = [
            row for row in rows if row.get("record_type") == "AUTHORIZATION_EVALUATED"
        ]
        finalization_rows = [
            row for row in rows if row.get("record_type") == "DECISION_FINALIZED"
        ]
        action_rows = [
            row
            for row in rows
            if row.get("record_type")
            in {"ACTION_EXECUTED", "ACTION_REJECTED", "POST_ACTION_VERIFIED"}
        ]
        decisions_by_case = {str(row["case_id"]): row for row in decisions}
        expected_case_ids = set(decisions_by_case)

        def rows_by_case(
            records: list[dict[str, Any]], record_type: str
        ) -> dict[str, dict[str, Any]]:
            indexed: dict[str, dict[str, Any]] = {}
            for record in records:
                payload = record.get("payload")
                if not isinstance(payload, dict):
                    raise ReplaySafetyViolation(
                        f"{record_type} audit record has no structured payload."
                    )
                case_id = str(payload.get("case_id", ""))
                if case_id in indexed:
                    raise ReplaySafetyViolation(
                        f"Audit evidence contains duplicate {record_type} records for {case_id!r}."
                    )
                indexed[case_id] = payload
            return indexed

        suppression_by_case = rows_by_case(suppression_rows, "EXECUTION_SUPPRESSED")
        authorization_by_case = rows_by_case(
            authorization_rows, "AUTHORIZATION_EVALUATED"
        )
        finalization_by_case = rows_by_case(finalization_rows, "DECISION_FINALIZED")
        if set(suppression_by_case) != expected_case_ids:
            raise ReplaySafetyViolation(
                "Audit evidence must contain exactly one EXECUTION_SUPPRESSED record per decision."
            )
        if set(authorization_by_case) != expected_case_ids:
            raise ReplaySafetyViolation(
                "Audit evidence must contain exactly one AUTHORIZATION_EVALUATED record per decision."
            )
        if set(finalization_by_case) != expected_case_ids:
            raise ReplaySafetyViolation(
                "Audit evidence must contain exactly one DECISION_FINALIZED record per decision."
            )

        for case_id, decision in decisions_by_case.items():
            suppression = suppression_by_case[case_id]
            if (
                suppression.get("execution_mode") != decision["execution_mode"]
                or suppression.get("authorization_attempted") is not False
                or suppression.get("broker_invocations") != 0
                or suppression.get("operational_effects") != 0
                or suppression.get("counterfactual_actions")
                != decision.get("counterfactual_actions", [])
            ):
                raise ReplaySafetyViolation(
                    f"EXECUTION_SUPPRESSED audit payload for {case_id!r} violates the read-only contract."
                )
            authorization = authorization_by_case[case_id]
            if (
                authorization.get("execution_mode") != decision["execution_mode"]
                or authorization.get("attempted") is not False
                or authorization.get("issued") is not False
                or authorization.get("token_id", "") != ""
                or authorization.get("permitted_actions", []) != []
                or authorization.get("error", "") != decision["authorization"]["error"]
            ):
                raise ReplaySafetyViolation(
                    f"AUTHORIZATION_EVALUATED audit payload for {case_id!r} violates the read-only contract."
                )
            finalization = finalization_by_case[case_id]
            if (
                finalization.get("decision_id") != decision["decision_id"]
                or finalization.get("final_disposition")
                != decision["final_disposition"]
                or finalization.get("decision_record_hash")
                != decision["decision_record_hash"]
            ):
                raise ReplaySafetyViolation(
                    f"DECISION_FINALIZED audit payload for {case_id!r} does not bind the decision."
                )
        if action_rows:
            raise ReplaySafetyViolation(
                "Replay audit evidence contains an action or post-action record."
            )
        return {
            "audit_validation_enforced": True,
            "audit_chain_valid": True,
            "audit_record_count": len(rows),
            "execution_suppression_records": len(suppression_rows),
            "authorization_evaluated_records": len(authorization_rows),
            "decision_finalized_records": len(finalization_rows),
            "action_executed_audit_records": 0,
        }

    def _build_run_manifest(
        self,
        *,
        manifest: ReplayManifest,
        execution_mode: ExecutionMode,
        paths: dict[str, Path],
        normalized_path: Path,
        diagnostics_path: Path,
        deterministic_path: Path,
        comparisons_path: Path,
        metrics_path: Path,
        raw_decisions_path: Path,
        audit_path: Path,
        normalized_count: int,
        decision_count: int,
        comparison_count: int,
        audit_assurance: dict[str, Any],
        input_snapshots: RunInputSnapshots,
        qualification_path: Path | None,
        rejections_path: Path | None,
        qualification_count: int,
        rejection_count: int,
        gate_b_summary: dict[str, Any] | None,
        output_guard: HistoricalOutputGuard | None = None,
    ) -> dict[str, Any]:
        output_dir = paths["output_dir"]

        def artifact_digest(path: Path) -> str:
            if output_guard is None:
                return sha256_file(path)
            return output_guard.sha256(path.relative_to(output_dir).as_posix())

        def deterministic_artifact(
            path: Path, record_count: int | None
        ) -> dict[str, Any]:
            value: dict[str, Any] = {
                "path": str(path.relative_to(output_dir)),
                "sha256": artifact_digest(path),
            }
            if record_count is not None:
                value["record_count"] = record_count
            return value

        def volatile_artifact(path: Path, record_count: int) -> dict[str, Any]:
            return {
                "path": str(path.relative_to(output_dir)),
                "sha256": artifact_digest(path),
                "record_count": record_count,
            }

        def input_snapshot(name: str) -> dict[str, Any]:
            value: dict[str, Any] = {
                "path": str(input_snapshots.paths[name].relative_to(output_dir)),
                "sha256": input_snapshots.sha256[name],
            }
            if name in input_snapshots.record_counts:
                value["record_count"] = input_snapshots.record_counts[name]
            return value

        value: dict[str, Any] = {
            "schema_version": "0.2.0",
            "contract_version": "0.2.0",
            "contract_adapter": self.config.contract_adapter,
            "dataset_id": manifest.dataset_id,
            "data_origin": manifest.data_origin,
            "historical_case_count": manifest.historical_case_count,
            "execution_mode": execution_mode.value,
            "live_actions_enabled": False,
            "record_failure_policy": self.config.record_failure_policy,
            "inputs": {
                "configuration": input_snapshot("configuration"),
                "dataset_manifest": input_snapshot("dataset_manifest"),
                "model": input_snapshot("model"),
                "policy": input_snapshot("policy"),
                "declared_files": {
                    entry.role: input_snapshot(entry.role) for entry in manifest.files
                },
                "snapshot_integrity_verified_before_and_after_execution": True,
            },
            "deterministic_artifacts": {
                "normalized_cases": deterministic_artifact(
                    normalized_path, normalized_count
                ),
                "normalization_diagnostics": deterministic_artifact(
                    diagnostics_path, None
                ),
                "replay_decisions": deterministic_artifact(
                    deterministic_path, decision_count
                ),
                "adjudication_comparison": deterministic_artifact(
                    comparisons_path, comparison_count
                ),
                "replay_metrics": deterministic_artifact(metrics_path, None),
            },
            "volatile_engine_artifacts": {
                "engine_decisions": volatile_artifact(
                    raw_decisions_path, decision_count
                ),
                "audit_log": volatile_artifact(
                    audit_path, int(audit_assurance["audit_record_count"])
                ),
                "reproducibility_note": (
                    "Digests bind this run's raw artifacts; they vary across runs because the "
                    "records contain timestamps, UUIDs, latency, and hash-chain values."
                ),
            },
            "read_only_assurance": {
                "authorization_tokens_issued": 0,
                "broker_invocations": 0,
                "operational_effects": 0,
                **audit_assurance,
            },
        }
        if qualification_path is not None and rejections_path is not None:
            value["deterministic_artifacts"]["qualification_accounting"] = (
                deterministic_artifact(qualification_path, qualification_count)
            )
            value["deterministic_artifacts"]["rejections"] = deterministic_artifact(
                rejections_path, rejection_count
            )
            value["record_qualification"] = {
                "taxonomy_version": QUALIFICATION_TAXONOMY_VERSION,
                "input_records": qualification_count,
                "accepted_records": normalized_count,
                "rejected_records": rejection_count,
                "decision_records": decision_count,
                "complete_accounting_verified": (
                    qualification_count == normalized_count + rejection_count
                    and normalized_count == decision_count
                ),
            }
        if gate_b_summary is not None:
            gate_b_input_roles = (
                "gate_b_authorization",
                *sorted(GATE_B_SNAPSHOT_ROLE_BY_ARTIFACT.values()),
            )
            for role in gate_b_input_roles:
                value["inputs"][role] = input_snapshot(role)
            value["gate_b_preflight"] = dict(gate_b_summary)
        return value
