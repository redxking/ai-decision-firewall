from __future__ import annotations

import hashlib
import json
import shutil
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
    MAX_JSONL_LINE_BYTES,
    ManifestFile,
    ReplayConfig,
    ReplayManifest,
    count_jsonl_records,
    load_and_validate_manifest,
    sha256_file,
)
from .metrics import build_comparisons, compute_replay_metrics
from .normalizer import normalize_cases_with_diagnostics
from .qualification import QUALIFICATION_TAXONOMY_VERSION, qualify_case_file


class ReplaySafetyViolation(RuntimeError):
    """Raised when a replay/shadow run attempts or reports an operational effect."""


EngineRunner = Callable[..., list[dict[str, Any]]]


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


@dataclass(frozen=True, slots=True)
class RunInputSnapshots:
    paths: dict[str, Path]
    sha256: dict[str, str]
    record_counts: dict[str, int]


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

    def validate_inputs(self) -> tuple[ReplayManifest, AdapterCaseBatch]:
        paths = self.config.resolve_paths(self.repository_root)
        manifest = self._load_manifest(paths["dataset_manifest"])
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
        return manifest, case_batch

    def _load_manifest(self, manifest_path: Path) -> ReplayManifest:
        manifest = load_and_validate_manifest(manifest_path)
        if manifest.intended_mode != self.config.execution_mode:
            raise ContractValidationError(
                "Configuration execution_mode does not match the dataset manifest intended_mode."
            )
        return manifest

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
        paths = self.config.resolve_paths(self.repository_root)
        output_dir = paths["output_dir"]
        if output_dir.exists():
            if not output_dir.is_dir():
                raise ReplaySafetyViolation("Configured output_dir exists and is not a directory.")
            if any(output_dir.iterdir()):
                raise ReplaySafetyViolation(
                    "Configured output_dir is non-empty; refusing to overwrite prior replay evidence."
                )
        manifest = self._load_manifest(paths["dataset_manifest"])
        output_dir.mkdir(parents=True, exist_ok=True)
        input_snapshots = self._snapshot_inputs(
            output_dir=output_dir,
            manifest=manifest,
            paths=paths,
        )
        cases_entry = manifest.file_for_role("cases")
        assert cases_entry is not None
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
        write_jsonl(normalized_path, normalized_cases)
        write_json(diagnostics_path, normalization_diagnostics)

        execution_mode = ExecutionMode[self.config.execution_mode]
        runner = self._default_engine_runner()
        runner(
            cases_path=normalized_path,
            model_path=input_snapshots.paths["model"],
            policy_path=input_snapshots.paths["policy"],
            decisions_path=raw_decisions_path,
            audit_path=audit_path,
            execution_mode=execution_mode,
        )
        self._verify_snapshot_integrity(input_snapshots)
        if not raw_decisions_path.exists():
            raise ReplaySafetyViolation("The decision engine did not produce its declared output.")
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
        write_jsonl(deterministic_path, deterministic_decisions)
        audit_assurance = self._validate_audit_assurance(
            audit_path,
            decisions=decisions,
        )
        if qualification_enabled:
            # The engine never receives qualification artifact paths. Emit the
            # metadata-only artifacts only after engine and audit closure so a
            # runner cannot replace them with payload-bearing output.
            write_jsonl(qualification_path, list(case_batch.qualification_records))
            write_jsonl(rejections_path, list(case_batch.rejection_records))
            self._verify_qualification_artifacts(
                qualification_path=qualification_path,
                rejections_path=rejections_path,
                expected_accounting=case_batch.qualification_records,
                expected_rejections=case_batch.rejection_records,
            )

        # Deliberately load evaluator-only adjudications only after decision execution
        # and read-only safety validation have completed.
        adjudication_entry = manifest.file_for_role("adjudications", required=False)
        adjudications: list[dict[str, Any]] = []
        if adjudication_entry is not None:
            cases_entry = manifest.file_for_role("cases")
            assert cases_entry is not None
            if adjudication_entry.resolved_path == cases_entry.resolved_path:
                raise ReplaySafetyViolation(
                    "Cases and adjudications must be stored in physically separate files."
                )
            snapshotted_adjudication_entry = replace(
                adjudication_entry,
                resolved_path=input_snapshots.paths["adjudications"],
            )
            adjudications = self._adapter.load_adjudications(
                snapshotted_adjudication_entry,
                known_case_ids=expected_case_ids,
            )
        comparisons = build_comparisons(decisions, adjudications)
        write_jsonl(comparisons_path, comparisons)

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
            raise ReplaySafetyViolation("Replay metrics report a non-zero execution effect.")
        write_json(metrics_path, metrics)
        self._verify_snapshot_integrity(input_snapshots)
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
        )
        write_json(run_manifest_path, artifact_manifest)
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
            metrics=metrics,
            qualification_accounting_path=(
                qualification_path if qualification_enabled else None
            ),
            rejections_path=(rejections_path if qualification_enabled else None),
        )

    def _validate_qualification_batch(
        self,
        batch: AdapterCaseBatch,
        *,
        cases_entry: ManifestFile,
        dataset_id: str,
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
            with cases_entry.resolved_path.open("rb") as handle:
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
        independently_qualified = qualify_case_file(
            cases_entry.resolved_path,
            cases_entry.sha256,
            dataset_id=dataset_id,
        )
        if (
            independently_qualified.accounting_records
            != batch.qualification_records
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

    def _snapshot_inputs(
        self,
        *,
        output_dir: Path,
        manifest: ReplayManifest,
        paths: dict[str, Path],
    ) -> RunInputSnapshots:
        snapshot_dir = output_dir / "input_snapshot"
        snapshot_dir.mkdir(parents=True, exist_ok=False)
        snapshot_paths: dict[str, Path] = {}
        snapshot_hashes: dict[str, str] = {}
        record_counts: dict[str, int] = {}

        def copy_verified(
            name: str,
            source: Path,
            destination_name: str,
            *,
            expected_sha256: str | None = None,
            record_count: int | None = None,
        ) -> None:
            source_digest = expected_sha256 or sha256_file(source)
            destination = snapshot_dir / destination_name
            try:
                shutil.copyfile(source, destination)
            except OSError as exc:
                raise ReplaySafetyViolation(
                    f"Unable to snapshot replay input {name!r}: {exc}"
                ) from exc
            destination_digest = sha256_file(destination)
            if destination_digest != source_digest:
                raise ReplaySafetyViolation(
                    f"Replay input {name!r} changed while it was being snapshotted."
                )
            if record_count is not None:
                actual_count = count_jsonl_records(destination)
                if actual_count != record_count:
                    raise ReplaySafetyViolation(
                        f"Replay input snapshot {name!r} has an unexpected record count."
                    )
                record_counts[name] = record_count
            snapshot_paths[name] = destination
            snapshot_hashes[name] = destination_digest

        copy_verified(
            "configuration",
            self.config.path,
            "configuration.json",
            expected_sha256=self.config.source_sha256,
        )
        copy_verified(
            "dataset_manifest",
            manifest.path,
            "dataset_manifest.json",
            expected_sha256=manifest.source_sha256,
        )
        copy_verified("model", paths["model_path"], "model.json")
        copy_verified("policy", paths["policy_path"], "policy.json")
        for entry in manifest.files:
            copy_verified(
                entry.role,
                entry.resolved_path,
                f"{entry.role}.jsonl",
                expected_sha256=entry.sha256,
                record_count=entry.record_count,
            )
        snapshots = RunInputSnapshots(
            paths=snapshot_paths,
            sha256=snapshot_hashes,
            record_counts=record_counts,
        )
        self._verify_snapshot_integrity(snapshots)
        return snapshots

    @staticmethod
    def _verify_snapshot_integrity(snapshots: RunInputSnapshots) -> None:
        for name, path in snapshots.paths.items():
            if sha256_file(path) != snapshots.sha256[name]:
                raise ReplaySafetyViolation(
                    f"Snapshotted replay input {name!r} changed during the run."
                )
            if name in snapshots.record_counts:
                actual_count = count_jsonl_records(path)
                if actual_count != snapshots.record_counts[name]:
                    raise ReplaySafetyViolation(
                        f"Snapshotted replay input {name!r} changed record count during the run."
                    )

    @staticmethod
    def _default_engine_runner() -> EngineRunner:
        from adf_poc.engine import run_engine

        return run_engine

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
            if not isinstance(proposal, dict) or proposal.get("executable_actions") != []:
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
            raise ReplaySafetyViolation("Decision case IDs do not match normalized input case IDs.")

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
    ) -> dict[str, Any]:
        try:
            valid, errors = AuditLogger.verify(audit_path)
        except (OSError, UnicodeError, ValueError, TypeError, KeyError, AttributeError) as exc:
            raise ReplaySafetyViolation(
                f"Replay audit evidence could not be decoded or verified: {exc}"
            ) from exc
        if not valid:
            raise ReplaySafetyViolation(
                "Replay audit chain is invalid: " + "; ".join(errors)
            )
        try:
            rows = AuditLogger(audit_path).read_all()
        except (OSError, UnicodeError, ValueError, TypeError, KeyError) as exc:
            raise ReplaySafetyViolation(
                f"Replay audit evidence could not be read after verification: {exc}"
            ) from exc
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

        def rows_by_case(records: list[dict[str, Any]], record_type: str) -> dict[str, dict[str, Any]]:
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
        finalization_by_case = rows_by_case(
            finalization_rows, "DECISION_FINALIZED"
        )
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
                or authorization.get("error", "")
                != decision["authorization"]["error"]
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
    ) -> dict[str, Any]:
        output_dir = paths["output_dir"]

        def deterministic_artifact(path: Path, record_count: int | None) -> dict[str, Any]:
            value: dict[str, Any] = {
                "path": str(path.relative_to(output_dir)),
                "sha256": sha256_file(path),
            }
            if record_count is not None:
                value["record_count"] = record_count
            return value

        def volatile_artifact(path: Path, record_count: int) -> dict[str, Any]:
            return {
                "path": str(path.relative_to(output_dir)),
                "sha256": sha256_file(path),
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
        return value
